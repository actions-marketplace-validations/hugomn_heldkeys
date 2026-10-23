# Running heldkeys in sandboxes

heldkeys answers "which credentials could a hijacked agent use from here?", and *here* has to be where the agent actually runs. A container sees its own environment variables, mounts and service account, not your laptop's. A coding agent's sandbox profile can hide your home directory, or not. Running heldkeys next to the sandbox tells you about the wrong machine.

So every recipe on this page does the same three things: get the static binary into the sandbox, run it there, and read the verdict or the JSON back.

- **`heldkeys preflight`** is for start hooks and entrypoints. It prints one line (`heldkeys preflight: PASS, ...` or `heldkeys preflight: FAIL, 3 high-severity credentials reachable (2 long-lived with write access)`), lists what caused a failure (most urgent first, machine-wide credentials before project files, at most 10 lines unless you add `--details`), and exits 1 when a finding reaches `--fail-on` (default `high`). Use `--fail-on long-lived-write` for the narrowest policy ("never start an agent that holds a long-lived write credential"), or `medium` for a stricter one. With `--format json`, stdout is the full report with a `preflight` object added, and the verdict line goes to stderr.
- **`heldkeys scan --docker <container>` / `--kube <pod>`** is for checking something that is already running, from outside.

Get a Linux binary first: the `heldkeys` binary from the release archive `heldkeys-x86_64-unknown-linux-musl.tar.xz` (or `heldkeys-aarch64-unknown-linux-musl.tar.xz` on ARM hosts), or your own build from [building.md](building.md). The snippets below assume you saved it as `heldkeys-linux-x86_64`.

Exit codes everywhere: `0` nothing reached the threshold, `1` something did, `2` usage or runtime error. Treat `2` as a failure too, or a broken check will quietly let everything through.

## Failing closed with `--strict`

By default a file heldkeys finds but cannot check does not fail the gate: a credentials file over the size limit, a kubeconfig that is not valid YAML, a FIFO or directory where a config file should be, a project `.env` symlinked out of the working directory, or a file the scan has no permission to read. Each one is reported as an Info finding, [HK-READ-001](rules/HK-READ-001.md) ("could not read `<path>`: `<reason>`"), and the PASS line says how many there were:

```text
heldkeys preflight: PASS, no credentials reachable (1 file could not be read; --strict fails on that)
```

Any of those files may hold a credential the agent can read. When the gate must fail closed, add `--strict`; it then fails on them as well, and lists them under the verdict:

```sh
heldkeys preflight --fail-on high --strict
```

```text
heldkeys preflight: FAIL, 1 file could not be read (--strict)
  INFO  File could not be read  ~/.kube/config
```

`--strict` works the same way for `scan` and `ci`: the exit code is 1 when anything could not be analysed, that is any HK-READ-001 finding and, in `ci`, any [HK-WF-007](rules/HK-WF-007.md) finding (a workflow file it could not analyse).

## Docker and devcontainers

### Entrypoint preflight

Bake the binary into the image and run `preflight` before the agent starts. The agent only starts if the check passes:

```dockerfile
COPY heldkeys-linux-x86_64 /usr/local/bin/heldkeys

ENTRYPOINT ["/bin/sh", "-c", "heldkeys preflight --fail-on high && exec \"$@\"", "--"]
CMD ["your-agent", "--its-flags"]
```

`exec "$@"` hands PID 1 to the agent, so signals still reach it. Images without a shell (distroless, scratch) cannot chain commands like this; run `heldkeys preflight` as a separate step in whatever starts the container instead, or use `scan --docker` below.

Credentials passed with `docker run -e`, `--env-file`, mounted volumes (`-v ~/.aws:/root/.aws`) and a mounted Docker socket are all visible to the entrypoint, so the entrypoint is the right place to check.

### Devcontainers

Dev Containers forward a lot from the host by default: your git credential helper, your SSH agent socket, sometimes `~/.aws` or the Docker socket through `mounts`. Check what actually arrived:

```jsonc
// .devcontainer/devcontainer.json
{
  "postStartCommand": "heldkeys preflight --fail-on high"
}
```

Install the binary in the image (`COPY` in the Dockerfile) or through a feature. A failing `postStartCommand` does not stop the container, but it shows the verdict and the offending findings in the creation log, where you will see it before handing the container to an agent.

### Checking a running container from outside

```sh
heldkeys scan --docker agent-box --binary ./heldkeys-linux-x86_64
heldkeys scan --docker agent-box --binary ./heldkeys-linux-x86_64 --format json --fail-on high
```

This finds the container's OS and CPU (`uname -sm` inside it, or the image metadata if there is no `uname`), checks that the binary you are about to copy matches, `docker cp`s it to `/tmp/heldkeys-<random>`, runs `scan --format json` there, makes sure the copy is gone (see [what happens to the copy](#what-happens-to-the-copy)) and renders the result on your side in any `--format`. `--fail-on` applies locally. If the binary you run *is* a matching Linux build, `--binary` is not needed.

Two things to know. `docker exec` runs with the environment from the image and `docker run`, not with variables the entrypoint script exported later; when those matter, use the entrypoint preflight. And `docker` (like `kubectl` below) is found through your `PATH` and inherits your environment, so run it from a shell whose `PATH` you trust.

The container is treated as hostile: every command is killed after 120 seconds, its output is capped, and everything it sends back (the `uname` output, error messages, the JSON report) is made inert before it reaches your terminal. The [threat model](threat-model.md) has the details.

### What happens to the copy

The copy runs as `/tmp/heldkeys-<random> --remove-self scan ...`. `--remove-self` is a hidden flag that makes heldkeys delete its own file before it reads any other argument; Linux lets a running program do that, and the program keeps running from memory. So once the copy has started, its file is gone, whatever then happens to the scan or to the heldkeys on your side.

heldkeys still runs `rm -f` on that exact path after the scan (in Docker as root, `docker exec -u 0 <container> rm -f /tmp/heldkeys-<random>`, see below), for a copy that never started (a `noexec` `/tmp`, a dynamically linked build whose loader is missing). It also runs it after a `docker cp` or `kubectl cp` that failed, since a copy that failed partway may have written part of the file. Ctrl-C or SIGTERM during the copy or the scan stops that step and still runs the `rm -f`, then exits with an error; a second Ctrl-C exits at once, without cleaning up.

What can still leave the file behind:

- **heldkeys on your side dies without cleaning up** (SIGKILL, a crash, the machine going down) after `docker cp` or `kubectl cp` started writing the file and before the copied binary started. That is the length of the copy plus one `docker exec` or `kubectl exec` round trip. Once the copied binary is running, killing heldkeys no longer matters.
- **The copy cannot start, and the image has no `rm`** (distroless, scratch). heldkeys warns and names the path.
- **A Docker container that runs as a non-root user, on a runtime that refuses `docker exec -u 0`** (see the next paragraph). heldkeys warns and names the path.

Containers that run as a non-root user are covered too. `docker cp` creates the file owned by root, and `/tmp` is normally sticky, so the copy cannot delete itself there; that is why the Docker `rm -f` runs as root (`-u 0`). It removes only the one path heldkeys created, never a pattern. A runtime or policy that refuses `docker exec -u 0` leaves the file in that case, and heldkeys warns and names the path. `kubectl cp` writes the file as the container's own user, so in pods both the copy and a plain `rm -f` can delete it.

When the `rm -f` fails after a scan that ran, heldkeys cannot tell whether the copy deleted itself, so it warns that it could not confirm the file is gone. A failed cleanup after a failed copy or scan is part of the error message.

`--binary` must point at heldkeys 0.2.1 or later: older builds do not know `--remove-self` and refuse to run.

## Kubernetes

### Before the agent starts

An init container on its own is not enough: it has its own environment, so it does not see the variables and secrets that only the agent container gets. Use the init container to deliver the binary, and run the check in the agent container itself:

```yaml
spec:
  volumes:
    - name: heldkeys
      emptyDir: {}
  initContainers:
    - name: heldkeys-install
      image: your-registry/heldkeys:0.3.0     # any image that contains the static binary
      command: ["cp", "/usr/local/bin/heldkeys", "/heldkeys/heldkeys"]
      volumeMounts:
        - { name: heldkeys, mountPath: /heldkeys }
  containers:
    - name: agent
      image: your-agent-image
      command: ["/bin/sh", "-c", "/heldkeys/heldkeys preflight --fail-on high && exec your-agent"]
      volumeMounts:
        - { name: heldkeys, mountPath: /heldkeys, readOnly: true }
```

A failing preflight makes the container exit with status 1, so the pod goes into `CrashLoopBackOff` and `kubectl logs` shows the verdict line, so the agent never starts with a credential the policy forbids. The `k8s-service-account` check will tell you if the pod still has an automounted service account token; set `automountServiceAccountToken: false` on agent pods that do not need the API.

### Checking a running pod from outside

```sh
heldkeys scan --kube agent-7f9c -n sandboxes -c agent --binary ./heldkeys-linux-x86_64
```

Same flow as `--docker`, through `kubectl cp` and `kubectl exec`, including [what happens to the copy](#what-happens-to-the-copy). `-n` and `-c` are passed to kubectl as given. `kubectl cp` needs `tar` in the container. If `uname` is missing, the CPU is read from the node the pod runs on, which needs permission to `get` nodes.

## Hosted sandboxes

The pattern is the same for every provider: put the static binary in the sandbox, run `preflight --format json`, parse stdout, and decide in your own code whether to continue. Two ways to get the binary in:

- **Bake it into the sandbox image or template** (`COPY heldkeys /usr/local/bin/heldkeys` in the provider's Dockerfile, template or image definition). Simplest and fastest; do this when you control the image.
- **Upload it at runtime** with the SDK's file-write call, then `chmod +x`. Works with stock images.

The snippets below show the runtime upload. They are sketches: SDKs change, so lines marked **check SDK docs** name the call to look up rather than promising its exact signature.

### E2B

```python
import json
from e2b import Sandbox, CommandExitException   # check SDK docs: package and exception names

sbx = Sandbox.create()                           # check SDK docs: Sandbox() in older versions
with open("heldkeys-linux-x86_64", "rb") as f:
    sbx.files.write("/tmp/heldkeys", f)
sbx.commands.run("chmod +x /tmp/heldkeys")

try:
    result = sbx.commands.run("/tmp/heldkeys preflight --format json")
    report = json.loads(result.stdout)           # exit 0: PASS
except CommandExitException as e:                # non-zero exit raises; check SDK docs
    report = json.loads(e.stdout) if e.exit_code == 1 else None
    # exit 1: FAIL, report["preflight"]["verdict"] says why; exit 2: heldkeys error

if report is None or report["preflight"]["result"] != "pass":
    sbx.kill()
    raise SystemExit("sandbox exposes credentials; not starting the agent")
```

For templates, add `COPY heldkeys-linux-x86_64 /usr/local/bin/heldkeys` to the template's Dockerfile.

### Daytona

```python
import json
from daytona import Daytona

daytona = Daytona()
sandbox = daytona.create()

with open("heldkeys-linux-x86_64", "rb") as f:
    sandbox.fs.upload_file(f.read(), "/tmp/heldkeys")      # check SDK docs: argument order differs between versions
resp = sandbox.process.exec("chmod +x /tmp/heldkeys && /tmp/heldkeys preflight --format json")

report = json.loads(resp.result)                           # check SDK docs: stdout field name
if resp.exit_code != 0:
    print(report["preflight"]["verdict"] if resp.exit_code == 1 else "heldkeys failed")
```

### Modal

Modal sandboxes are built from images, so baking the binary in is the natural route:

```python
import json
import modal

app = modal.App.lookup("agent-sandboxes", create_if_missing=True)
image = (
    modal.Image.debian_slim()
    .add_local_file("heldkeys-linux-x86_64", "/usr/local/bin/heldkeys", copy=True)  # check SDK docs
    .run_commands("chmod +x /usr/local/bin/heldkeys")
)
sb = modal.Sandbox.create(app=app, image=image)    # pass your secrets/volumes here, as the agent would get them

proc = sb.exec("heldkeys", "preflight", "--format", "json")
out = proc.stdout.read()
proc.wait()
report = json.loads(out)
if proc.returncode != 0:
    sb.terminate()
    raise SystemExit(report["preflight"]["verdict"])
```

Run the check with the same `secrets=` and volumes the agent will get, or it checks a different sandbox.

### Vercel Sandbox

```ts
import { readFile } from "node:fs/promises";
import { Sandbox } from "@vercel/sandbox";

const sandbox = await Sandbox.create();
await sandbox.writeFiles([
  { path: "/tmp/heldkeys", content: await readFile("heldkeys-linux-x86_64") },   // check SDK docs: content vs stream field
]);
await sandbox.runCommand({ cmd: "chmod", args: ["+x", "/tmp/heldkeys"] });

const run = await sandbox.runCommand({ cmd: "/tmp/heldkeys", args: ["preflight", "--format", "json"] });
const report = JSON.parse(await run.stdout());                                   // check SDK docs: stdout() accessor
if (run.exitCode !== 0) {
  await sandbox.stop();
  throw new Error(report.preflight?.verdict ?? "heldkeys failed");
}
```

Vercel Sandbox runs x86_64 Linux, so use the `x86_64-unknown-linux-musl` build.

### Cloudflare Sandbox

Cloudflare sandboxes are containers defined by a Dockerfile, so bake the binary in:

```dockerfile
FROM docker.io/cloudflare/sandbox:<version>
COPY heldkeys-linux-x86_64 /usr/local/bin/heldkeys
```

Then, from the Worker:

```ts
import { getSandbox } from "@cloudflare/sandbox";

const sandbox = getSandbox(env.Sandbox, "agent-session-1");
const result = await sandbox.exec("heldkeys preflight --format json");          // check SDK docs: exec result fields
const report = JSON.parse(result.stdout);
if (result.exitCode !== 0) {
  return new Response(report.preflight?.verdict ?? "heldkeys failed", { status: 503 });
}
```

To upload at runtime instead, write the binary with the SDK's file-write call (base64-encoded; **check SDK docs** for the encoding option) and `chmod +x` it before running.

## Through your agent: Claude Code, Codex, Cursor

Coding agents on your laptop often run their shell commands in a sandbox of their own: Seatbelt profiles on macOS, bubblewrap or Landlock/seccomp on Linux, or a devcontainer. Those profiles decide which files the agent can read, which environment it inherits and whether it has network access. They differ by tool, by version and by setting, and they are easy to get wrong in both directions.

Running heldkeys from your own terminal shows what *you* can reach. To see what the *agent* can reach, have the agent run it, as an ordinary tool call, under its own sandbox profile:

> Run `heldkeys scan --format json` and summarise which credentials you can reach, by severity. Don't print any values or open the files it mentions.

What changes compared to your terminal:

- **Files.** A sandbox that denies reads outside the project hides `~/.aws/credentials` from the agent; one that only restricts writes does not. heldkeys reports what the agent's process can actually open.
- **Environment.** Agents can inject variables (Claude Code's `env` setting, MCP server env, CI secrets) or strip them. The `env` check sees the agent's real environment.
- **Sockets.** The SSH agent socket and the Docker socket are reachable unless the profile blocks them.
- **Network.** `cloud-metadata` reports whether the metadata endpoint is reachable from inside the sandbox.

The [`heldkeys` agent skill](../skill/heldkeys/SKILL.md) packages this: it tells the agent how to run the scan, how to summarise it without ever printing a secret, and how to suggest fixes. Install it where your agent loads skills, for example `~/.claude/skills/heldkeys/SKILL.md` for Claude Code (or `.claude/skills/` in a project), and the equivalent skills directory for Codex (**check the Codex docs** for the current location).

A shorter list through the agent means its sandbox hides some credentials from it; the same list means it hides none.
