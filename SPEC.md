# heldkeys: spec v0.1 (implemented)

> **Status:** implemented on `main` for v0.1.1. Where the code and this document differ, the code and `heldkeys --help` win; the CLI block below matches the code.

> **Name:** `heldkeys` (decided 15 Oct). Repo: `hugomn/heldkeys`. Rule IDs are prefixed `HK-`. Env vars are prefixed `HELDKEYS_`. Tagline idea: "Which keys is your agent holding?"

## Positioning (from the prior-art check, 15 Oct)

- **The headline is CI and AI agents.** No existing tool combines (a) an inventory of what a CI job can reach at runtime (secrets in the environment, effective GITHUB_TOKEN permissions, OIDC, metadata) with (b) deterministic static analysis of the AI-agent steps in the workflow, with SARIF output. zizmor covers generic Actions risks very well, and we point to it rather than duplicate it. Trail of Bits has an LLM skill for agentic actions, but it isn't a deterministic linter.
- **Local mode is table stakes.** `credential-reach` (Python, 0 stars) already inventories local credentials for agents, but not MCP configs. Ours has to be faster, cover MCP, and share one engine with CI.
- **Must-have workflow rules** (each with a stable rule ID and a docs page):
  - `HK-WF-001`: an agent step on an untrusted trigger (`pull_request_target`, `issue_comment`, `issues`, `discussion_comment`, `workflow_run`) holding secrets or write permissions.
  - `HK-WF-002`: an agent step running after a checkout of the PR head ref on an untrusted trigger. The agent loads attacker-controlled config (`.mcp.json`, `CLAUDE.md`, `AGENTS.md`, `.cursor/`), as in CVE-2026-47751.
  - `HK-WF-003`: an agent step in a job with `permissions: write-all`, or with default permissions not restricted.
  - `HK-WF-004`: secrets passed to an agent step that the step's documented inputs don't need, for example the whole `secrets` context or cloud credentials.
  - `HK-WF-005`: an agent action pinned to a tag or branch, not a SHA.
  - `HK-WF-006`: an agent allowed to run arbitrary shell (`allowed_tools`/`--dangerously-skip-permissions`/`Bash(*)`) while holding a write token.
  - `HK-WF-007` (context): a workflow file that could not be analysed, so a pass never hides an unchecked agent step.
  - All of them follow local reusable workflows (`jobs.<id>.uses: ./.github/workflows/x.yml`) with the caller's triggers, permissions and secrets.
- **Detection rules:** reuse token regexes from gitleaks or betterleaks (MIT), keeping their copyright in NOTICE. Do NOT copy from trufflehog (AGPL) or secrets-patterns-db (CC-BY-SA).

## The question it answers

If an AI agent running here got hijacked by a prompt injection and could run one shell command, which credentials could it use?

You run `heldkeys` in the same place the agent runs: the terminal your coding agent uses, the agent's sandbox or container, or the CI job. It prints every credential that place exposes, how dangerous each one is, and how to shrink the list.

## Principles (non-negotiable)

1. **Read-only.** It never writes, modifies or deletes anything, except an output file the user asks for.
2. **Never prints a secret.** Values are shown only as redacted fingerprints. The full value never reaches stdout, stderr, logs, JSON or SARIF. There are tests for this.
3. **Never sends anything anywhere.** No telemetry. No network calls by default, apart from a single TCP connect, with no payload, to the cloud metadata address to see whether it's reachable. Any future network call that touches a credential (for example, checking a token's scopes) will be opt-in with `--deep` and only ever talk to that credential's own issuer. In v0.1 `--deep` is reserved and does nothing.
4. **Readable code.** Plain Rust: no async, no macros we wrote ourselves, no clever generics. Small files, one check per file, comments that explain *why*. A security engineer who doesn't write Rust every day should be able to audit it in an evening.
5. **Fast and dependency-light.** A single self-contained binary (the Linux release builds are static musl binaries), with startup and a full scan in well under 100 ms on a laptop.

## CLI

```
heldkeys                         # same as `heldkeys scan`
heldkeys scan                    # this machine or container, as the agent sees it
                                 # (--deep is accepted but reserved: no check uses it yet)
heldkeys scan --docker <container> [--binary <path>]
                                 # copy a Linux heldkeys into a running container, scan there, remove it
heldkeys scan --kube <pod> [-n <namespace>] [-c <container>] [--binary <path>]
                                 # the same for a Kubernetes pod, through kubectl cp/exec
heldkeys preflight               # one-line PASS/FAIL verdict for entrypoints and start hooks
                                 # (--format text|json; --fail-on defaults to high)
heldkeys ci [--repo-secrets]     # inside CI: runtime exposure + static analysis of workflows;
                                 # --repo-secrets also scans tracked files for tokens
heldkeys checks                  # list all checks and rules (--format json for scripts)

Common flags (before or after the subcommand):
  --format text|json|markdown|sarif   (default: text)
  --output <file>  write the report to a file; the summary line still goes to stdout
  --fail-on none|high|medium|low|long-lived-write
                   (default: none for scan, high for ci and preflight)
  --home <dir>     override $HOME (used by tests and for scanning another user's profile)
  --path <dir>     the working directory (where .env files, project MCP configs and workflows are read)
  --no-color       also honoured: NO_COLOR
  --quiet          only the summary line
  --details, -v    every finding, grouped by place and file (text output)
  --strict         also exit 1 when something could not be analysed: a file a check looks at
                   could not be read or parsed (HK-READ-001), or a workflow could not be
                   analysed (HK-WF-007)

Environment:
  HELDKEYS_NO_NET=1   skip the metadata reachability probe
```

Exit codes: 0 means nothing reached the `--fail-on` threshold. 1 means findings reached the threshold, or, with `--strict`, something could not be analysed (an HK-READ-001 or HK-WF-007 finding). 2 means a usage or runtime error.

## Data model

```rust
struct Finding {
    check: &'static str,      // e.g. "aws"
    rule: &'static str,       // e.g. "HK-AWS-001"
    title: String,            // "Long-lived AWS access key"
    location: String,         // "~/.aws/credentials [default]" or "env: GITHUB_TOKEN"
    fingerprint: Option<String>, // "AKIA…7Q2" never more than 4 leading + 3 trailing chars
    severity: Severity,       // High | Medium | Low | Info
    lifetime: Lifetime,       // LongLived | ShortLived | Unknown
    access: Access,           // Write | Read | Unknown
    detail: Option<String>,   // scopes, profile, context, etc. Never the secret
    fix: String,              // one-line remediation
}
```

Severity rule of thumb:
- **High:** long-lived plus write access, or unknown access on a cloud or SCM credential.
- **Medium:** short-lived write, long-lived read, or an SSH key loaded in an agent.
- **Low:** test-mode keys and read-only tokens with narrow scope.
- **Info:** a context fact, such as the metadata endpoint being reachable.

## Checks (v0.1)

Local (`scan`):
- `env`: environment variables that look like credentials, matched by name (`*_TOKEN`, `*_SECRET`, `*_KEY`, `AWS_*`, `DATABASE_URL`, ...) and by value pattern (known token prefixes such as `ghp_`, `github_pat_`, `sk-`, `xoxb-`, `AKIA`...).
- `aws`: `~/.aws/credentials` and `~/.aws/config` profiles, flagging static keys versus SSO/role profiles.
- `gcloud`, `azure`, `kube`, `docker`: their standard config and credential files.
- `netrc`, `git-credentials`, `npmrc`, `pypirc`, `cargo-credentials`: package and git credential files.
- `dotenv`: `.env*` files in the current directory tree, gitignored ones included (depth 4, skipping dependency directories, following symlinks only while they stay inside the tree).
- `ssh-agent`: keys loaded in the running ssh-agent (via `ssh-add -l`, fingerprints only), plus private keys in `~/.ssh` that have no passphrase.
- `git-helper`: configured credential helpers, and `gh` auth in `~/.config/gh/hosts.yml`.
- `git-config`: tokens in `url.<base>.insteadOf` rewrites, `http.extraheader` and remote URLs in `~/.gitconfig`, `~/.config/git/config` and `./.git/config`.
- `mcp`: MCP server configs for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, Codex and Gemini CLI that embed tokens in `env`, `args`, URLs or headers, plus project-level configs that start servers when an agent opens the directory.
- `docker-socket`, `k8s-service-account`: see Sandboxes below.
- `cloud-metadata`: whether 169.254.169.254 is reachable (TCP connect, 300 ms timeout, no payload).
- `read-errors`: files the other checks found but could not read or parse (HK-READ-001, Info), so nothing is skipped silently; `--strict` fails on them, and on HK-WF-007 in `ci`. Reported in every mode.

CI (`ci`):
- `ci-runtime`: when `GITHUB_ACTIONS=true` (or `GITLAB_CI=true`), which secrets are present in this job's environment, whether OIDC is available (`ACTIONS_ID_TOKEN_REQUEST_URL`), whether `GITHUB_TOKEN` or the Actions runtime token is present, whether `actions/checkout` left the token in `.git/config`, GitLab's `CI_JOB_TOKEN`, and whether the runner is self-hosted.
- `workflows`: static analysis of `.github/workflows/*.yml`, following local reusable workflows into the workflow they call. For every job that runs an AI agent step (anthropics/claude-code-action, openai/codex-action, google-github-actions/run-gemini-cli, Copilot coding agent setup, aider, and others in a maintained list), it reports which secrets the step receives, the job's effective `permissions`, and whether the workflow can be triggered by untrusted input (`pull_request_target`, `issue_comment`, `issues`, `discussion_comment`, a fork PR with secrets). "An agent that reads untrusted text while holding a write token" is High.
- `git-config`: the repository half of the local check, on the checkout's `./.git/config` only (remote URLs, `url.<base>.insteadOf` rewrites, `http.extraheader`). Inside GitHub Actions the checkout's `Authorization` extraheader is left to `ci-runtime` (HK-CI-005), so it is not reported twice.
- `repo-secrets` (optional, `--repo-secrets`): tracked files on the current branch matched against token patterns. We are not trying to replace gitleaks here. It's a fast sanity check, and the README points to gitleaks and trufflehog for deep history scans.

## Sandboxes (first-class use case)

The tool has to run *where the agent runs*, not next to it, because sandboxes change what's visible.

- **Static binaries:** a static musl build for Linux x86_64 and arm64 (plus regular macOS builds for laptops). No runtime, no HOME required, and it works on a read-only filesystem. Uploading one file to any sandbox is enough.
- **`preflight` subcommand:** `heldkeys preflight --fail-on high` is meant for a container entrypoint or a sandbox start hook. It prints a one-line verdict, emits JSON on request, and exits non-zero when the sandbox exposes more than the policy allows. The idea is "refuse to start the agent if its sandbox can reach a long-lived write credential".
- **`--docker <container>`:** copies the binary into a running container (`docker cp`), runs it there (`docker exec`), streams the result back and removes the binary. `--kube <pod>` works the same way via `kubectl cp/exec`. These are the only modes that run `docker` or `kubectl`, and only because the user named the target explicitly. Outside them, heldkeys touches only `ssh-add -l` (to list loaded keys), each Docker socket it finds (connect and close, no payload), the metadata address (one TCP connect, no payload, off with `HELDKEYS_NO_NET=1`) and, with `ci --repo-secrets`, `git ls-files`.
- **Through the agent itself:** the docs show how to ask Claude Code, Codex or Cursor to run it as a tool call, so the result reflects the agent's own sandbox profile (seatbelt, bubblewrap, devcontainer). We'll also ship an agent skill (`SKILL.md`) for this.
- **Hosted sandboxes** (E2B, Daytona, Modal, Vercel Sandbox, Cloudflare Sandbox): copy-paste snippets that upload the binary, run `preflight` and read back the JSON.
- **Sandbox-specific checks:**
  - `docker-socket`: Docker socket access is equivalent to root on the host.
  - `k8s-service-account`: a mounted service account token.
  - `cloud-metadata`: an instance role.
  - Host mounts that expose `~/.aws`, `~/.ssh` or `~/.config`. (v0.1 has no separate check: a mounted directory is found by the regular checks when it lands in the home being scanned.)

## Output

- **text:** a summary first (the distinct credentials to fix first, counts by place, secrets found in several places, a few generic next steps), coloured, fitted to `COLUMNS` (default 100); `--details` lists every finding grouped by place and file. Then a summary line, for example "7 credentials reachable, 2 long-lived with write access. If a prompt injection can run one shell command here, it can use all of them." In `ci` mode the line counts workflow risks apart from job credentials: "3 AI agent workflow risks, 2 credentials reachable in this job."
- **json:** a stable schema, versioned (`"schema": "heldkeys/v1"`).
- **markdown:** for PR comments and job summaries (`$GITHUB_STEP_SUMMARY`).
- **sarif:** 2.1.0, for GitHub code scanning (CI mode).

## Packaging

- Cargo workspace with a single crate, `heldkeys`, plus a binary.
- `action.yml` (a composite action) that downloads the release binary, runs `heldkeys ci`, writes the Markdown job summary and can optionally upload SARIF.
- Release config is prepared but not run: nothing gets published without Hugo.
- A VHS `demo.tape` for the README GIF.

## Testing

- Unit tests per check, using fixture homes under `tests/fixtures/` with clearly fake credentials (AWS's documented example key `AKIAIOSFODNN7EXAMPLE`, `ghp_` followed by obvious filler, and so on).
- Integration tests run the binary with `--home tests/fixtures/<case>` and an empty, controlled environment.
- A **redaction test**: run every fixture through every output format and assert that no fixture secret appears in full anywhere.
- Never run against the real `$HOME` in tests.

## Out of scope for v0.1

Windows support (not supported yet), cloud API enumeration (`--deep` is reserved for it and does nothing yet), and git history scanning.
