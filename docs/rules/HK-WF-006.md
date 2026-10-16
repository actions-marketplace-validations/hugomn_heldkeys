# HK-WF-006: AI agent allowed to run any shell command while holding a write token

| Check | Runs in | Default severity |
|---|---|---|
| `workflows` | `heldkeys ci` | High when the job's token can write. Medium when the job's permissions are not set (the token depends on the repository default). Not reported when the token is read-only. |

## What it detects

An agent step configured to run shell commands without restriction or approval, in a job whose token can write (write scopes, `write-all`, `id-token: write`, or a personal access token passed to the step). heldkeys looks in the step's `with:`, `env:` and `run:` for:

- Claude Code: `--dangerously-skip-permissions`, permission mode `bypassPermissions`, or `Bash`, `Bash(*)` or `Bash(:*)` in `--allowedTools` / `allowed_tools` / `settings` (`--disallowedTools Bash` is not mistaken for a grant);
- a filtered entry whose command still runs any code: an interpreter or build runner such as `Bash(npm test:*)`, `Bash(make:*)`, `Bash(npx:*)`, `Bash(python:*)`, `Bash(node:*)`, `Bash(cargo test:*)`, `Bash(go:*)`, `Bash(gradle:*)`, a shell (`bash`, `sh`, `sudo`, `env`, `xargs`, `find`, `awk`, `sed`, `docker`...), a script from the repository (`./scripts/x.sh`), `git` with `config`, `-c`, `alias`, `rebase` or `submodule`, and `gh alias` or `gh extension`. The same applies to Gemini CLI's `run_shell_command(...)` and the Copilot CLI's `--allow-tool 'shell(...)'`. `npm test` runs whatever `package.json` says and `make` runs the `Makefile`, both of which a pull request or a prompt injection can change, so they can run any command. Read-only commands such as `Bash(gh pr diff:*)`, `Bash(gh pr view:*)` or `Bash(git diff:*)` are fine;
- Codex: `--dangerously-bypass-approvals-and-sandbox`, `--full-auto`, sandbox `danger-full-access`, or codex-action's `safety-strategy: unsafe`;
- Gemini CLI: `--yolo`, approval mode `yolo`, or an unfiltered `run_shell_command` in its settings;
- aider `--yes-always`, and the Copilot CLI's `--allow-all-tools` or `--allow-tool shell`.

Flags only count where they act as arguments: in inputs such as `claude_args`, `settings` or `allowed_tools`, and in the code of a `run:` script. A prompt (`prompt`, `direct_prompt`, `prompt_file`, `custom_instructions` and other prompt or instruction inputs), a quoted string, a comment or a heredoc body that mentions `--yolo` grants nothing.

## Why it matters for agents

The difference between "an agent was told something malicious" and "an attacker ran code in your CI" is whether the agent can turn text into commands. With an unrestricted shell, one injected sentence becomes `git push`, `gh release create` or `curl` with the token in a header. A write token makes that permanent: a pushed commit or a poisoned release outlives the job.

These flags are also exactly what malware looks for. In the Nx "s1ngularity" compromise of August 2025, the malicious package invoked locally installed AI CLIs with `--dangerously-skip-permissions`, `--yolo` and `--trust-all-tools` to search the machine for secrets. An agent in CI configured the same way gives that same access, with a write token in reach.

## Vulnerable

```yaml
on: workflow_dispatch

permissions:
  contents: write

jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@<sha> # v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: --dangerously-skip-permissions --allowedTools "Read,Bash(npm test:*)"
```

## Fixed

Allow only commands that read, by prefix, and keep the token read-only unless the job's purpose is to write. Leave out anything that runs the repository's code (tests, builds, scripts): run those in a separate job without the agent and give the agent their output. If the agent should propose changes, let it open a pull request with `pull-requests: write` instead of pushing with `contents: write`.

```yaml
on: workflow_dispatch

permissions:
  contents: read

jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@<sha> # v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: --allowedTools "Bash(gh pr diff:*),Bash(git diff:*),Read,Grep"
```

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "workflows",
  "rule": "HK-WF-006",
  "title": "Agent runs any shell with write token",
  "location": ".github/workflows/claude.yml:10 jobs.claude.steps[0] (uses: anthropics/claude-code-action@0123456)",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "short-lived",
  "access": "write",
  "detail": "claude --dangerously-skip-permissions, Bash(npm test:*) runs any code (npm); write token (contents: write)",
  "fix": "Allow only read-only commands that run no repository code (for example Bash(gh pr diff:*)), or make the job's token read-only.",
  "category": "workflow"
}
```

## References

- [Claude Code: permissions and allowed tools](https://docs.anthropic.com/en/docs/claude-code/iam)
- [Codex: sandbox and approvals](https://github.com/openai/codex/blob/main/docs/sandbox.md)
- [Gemini CLI: configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/configuration.md)
- [OWASP GenAI: LLM06 excessive agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
