# HK-AI-003: Credential or API key helper in Claude Code settings

| Check | Runs in | Default severity |
|---|---|---|
| `ai-logins` | `heldkeys scan`, `heldkeys preflight` | By format, or Medium for apiKeyHelper |

## What it detects

Two things in Claude Code's settings files:

- the `env` block of `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`), `./.claude/settings.json` and `./.claude/settings.local.json`: every variable Claude Code sets for itself and the commands it runs. Each entry is judged like an environment variable, so a known token format (`sk-ant-`, `ghp_`, ...) is titled after its format and a credential-named entry with a secret-looking value is a "Possible credential". Settings such as `DISABLE_TELEMETRY` are not reported.
- `apiKeyHelper` in the user settings: a command Claude Code runs to get an API key. Only the program name is shown, because arguments can carry secrets.

## Why it matters for agents

A key in the `env` block is in a plain file, and it is also in the environment of every command Claude Code runs, so a prompt injection only has to print the environment. An `apiKeyHelper` hands out a key to any process that runs it, not only to Claude Code.

## How to fix

- Move keys out of the `env` block into `apiKeyHelper` backed by a secret manager, and rotate them.
- Keep `settings.local.json` out of shared directories, and never commit keys to `.claude/settings.json`.
- Make the helper ask for user presence, or hand out short-lived keys.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "ai-logins",
  "rule": "HK-AI-003",
  "title": "Anthropic API key",
  "location": "~/.claude/settings.json env.ANTHROPIC_API_KEY",
  "fingerprint": "sk-a…004",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Claude Code settings",
  "fix": "Move the key out of the settings env block (use apiKeyHelper with a secret manager) and rotate it.",
  "category": "ai-tools"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Claude Code settings](https://docs.claude.com/en/docs/claude-code/settings)
