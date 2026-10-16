# HK-AI-002: Claude Code OAuth login stored in .credentials.json

| Check | Runs in | Default severity |
|---|---|---|
| `ai-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`~/.claude/.credentials.json` (or `$CLAUDE_CONFIG_DIR/.credentials.json`), where Claude Code keeps its OAuth login (`claudeAiOauth.refreshToken` and `claudeAiOauth.accessToken`) on Linux and in containers. On macOS Claude Code keeps the login in the keychain; heldkeys never reads the keychain, so a macOS login is not reported.

## Why it matters for agents

The refresh token lets anyone who copies the file use your Claude subscription or Console account without signing in. Another agent running as you, or a script a prompt injection gets it to run, can read the file with one `cat`.

## How to fix

- Run `/logout` in Claude Code where other agents or untrusted code run.
- In shared containers, sign in with a dedicated account or a Console API key that has a spending limit.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "ai-logins",
  "rule": "HK-AI-002",
  "title": "Claude Code OAuth login tokens",
  "location": "~/.claude/.credentials.json",
  "fingerprint": "sk-a…003",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Claude Code: claudeAiOauth.refreshToken, claudeAiOauth.accessToken",
  "fix": "Run /logout in Claude Code where other agents or untrusted code run; on Linux the login is a plain file.",
  "category": "ai-tools"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Claude Code: identity and access management](https://docs.claude.com/en/docs/claude-code/iam)
