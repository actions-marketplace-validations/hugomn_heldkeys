# HK-AI-001: OpenAI Codex CLI login or API key in auth.json

| Check | Runs in | Default severity |
|---|---|---|
| `ai-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`~/.codex/auth.json` (or `$CODEX_HOME/auth.json`), where `codex login` keeps either an OpenAI API key (`OPENAI_API_KEY`) or a ChatGPT sign-in (`tokens.refresh_token`, `tokens.access_token`, `tokens.id_token`). The API key and the ChatGPT login are separate findings, with the titles "OpenAI API key in Codex auth.json" and "Codex CLI ChatGPT login tokens". An empty or `null` value is skipped.

## Why it matters for agents

Codex reads this file itself, but so can every other process running as you, including a different agent that got hijacked. The API key spends money on your OpenAI account. The refresh token keeps the ChatGPT login alive without a password or a browser, so whoever copies it can keep using your plan.

## How to fix

- Run `codex logout` on machines and in sandboxes where other agents run.
- If an agent needs OpenAI access, give it its own project key with a spending limit, passed only to the process that needs it.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "ai-logins",
  "rule": "HK-AI-001",
  "title": "OpenAI API key in Codex auth.json",
  "location": "~/.codex/auth.json",
  "fingerprint": "sk-p…001",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Codex CLI: OPENAI_API_KEY",
  "fix": "Run codex logout where other agents run, or log Codex in with a project key that has a spending limit.",
  "category": "ai-tools"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [OpenAI Codex CLI](https://github.com/openai/codex)
