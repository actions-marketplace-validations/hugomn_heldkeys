# HK-ENV-001: Environment variable holding a token of a known format

| Check | Runs in | Default severity |
|---|---|---|
| `env` | `heldkeys scan` | Depends on the token format. High for long-lived cloud, source-control and AI provider keys, Medium for short-lived ones, Low for test-mode keys. |

## What it detects

An environment variable whose value matches a known token format, such as `ghp_` and `github_pat_` (GitHub), `AKIA` (AWS), `sk-ant-` (Anthropic), `sk-proj-` (OpenAI), `xoxb-` (Slack), `npm_`, `pypi-`, `glpat-` and others. The variable name does not matter: `SOMETHING=sk-ant-...` is reported too. Because the prefix is public, heldkeys shows a fingerprint of the first 4 and last 3 characters so you can tell which token it is.

## Why it matters for agents

The environment is the first thing a hijacked agent sees. `env`, `printenv` and `/proc/self/environ` list it without touching a single file, and every process the agent starts inherits it. A variable exported once in a shell profile is therefore handed to every tool call the agent makes.

## How to fix

- Remove the variable from the agent's environment. Pass it only to the one command that needs it, for example `GITHUB_TOKEN=$(op read ...) gh release create`, instead of exporting it in a shell profile.
- Start agents from a clean environment (`env -i` plus an allowlist) or a sandbox profile that does not forward secrets.
- If the agent really needs the credential, give it its own token with the narrowest scope and a short expiry.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "env",
  "rule": "HK-ENV-001",
  "title": "Anthropic API key",
  "location": "env: ANTHROPIC_API_KEY",
  "fingerprint": "sk-a…AKE",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": null,
  "fix": "Remove it from the agent's environment; pass it only to the one command that needs it.",
  "category": "environment"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [OWASP: Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitHub: managing your personal access tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [OWASP GenAI: LLM01 prompt injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
