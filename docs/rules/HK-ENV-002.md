# HK-ENV-002: Credential-named environment variable with a secret-looking value

| Check | Runs in | Default severity |
|---|---|---|
| `env` | `heldkeys scan` | Medium. A name that points at a cloud or source-control provider (`GITHUB_`, `AWS_`, `AZURE`, `GOOGLE`, ...) is titled "Possible cloud or SCM credential". |

## What it detects

A variable whose name usually holds a secret (`*_TOKEN`, `*_SECRET`, `*_API_KEY`, `*_PASSWORD`, `DATABASE_URL`, `PGPASSWORD`, ...) and whose value looks real: not empty, not a placeholder such as `changeme` or `${OTHER}`, not a boolean, number or file path. The format is unknown, so lifetime and access are unknown and no fingerprint is shown: the ends of an arbitrary secret are part of the secret.

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
  "rule": "HK-ENV-002",
  "title": "Possible credential",
  "location": "env: MY_SERVICE_PASSWORD",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": null,
  "fix": "Remove it from the agent's environment; pass it only to the one command that needs it.",
  "category": "environment"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [OWASP: Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
