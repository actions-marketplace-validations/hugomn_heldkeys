# HK-CLI-003: Vercel CLI login token in auth.json

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

The `token` in the Vercel CLI's `auth.json`: `~/Library/Application Support/com.vercel.cli/auth.json` on macOS, `~/.local/share/com.vercel.cli/auth.json` (or under `$XDG_DATA_HOME`) on Linux.

## Why it matters for agents

The login token can deploy, change environment variables (and read the ones that are not marked sensitive) and manage domains for every team you belong to.

## How to fix

- Run `vercel logout` where agents run.
- Give automation a token scoped to one team, with an expiry, passed only to the deploy command.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-003",
  "title": "Vercel CLI login token",
  "location": "~/Library/Application Support/com.vercel.cli/auth.json",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Vercel CLI: token",
  "fix": "Run vercel logout where agents run; pass a scoped token with an expiry only to the deploy command.",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Vercel CLI: login](https://vercel.com/docs/cli/login)
