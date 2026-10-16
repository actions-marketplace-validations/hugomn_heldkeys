# HK-CLI-010: Railway CLI login token in config.json

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`user.token` (and `user.accessToken` or `user.refreshToken` where present) in `~/.railway/config.json`, written by `railway login`.

## Why it matters for agents

The login token can deploy, read and change variables, and delete services in every project you can reach.

## How to fix

- Run `railway logout` where agents run.
- Use a project token for automation.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-010",
  "title": "Railway CLI login token",
  "location": "~/.railway/config.json",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Railway CLI: user.token",
  "fix": "Run railway logout where agents run; use a project token for automation.",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Railway CLI](https://docs.railway.com/guides/cli)
