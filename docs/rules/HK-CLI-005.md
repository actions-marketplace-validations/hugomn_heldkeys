# HK-CLI-005: Fly.io CLI access token in config.yml

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`access_token` in `~/.fly/config.yml`, written by `fly auth login`.

## Why it matters for agents

The login token can deploy, read secrets into machines, open SSH sessions and delete apps in every organization you belong to.

## How to fix

- Run `fly auth logout` where agents run.
- Give automation a deploy token scoped to one app (`fly tokens create deploy`).

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-005",
  "title": "Fly.io CLI access token",
  "location": "~/.fly/config.yml",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "flyctl: access_token",
  "fix": "Run fly auth logout where agents run; give automation a deploy token scoped to one app (fly tokens create deploy).",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Fly.io: access tokens](https://fly.io/docs/security/tokens/)
