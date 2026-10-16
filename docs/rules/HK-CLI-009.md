# HK-CLI-009: Doppler CLI token in .doppler.yaml

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`scoped.<directory>.token` in `~/.doppler/.doppler.yaml`. The Doppler CLI writes the token there when no OS keyring is available. One finding per scope; the scope directory is shown relative to your home.

## Why it matters for agents

A CLI token reads every secret of every project and config the user can access, and can change them. It is a key to all the other keys.

## How to fix

- Run `doppler logout` where agents run.
- Give agents a service token scoped to one config, read-only.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-009",
  "title": "Doppler CLI token",
  "location": "~/.doppler/.doppler.yaml [/]",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "Doppler CLI: scoped.*.token",
  "fix": "Run doppler logout where agents run; give agents a service token scoped to one config.",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Doppler CLI](https://docs.doppler.com/docs/cli)
- [Doppler service tokens](https://docs.doppler.com/docs/service-tokens)
