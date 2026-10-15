# HK-DOCKER-001: Registry login stored inline in ~/.docker/config.json

| Check | Runs in | Default severity |
|---|---|---|
| `docker` | `heldkeys scan` | High |

## What it detects

A registry under `auths` in `~/.docker/config.json` (or `$DOCKER_CONFIG/config.json`) with an `auth`, `identitytoken`, `password` or `registrytoken` value. `auth` is `user:password` in base64, which is plaintext for practical purposes.

## Why it matters for agents

A registry login can usually push. A hijacked agent could publish a new image under a tag your deployments pull, which turns one prompt injection into a supply-chain compromise.

## How to fix

- Use a credential helper (`credsStore`) so logins live in the OS keychain.
- Give the agent a read-only, short-lived registry token, or none.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "docker",
  "rule": "HK-DOCKER-001",
  "title": "Docker registry credentials (plaintext)",
  "location": "~/.docker/config.json (https://index.docker.io/v1/)",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": null,
  "fix": "Use a credential helper (credsStore), or a read-only, short-lived registry token for the agent.",
  "category": "package-registry"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Docker: docker login and credential stores](https://docs.docker.com/reference/cli/docker/login/)
