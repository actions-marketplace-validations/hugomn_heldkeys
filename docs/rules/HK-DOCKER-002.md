# HK-DOCKER-002: Registry logins retrievable through a Docker credential helper

| Check | Runs in | Default severity |
|---|---|---|
| `docker` | `heldkeys scan` | Medium |

## What it detects

A `credsStore` or `credHelpers` entry in `~/.docker/config.json`.

## Why it matters for agents

A helper keeps the secret out of the file, but any process running as you can still ask for it: `docker-credential-<helper> get` returns the stored login. That is how `docker push` works without a prompt, and it works the same for an agent.

## How to fix

- Log out of registries the agent does not need (`docker logout <registry>`).
- Run agents in a sandbox without your Docker config.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "docker",
  "rule": "HK-DOCKER-002",
  "title": "Docker credential helper",
  "location": "~/.docker/config.json (helper ecr-login)",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "docker-credential-ecr-login returns stored logins to any process running as this user",
  "fix": "Log out of registries the agent does not need (docker logout <registry>).",
  "category": "package-registry"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Docker: docker login and credential stores](https://docs.docker.com/reference/cli/docker/login/)
