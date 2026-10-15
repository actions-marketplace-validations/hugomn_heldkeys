# HK-SOCK-001: Docker daemon socket reachable by this user

| Check | Runs in | Default severity |
|---|---|---|
| `docker-socket` | `heldkeys scan` | High |

## What it detects

A Docker daemon socket this user can connect to: `$DOCKER_HOST` (unix), `/var/run/docker.sock`, `/run/docker.sock`, rootless Docker under `$XDG_RUNTIME_DIR`, or Docker Desktop's `~/.docker/run/docker.sock`. heldkeys opens a connection and closes it right away. Nothing is sent.

## Why it matters for agents

Whoever can talk to the Docker daemon can start a privileged container that mounts the host's filesystem. Access to the socket is root on the host. Agent sandboxes often mount it for convenience, which removes the sandbox.

## How to fix

- Do not mount the Docker socket into agent sandboxes.
- Use rootless Docker, or a separate build service the agent can call with a narrow API.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "docker-socket",
  "rule": "HK-SOCK-001",
  "title": "Docker daemon socket is accessible",
  "location": "/var/run/docker.sock",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "access to the Docker socket is root on the host",
  "fix": "Do not mount the Docker socket into agent sandboxes; use rootless Docker or a separate build service.",
  "category": "host"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Docker: daemon attack surface](https://docs.docker.com/engine/security/#docker-daemon-attack-surface)
- [Docker: rootless mode](https://docs.docker.com/engine/security/rootless/)
