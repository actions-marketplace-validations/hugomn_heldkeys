# HK-SSH-001: SSH key loaded in the running ssh-agent

| Check | Runs in | Default severity |
|---|---|---|
| `ssh-agent` | `heldkeys scan` | Medium |

## What it detects

Keys listed by `ssh-add -l` against the agent socket in `SSH_AUTH_SOCK`. heldkeys shows the public key hash, shortened, plus the key type and size. It never touches key material.

## Why it matters for agents

Any process that can reach the socket can sign with the loaded keys, for example to `git push` over SSH or to log into servers. Forwarding the agent socket into a container or sandbox forwards that power with it.

## How to fix

- Load keys with `ssh-add -c` (confirm each use) or `ssh-add -t` (time limit).
- Do not forward `SSH_AUTH_SOCK` into agent sandboxes.
- Use a hardware-backed key that requires a touch.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "ssh-agent",
  "rule": "HK-SSH-001",
  "title": "SSH key loaded in ssh-agent",
  "location": "ssh-agent: you@laptop",
  "fingerprint": "q9Fz…Kw8",
  "severity": "medium",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "ED25519 256 bits",
  "fix": "Load keys with ssh-add -c (confirm each use) or -t (time limit), or do not forward the agent socket into the sandbox.",
  "category": "ssh"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [ssh-add(1)](https://man.openbsd.org/ssh-add)
- [ssh_config(5): ForwardAgent](https://man.openbsd.org/ssh_config#ForwardAgent)
