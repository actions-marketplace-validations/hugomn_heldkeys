# HK-SSH-002: SSH private key file without a passphrase

| Check | Runs in | Default severity |
|---|---|---|
| `ssh-agent` | `heldkeys scan` | High |

## What it detects

Private key files in `~/.ssh` without a passphrase. heldkeys reads only the PEM header and, for OpenSSH keys, the first bytes of the body that name the cipher. Key material is never decoded, stored or printed.

## Why it matters for agents

An unencrypted key can be used by any process that can read it, and copied off the machine in one command. It never expires.

## How to fix

- Add a passphrase (`ssh-keygen -p -f <file>`) and load the key into ssh-agent with a time limit.
- Or move to a hardware-backed key (`ed25519-sk`).

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "ssh-agent",
  "rule": "HK-SSH-002",
  "title": "SSH private key without a passphrase",
  "location": "~/.ssh/id_ed25519",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": null,
  "fix": "Add a passphrase (ssh-keygen -p -f <file>) and load it into ssh-agent with a time limit, or use a hardware-backed key.",
  "category": "ssh"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen)
- [ssh-add(1)](https://man.openbsd.org/ssh-add)
