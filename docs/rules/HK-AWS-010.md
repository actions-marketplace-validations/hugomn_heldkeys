# HK-AWS-010: Granted configured to keep AWS credentials in a file keyring

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan`, `heldkeys preflight` | Low |

## What it detects

`Backend = "file"` in the `[Keyring]` section of `~/.granted/config`. Granted then keeps its SSO tokens and stored credentials in encrypted files (in `FileDir` when set) instead of the OS keychain. heldkeys reads only the config; the encrypted files are not opened.

## Why it matters for agents

The files are encrypted with a passphrase, so on their own they are Low. A passphrase kept in a file or the environment an agent can read turns them into usable AWS credentials.

## How to fix

- Use the OS keychain backend where agents run.
- Keep the keyring passphrase out of files and the environment.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-010",
  "title": "Granted credentials in a file keyring",
  "location": "~/.granted/config [Keyring]",
  "fingerprint": null,
  "severity": "low",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "encrypted files in ~/.granted/keyring, usable with the keyring passphrase",
  "fix": "Use the OS keychain backend for Granted where agents run, and keep the keyring passphrase out of reach.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Granted documentation](https://docs.commonfate.io/granted/introduction)
