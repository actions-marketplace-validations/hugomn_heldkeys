# HK-AWS-009: AWS keys in an aws-vault file keyring

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan`, `heldkeys preflight` | Low, or High with the passphrase in the environment |

## What it detects

Files in `~/.awsvault/keys` (or `$AWS_VAULT_FILE_DIR`): aws-vault's `file` backend, one encrypted file per stored key or session. heldkeys only counts them. When `AWS_VAULT_FILE_PASSPHRASE` is set in the environment, the finding is High and titled "aws-vault file keyring with its passphrase".

## Why it matters for agents

The files usually hold long-lived IAM user keys. They are encrypted with a passphrase, so on their own they are Low. With the passphrase in the environment, any process can run `aws-vault exec` or decrypt the files, and the keys are as exposed as a plain `~/.aws/credentials`.

## How to fix

- Keep `AWS_VAULT_FILE_PASSPHRASE` out of the environment and out of files agents can read, so aws-vault prompts for it.
- Prefer the OS keychain backend where one is available.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-009",
  "title": "AWS keys in an aws-vault file keyring",
  "location": "~/.awsvault/keys",
  "fingerprint": null,
  "severity": "low",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "1 encrypted item(s), usable with the keyring passphrase",
  "fix": "Keep the passphrase out of the environment and files agents can read, or use the OS keychain backend.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [aws-vault usage: backends](https://github.com/99designs/aws-vault/blob/master/USAGE.md)
