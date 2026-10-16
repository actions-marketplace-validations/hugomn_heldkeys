# HK-CLI-001: HashiCorp Vault token in ~/.vault-token

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`~/.vault-token`, where the Vault CLI's default token helper stores the token after `vault login`. A `VAULT_TOKEN` in the environment is reported by the `env` check.

## Why it matters for agents

A Vault token opens every secret its policies allow, often for many systems at once. Tokens from `vault login` are commonly valid for days, and an agent can renew them.

## How to fix

- Revoke the token when you are done (`vault token revoke -self`), and keep token TTLs short.
- Give agents their own token with a narrow policy, or none.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-001",
  "title": "HashiCorp Vault token",
  "location": "~/.vault-token",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "Vault CLI",
  "fix": "Revoke the token when done (vault token revoke -self) and keep token TTLs short where agents run.",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Vault: tokens](https://developer.hashicorp.com/vault/docs/concepts/tokens)
- [Vault: token helpers](https://developer.hashicorp.com/vault/docs/commands/token-helper)
