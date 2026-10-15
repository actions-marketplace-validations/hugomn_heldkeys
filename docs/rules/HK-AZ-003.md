# HK-AZ-003: Azure CLI token cache encrypted for the current user

| Check | Runs in | Default severity |
|---|---|---|
| `azure` | `heldkeys scan` | High |

## What it detects

`msal_token_cache.bin`, the token cache the Azure CLI encrypts at rest (the default on Windows).

## Why it matters for agents

The cache is encrypted for your user, and the agent runs as your user. The `az` CLI decrypts it transparently, so encryption at rest does not keep it away from a hijacked agent.

## How to fix

- Run `az logout` when you are done.
- Or give the agent its own `AZURE_CONFIG_DIR`, signed in as a narrowly scoped identity.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "azure",
  "rule": "HK-AZ-003",
  "title": "Encrypted Azure CLI token cache",
  "location": "~/.azure/msal_token_cache.bin",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "encrypted at rest, but usable by any process running as this user",
  "fix": "Run az logout when done, or give the agent its own AZURE_CONFIG_DIR with a narrowly scoped identity.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Azure CLI: sign in with Azure CLI](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli)
- [Microsoft identity platform: acquire and cache tokens with MSAL](https://learn.microsoft.com/en-us/entra/identity-platform/msal-acquire-cache-tokens)
