# HK-AZ-001: Azure CLI MSAL cache with refresh tokens

| Check | Runs in | Default severity |
|---|---|---|
| `azure` | `heldkeys scan` | High |

## What it detects

A plaintext `msal_token_cache.json` in `~/.azure` (or `AZURE_CONFIG_DIR`) that holds refresh tokens. The detail counts refresh and access tokens.

## Why it matters for agents

The Azure CLI and the Azure SDKs reuse these tokens automatically. A hijacked agent can run `az account get-access-token` or any `az` command and act as the signed-in identity, in every subscription it can reach. Refresh tokens are long-lived: they keep minting new access tokens long after you closed the terminal.

## How to fix

- Run `az logout` when you are done.
- Or give the agent its own `AZURE_CONFIG_DIR`, signed in as a narrowly scoped identity.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "azure",
  "rule": "HK-AZ-001",
  "title": "Azure CLI refresh tokens",
  "location": "~/.azure/msal_token_cache.json",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "1 refresh token(s), 1 access token(s)",
  "fix": "Run az logout when done, or give the agent its own AZURE_CONFIG_DIR with a narrowly scoped identity.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Azure CLI: sign in with Azure CLI](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli)
- [Microsoft identity platform: acquire and cache tokens with MSAL](https://learn.microsoft.com/en-us/entra/identity-platform/msal-acquire-cache-tokens)
