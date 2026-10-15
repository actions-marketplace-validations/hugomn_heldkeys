# HK-AZ-004: Pre-MSAL Azure CLI token cache with refresh tokens

| Check | Runs in | Default severity |
|---|---|---|
| `azure` | `heldkeys scan` | High |

## What it detects

`accessTokens.json`, the ADAL token cache written by Azure CLI versions before 2.30, with refresh tokens in it.

## Why it matters for agents

The Azure CLI and the Azure SDKs reuse these tokens automatically. A hijacked agent can run `az account get-access-token` or any `az` command and act as the signed-in identity, in every subscription it can reach. This file is often left behind after an upgrade, and its refresh tokens can still be valid.

## How to fix

- Run `az logout`, then delete `~/.azure/accessTokens.json` if it is still there.
- Upgrade the Azure CLI if it still writes this file.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "azure",
  "rule": "HK-AZ-004",
  "title": "Azure CLI legacy refresh tokens",
  "location": "~/.azure/accessTokens.json",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "1 refresh token(s) in the pre-MSAL cache",
  "fix": "Run az logout when done, or give the agent its own AZURE_CONFIG_DIR with a narrowly scoped identity.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Azure CLI: sign in with Azure CLI](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli)
