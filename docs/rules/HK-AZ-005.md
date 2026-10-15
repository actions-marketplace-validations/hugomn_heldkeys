# HK-AZ-005: Azure service principal secret stored by az login

| Check | Runs in | Default severity |
|---|---|---|
| `azure` | `heldkeys scan` | High |

## What it detects

`service_principal_entries.json` with a client secret or certificate, written by `az login --service-principal`.

## Why it matters for agents

A service principal secret is a password for a non-human identity. It works from anywhere until it expires or is rotated, often months later, and the file is plain JSON.

## How to fix

- Run `az logout` to remove stored secrets.
- Prefer managed identity or workload identity federation over client secrets.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "azure",
  "rule": "HK-AZ-005",
  "title": "Azure service principal secret",
  "location": "~/.azure/service_principal_entries.json",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "1 service principal(s)",
  "fix": "Run az logout to remove stored secrets; prefer managed identity or workload identity federation.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Azure CLI: sign in with Azure CLI](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli)
- [Managed identities for Azure resources](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
