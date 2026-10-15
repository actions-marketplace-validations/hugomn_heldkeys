# HK-GCP-005: Google workload identity federation config

| Check | Runs in | Default severity |
|---|---|---|
| `gcloud` | `heldkeys scan` | Medium |

## What it detects

A credentials file of type `external_account` or `external_account_authorized_user`. These configs exchange an external token (from AWS, Azure, an OIDC provider or a file) for short-lived Google credentials.

## Why it matters for agents

Federation is the recommended setup, and the credentials it produces are short-lived. They still carry the federated principal's roles, which an agent can use for as long as the external token is available.

## How to fix

- Scope the federated principal's roles to what the agent needs.
- Restrict the attribute conditions on the workload identity provider.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "gcloud",
  "rule": "HK-GCP-005",
  "title": "Google workload identity federation config",
  "location": "~/.config/gcloud/application_default_credentials.json",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": null,
  "fix": "Scope the federated principal's roles to what the agent needs.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Google Cloud: workload identity federation](https://cloud.google.com/iam/docs/workload-identity-federation)
