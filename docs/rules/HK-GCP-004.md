# HK-GCP-004: Google impersonation credentials with a source refresh token

| Check | Runs in | Default severity |
|---|---|---|
| `gcloud` | `heldkeys scan` | High |

## What it detects

A credentials file of type `impersonated_service_account`. It embeds the source credentials, usually your user refresh token, used to impersonate the target service account.

## Why it matters for agents

gcloud and every Google Cloud client library find these credentials on their own. Refresh tokens do not expire with the terminal session: any process running as you can mint fresh access tokens from them. The file gives the agent both the impersonated account's access and, through the embedded refresh token, your own.

## How to fix

- Revoke the source credentials when you are done; the impersonated account's access is reachable while they live.
- Scope the impersonation grant (`roles/iam.serviceAccountTokenCreator`) to the one service account the agent needs.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "gcloud",
  "rule": "HK-GCP-004",
  "title": "Google impersonation credentials",
  "location": "~/.config/gcloud/application_default_credentials.json",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": null,
  "fix": "Revoke the source credentials when done; the impersonated account's access is reachable while they live.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Google Cloud: use service account impersonation](https://cloud.google.com/docs/authentication/use-service-account-impersonation)
- [Google Cloud: how application default credentials work](https://cloud.google.com/docs/authentication/application-default-credentials)
