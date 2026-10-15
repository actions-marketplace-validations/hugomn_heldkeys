# HK-GCP-002: Application default credentials with a user refresh token

| Check | Runs in | Default severity |
|---|---|---|
| `gcloud` | `heldkeys scan` | High |

## What it detects

`application_default_credentials.json` of type `authorized_user`, written by `gcloud auth application-default login`.

## Why it matters for agents

gcloud and every Google Cloud client library find these credentials on their own. Refresh tokens do not expire with the terminal session: any process running as you can mint fresh access tokens from them. Any script the agent writes picks up application default credentials without being told to, and acts with your identity.

## How to fix

- Run `gcloud auth application-default revoke` when you are done.
- Prefer short-lived service account impersonation for agents.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "gcloud",
  "rule": "HK-GCP-002",
  "title": "Google ADC user refresh token",
  "location": "~/.config/gcloud/application_default_credentials.json",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": null,
  "fix": "Run gcloud auth application-default revoke when done; prefer short-lived impersonation for agents.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Google Cloud: how application default credentials work](https://cloud.google.com/docs/authentication/application-default-credentials)
- [Google Cloud: use service account impersonation](https://cloud.google.com/docs/authentication/use-service-account-impersonation)
