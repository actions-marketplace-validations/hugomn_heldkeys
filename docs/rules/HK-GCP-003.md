# HK-GCP-003: Google service account key file

| Check | Runs in | Default severity |
|---|---|---|
| `gcloud` | `heldkeys scan` | High |

## What it detects

A credentials file of type `service_account`, found as application default credentials or through `GOOGLE_APPLICATION_CREDENTIALS`. The fingerprint comes from `private_key_id`, which identifies the key without revealing it; the detail names the service account.

## Why it matters for agents

A service account key is a private key that never expires unless someone deletes it. Copied out by an agent, it works from anywhere, with every role the service account holds.

## How to fix

- Delete the key file, and delete the key in IAM.
- Use workload identity federation or service account impersonation instead of keys.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "gcloud",
  "rule": "HK-GCP-003",
  "title": "Google service account key",
  "location": "~/keys/deployer.json",
  "fingerprint": "0f1e…cdd",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "service account ci-deployer@example-project.iam.gserviceaccount.com",
  "fix": "Delete the key file and the key in IAM; use workload identity or impersonation instead.",
  "category": "cloud-cli"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Google Cloud: best practices for managing service account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [Google Cloud: workload identity federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [Google Cloud: use service account impersonation](https://cloud.google.com/docs/authentication/use-service-account-impersonation)
