# HK-GCP-001: gcloud stored login refresh tokens

| Check | Runs in | Default severity |
|---|---|---|
| `gcloud` | `heldkeys scan` | High |

## What it detects

A non-empty `credentials.db` or one or more accounts in `legacy_credentials/` under the gcloud config directory (`~/.config/gcloud`, or `CLOUDSDK_CONFIG`). `gcloud auth login` writes them.

## Why it matters for agents

gcloud and every Google Cloud client library find these credentials on their own. Refresh tokens do not expire with the terminal session: any process running as you can mint fresh access tokens from them. A hijacked agent can run `gcloud auth print-access-token` and act as you in every project you can reach.

## How to fix

- Run `gcloud auth revoke <account>` for accounts the agent should not use.
- Or give the agent its own config directory with `CLOUDSDK_CONFIG`, logged in as a narrowly scoped identity.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "gcloud",
  "rule": "HK-GCP-001",
  "title": "gcloud stored login (refresh tokens)",
  "location": "~/.config/gcloud/credentials.db",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "1 account(s) in legacy_credentials",
  "fix": "Run gcloud auth revoke for accounts the agent should not use, or give the agent its own config dir (CLOUDSDK_CONFIG).",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [gcloud auth revoke](https://cloud.google.com/sdk/gcloud/reference/auth/revoke)
- [Google Cloud: how application default credentials work](https://cloud.google.com/docs/authentication/application-default-credentials)
