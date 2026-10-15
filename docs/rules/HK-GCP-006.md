# HK-GCP-006: Google credentials file of an unrecognised type

| Check | Runs in | Default severity |
|---|---|---|
| `gcloud` | `heldkeys scan` | Medium |

## What it detects

A JSON credentials file, found as application default credentials or through `GOOGLE_APPLICATION_CREDENTIALS`, whose `type` heldkeys does not recognise.

## Why it matters for agents

Client libraries may still accept it. heldkeys cannot tell what it grants, so it reports the file rather than staying silent.

## How to fix

- Check what the file grants and remove it if the agent does not need it.
- If it is a valid type that heldkeys should know about, please open an issue.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "gcloud",
  "rule": "HK-GCP-006",
  "title": "Google credentials file",
  "location": "~/keys/legacy.json",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": null,
  "fix": "Check what this file grants and remove it if the agent does not need it.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Google Cloud: how application default credentials work](https://cloud.google.com/docs/authentication/application-default-credentials)
