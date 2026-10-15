# HK-AWS-004: AWS SSO profile without a cached session (context)

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan` | Info |

## What it detects

An IAM Identity Center profile with no cached session token. Reported as context only: it does not count as a reachable credential.

## Why it matters for agents

Nothing is usable right now, because a human has to log in through a browser first. It is listed so you know the profile exists: if someone runs `aws sso login` in this shell, it becomes [HK-AWS-003](HK-AWS-003.md).

## How to fix

- No action needed. A human has to log in before this profile works.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-004",
  "title": "AWS SSO profile (no cached session)",
  "location": "~/.aws/config [profile sso-ro]",
  "fingerprint": null,
  "severity": "info",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "role ReadOnly",
  "fix": "No action needed; a human has to log in before this profile works.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [AWS CLI: IAM Identity Center authentication](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
