# HK-AWS-002: Temporary AWS keys stored in a credentials or config file

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan` | Medium |

## What it detects

A profile with an `aws_access_key_id` that starts with `ASIA`, or that has an `aws_session_token`. These are session credentials, often pasted from a console page or written by a helper script.

## Why it matters for agents

The AWS CLI and every AWS SDK read `~/.aws/credentials` and `~/.aws/config` on their own. A hijacked agent does not need to find or parse anything: `aws sts get-caller-identity --profile <name>` is enough to use the profile, with whatever permissions it carries. Temporary keys expire, but until then they carry the full permissions of the session, and stale ones are easy to forget about.

## How to fix

- Delete expired session keys from the file.
- Prefer `aws sso login` or a `role_arn` profile, which keep session credentials in a cache instead of in plain config.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-002",
  "title": "Temporary AWS credentials",
  "location": "~/.aws/credentials [temp]",
  "fingerprint": "ASIA…002",
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": null,
  "fix": "Delete expired session keys from the file; prefer aws sso login, which keeps them out of plain config.",
  "category": "cloud-cli"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [AWS CLI: configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
- [AWS CLI: IAM Identity Center authentication](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
