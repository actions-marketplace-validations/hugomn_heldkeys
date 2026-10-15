# HK-AWS-001: Long-lived AWS access key in a credentials or config file

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan` | High |

## What it detects

A profile in `~/.aws/credentials` or `~/.aws/config` (or the files named by `AWS_SHARED_CREDENTIALS_FILE` and `AWS_CONFIG_FILE`) with an `aws_access_key_id` and no session token. These are IAM user keys: they work until someone deactivates them.

## Why it matters for agents

The AWS CLI and every AWS SDK read `~/.aws/credentials` and `~/.aws/config` on their own. A hijacked agent does not need to find or parse anything: `aws sts get-caller-identity --profile <name>` is enough to use the profile, with whatever permissions it carries. A long-lived key is the worst case: once copied out, it keeps working after the agent session ends, from anywhere.

## How to fix

- Move the humans and agents on this machine to IAM Identity Center (`aws configure sso`) or an assumed role.
- Deactivate and delete the key in IAM once nothing uses it. Check `aws iam get-access-key-last-used` first.
- If an agent must use AWS, give it its own role with a narrow policy and a short session duration.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-001",
  "title": "Long-lived AWS access key",
  "location": "~/.aws/credentials [default]",
  "fingerprint": "AKIA…PLE",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": null,
  "fix": "Replace the static key with IAM Identity Center (aws configure sso) or an assumed role, then deactivate it.",
  "category": "cloud-cli"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [AWS CLI: configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)
- [AWS IAM: security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI: IAM Identity Center authentication](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
