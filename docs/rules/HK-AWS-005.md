# HK-AWS-005: AWS profile that assumes a role

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan` | Medium |

## What it detects

A profile with `role_arn`, using a `source_profile`, a `credential_source` or a `web_identity_token_file` to get the role's credentials. The detail line says which.

## Why it matters for agents

The AWS CLI and every AWS SDK read `~/.aws/credentials` and `~/.aws/config` on their own. A hijacked agent does not need to find or parse anything: `aws sts get-caller-identity --profile <name>` is enough to use the profile, with whatever permissions it carries. The CLI assumes the role on demand, so the agent gets the role's permissions as long as the source credentials work.

## How to fix

- Give the agent its own narrowly scoped role instead of one a human uses.
- Check what the source profile is: a role chained from a long-lived key ([HK-AWS-001](HK-AWS-001.md)) is only as safe as that key.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-005",
  "title": "AWS role profile",
  "location": "~/.aws/config [profile admin]",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "assumes a role using source_profile default",
  "fix": "Give the agent its own narrowly scoped role instead of one a human uses.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [AWS CLI: using an IAM role](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html)
- [AWS IAM: security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
