# HK-AWS-003: AWS SSO profile with a cached session token

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan` | Medium |

## What it detects

A profile that uses IAM Identity Center (`sso_session` or `sso_start_url`) while `~/.aws/sso/cache` holds a session token. The token may have expired; heldkeys does not call AWS to find out.

## Why it matters for agents

The AWS CLI and every AWS SDK read `~/.aws/credentials` and `~/.aws/config` on their own. A hijacked agent does not need to find or parse anything: `aws sts get-caller-identity --profile <name>` is enough to use the profile, with whatever permissions it carries. With a live SSO session, the agent can mint role credentials for every account and permission set the session covers, without any prompt.

## How to fix

- Run `aws sso logout` when you are done, especially before handing the shell to an agent.
- Use a permission set scoped to what the agent needs, and a short session duration.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-003",
  "title": "AWS SSO profile with a cached session",
  "location": "~/.aws/config [profile sso-dev]",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "role PowerUser; ~/.aws/sso/cache holds a session token (it may have expired)",
  "fix": "Run aws sso logout when you are done, and use a permission set scoped to what the agent needs.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [AWS CLI: IAM Identity Center authentication](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
