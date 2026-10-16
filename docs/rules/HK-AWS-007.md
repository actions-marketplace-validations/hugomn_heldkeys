# HK-AWS-007: Cached assumed-role credentials in ~/.aws/cli/cache

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan` | Medium |

## What it detects

JSON files in `~/.aws/cli/cache` that hold a `SecretAccessKey`. The AWS CLI writes them when it assumes a role and keeps them until they expire. heldkeys reads each session's `Expiration`: while one has not expired, the finding is titled "Cached AWS session usable without MFA" and says until when (in UTC). Sessions without an expiry are reported as "Cached AWS role credentials", possibly expired. A cache that only holds expired sessions is not reported, because nobody can use them any more.

## Why it matters for agents

The AWS CLI and every AWS SDK read `~/.aws/credentials` and `~/.aws/config` on their own. A hijacked agent does not need to find or parse anything: `aws sts get-caller-identity --profile <name>` is enough to use the profile, with whatever permissions it carries. The cache files contain ready-to-use temporary keys, readable by any process running as you.

## How to fix

- Clear the cache before handing a shell to an agent (delete `~/.aws/cli/cache`).
- Keep role session durations short.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-007",
  "title": "Cached AWS session usable without MFA",
  "location": "~/.aws/cli/cache",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "1 unexpired session(s), the last valid until 2099-01-01 12:00 UTC",
  "fix": "Clear the cache before handing a shell to an agent (delete ~/.aws/cli/cache), and keep role sessions short.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [AWS CLI: using an IAM role](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html)
