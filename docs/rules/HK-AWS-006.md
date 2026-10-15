# HK-AWS-006: AWS profile that mints credentials with credential_process

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan` | Medium |

## What it detects

A profile with `credential_process`. heldkeys reports the program name only, never its arguments, which sometimes carry secrets.

## Why it matters for agents

The AWS CLI and every AWS SDK read `~/.aws/credentials` and `~/.aws/config` on their own. A hijacked agent does not need to find or parse anything: `aws sts get-caller-identity --profile <name>` is enough to use the profile, with whatever permissions it carries. The CLI runs the process whenever it needs credentials. Unless that process asks a human (a hardware key touch, a password prompt), the agent gets credentials as easily as you do.

## How to fix

- Make sure the credential process requires user presence before it hands out keys.
- Or run the agent with a profile that does not use it.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-006",
  "title": "AWS profile with credential_process",
  "location": "~/.aws/config [profile proc]",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "runs fake-cred-tool to mint credentials",
  "fix": "Make sure the credential process requires user presence (for example a hardware key) before it hands out keys.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [AWS CLI: sourcing credentials with an external process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)
