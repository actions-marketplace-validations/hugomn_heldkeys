# HK-ENV-003: AWS access key pair in the environment

| Check | Runs in | Default severity |
|---|---|---|
| `env` | `heldkeys scan` | High for a long-lived `AKIA` key, Medium for temporary credentials (`ASIA` key or a session token). |

## What it detects

`AWS_ACCESS_KEY_ID` with `AWS_SECRET_ACCESS_KEY` (and optionally `AWS_SESSION_TOKEN`). The pair is reported once, fingerprinted by the access key id, which AWS does not treat as secret.

## Why it matters for agents

The environment is the first thing a hijacked agent sees. `env`, `printenv` and `/proc/self/environ` list it without touching a single file, and every process the agent starts inherits it. A variable exported once in a shell profile is therefore handed to every tool call the agent makes. Every AWS SDK and the AWS CLI pick these variables up automatically, ahead of any profile.

## How to fix

- Replace a static key with short-lived credentials from IAM Identity Center (`aws sso login`) or an assumed role, then deactivate the key in IAM.
- For temporary credentials, keep sessions short and scope the role's session policy to what the agent needs.
- Do not export AWS keys in the shell the agent inherits; use a named profile and pass `AWS_PROFILE` only to commands that need it.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "env",
  "rule": "HK-ENV-003",
  "title": "Long-lived AWS access key",
  "location": "env: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY",
  "fingerprint": "AKIA…PLE",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": null,
  "fix": "Replace the static key with short-lived credentials (aws sso login or an assumed role), then deactivate it.",
  "category": "environment"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [AWS CLI: environment variables](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html)
- [AWS IAM: security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS CLI: IAM Identity Center authentication](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
