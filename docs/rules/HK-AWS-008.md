# HK-AWS-008: Cached AWS session credentials in the awsume cache

| Check | Runs in | Default severity |
|---|---|---|
| `aws` | `heldkeys scan`, `heldkeys preflight` | Medium |

## What it detects

Files in `~/.awsume/cache` that hold a `SecretAccessKey`: the sessions awsume assumed, often after an MFA prompt. heldkeys reads each session's `Expiration`. While one has not expired the finding is titled "Cached AWS session usable without MFA" and says until when (in UTC); sessions without an expiry are reported as possibly expired; a cache that only holds expired sessions is not reported, because nobody can use them any more.

## Why it matters for agents

The MFA prompt happened when the session was created. Until it expires, any process running as you can read the cached keys and use the role, without MFA and without awsume.

## How to fix

- Clear the cache before handing a shell to an agent (`awsume --clean`, or delete `~/.awsume/cache`).
- Keep role session durations short.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "aws",
  "rule": "HK-AWS-008",
  "title": "Cached AWS session usable without MFA",
  "location": "~/.awsume/cache",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "1 unexpired session(s), the last valid until 2099-01-01 12:00 UTC",
  "fix": "Clear the cache before handing a shell to an agent (awsume --clean, or delete ~/.awsume/cache).",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [awsume](https://awsu.me/)
