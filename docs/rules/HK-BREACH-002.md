# HK-BREACH-002: Zeabur login or project: the platform database was read (14 to 15 Oct 2026)

| Check | Runs in | Default severity |
|---|---|---|
| `platform-breaches` | `heldkeys incident black-october` | Medium |

## What it detects

`~/.config/zeabur/cli.yaml` (the CLI's config and token) and `zbpack.json` in the working directory. The files are not read.

## Why it matters for agents

Zeabur's preliminary report says an attacker with leaked internal credentials read the platform database on 14 and 15 October 2026: 3,218,965 environment variable records and 321,810 accounts, plus root access to a number of dedicated servers. Every credential stored on Zeabur, including ones replaced after the August incident, is to be treated as leaked. Zeabur has announced it shuts down on 31 December 2026.

## How to fix

- Revoke every key stored in Zeabur variables with its provider, create new ones and redeploy; change database passwords directly, since changing the variable does not change them.
- Sign in again and recreate access tokens: the old ones were revoked.
- Plan the migration off Zeabur before 31 December 2026.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "platform-breaches",
  "rule": "HK-BREACH-002",
  "title": "Secrets stored on Zeabur need rotation",
  "location": "~/.config/zeabur/cli.yaml",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "the platform database, environment variables included, was read on 14 and 15 Oct 2026",
  "fix": "Revoke and recreate every credential stored in Zeabur variables, sign in again (all access tokens were revoked), and plan the move off Zeabur: it shuts down on 31 Dec 2026.",
  "category": "breaches"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [Zeabur: October 2026 security incident](https://zeabur.com/blogs/october-2026-security-incident)
