# HK-BREACH-001: Railway login or project: environment variables stored there may have been read (21 Oct 2026)

| Check | Runs in | Default severity |
|---|---|---|
| `platform-breaches` | `heldkeys incident black-october` | Medium |

## What it detects

`~/.railway/config.json` (the CLI login, which HK-CLI-010 reports as a credential), and `railway.json` or `railway.toml` in the working directory. The files are not read; their presence means secrets are stored on Railway's side.

## Why it matters for agents

Railway disclosed on 21 October 2026 that an unauthorised party may have accessed the systems that store customer environment variables and obtained the decrypted contents of some. Whatever an agent on this machine deploys there, its variables may be in someone else's hands.

## How to fix

- Roll every environment variable stored in Railway, API keys and database and private registry credentials included.
- Review the logs of the services those secrets reach for unusual activity.
- Keep an eye on Railway's status page for updates on affected projects.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "platform-breaches",
  "rule": "HK-BREACH-001",
  "title": "Secrets stored in Railway need rotation",
  "location": "~/.railway/config.json",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "an unauthorised party may have read stored environment variables, some decrypted",
  "fix": "Roll every environment variable, API key and private registry credential stored in Railway, and review those services' logs for unusual activity (Railway's disclosure of 21 Oct 2026).",
  "category": "breaches"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [Railway: security disclosure, Wednesday October 21st](https://blog.railway.com/p/security-disclosure-wednesday-october-21st)
