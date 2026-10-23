# HK-RT-001: PHP without the php2shell fixes (8.5.12, 8.4.27, 8.3.36, 8.2.35), or end of life

| Check | Runs in | Default severity |
|---|---|---|
| `runtime-versions` | `heldkeys incident black-october` | Low, or Medium for end-of-life versions |

## What it detects

The version printed by `php --version` on `PATH`, the versions installed by Homebrew, phpenv, asdf and phpbrew (from their directory names), and the versions the project pins in `FROM php:` lines of Dockerfiles, `image: php:` lines of compose files, `.php-version` and `.tool-versions`. 8.2 to 8.5 below the fixed release are Low; 8.1 and older, which get no fix, are Medium. Only full `X.Y.Z` versions are judged, except a major below 8, which is end of life whatever the rest.

## Why it matters for agents

CVE-2026-109618 and CVE-2026-109619 allow unauthenticated remote code execution in every PHP installation that serves web requests. This is not a credential: it is listed so the rotation list and the patch list come from one run, and so an agent sandbox built on an old PHP image is noticed.

## How to fix

- Update to 8.5.12, 8.4.27, 8.3.36 or 8.2.35, internet-facing systems first.
- Take systems that cannot be updated offline, and put a web application firewall in front of the rest meanwhile (CISA's advice).
- 8.1 and older get no fix: upgrade or take them offline.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "runtime-versions",
  "rule": "HK-RT-001",
  "title": "PHP 8.4.26 without the php2shell fix",
  "location": "php on PATH (/opt/homebrew/bin/php)",
  "fingerprint": null,
  "severity": "low",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "CVE-2026-109618 and CVE-2026-109619, unauthenticated remote code execution in PHP serving web requests",
  "fix": "Update to PHP 8.4.27 or later; CISA: patch immediately, internet-facing systems first, and take systems offline that cannot be updated.",
  "category": "runtimes"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [CISA: critical vulnerabilities in PHP require immediate patching (21 Oct 2026)](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- [PHP releases](https://www.php.net/releases/)
