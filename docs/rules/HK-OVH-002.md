# HK-OVH-002: ovhcloud CLI from the tampered release range, or installed in the tampering window

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-ovhcloud` | `heldkeys incident black-october` | Medium, Low or Info |

## What it detects

An `ovhcloud` binary whose MD5 is not on the list, judged by two weaker signs: its modification time inside the window of 19 October 2026, 12:47 to 14:21 UTC, when the assets were replaced (Medium), or a version from 0.11.0 to 0.15.0 in its path, as the Homebrew Caskroom records it (Low). A binary with neither sign is an Info note saying it was checked, so the report shows the check ran.

## Why it matters for agents

OVHcloud's list covers the five release assets; a binary repackaged from one of them, or installed through a wrapper, can carry the same code under a different hash. Downloads of those versions outside the window are clean.

## How to fix

- Update to ovhcloud-cli 0.16.0 or later.
- If the binary was downloaded in the window, treat it as HK-OVH-001 and rotate every credential in the report.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "ioc-ovhcloud",
  "rule": "HK-OVH-002",
  "title": "ovhcloud CLI 0.14.0 from the affected range",
  "location": "/opt/homebrew/Caskroom/ovhcloud-cli/0.14.0/ovhcloud",
  "fingerprint": null,
  "severity": "low",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "MD5 is not in OVHcloud's list; clean unless downloaded on 19 Oct 2026 between 12:47 and 14:21 UTC",
  "fix": "Update to ovhcloud-cli 0.16.0 or later.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [OVHcloud: ovhcloud-cli security incident of 19 October 2026 (GHSA-862f-55f5-vmvw)](https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw)
