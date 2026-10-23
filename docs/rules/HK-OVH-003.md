# HK-OVH-003: envchecker working directory left by the OVHcloud CLI stealer

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-ovhcloud` | `heldkeys incident black-october` | High |

## What it detects

A directory named `envchecker-` followed by nine or ten digits in `$TMPDIR`, `/tmp` or `/var/tmp`. The stealer creates one on every run to stage the files it copies, and never deletes it.

## Why it matters for agents

The replaced builds are the real CLI with a stealer compiled in: it copies the VS Code, Cursor, Continue, Cody and OpenCode databases, Claude's and Hermes's data, AWS, Google Cloud and Azure logins, Docker and Kubernetes configs, npm and doctl configs, SSH keys, Terraform credentials, `.netrc` and the global git config into a temporary directory, archives them and uploads the archive. The directory holds copies of those files, so it also shows exactly what was taken.

## How to fix

- Delete the binary and install ovhcloud-cli 0.16.0 or later (`brew upgrade --cask ovhcloud-cli`, or the install script).
- Rotate every credential in the report; the advisory lists what the build steals.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "ioc-ovhcloud",
  "rule": "HK-OVH-003",
  "title": "OVHcloud stealer working directory",
  "location": "/var/folders/ab/…/T/envchecker-1729345678",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "the malicious build copies what it steals here before uploading it",
  "fix": "Delete the binary, install ovhcloud-cli 0.16.0 or later, and rotate every credential below: the build copies AI tool databases, cloud logins, Docker and kube configs, SSH keys and .netrc.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [OVHcloud: ovhcloud-cli security incident of 19 October 2026 (GHSA-862f-55f5-vmvw)](https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw)
