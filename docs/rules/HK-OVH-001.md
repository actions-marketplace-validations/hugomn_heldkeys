# HK-OVH-001: ovhcloud CLI binary matching a published malicious build (MD5)

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-ovhcloud` | `heldkeys incident black-october` | High |

## What it detects

Every `ovhcloud` (or `ovhcloud.exe`) binary on `PATH`, in `~/.local/bin`, `$XDG_BIN_HOME`, `~/bin`, `~/go/bin`, `/usr/local/bin`, `/opt/homebrew/bin` and the Homebrew Caskroom, hashed with MD5 and compared with the five hashes OVHcloud published for the replaced release assets (Darwin arm64 and x86_64, Linux arm64 and x86_64, Windows x86_64). The binary is never run.

## Why it matters for agents

The replaced builds are the real CLI with a stealer compiled in: it copies the VS Code, Cursor, Continue, Cody and OpenCode databases, Claude's and Hermes's data, AWS, Google Cloud and Azure logins, Docker and Kubernetes configs, npm and doctl configs, SSH keys, Terraform credentials, `.netrc` and the global git config into a temporary directory, archives them and uploads the archive.

## How to fix

- Delete the binary and install ovhcloud-cli 0.16.0 or later (`brew upgrade --cask ovhcloud-cli`, or the install script).
- Rotate every credential in the report; the advisory lists what the build steals.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "ioc-ovhcloud",
  "rule": "HK-OVH-001",
  "title": "ovhcloud CLI is a known malicious build",
  "location": "~/.local/bin/ovhcloud",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "MD5 matches OVHcloud's list of replaced binaries",
  "fix": "Delete the binary, install ovhcloud-cli 0.16.0 or later, and rotate every credential below: the build copies AI tool databases, cloud logins, Docker and kube configs, SSH keys and .netrc.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [OVHcloud: ovhcloud-cli security incident of 19 October 2026 (GHSA-862f-55f5-vmvw)](https://github.com/ovh/ovhcloud-cli/security/advisories/GHSA-862f-55f5-vmvw)
