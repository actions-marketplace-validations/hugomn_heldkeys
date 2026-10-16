# HK-CLI-002: Terraform Cloud API token in credentials.tfrc.json

| Check | Runs in | Default severity |
|---|---|---|
| `cli-logins` | `heldkeys scan`, `heldkeys preflight` | High |

## What it detects

`credentials.<host>.token` entries in `~/.terraform.d/credentials.tfrc.json`, written by `terraform login` for HCP Terraform (`app.terraform.io`) or a Terraform Enterprise host. One finding per host.

## Why it matters for agents

A user API token can queue plans and applies in every workspace you can reach, read state files (which often hold secrets) and change variables.

## How to fix

- Run `terraform logout` where agents run.
- Give automation a team token scoped to the workspaces it needs.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cli-logins",
  "rule": "HK-CLI-002",
  "title": "Terraform Cloud API token",
  "location": "~/.terraform.d/credentials.tfrc.json [app.terraform.io]",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "write",
  "detail": "Terraform CLI: credentials.*.token",
  "fix": "Run terraform logout where agents run; give automation a team token scoped to the workspaces it needs.",
  "category": "dev-platform"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Terraform: terraform login](https://developer.hashicorp.com/terraform/cli/commands/login)
