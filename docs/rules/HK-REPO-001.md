# HK-REPO-001: Token of a known format in a tracked file

| Check | Runs in | Default severity |
|---|---|---|
| `repo-secrets` | `heldkeys ci --repo-secrets` (action input `repo-secrets: true`) | By format: High for long-lived cloud, source-control and AI provider keys, Medium for short-lived ones, Low for test-mode keys. |

## What it detects

Tokens of a known format (`ghp_`, `AKIA`, `sk-ant-`, `npm_`, `xoxb-`, connection strings with a password, ...) in files tracked by git on the current branch. The file list comes from `git ls-files`, run with a cleared environment and `core.fsmonitor` off, so the repository's own config cannot make git run a program. Binary files, files over 1 MiB and URLs whose password is an obvious placeholder (`postgres://user:password@localhost`) are skipped. The location is `file:line`; at most 200 findings are reported.

It is off unless you ask for it. It is a quick check of the current tree, not a history scanner: a token removed in a later commit is still in git history, and heldkeys does not look there.

## Why it matters for agents

An agent working in a repository reads its files: that is its job. A token committed to any of them is a token the agent holds, and so is every agent, CI job and person who can clone the repository.

## How to fix

- Revoke and rotate the token first; removing it from the file does not remove it from history.
- Remove it from the file and load it at runtime from a secret store or the CI's secrets.
- Scan the full history with [gitleaks](https://github.com/gitleaks/gitleaks) or [TruffleHog](https://github.com/trufflesecurity/trufflehog).

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "repo-secrets",
  "rule": "HK-REPO-001",
  "title": "GitHub personal access token (classic)",
  "location": "config/settings.py:2",
  "fingerprint": "ghp_…401",
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "tracked on the current branch: anyone who can read the repo, and any agent working in it, can use it",
  "fix": "Revoke and rotate it, then remove it from the file; git history still has it, so scan history with gitleaks.",
  "category": "repo-files"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format. heldkeys never prints the value.

## References

- [GitHub: removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [gitleaks](https://github.com/gitleaks/gitleaks)
