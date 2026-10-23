# HK-LITELLM-005: Detached Python process of the LiteLLM remote code loader

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-litellm` | `heldkeys incident black-october` | High |

## What it detects

Only looked for when HK-LITELLM-003 found a marker or the lock file. On Linux, every process in `/proc` whose open files include `/tmp/remote_code_loader.lock`, or that is a `python` with parent PID 1 and working directory `/` (the loader forks, calls `setsid()` and changes to `/`). Elsewhere, `lsof -t` on the lock file. The process is not touched.

## Why it matters for agents

The daemon fetches a hostname from a dead drop and runs whatever `/codepy` on that host returns, every hour, with the user's credentials around it.

## How to fix

- Kill the process (`kill -9 <pid>`) before deleting the files, or Python's next start would recreate it.
- Then follow HK-LITELLM-002's cleanup and rotate every credential in the report.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "ioc-litellm",
  "rule": "HK-LITELLM-005",
  "title": "LiteLLM loader daemon running",
  "location": "pid 4242",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "holds the loader lock file: python3 -c import sitecustomize",
  "fix": "Kill the process before deleting the stealer files (kill -9 <pid>), then follow the LiteLLM advisory and rotate every credential below.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [LiteLLM: release v1.107.0 compromised (21 Oct 2026)](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
- [SafeDep: analysis and file hashes](https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/)
- [StepSecurity: indicators, loader behaviour and image digests](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
