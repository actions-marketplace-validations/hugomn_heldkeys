# HK-LITELLM-004: PRIVCOLLECT_ACTIVE set in the environment by the LiteLLM stealer

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-litellm` | `heldkeys incident black-october` | High |

## What it detects

The environment variable `PRIVCOLLECT_ACTIVE`, which the stealer sets (to `1`) so it does not run twice in one process tree. Its presence is the finding; the value is not shown.

## Why it matters for agents

A shell that inherits this variable descends from a Python process that ran the stealer.

## How to fix

- Treat the host as compromised: take it off the network first.
- Kill the detached Python daemon (the process holding `/tmp/remote_code_loader.lock`), then delete `cook.pth`, `cook.py`, `sitecustomize.py` and their `__pycache__` entries from every site-packages directory. Do not run `pip` first: Python's startup would run the loader again.
- Reinstall `litellm==1.106.2` (or a later clean release) in a fresh environment, or rebuild the image.
- Rotate every credential in the report, cloud, source-control and CI tokens first, and check their audit logs around the install time.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "ioc-litellm",
  "rule": "HK-LITELLM-004",
  "title": "LiteLLM stealer flag in the environment",
  "location": "env: PRIVCOLLECT_ACTIVE",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "the stealer sets it so it runs once per process tree",
  "fix": "Treat this host as compromised: delete cook.pth, cook.py, sitecustomize.py and their __pycache__ entries from every site-packages, kill the detached Python daemon, reinstall litellm==1.106.2 from scratch, then rotate every credential below.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [LiteLLM: release v1.107.0 compromised (21 Oct 2026)](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
- [SafeDep: analysis and file hashes](https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/)
- [StepSecurity: indicators, loader behaviour and image digests](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
