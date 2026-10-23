# HK-LITELLM-003: Marker or lock file of the LiteLLM stealer in the temp directory

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-litellm` | `heldkeys incident black-october` | High |

## What it detects

`/tmp/.pc_once_72129118c59f5636c0bb`, which the stealer writes after a successful upload so it only collects once per host, `/tmp/remote_code_loader.lock`, which the loader's daemon holds while it runs, and `.pc_sq_*` or `.pc_e_*` scratch files in `$TMPDIR`, `/tmp` and `/var/tmp`.

## Why it matters for agents

The upload marker means the collected credentials left the machine. The lock file means the loader is still running and can fetch new code every hour.

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
  "rule": "HK-LITELLM-003",
  "title": "LiteLLM loader lock file",
  "location": "/tmp/remote_code_loader.lock",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "held by the loader's daemon while it runs",
  "fix": "Treat this host as compromised: delete cook.pth, cook.py, sitecustomize.py and their __pycache__ entries from every site-packages, kill the detached Python daemon, reinstall litellm==1.106.2 from scratch, then rotate every credential below.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [LiteLLM: release v1.107.0 compromised (21 Oct 2026)](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
- [SafeDep: analysis and file hashes](https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/)
- [StepSecurity: indicators, loader behaviour and image digests](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
