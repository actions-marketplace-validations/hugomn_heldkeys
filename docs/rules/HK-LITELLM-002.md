# HK-LITELLM-002: LiteLLM stealer or loader file in a site-packages directory

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-litellm` | `heldkeys incident black-october` | High |

## What it detects

`cook.pth`, `cook.py` or `sitecustomize.py` in one of the site-packages directories HK-LITELLM-001 looks in, hashed with SHA-256 against the published samples (Linux and macOS wheels, and the Windows wheel). `cook.pth` and `cook.py` are reported by name even when the hash differs; `sitecustomize.py` exists legitimately in some distributions, so it only counts when its hash matches or the `cook` files sit next to it. Compiled copies in `__pycache__` are reported too, since the source may have been deleted.

## Why it matters for agents

The malicious wheels install a credential stealer that Python runs on every start, whether or not litellm is imported: it collects cloud CLI logins, SSH keys, browser passwords, AI tool logins, `.netrc`, kubeconfigs, CI runner configs and the LiteLLM proxy's own database of provider keys, uploads them, and leaves a loader that fetches more code every hour. Every credential heldkeys lists for this machine should be treated as taken.

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
  "rule": "HK-LITELLM-002",
  "title": "LiteLLM stealer file in site-packages",
  "location": "./.venv/lib/python3.12/site-packages/cook.pth",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "SHA-256 matches the published sample",
  "fix": "Treat this host as compromised: delete cook.pth, cook.py, sitecustomize.py and their __pycache__ entries from every site-packages, kill the detached Python daemon, reinstall litellm==1.106.2 from scratch, then rotate every credential below.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [LiteLLM: release v1.107.0 compromised (21 Oct 2026)](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
- [SafeDep: analysis and file hashes](https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/)
- [StepSecurity: indicators, loader behaviour and image digests](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
