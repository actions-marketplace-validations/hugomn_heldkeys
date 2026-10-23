# HK-LITELLM-001: litellm 1.107.0 installed in a Python environment

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-litellm` | `heldkeys incident black-october` | High |

## What it detects

A `litellm-1.107.0.dist-info` directory in a site-packages directory: the project's virtualenvs (any directory with a `pyvenv.cfg` under the working directory, four levels deep), the user's (`~/.venv`, `~/.virtualenvs`, pipx, poetry, uv tools, pyenv, conda, `~/.local/lib/python3.*`, `~/Library/Python`) and the system's (`/usr/lib`, `/usr/local/lib`, Homebrew, the Python.framework, `/opt/conda`, `/app/.venv` in containers). Only the files are read; Python is never run, because running it is what starts the malware.

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
  "rule": "HK-LITELLM-001",
  "title": "litellm 1.107.0 installed",
  "location": "./.venv/lib/python3.12/site-packages",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "litellm-1.107.0.dist-info present",
  "fix": "Treat this host as compromised: delete cook.pth, cook.py, sitecustomize.py and their __pycache__ entries from every site-packages, kill the detached Python daemon, reinstall litellm==1.106.2 from scratch, then rotate every credential below.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [LiteLLM: release v1.107.0 compromised (21 Oct 2026)](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
- [SafeDep: analysis and file hashes](https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/)
- [StepSecurity: indicators, loader behaviour and image digests](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
