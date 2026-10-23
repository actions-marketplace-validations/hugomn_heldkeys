# HK-LITELLM-007: Project requirements or lockfile pin litellm 1.107.0

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-litellm` | `heldkeys incident black-october` | Medium |

## What it detects

An exact pin of `1.107.0` in `requirements*.txt`, `constraints*.txt`, `pyproject.toml` or `Pipfile`, or the locked version in `poetry.lock`, `uv.lock`, `pdm.lock` or `Pipfile.lock`, under the working directory (four levels deep, dependency directories skipped). Looser specifiers (`>=`, `~=`) are not reported.

## Why it matters for agents

PyPI removed the release, so a fresh install fails, but a pip or uv cache that still holds the wheel installs the stealer again, and the pin says this environment was meant to run it.

## How to fix

- Pin `litellm==1.106.2` or a later clean release.
- Reinstall in a fresh environment, and check that environment with HK-LITELLM-001 and HK-LITELLM-002.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "ioc-litellm",
  "rule": "HK-LITELLM-007",
  "title": "Project pins litellm 1.107.0",
  "location": "./api/requirements.txt:12",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "exact pin ==1.107.0",
  "fix": "Pin litellm==1.106.2 or a later clean release and reinstall in a fresh environment: PyPI removed 1.107.0, but a cached wheel would still install it.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [LiteLLM: release v1.107.0 compromised (21 Oct 2026)](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
- [SafeDep: analysis and file hashes](https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/)
- [StepSecurity: indicators, loader behaviour and image digests](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
