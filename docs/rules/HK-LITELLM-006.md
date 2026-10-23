# HK-LITELLM-006: LiteLLM Docker image with a compromised digest or the v1.107.0 tag

| Check | Runs in | Default severity |
|---|---|---|
| `ioc-litellm` | `heldkeys incident black-october` | High, or Medium for the tag alone |

## What it detects

`docker image ls --digests` (run only when `docker` is on `PATH`, with a timeout) for images whose repository name contains `litellm`: the image index digest `sha256:1bbcb144…c339e` and the amd64 manifest `sha256:bd1aeee4…3ea5` published for `litellm/litellm` and `ghcr.io/berriai/litellm`, and the truncated digests published for `litellm-database` and `litellm-non_root`, give a High finding. An image tagged `v1.107.0` whose digest is not on the list gives a Medium one, because that tag was only ever published with the stealer.

## Why it matters for agents

Containers started from the image ran the stealer with every secret mounted or passed into them, including the proxy's database of provider keys.

## How to fix

- Remove the image and rebuild every container that ran it from `v1.106.2` pulled by digest.
- Rotate the secrets those containers held: the proxy master and virtual keys, every provider key in the proxy database, `DATABASE_URL`, and the instance or task role.

## Example

One finding as `heldkeys incident black-october --format json` reports it:

```json
{
  "check": "ioc-litellm",
  "rule": "HK-LITELLM-006",
  "title": "LiteLLM image with a compromised digest",
  "location": "docker image ghcr.io/berriai/litellm:main-latest",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "digest sha256:1bbcb1443bc9… is one published for the compromised images",
  "fix": "Remove the image, rebuild every container that ran it from litellm v1.106.2 pulled by digest, and rotate the secrets those containers held.",
  "category": "indicators"
}
```

No fingerprint is shown for this finding: it is an indicator, not a credential, and heldkeys never prints the value of either.

## References

- [LiteLLM: release v1.107.0 compromised (21 Oct 2026)](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
- [SafeDep: analysis and file hashes](https://safedep.io/litellm-pypi-compromise-credential-stealer-backdoor/)
- [StepSecurity: indicators, loader behaviour and image digests](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
