# HK-META-001: Cloud instance metadata endpoint reachable (context)

| Check | Runs in | Default severity |
|---|---|---|
| `cloud-metadata` | `heldkeys scan` | Info |

## What it detects

Whether a TCP connection to 169.254.169.254 port 80 opens within 300 ms. No HTTP request is made and nothing is sent. This is the only network access heldkeys makes by default; `HELDKEYS_NO_NET=1` turns it off.

## Why it matters for agents

On AWS, Google Cloud, Azure and most other clouds, the metadata service hands out the instance's role credentials to any local process. heldkeys reports reachability as context, not as a credential, because it cannot see what the instance role allows without asking for credentials, which it never does.

## How to fix

- Block 169.254.169.254 from the agent's sandbox (network policy, firewall rule).
- On AWS, require IMDSv2 with a hop limit of 1, so containers cannot reach it.
- Give the instance role only what the workload needs.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "cloud-metadata",
  "rule": "HK-META-001",
  "title": "Cloud metadata endpoint is reachable",
  "location": "169.254.169.254:80",
  "fingerprint": null,
  "severity": "info",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "any process here may be able to fetch the instance role's credentials",
  "fix": "Block 169.254.169.254 from the agent's sandbox, or require IMDSv2 with a hop limit of 1.",
  "category": "host"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Amazon EC2: configure the instance metadata service (IMDSv2)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Google Cloud: about VM metadata](https://cloud.google.com/compute/docs/metadata/overview)
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
