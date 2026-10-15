# HK-K8SSA-001: Readable Kubernetes service account token

| Check | Runs in | Default severity |
|---|---|---|
| `k8s-service-account` | `heldkeys scan` | High |

## What it detects

A non-empty token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. The detail names the namespace.

## Why it matters for agents

Unless `automountServiceAccountToken: false` is set, every pod gets this token. An agent running in the pod can call the cluster API with whatever RBAC the service account has. Projected tokens expire, but the kubelet keeps refreshing the file, so the agent always has a valid one.

## How to fix

- Set `automountServiceAccountToken: false` for pods that run agents.
- Or bind the service account to a minimal Role in its own namespace.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "k8s-service-account",
  "rule": "HK-K8SSA-001",
  "title": "Kubernetes service account token",
  "location": "/var/run/secrets/kubernetes.io/serviceaccount/token",
  "fingerprint": "eyJh…014",
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "namespace agents",
  "fix": "Set automountServiceAccountToken: false for pods that run agents, or bind the account to a minimal Role.",
  "category": "host"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Kubernetes: configure service accounts for pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Kubernetes: RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
