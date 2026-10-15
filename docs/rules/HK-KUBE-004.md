# HK-KUBE-004: kubeconfig user with a basic-auth password

| Check | Runs in | Default severity |
|---|---|---|
| `kube` | `heldkeys scan` | High |

## What it detects

A kubeconfig user with `password`.

## Why it matters for agents

`kubectl` and every Kubernetes client read the kubeconfig on their own. Each `user` entry is a way into a cluster, with whatever RBAC that user has. The detail line lists the contexts that use it, so you can tell which cluster is exposed. Static passwords are long-lived and plaintext in the file.

## How to fix

- Replace static credentials with an exec plugin that uses your cloud's SSO or OIDC.
- Give the agent its own kubeconfig with a namespaced, read-only user.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "kube",
  "rule": "HK-KUBE-004",
  "title": "Kubernetes basic-auth password",
  "location": "~/.kube/config user admin",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "contexts: legacy",
  "fix": "Replace static credentials with an exec plugin (cloud SSO/OIDC), or give the agent a kubeconfig with a namespaced, read-only user.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Kubernetes: authenticating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
