# HK-KUBE-006: kubeconfig user with auth-provider tokens

| Check | Runs in | Default severity |
|---|---|---|
| `kube` | `heldkeys scan` | High when the config caches a refresh token, Medium otherwise. |

## What it detects

A kubeconfig user with the legacy `auth-provider` block (for example `oidc`), which caches id and refresh tokens in the file.

## Why it matters for agents

`kubectl` and every Kubernetes client read the kubeconfig on their own. Each `user` entry is a way into a cluster, with whatever RBAC that user has. The detail line lists the contexts that use it, so you can tell which cluster is exposed. A cached refresh token keeps working long after the id token expires.

## How to fix

- Give the agent a separate kubeconfig whose user maps to a narrowly scoped role.
- Move to an exec plugin; the built-in `auth-provider` plugins are deprecated in favour of exec plugins.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "kube",
  "rule": "HK-KUBE-006",
  "title": "Kubernetes auth-provider credentials",
  "location": "~/.kube/config user gke-user",
  "fingerprint": null,
  "severity": "high",
  "lifetime": "long-lived",
  "access": "unknown",
  "detail": "provider oidc; contexts: gke-prod",
  "fix": "Give the agent a separate kubeconfig whose user maps to a narrowly scoped role.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Kubernetes: authenticating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
