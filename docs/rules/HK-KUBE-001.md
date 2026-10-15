# HK-KUBE-001: kubeconfig user with a static bearer token

| Check | Runs in | Default severity |
|---|---|---|
| `kube` | `heldkeys scan` | High |

## What it detects

A `users[].user.token` in `$KUBECONFIG` (every file in the list) or `~/.kube/config`. The fingerprint is shown when the token has a known format, such as a JWT.

## Why it matters for agents

`kubectl` and every Kubernetes client read the kubeconfig on their own. Each `user` entry is a way into a cluster, with whatever RBAC that user has. The detail line lists the contexts that use it, so you can tell which cluster is exposed. A static token works until someone revokes it, and many are cluster-admin tokens created for convenience.

## How to fix

- Replace static credentials with an exec plugin that uses your cloud's SSO or OIDC.
- Give the agent its own kubeconfig with a namespaced, read-only user.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "kube",
  "rule": "HK-KUBE-001",
  "title": "Kubernetes bearer token",
  "location": "~/.kube/config user prod-admin",
  "fingerprint": "eyJh…006",
  "severity": "high",
  "lifetime": "unknown",
  "access": "unknown",
  "detail": "contexts: prod",
  "fix": "Replace static credentials with an exec plugin (cloud SSO/OIDC), or give the agent a kubeconfig with a namespaced, read-only user.",
  "category": "cloud-cli"
}
```

The fingerprint shows at most the first 4 and last 3 characters of a known token format, whose prefix is public anyway. heldkeys never prints the value.

## References

- [Kubernetes: authenticating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Kubernetes: organizing cluster access using kubeconfig files](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/)
- [Kubernetes: RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
