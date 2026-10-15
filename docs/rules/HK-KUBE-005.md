# HK-KUBE-005: kubeconfig user with an exec credential plugin

| Check | Runs in | Default severity |
|---|---|---|
| `kube` | `heldkeys scan` | Medium |

## What it detects

A kubeconfig user with an `exec` plugin, such as `aws eks get-token`, `gke-gcloud-auth-plugin` or `kubelogin`. Only the program name is reported.

## Why it matters for agents

`kubectl` and every Kubernetes client read the kubeconfig on their own. Each `user` entry is a way into a cluster, with whatever RBAC that user has. The detail line lists the contexts that use it, so you can tell which cluster is exposed. The plugin mints short-lived tokens on demand, from whatever credential it relies on. Unless it asks a human, the agent gets cluster access as easily as you do.

## How to fix

- Give the agent a separate kubeconfig whose user maps to a narrowly scoped role.

## Example

One finding as `heldkeys --format json` reports it:

```json
{
  "check": "kube",
  "rule": "HK-KUBE-005",
  "title": "Kubernetes exec credential plugin",
  "location": "~/.kube/config user eks-user",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "runs aws; contexts: eks-dev",
  "fix": "Give the agent a separate kubeconfig whose user maps to a narrowly scoped role.",
  "category": "cloud-cli"
}
```

No fingerprint is shown for this finding: heldkeys only fingerprints values of a known format, and never prints the value itself.

## References

- [Kubernetes: authenticating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Kubernetes: organizing cluster access using kubeconfig files](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/)
