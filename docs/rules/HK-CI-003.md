# HK-CI-003: OIDC token requests available: the job can mint cloud credentials

| Check | Runs in | Default severity |
|---|---|---|
| `ci-runtime` | `heldkeys ci` | Medium. High on a self-hosted runner. |

## What it detects

Both `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` in the environment of the heldkeys step, inside GitHub Actions. GitHub sets them when the job has `permissions: id-token: write`. With them, any process in the job can ask GitHub for an OIDC token that names this repository, workflow, ref and environment.

## Why it matters for agents

An OIDC token is not a cloud credential by itself, but every cloud role that trusts this repository's tokens will trade one for credentials: an AWS role through `AssumeRoleWithWebIdentity`, a Google service account through workload identity federation, an Azure app through federated credentials. A hijacked agent in this job can do that trade with `curl`, without any secret appearing in the environment.

How bad that is depends on the trust policies, which heldkeys cannot see. A policy that trusts `repo:owner/name:*` accepts tokens from every branch, pull request and workflow of the repository, including the one running the agent.

claude-code-action also uses `id-token: write` to fetch a Claude GitHub App token, which [HK-WF-001](HK-WF-001.md) counts as a write token.

## How to fix

- Grant `id-token: write` only to the job that deploys, not to a job that runs an agent.
- Pin cloud trust policies to a branch or a protected environment in the `sub` claim, never `repo:owner/name:*`.
- Keep the roles that OIDC can assume as narrow as the deploy needs.

## Example

One finding as `heldkeys ci --format json` reports it:

```json
{
  "check": "ci-runtime",
  "rule": "HK-CI-003",
  "title": "OIDC: this job can mint cloud credentials",
  "location": ".github/workflows/review.yml env: ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "fingerprint": null,
  "severity": "medium",
  "lifetime": "short-lived",
  "access": "unknown",
  "detail": "the job has id-token: write; any cloud role that trusts this repository's OIDC tokens can be assumed from here",
  "fix": "Grant id-token: write only to the job that deploys, and pin cloud trust policies to a branch or environment in the sub claim.",
  "category": "ci-job"
}
```

## References

- [GitHub: about security hardening with OpenID Connect](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [AWS: configuring a role for GitHub OIDC](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)
- [Google Cloud: workload identity federation with deployment pipelines](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
