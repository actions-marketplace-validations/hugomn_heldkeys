//! `k8s-service-account`: the pod's Kubernetes service account token.
//!
//! Unless `automountServiceAccountToken: false` is set, every pod gets a token
//! at a well-known path. An agent running in the pod can call the cluster API
//! with whatever RBAC that service account has.

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::redact;

pub struct K8sServiceAccountCheck;

const ID: &str = "k8s-service-account";

const SA_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-K8SSA-001",
    summary: "Readable Kubernetes service account token",
};

const RULES: &[Rule] = &[SA_TOKEN];

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

impl Check for K8sServiceAccountCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "A readable Kubernetes service account token at /var/run/secrets/kubernetes.io/serviceaccount."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let dir = ctx.root_path(SA_DIR);
        let token_path = dir.join("token");
        let Some(token) = ctx.read_file(&token_path) else {
            return Vec::new();
        };
        let token = token.trim();
        if token.is_empty() {
            return Vec::new();
        }
        let namespace = ctx
            .read_file(&dir.join("namespace"))
            .map(|n| crate::checks::display::label(n.trim()))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        vec![
            Finding::new(
                SA_TOKEN,
                "Kubernetes service account token",
                // Shown as the real path, not the fixture path.
                format!("{SA_DIR}/token"),
                // Access depends on RBAC we cannot see without calling the API.
                // Unknown access on a cluster credential is High.
                Severity::High,
                // Projected tokens expire, but the kubelet keeps refreshing the
                // file, so the agent always has a valid one.
                Lifetime::Unknown,
                Access::Unknown,
                "Set automountServiceAccountToken: false for pods that run agents, or bind the account to a minimal Role.",
            )
            .with_fingerprint(redact::fingerprint(token))
            .with_detail(format!("namespace {namespace}")),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, fixture_ctx, write};

    #[test]
    fn token_with_namespace() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "var/run/secrets/kubernetes.io/serviceaccount/token",
            concat!(
                "eyJhbGciOiJGQUtFIn0.",
                "eyJzdWIiOiJGQUtFRkFLRSJ9.FAKEFAKEsig\n"
            ),
        );
        write(
            dir.path(),
            "var/run/secrets/kubernetes.io/serviceaccount/namespace",
            "agents\n",
        );
        let f = K8sServiceAccountCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detail.as_deref(), Some("namespace agents"));
        assert_eq!(f[0].fingerprint.as_deref(), Some("eyJh…sig"));
        assert_eq!(
            f[0].location,
            "/var/run/secrets/kubernetes.io/serviceaccount/token"
        );
    }

    #[test]
    fn empty_fixture() {
        assert!(K8sServiceAccountCheck.run(&fixture_ctx("empty")).is_empty());
    }
}
