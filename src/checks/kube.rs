//! `kube`: users in kubeconfig files (`$KUBECONFIG` or `~/.kube/config`).
//!
//! Every user entry is a way into a cluster. Static tokens, client keys and
//! passwords work until someone revokes them; exec plugins and auth providers
//! mint short-lived tokens from some other credential.

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::checks::display;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::redact;
use crate::yaml::{self, Yaml};

pub struct KubeCheck;

const ID: &str = "kube";

const TOKEN: Rule = Rule {
    check: ID,
    id: "HK-KUBE-001",
    summary: "kubeconfig user with a static bearer token",
};

const TOKEN_FILE: Rule = Rule {
    check: ID,
    id: "HK-KUBE-002",
    summary: "kubeconfig user reading a bearer token from a file",
};

const CLIENT_KEY: Rule = Rule {
    check: ID,
    id: "HK-KUBE-003",
    summary: "kubeconfig user with a client certificate key",
};

const PASSWORD: Rule = Rule {
    check: ID,
    id: "HK-KUBE-004",
    summary: "kubeconfig user with a basic-auth password",
};

const EXEC: Rule = Rule {
    check: ID,
    id: "HK-KUBE-005",
    summary: "kubeconfig user with an exec credential plugin",
};

const AUTH_PROVIDER: Rule = Rule {
    check: ID,
    id: "HK-KUBE-006",
    summary: "kubeconfig user with auth-provider tokens",
};

const RULES: &[Rule] = &[TOKEN, TOKEN_FILE, CLIENT_KEY, PASSWORD, EXEC, AUTH_PROVIDER];

const FIX_STATIC: &str = "Replace static credentials with an exec plugin (cloud SSO/OIDC), or give the agent a kubeconfig with a namespaced, read-only user.";
const FIX_DYNAMIC: &str =
    "Give the agent a separate kubeconfig whose user maps to a narrowly scoped role.";

impl Check for KubeCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Kubernetes: users in $KUBECONFIG or ~/.kube/config with static tokens, client keys, passwords, exec plugins or auth providers."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        kubeconfig_paths(ctx)
            .iter()
            .flat_map(|path| check_file(ctx, path))
            .collect()
    }
}

/// `$KUBECONFIG` is a list of files separated like `$PATH`.
fn kubeconfig_paths(ctx: &Context) -> Vec<PathBuf> {
    match ctx.var("KUBECONFIG") {
        Some(list) => std::env::split_paths(list)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| ctx.resolve(&p.to_string_lossy()))
            .collect(),
        None => vec![ctx.home_path(".kube/config")],
    }
}

fn check_file(ctx: &Context, path: &Path) -> Vec<Finding> {
    let Some(doc) = crate::checks::read_yaml(ctx, path) else {
        return Vec::new();
    };
    let contexts = yaml::list_at(&doc, "contexts");
    yaml::list_at(&doc, "users")
        .iter()
        .filter_map(|entry| {
            let name = yaml::str_at(entry, "name").unwrap_or("(unnamed)");
            // User names are free text; people have put URLs with
            // credentials in them.
            let location = format!("{} user {}", ctx.display_path(path), display::label(name));
            let finding = classify_user(&entry["user"], location)?;
            Some(add_contexts(finding, contexts, name))
        })
        .collect()
}

/// Decides what kind of credential a kubeconfig `user` holds.
fn classify_user(user: &Yaml, location: String) -> Option<Finding> {
    if let Some(token) = yaml::str_at(user, "token") {
        return Some(
            Finding::new(
                TOKEN,
                "Kubernetes bearer token",
                location,
                Severity::High,
                Lifetime::Unknown,
                Access::Unknown,
                FIX_STATIC,
            )
            .with_fingerprint(redact::fingerprint(token)),
        );
    }
    if yaml::has(user, "tokenFile") {
        return Some(Finding::new(
            TOKEN_FILE,
            "Kubernetes bearer token (from file)",
            location,
            Severity::High,
            Lifetime::Unknown,
            Access::Unknown,
            FIX_STATIC,
        ));
    }
    if yaml::has(user, "client-key-data") || yaml::has(user, "client-key") {
        return Some(Finding::new(
            CLIENT_KEY,
            "Kubernetes client certificate key",
            location,
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            FIX_STATIC,
        ));
    }
    if yaml::has(user, "password") {
        return Some(Finding::new(
            PASSWORD,
            "Kubernetes basic-auth password",
            location,
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            FIX_STATIC,
        ));
    }
    if yaml::has(user, "exec") {
        let command = yaml::str_at(&user["exec"], "command").unwrap_or("");
        return Some(
            Finding::new(
                EXEC,
                "Kubernetes exec credential plugin",
                location,
                Severity::Medium,
                Lifetime::ShortLived,
                Access::Unknown,
                FIX_DYNAMIC,
            )
            .with_detail(format!("runs {}", program_name(command))),
        );
    }
    if yaml::has(user, "auth-provider") {
        let provider = &user["auth-provider"];
        let name = display::label(yaml::str_at(provider, "name").unwrap_or("unknown"));
        let config = &provider["config"];
        // A cached refresh token keeps working long after the id token expires.
        let (severity, lifetime) = if yaml::has(config, "refresh-token") {
            (Severity::High, Lifetime::LongLived)
        } else {
            (Severity::Medium, Lifetime::ShortLived)
        };
        return Some(
            Finding::new(
                AUTH_PROVIDER,
                "Kubernetes auth-provider credentials",
                location,
                severity,
                lifetime,
                Access::Unknown,
                FIX_DYNAMIC,
            )
            .with_detail(format!("provider {name}")),
        );
    }
    None
}

/// Adds which contexts use this user, so the reader can tell which cluster it reaches.
fn add_contexts(finding: Finding, contexts: &[Yaml], user: &str) -> Finding {
    let names: Vec<String> = contexts
        .iter()
        .filter(|c| yaml::str_at(&c["context"], "user") == Some(user))
        .filter_map(|c| yaml::str_at(c, "name"))
        .map(display::label)
        .collect();
    if names.is_empty() {
        return finding;
    }
    let contexts = format!("contexts: {}", names.join(", "));
    let detail = match &finding.detail {
        Some(d) => format!("{d}; {contexts}"),
        None => contexts,
    };
    finding.with_detail(detail)
}

/// Only the program's file name: the full command line may carry secrets.
fn program_name(command: &str) -> String {
    display::program_name(command).unwrap_or_else(|| "an exec plugin".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, fixture_ctx, write};

    #[test]
    fn full_fixture() {
        let f = KubeCheck.run(&fixture_ctx("full"));
        assert_eq!(f.len(), 3, "{f:?}");
        let token = f
            .iter()
            .find(|f| f.title == "Kubernetes bearer token")
            .unwrap();
        assert_eq!(token.location, "~/.kube/config user prod-admin");
        assert_eq!(token.detail.as_deref(), Some("contexts: prod"));
        assert!(
            f.iter()
                .any(|f| f.title == "Kubernetes client certificate key")
        );
        let exec = f
            .iter()
            .find(|f| f.title == "Kubernetes exec credential plugin")
            .unwrap();
        assert_eq!(exec.detail.as_deref(), Some("runs aws; contexts: eks-dev"));
    }

    #[test]
    fn kubeconfig_env_list() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.yaml",
            "users:\n- name: a\n  user:\n    password: fakepass\n",
        );
        write(
            dir.path(),
            "b.yaml",
            "users:\n- name: b\n  user:\n    tokenFile: /x\n",
        );
        let list = format!("a.yaml{}b.yaml", if cfg!(windows) { ";" } else { ":" });
        let ctx = ctx_with_env(dir.path(), &[("KUBECONFIG", &list)]);
        let f = KubeCheck.run(&ctx);
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn invalid_yaml_is_recorded_not_reported_as_a_credential() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".kube/config", "users: [\n");
        let ctx = ctx_with_env(dir.path(), &[]);
        assert!(KubeCheck.run(&ctx).is_empty());
        let problems = ctx.take_unreadable();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].1.starts_with("not valid YAML"), "{problems:?}");
    }

    #[test]
    fn user_names_with_credentials_are_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".kube/config",
            "users:\n- name: \"https://dave:FAKEkubeName0013@k8s\"\n  user:\n    token: abc\ncontexts:\n- name: ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000013\n  context:\n    user: \"https://dave:FAKEkubeName0013@k8s\"\n",
        );
        let f = KubeCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f[0].location, "~/.kube/config user https://k8s");
        assert_eq!(f[0].detail.as_deref(), Some("contexts: ghp_…013"));
    }
}
