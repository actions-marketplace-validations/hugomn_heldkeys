//! `env`: environment variables that look like credentials.
//!
//! The environment is the first thing a hijacked agent sees (`env`, `printenv`,
//! `/proc/self/environ`), and every child process inherits it.

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::redact;
use crate::rules;

pub struct EnvCheck;

const ID: &str = "env";

const KNOWN_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-ENV-001",
    summary: "Environment variable holding a token of a known format",
};

const BY_NAME: Rule = Rule {
    check: ID,
    id: "HK-ENV-002",
    summary: "Credential-named environment variable with a secret-looking value",
};

const AWS_KEYS: Rule = Rule {
    check: ID,
    id: "HK-ENV-003",
    summary: "AWS access key pair in the environment",
};

const RULES: &[Rule] = &[KNOWN_TOKEN, BY_NAME, AWS_KEYS];

/// Variables other checks look at, or that are pointers rather than secrets.
/// `GOOGLE_APPLICATION_CREDENTIALS` and `KUBECONFIG` hold file paths that the
/// `gcloud` and `kube` checks follow.
const SKIP: &[&str] = &[
    "GOOGLE_APPLICATION_CREDENTIALS",
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
    // Reported together with AWS_ACCESS_KEY_ID as one credential.
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    // Our own settings. Only the exact names heldkeys reads: anything else
    // named HELDKEYS_* is checked like any other variable, so a secret
    // cannot hide behind the prefix.
    crate::context::NO_NET_VAR,
];

const FIX: &str =
    "Remove it from the agent's environment; pass it only to the one command that needs it.";

impl Check for EnvCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Environment variables that look like credentials, by name (*_TOKEN, *_API_KEY, ...) and by value (ghp_, sk-, AKIA, ...)."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        if let Some(f) = aws_env(ctx) {
            findings.push(f);
        }
        for (name, value) in &ctx.env {
            if SKIP.contains(&name.as_str()) || name == "AWS_ACCESS_KEY_ID" {
                continue;
            }
            if let Some(c) = rules::classify_named_value(name, value) {
                let rule = if c.rule_id.is_some() {
                    KNOWN_TOKEN
                } else {
                    BY_NAME
                };
                findings.push(
                    Finding::new(
                        rule,
                        c.title,
                        format!("env: {name}"),
                        c.severity,
                        c.lifetime,
                        c.access,
                        FIX,
                    )
                    .with_fingerprint(c.fingerprint)
                    .with_secret(value),
                );
            }
        }
        findings
    }
}

/// AWS keys come as a pair (plus a session token for temporary ones). We
/// report the pair once, fingerprinted by the access key id.
fn aws_env(ctx: &Context) -> Option<Finding> {
    let key_id = ctx.var("AWS_ACCESS_KEY_ID");
    let secret = ctx.var("AWS_SECRET_ACCESS_KEY");
    if secret.is_none() && ctx.var("AWS_SESSION_TOKEN").is_none() {
        return None;
    }
    let temporary =
        key_id.is_some_and(|k| k.starts_with("ASIA")) || ctx.var("AWS_SESSION_TOKEN").is_some();
    let (title, severity, lifetime) = if temporary {
        (
            "Temporary AWS credentials",
            Severity::Medium,
            Lifetime::ShortLived,
        )
    } else {
        (
            "Long-lived AWS access key",
            Severity::High,
            Lifetime::LongLived,
        )
    };
    let location = if key_id.is_some() {
        "env: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY"
    } else {
        "env: AWS_SECRET_ACCESS_KEY"
    };
    let fix = if temporary {
        "Scope the role's session policy to what the agent needs, and keep sessions short."
    } else {
        "Replace the static key with short-lived credentials (aws sso login or an assumed role), then deactivate it."
    };
    let finding = Finding::new(
        AWS_KEYS,
        title,
        location,
        severity,
        lifetime,
        Access::Unknown,
        fix,
    )
    .with_fingerprint(key_id.and_then(redact::fingerprint));
    Some(match key_id.or(secret) {
        Some(value) => finding.with_secret(value),
        None => finding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::ctx_with_env;

    fn run(env: &[(&str, &str)]) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        EnvCheck.run(&ctx_with_env(dir.path(), env))
    }

    #[test]
    fn empty_env_has_no_findings() {
        assert!(run(&[]).is_empty());
    }

    #[test]
    fn github_token_by_value() {
        let f = run(&[("GITHUB_TOKEN", "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000001")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].location, "env: GITHUB_TOKEN");
        assert_eq!(f[0].fingerprint.as_deref(), Some("ghp_…001"));
    }

    #[test]
    fn value_match_with_innocent_name() {
        let f = run(&[("SOMETHING", "sk-ant-api03-FAKEFAKEFAKEFAKEFAKE-FAKE")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Anthropic API key");
    }

    #[test]
    fn name_match_without_known_format() {
        let f = run(&[("MY_SERVICE_TOKEN", "q8Zr1vLx0pTn4Wm2")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].fingerprint, None);
    }

    #[test]
    fn ordinary_env_is_ignored() {
        let f = run(&[
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/home/x"),
            ("PWD", "/tmp"),
            ("AWS_REGION", "eu-west-1"),
            ("FEATURE_KEY", "true"),
        ]);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn only_our_exact_settings_are_skipped() {
        let f = run(&[
            ("HELDKEYS_NO_NET", "1"),
            (
                "HELDKEYS_GITHUB_TOKEN",
                "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000777",
            ),
        ]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].location, "env: HELDKEYS_GITHUB_TOKEN");
    }

    #[test]
    fn aws_pair_is_one_finding() {
        let f = run(&[
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            (
                "AWS_SECRET_ACCESS_KEY",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ),
        ]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].lifetime, Lifetime::LongLived);
        assert_eq!(f[0].fingerprint.as_deref(), Some("AKIA…PLE"));
    }

    #[test]
    fn aws_session_is_short_lived() {
        let f = run(&[
            ("AWS_ACCESS_KEY_ID", "ASIAIOSFODNN7EXAMPLE"),
            (
                "AWS_SECRET_ACCESS_KEY",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ),
            ("AWS_SESSION_TOKEN", "FwoGZXIvYXdzEFAKEFAKEFAKE"),
        ]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].lifetime, Lifetime::ShortLived);
    }

    #[test]
    fn database_url_with_password() {
        let f = run(&[(
            "DATABASE_URL",
            "postgres://app:fakepass@db.internal:5432/app",
        )]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Connection string with embedded password");
        assert_eq!(f[0].fingerprint, None);
    }
}
