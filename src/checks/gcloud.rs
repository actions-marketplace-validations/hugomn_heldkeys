//! `gcloud`: Google Cloud SDK logins and application default credentials.
//!
//! `gcloud auth login` stores refresh tokens in `credentials.db`, and
//! `gcloud auth application-default login` writes one to
//! `application_default_credentials.json`. Both outlive the terminal session:
//! any process running as the user can mint access tokens from them.

use std::path::Path;

use serde_json::Value;

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::fsutil;
use crate::redact;

pub struct GcloudCheck;

const ID: &str = "gcloud";

const STORED_LOGIN: Rule = Rule {
    check: ID,
    id: "HK-GCP-001",
    summary: "gcloud stored login refresh tokens",
};

const ADC_USER: Rule = Rule {
    check: ID,
    id: "HK-GCP-002",
    summary: "Application default credentials with a user refresh token",
};

const SA_KEY: Rule = Rule {
    check: ID,
    id: "HK-GCP-003",
    summary: "Google service account key file",
};

const IMPERSONATION: Rule = Rule {
    check: ID,
    id: "HK-GCP-004",
    summary: "Google impersonation credentials with a source refresh token",
};

const FEDERATION: Rule = Rule {
    check: ID,
    id: "HK-GCP-005",
    summary: "Google workload identity federation config",
};

const OTHER_FILE: Rule = Rule {
    check: ID,
    id: "HK-GCP-006",
    summary: "Google credentials file of an unrecognised type",
};

const RULES: &[Rule] = &[
    STORED_LOGIN,
    ADC_USER,
    SA_KEY,
    IMPERSONATION,
    FEDERATION,
    OTHER_FILE,
];

impl Check for GcloudCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Google Cloud SDK: stored gcloud logins, application default credentials and GOOGLE_APPLICATION_CREDENTIALS key files."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let dir = ctx.path_from_env("CLOUDSDK_CONFIG", ctx.config_dir().join("gcloud"));
        let mut findings = Vec::new();
        findings.extend(stored_logins(ctx, &dir));

        let adc = dir.join("application_default_credentials.json");
        findings.extend(credentials_file(ctx, &adc));

        if let Some(path) = ctx.var("GOOGLE_APPLICATION_CREDENTIALS") {
            let path = ctx.resolve(path);
            // Avoid reporting the same file twice.
            if path != adc {
                findings.extend(credentials_file(ctx, &path));
            }
        }
        findings
    }
}

/// `credentials.db` (current gcloud) and `legacy_credentials/<account>/`
/// (older gcloud, still written) hold refresh tokens for logged-in accounts.
fn stored_logins(ctx: &Context, dir: &Path) -> Option<Finding> {
    let db = dir.join("credentials.db");
    let db_has_data = ctx.file_len(&db).is_some_and(|len| len > 0);
    let accounts = fsutil::list_dir(&dir.join("legacy_credentials"))
        .iter()
        .filter(|p| p.is_dir())
        .count();
    if !db_has_data && accounts == 0 {
        return None;
    }
    let location = if db_has_data {
        ctx.display_path(&db)
    } else {
        ctx.display_path(&dir.join("legacy_credentials"))
    };
    let mut finding = Finding::new(
        STORED_LOGIN,
        "gcloud stored login (refresh tokens)",
        location,
        Severity::High,
        Lifetime::LongLived,
        Access::Unknown,
        "Run gcloud auth revoke for accounts the agent should not use, or give the agent its own config dir (CLOUDSDK_CONFIG).",
    );
    if accounts > 0 {
        finding = finding.with_detail(format!("{accounts} account(s) in legacy_credentials"));
    }
    Some(finding)
}

/// An ADC or service-account JSON file, classified by its `type` field.
fn credentials_file(ctx: &Context, path: &Path) -> Option<Finding> {
    let json = crate::checks::read_json(ctx, path)?;
    let kind = json.get("type").and_then(Value::as_str).unwrap_or("");
    let location = ctx.display_path(path);
    let finding = match kind {
        "authorized_user" => Finding::new(
            ADC_USER,
            "Google ADC user refresh token",
            location,
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            "Run gcloud auth application-default revoke when done; prefer short-lived impersonation for agents.",
        ),
        "service_account" => {
            let email = json
                .get("client_email")
                .and_then(Value::as_str)
                .map(crate::checks::display::label)
                .unwrap_or_else(|| "unknown".to_string());
            // private_key_id identifies the key without revealing it.
            let key_id = json
                .get("private_key_id")
                .and_then(Value::as_str)
                .and_then(redact::shorten);
            Finding::new(
                SA_KEY,
                "Google service account key",
                location,
                Severity::High,
                Lifetime::LongLived,
                Access::Unknown,
                "Delete the key file and the key in IAM; use workload identity or impersonation instead.",
            )
            .with_fingerprint(key_id)
            .with_detail(format!("service account {email}"))
        }
        "impersonated_service_account" => Finding::new(
            IMPERSONATION,
            "Google impersonation credentials",
            location,
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            "Revoke the source credentials when done; the impersonated account's access is reachable while they live.",
        ),
        "external_account" | "external_account_authorized_user" => Finding::new(
            FEDERATION,
            "Google workload identity federation config",
            location,
            Severity::Medium,
            Lifetime::ShortLived,
            Access::Unknown,
            "Scope the federated principal's roles to what the agent needs.",
        ),
        _ => Finding::new(
            OTHER_FILE,
            "Google credentials file",
            location,
            Severity::Medium,
            Lifetime::Unknown,
            Access::Unknown,
            "Check what this file grants and remove it if the agent does not need it.",
        ),
    };
    Some(finding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, fixture_ctx, write};

    #[test]
    fn full_fixture() {
        let f = GcloudCheck.run(&fixture_ctx("full"));
        assert!(
            f.iter()
                .any(|f| f.title == "gcloud stored login (refresh tokens)")
        );
        let adc = f
            .iter()
            .find(|f| f.location == "~/.config/gcloud/application_default_credentials.json")
            .expect("adc");
        assert_eq!(adc.severity, Severity::High);
        assert_eq!(adc.fingerprint, None);
    }

    #[test]
    fn service_account_key_via_env() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "keys/sa.json",
            r#"{"type":"service_account","client_email":"fake@fake-project.iam.gserviceaccount.com","private_key_id":"0123456789abcdef0123456789abcdef01234567","private_key":"FAKE-NOT-A-KEY"}"#,
        );
        let ctx = ctx_with_env(
            dir.path(),
            &[("GOOGLE_APPLICATION_CREDENTIALS", "keys/sa.json")],
        );
        let f = GcloudCheck.run(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Google service account key");
        assert_eq!(f[0].fingerprint.as_deref(), Some("0123…567"));
        assert_eq!(
            f[0].detail.as_deref(),
            Some("service account fake@fake-project.iam.gserviceaccount.com")
        );
    }

    #[test]
    fn empty_home() {
        assert!(GcloudCheck.run(&fixture_ctx("empty")).is_empty());
    }
}
