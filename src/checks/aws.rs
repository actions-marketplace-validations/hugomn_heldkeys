//! `aws`: profiles in `~/.aws/credentials` and `~/.aws/config`.
//!
//! The question for each profile is whether the agent can get AWS credentials
//! from it without a human: static keys (worst, they never expire), cached SSO
//! sessions and cached role credentials (short-lived), and profiles that mint
//! credentials on demand (role_arn, credential_process).

use std::path::Path;

use crate::checks::Check;
use crate::checks::display;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::fsutil;
use crate::ini::{self, Section};
use crate::redact;

pub struct AwsCheck;

const ID: &str = "aws";

const STATIC_KEY: Rule = Rule {
    check: ID,
    id: "HK-AWS-001",
    summary: "Long-lived AWS access key in a credentials or config file",
};

const TEMP_KEYS: Rule = Rule {
    check: ID,
    id: "HK-AWS-002",
    summary: "Temporary AWS keys stored in a credentials or config file",
};

const SSO_CACHED: Rule = Rule {
    check: ID,
    id: "HK-AWS-003",
    summary: "AWS SSO profile with a cached session token",
};

const SSO_NOT_CACHED: Rule = Rule {
    check: ID,
    id: "HK-AWS-004",
    summary: "AWS SSO profile without a cached session (context)",
};

const ROLE_PROFILE: Rule = Rule {
    check: ID,
    id: "HK-AWS-005",
    summary: "AWS profile that assumes a role",
};

const CREDENTIAL_PROCESS: Rule = Rule {
    check: ID,
    id: "HK-AWS-006",
    summary: "AWS profile that mints credentials with credential_process",
};

const CLI_CACHE: Rule = Rule {
    check: ID,
    id: "HK-AWS-007",
    summary: "Cached assumed-role credentials in ~/.aws/cli/cache",
};

const RULES: &[Rule] = &[
    STATIC_KEY,
    TEMP_KEYS,
    SSO_CACHED,
    SSO_NOT_CACHED,
    ROLE_PROFILE,
    CREDENTIAL_PROCESS,
    CLI_CACHE,
];

impl Check for AwsCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "AWS profiles in ~/.aws/credentials and ~/.aws/config: static keys versus SSO, role and credential_process profiles, plus cached sessions."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let aws_dir = ctx.home_path(".aws");
        let credentials =
            ctx.path_from_env("AWS_SHARED_CREDENTIALS_FILE", aws_dir.join("credentials"));
        let config = ctx.path_from_env("AWS_CONFIG_FILE", aws_dir.join("config"));

        let mut findings = Vec::new();
        let sso_cached = has_cached_file(ctx, &aws_dir.join("sso").join("cache"), "accessToken");

        if let Some(text) = ctx.read_file(&credentials) {
            for section in ini::parse(&text) {
                let location = format!("{} [{}]", ctx.display_path(&credentials), section.name);
                findings.extend(static_keys(&section, &location));
            }
        }
        if let Some(text) = ctx.read_file(&config) {
            for section in ini::parse(&text) {
                // sso-session and services sections are referenced by profiles,
                // they are not profiles themselves.
                if section.name.starts_with("sso-session") || section.name.starts_with("services") {
                    continue;
                }
                let location = format!(
                    "{} [{}]",
                    ctx.display_path(&config),
                    display::label(&section.name)
                );
                findings.extend(static_keys(&section, &location));
                findings.extend(profile_kind(&section, &location, sso_cached));
            }
        }
        findings.extend(cached_role_credentials(ctx, &aws_dir));
        findings
    }
}

/// `aws_access_key_id` in a profile: a static key pair, or temporary keys if
/// there is a session token too.
fn static_keys(section: &Section, location: &str) -> Option<Finding> {
    let key_id = section.get("aws_access_key_id")?;
    let temporary = key_id.starts_with("ASIA") || section.get("aws_session_token").is_some();
    let finding = if temporary {
        Finding::new(
            TEMP_KEYS,
            "Temporary AWS credentials",
            location,
            Severity::Medium,
            Lifetime::ShortLived,
            Access::Unknown,
            "Delete expired session keys from the file; prefer aws sso login, which keeps them out of plain config.",
        )
    } else {
        Finding::new(
            STATIC_KEY,
            "Long-lived AWS access key",
            location,
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            "Replace the static key with IAM Identity Center (aws configure sso) or an assumed role, then deactivate it.",
        )
    };
    Some(finding.with_fingerprint(redact::fingerprint(key_id)))
}

/// Profiles that produce credentials on demand rather than storing them.
fn profile_kind(section: &Section, location: &str, sso_cached: bool) -> Option<Finding> {
    if section.get("aws_access_key_id").is_some() {
        return None; // already reported as a static key
    }
    if section.get("sso_session").is_some() || section.get("sso_start_url").is_some() {
        return Some(sso_profile(section, location, sso_cached));
    }
    if let Some(command) = section.get("credential_process") {
        // Only the program name: arguments sometimes carry secrets, and an
        // odd first word (`tool:secret`) is not shown at all.
        let program = display::program_name(command).unwrap_or_else(|| "a program".to_string());
        return Some(
            Finding::new(
                CREDENTIAL_PROCESS,
                "AWS profile with credential_process",
                location,
                Severity::Medium,
                Lifetime::Unknown,
                Access::Unknown,
                "Make sure the credential process requires user presence (for example a hardware key) before it hands out keys.",
            )
            .with_detail(format!("runs {program} to mint credentials")),
        );
    }
    if section.get("role_arn").is_some() {
        let via = match (
            section.get("source_profile"),
            section.get("credential_source"),
            section.get("web_identity_token_file"),
        ) {
            (Some(p), _, _) => format!("assumes a role using source_profile {}", display::label(p)),
            (_, Some(s), _) => format!(
                "assumes a role using credential_source {}",
                display::label(s)
            ),
            (_, _, Some(_)) => "assumes a role with a web identity token file".to_string(),
            _ => "assumes a role".to_string(),
        };
        return Some(
            Finding::new(
                ROLE_PROFILE,
                "AWS role profile",
                location,
                Severity::Medium,
                Lifetime::ShortLived,
                Access::Unknown,
                "Give the agent its own narrowly scoped role instead of one a human uses.",
            )
            .with_detail(via),
        );
    }
    None
}

fn sso_profile(section: &Section, location: &str, cached: bool) -> Finding {
    let role = display::label(section.get("sso_role_name").unwrap_or("unknown role"));
    if cached {
        Finding::new(
            SSO_CACHED,
            "AWS SSO profile with a cached session",
            location,
            Severity::Medium,
            Lifetime::ShortLived,
            Access::Unknown,
            "Run aws sso logout when you are done, and use a permission set scoped to what the agent needs.",
        )
        .with_detail(format!("role {role}; ~/.aws/sso/cache holds a session token (it may have expired)"))
    } else {
        Finding::new(
            SSO_NOT_CACHED,
            "AWS SSO profile (no cached session)",
            location,
            Severity::Info,
            Lifetime::ShortLived,
            Access::Unknown,
            "No action needed; a human has to log in before this profile works.",
        )
        .with_detail(format!("role {role}"))
    }
}

/// `~/.aws/cli/cache` keeps the temporary keys of assumed roles until they expire.
fn cached_role_credentials(ctx: &Context, aws_dir: &Path) -> Option<Finding> {
    let cache = aws_dir.join("cli").join("cache");
    let count = count_cached_files(ctx, &cache, "SecretAccessKey");
    if count == 0 {
        return None;
    }
    Some(
        Finding::new(
            CLI_CACHE,
            "Cached AWS role credentials",
            ctx.display_path(&cache),
            Severity::Medium,
            Lifetime::ShortLived,
            Access::Unknown,
            "Clear ~/.aws/cli/cache when you hand the shell to an agent.",
        )
        .with_detail(format!("{count} cached session(s), possibly expired")),
    )
}

fn has_cached_file(ctx: &Context, dir: &Path, marker: &str) -> bool {
    count_cached_files(ctx, dir, marker) > 0
}

/// Counts `*.json` files in `dir` that contain `marker`.
fn count_cached_files(ctx: &Context, dir: &Path, marker: &str) -> usize {
    fsutil::list_dir(dir)
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| ctx.read_file(p).is_some_and(|t| t.contains(marker)))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, fixture_ctx, write};

    #[test]
    fn full_fixture() {
        let f = AwsCheck.run(&fixture_ctx("full"));
        let static_key = f
            .iter()
            .find(|f| f.location == "~/.aws/credentials [default]")
            .expect("default profile");
        assert_eq!(static_key.severity, Severity::High);
        assert_eq!(static_key.fingerprint.as_deref(), Some("AKIA…PLE"));

        let temp = f
            .iter()
            .find(|f| f.location == "~/.aws/credentials [temp]")
            .expect("temp profile");
        assert_eq!(temp.lifetime, Lifetime::ShortLived);

        assert!(
            f.iter()
                .any(|f| f.title == "AWS SSO profile with a cached session")
        );
        assert!(f.iter().any(|f| f.title == "AWS role profile"));
        assert!(
            f.iter()
                .any(|f| f.title == "AWS profile with credential_process"
                    && f.detail.as_deref() == Some("runs fake-cred-tool to mint credentials"))
        );
    }

    #[test]
    fn sso_only_fixture_has_no_static_keys() {
        let f = AwsCheck.run(&fixture_ctx("aws-sso"));
        assert!(!f.is_empty());
        assert!(f.iter().all(|f| f.lifetime != Lifetime::LongLived), "{f:?}");
        assert!(
            f.iter()
                .any(|f| f.title == "AWS SSO profile (no cached session)")
        );
    }

    #[test]
    fn empty_home() {
        assert!(AwsCheck.run(&fixture_ctx("empty")).is_empty());
    }

    #[test]
    fn honours_shared_credentials_file_env() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "elsewhere/creds",
            "[x]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
        );
        let ctx = ctx_with_env(
            dir.path(),
            &[("AWS_SHARED_CREDENTIALS_FILE", "~/elsewhere/creds")],
        );
        let f = AwsCheck.run(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].location, "~/elsewhere/creds [x]");
    }

    #[test]
    fn odd_credential_process_is_not_echoed() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".aws/config",
            "[profile cp]\ncredential_process = FAKEproc0019:secret --x\n[profile q]\ncredential_process = \"/opt/my tools/fetch-creds\" --key FAKEarg\n",
        );
        let f = AwsCheck.run(&ctx_with_env(dir.path(), &[]));
        let details: Vec<&str> = f.iter().filter_map(|f| f.detail.as_deref()).collect();
        assert!(
            details.contains(&"runs a program to mint credentials"),
            "{details:?}"
        );
        assert!(
            details.contains(&"runs fetch-creds to mint credentials"),
            "{details:?}"
        );
        assert!(!format!("{f:?}").contains("FAKE"), "{f:?}");
    }

    #[test]
    fn cli_cache() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".aws/cli/cache/abc.json",
            "{\"Credentials\":{\"SecretAccessKey\":\"FAKE\"}}",
        );
        let f = AwsCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].title, "Cached AWS role credentials");
    }
}
