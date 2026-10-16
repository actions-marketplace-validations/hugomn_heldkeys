//! `aws`: profiles in `~/.aws/credentials` and `~/.aws/config`.
//!
//! The question for each profile is whether the agent can get AWS credentials
//! from it without a human: static keys (worst, they never expire), cached SSO
//! sessions and cached role credentials (short-lived), and profiles that mint
//! credentials on demand (role_arn, credential_process).
//!
//! Tools around the AWS CLI keep sessions too: awsume caches the sessions it
//! assumes (often after an MFA prompt) in `~/.awsume/cache`, aws-vault's
//! file backend keeps keys in `~/.awsvault/keys`, and Granted can be set to
//! keep its credentials in an encrypted file keyring. For cached sessions we
//! read the expiry: a session that has not expired can be used without MFA
//! until it does, and one that has expired is skipped, because nobody can
//! use it any more.

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

const AWSUME_CACHE: Rule = Rule {
    check: ID,
    id: "HK-AWS-008",
    summary: "Cached AWS session credentials in the awsume cache",
};

const AWS_VAULT_FILE: Rule = Rule {
    check: ID,
    id: "HK-AWS-009",
    summary: "AWS keys in an aws-vault file keyring",
};

const GRANTED_FILE: Rule = Rule {
    check: ID,
    id: "HK-AWS-010",
    summary: "Granted configured to keep AWS credentials in a file keyring",
};

const RULES: &[Rule] = &[
    STATIC_KEY,
    TEMP_KEYS,
    SSO_CACHED,
    SSO_NOT_CACHED,
    ROLE_PROFILE,
    CREDENTIAL_PROCESS,
    CLI_CACHE,
    AWSUME_CACHE,
    AWS_VAULT_FILE,
    GRANTED_FILE,
];

/// Title of a cached session that has not expired yet.
const USABLE_SESSION: &str = "Cached AWS session usable without MFA";
const CACHE_FIX: &str = "Clear the cache before handing a shell to an agent";

impl Check for AwsCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "AWS profiles in ~/.aws/credentials and ~/.aws/config: static keys versus SSO, role and credential_process profiles, plus cached sessions (AWS CLI, awsume) and aws-vault and Granted file keyrings."
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
        findings.extend(awsume_cache(ctx));
        findings.extend(aws_vault_keys(ctx));
        findings.extend(granted_keyring(ctx));
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
    let sessions = read_session_cache(ctx, &cache, true);
    session_finding(
        ctx,
        &cache,
        &sessions,
        CLI_CACHE,
        "Cached AWS role credentials",
        &format!("{CACHE_FIX} (delete ~/.aws/cli/cache), and keep role sessions short."),
    )
}

/// awsume caches the sessions it assumes, often after an MFA prompt, as
/// JSON files without an extension.
fn awsume_cache(ctx: &Context) -> Option<Finding> {
    let cache = ctx.home_path(".awsume/cache");
    let sessions = read_session_cache(ctx, &cache, false);
    session_finding(
        ctx,
        &cache,
        &sessions,
        AWSUME_CACHE,
        "Cached awsume session credentials",
        &format!("{CACHE_FIX} (awsume --clean, or delete ~/.awsume/cache)."),
    )
}

/// What a directory of cached sessions holds.
#[derive(Debug, Default, PartialEq, Eq)]
struct Sessions {
    /// Not expired yet, and the latest expiry among them (Unix seconds).
    usable: usize,
    latest: u64,
    /// Without a readable expiry: possibly usable.
    undated: usize,
}

/// Reads every cached session in `dir` (only `*.json` files if `json_only`).
/// Expired sessions are not counted.
fn read_session_cache(ctx: &Context, dir: &Path, json_only: bool) -> Sessions {
    let now = now_unix();
    let mut sessions = Sessions::default();
    for path in fsutil::list_dir(dir) {
        if json_only && path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        if !json_only && path.is_dir() {
            continue;
        }
        let Some(text) = ctx.read_file(&path) else {
            continue;
        };
        if !text.contains("SecretAccessKey") {
            continue;
        }
        let parsed: Option<serde_json::Value> = serde_json::from_str(&text).ok();
        let expiry = parsed.as_ref().and_then(|v| {
            let creds = v.get("Credentials").unwrap_or(v);
            parse_time(creds.get("Expiration")?.as_str()?)
        });
        match expiry {
            Some(t) if t <= now => {}
            Some(t) => {
                sessions.usable += 1;
                sessions.latest = sessions.latest.max(t);
            }
            None => sessions.undated += 1,
        }
    }
    sessions
}

/// One finding for a session cache: Medium while a session in it is still
/// valid (or may be), nothing once every session in it has expired.
fn session_finding(
    ctx: &Context,
    dir: &Path,
    sessions: &Sessions,
    rule: Rule,
    undated_title: &str,
    fix: &str,
) -> Option<Finding> {
    let (title, detail) = if sessions.usable > 0 {
        let mut detail = format!(
            "{} unexpired session(s), the last valid until {}",
            sessions.usable,
            format_time(sessions.latest, now_unix())
        );
        if sessions.undated > 0 {
            detail.push_str(&format!(", and {} without an expiry", sessions.undated));
        }
        (USABLE_SESSION, detail)
    } else if sessions.undated > 0 {
        (
            undated_title,
            format!("{} cached session(s), possibly expired", sessions.undated),
        )
    } else {
        return None;
    };
    Some(
        Finding::new(
            rule,
            title,
            ctx.display_path(dir),
            Severity::Medium,
            Lifetime::ShortLived,
            Access::Unknown,
            fix,
        )
        .with_detail(detail),
    )
}

/// aws-vault's file backend: one encrypted file per stored key or session
/// under `~/.awsvault/keys` (or `AWS_VAULT_FILE_DIR`). The files are
/// encrypted with a passphrase; with the passphrase in the environment
/// (`AWS_VAULT_FILE_PASSPHRASE`), any process can decrypt them.
fn aws_vault_keys(ctx: &Context) -> Option<Finding> {
    let dir = ctx.path_from_env("AWS_VAULT_FILE_DIR", ctx.home_path(".awsvault/keys"));
    let mut items = 0;
    for path in fsutil::list_dir(&dir) {
        if path.is_dir() {
            continue;
        }
        // Read a few bytes so a file we cannot open, or a FIFO, is recorded
        // for `read-errors` instead of counted.
        match ctx.try_read_head(&path, 16) {
            Ok(Some(_)) => items += 1,
            Ok(None) => {}
            Err(reason) => ctx.note_unreadable(&path, reason),
        }
    }
    if items == 0 {
        return None;
    }
    let location = ctx.display_path(&dir);
    let finding = if ctx.var("AWS_VAULT_FILE_PASSPHRASE").is_some() {
        Finding::new(
            AWS_VAULT_FILE,
            "aws-vault file keyring with its passphrase",
            location,
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            "Unset AWS_VAULT_FILE_PASSPHRASE where agents run, so aws-vault prompts for it.",
        )
        .with_detail(format!(
            "{items} encrypted item(s); AWS_VAULT_FILE_PASSPHRASE is set, so any process can decrypt them"
        ))
    } else {
        Finding::new(
            AWS_VAULT_FILE,
            "AWS keys in an aws-vault file keyring",
            location,
            Severity::Low,
            Lifetime::LongLived,
            Access::Unknown,
            "Keep the passphrase out of the environment and files agents can read, or use the OS keychain backend.",
        )
        .with_detail(format!("{items} encrypted item(s), usable with the keyring passphrase"))
    };
    Some(finding)
}

/// Granted keeps credentials in the OS keychain unless `[Keyring] Backend`
/// in `~/.granted/config` is `file`: then they are encrypted files on disk.
fn granted_keyring(ctx: &Context) -> Option<Finding> {
    let config = ctx.home_path(".granted/config");
    let text = ctx.read_file(&config)?;
    let root = crate::toml_subset::parse(&text);
    let keyring = root.get("Keyring")?;
    let backend = keyring.get("Backend")?.as_str()?;
    if !backend.eq_ignore_ascii_case("file") {
        return None;
    }
    let dir = match keyring.get("FileDir").and_then(|d| d.as_str()) {
        Some(d) if !d.is_empty() => display::label(&ctx.display_path(&ctx.resolve(d))),
        _ => "the default directory".to_string(),
    };
    Some(
        Finding::new(
            GRANTED_FILE,
            "Granted credentials in a file keyring",
            format!("{} [Keyring]", ctx.display_path(&config)),
            Severity::Low,
            Lifetime::Unknown,
            Access::Unknown,
            "Use the OS keychain backend for Granted where agents run, and keep the keyring passphrase out of reach.",
        )
        .with_detail(format!("encrypted files in {dir}, usable with the keyring passphrase")),
    )
}

/// Seconds since 1970 now. 0 if the clock is before 1970.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parses `2026-10-16T12:34:56Z`, with optional fractional seconds and a
/// `+hh:mm` offset, or `2026-10-16 12:34:56` (no zone, read as UTC), into
/// Unix seconds. `None` for anything else.
fn parse_time(s: &str) -> Option<u64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b' ') {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(range)?;
        part.chars()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        rest = fraction.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let offset = match rest {
        "" | "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let digits = rest[1..].replace(':', "");
            if digits.len() != 4 || !digits.chars().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let (h, m): (i64, i64) = (digits[..2].parse().ok()?, digits[2..].parse().ok()?);
            sign * (h * 3600 + m * 60)
        }
    };
    let seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(seconds).ok()
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day count (the inverse of `days_from_civil`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `14:05 UTC` for a time later today (UTC), `2026-10-17 14:05 UTC` otherwise.
fn format_time(t: u64, now: u64) -> String {
    let t = t as i64;
    let (hour, minute) = ((t % 86_400) / 3600, (t % 3600) / 60);
    if t / 86_400 == now as i64 / 86_400 {
        format!("{hour:02}:{minute:02} UTC")
    } else {
        let (y, m, d) = civil_from_days(t / 86_400);
        format!("{y:04}-{m:02}-{d:02} {hour:02}:{minute:02} UTC")
    }
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
        assert_eq!(
            f[0].detail.as_deref(),
            Some("1 cached session(s), possibly expired")
        );
    }

    fn session(expiration: &str) -> String {
        format!(
            "{{\"Credentials\": {{\"AccessKeyId\": \"ASIAFAKEFAKEFAKE1080\", \"SecretAccessKey\": \"FAKEcachedSECRET1080\", \"SessionToken\": \"FAKEcachedSESSION1080\", \"Expiration\": \"{expiration}\"}}}}"
        )
    }

    #[test]
    fn cli_cache_expiry() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".aws/cli/cache/old.json",
            &session("2020-01-01T00:00:00Z"),
        );
        let ctx = ctx_with_env(dir.path(), &[]);
        // Only expired sessions: nothing to report.
        assert!(AwsCheck.run(&ctx).is_empty());

        write(
            dir.path(),
            ".aws/cli/cache/new.json",
            &session("2099-05-04T03:02:01+00:00"),
        );
        write(
            dir.path(),
            ".aws/cli/cache/newer.json",
            &session("2099-05-04T05:02:01.123Z"),
        );
        let f = AwsCheck.run(&ctx);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].rule, "HK-AWS-007");
        assert_eq!(f[0].title, "Cached AWS session usable without MFA");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(
            f[0].detail.as_deref(),
            Some("2 unexpired session(s), the last valid until 2099-05-04 05:02 UTC")
        );
        assert!(
            f[0].fix
                .starts_with("Clear the cache before handing a shell to an agent")
        );
        assert!(!format!("{f:?}").contains("FAKE"));
    }

    #[test]
    fn awsume_cache() {
        let dir = tempfile::tempdir().unwrap();
        // awsume names its cache files without an extension.
        write(
            dir.path(),
            ".awsume/cache/aws-credentials-AKIAFAKEFAKEFAKE1081",
            &session("2099-01-01 10:00:00"),
        );
        write(
            dir.path(),
            ".awsume/cache/expired",
            &session("2020-01-01 10:00:00"),
        );
        let f = AwsCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].rule, "HK-AWS-008");
        assert_eq!(f[0].location, "~/.awsume/cache");
        assert_eq!(
            f[0].detail.as_deref(),
            Some("1 unexpired session(s), the last valid until 2099-01-01 10:00 UTC")
        );
    }

    #[test]
    fn aws_vault_file_keyring() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".awsvault/keys/default",
            "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0.FAKE1082",
        );
        write(
            dir.path(),
            ".awsvault/keys/session,abc",
            "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIn0.FAKE1083",
        );
        let f = AwsCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!((f[0].rule, f[0].severity), ("HK-AWS-009", Severity::Low));
        assert_eq!(f[0].location, "~/.awsvault/keys");
        let with_passphrase = AwsCheck.run(&ctx_with_env(
            dir.path(),
            &[("AWS_VAULT_FILE_PASSPHRASE", "FAKEpassphrase1084")],
        ));
        assert_eq!(with_passphrase[0].severity, Severity::High);
        assert!(!format!("{with_passphrase:?}").contains("FAKE"));
    }

    #[test]
    fn granted_file_keyring() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".granted/config",
            "DefaultBrowser = \"STDOUT\"\n[Keyring]\n  Backend = \"file\"\n  FileDir = \"~/.granted/keyring\"\n",
        );
        let f = AwsCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].rule, "HK-AWS-010");
        assert_eq!(f[0].location, "~/.granted/config [Keyring]");
        assert_eq!(
            f[0].detail.as_deref(),
            Some("encrypted files in ~/.granted/keyring, usable with the keyring passphrase")
        );
        write(
            dir.path(),
            ".granted/config",
            "[Keyring]\n  Backend = \"keychain\"\n",
        );
        assert!(AwsCheck.run(&ctx_with_env(dir.path(), &[])).is_empty());
    }

    #[test]
    fn times() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("2026-10-16T12:00:00Z"), Some(1_792_152_000));
        assert_eq!(parse_time("2026-10-16T14:00:00+02:00"), Some(1_792_152_000));
        assert_eq!(parse_time("2026-10-16 12:00:00"), Some(1_792_152_000));
        assert_eq!(parse_time("2026-10-16T12:00:00.5Z"), Some(1_792_152_000));
        assert_eq!(parse_time("tomorrow"), None);
        assert_eq!(parse_time("2026-13-16T12:00:00Z"), None);
        assert_eq!(parse_time("2026-10-16T12:00:00 UTC"), None);
        assert_eq!(format_time(1_792_152_000 + 300, 1_792_152_000), "12:05 UTC");
        assert_eq!(
            format_time(1_792_152_000, 1_700_000_000),
            "2026-10-16 12:00 UTC"
        );
        for days in [-1, 0, 365, 20_000, 30_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
