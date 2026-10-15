//! `git-credentials`: the plaintext store of `git credential-store`.
//!
//! `credential.helper = store` writes `https://user:token@host` lines to
//! `~/.git-credentials` (or `$XDG_CONFIG_HOME/git/credentials`). Each line
//! is a working login that can push code.

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::checks::display;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::redact;
use crate::rules;

pub struct GitCredentialsCheck;

const ID: &str = "git-credentials";

const STORED_LOGIN: Rule = Rule {
    check: ID,
    id: "HK-GITCRED-001",
    summary: "Plaintext git login in a credential-store file",
};

const RULES: &[Rule] = &[STORED_LOGIN];

const FIX: &str = "Switch to a keychain-backed helper (osxkeychain, libsecret, manager) or gh auth, then delete the file and rotate the token.";

impl Check for GitCredentialsCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Plaintext git logins in ~/.git-credentials and ~/.config/git/credentials (credential-store)."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        candidate_files(ctx)
            .iter()
            .flat_map(|path| check_file(ctx, path))
            .collect()
    }
}

fn candidate_files(ctx: &Context) -> Vec<PathBuf> {
    vec![
        ctx.home_path(".git-credentials"),
        ctx.config_dir().join("git").join("credentials"),
    ]
}

fn check_file(ctx: &Context, path: &Path) -> Vec<Finding> {
    let Some(text) = ctx.read_file(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(parse_line)
        .map(|(host, secret)| {
            let host = if display::is_host(host) {
                host
            } else {
                "(not a host name)"
            };
            let location = format!("{} ({host})", ctx.display_path(path));
            let title = rules::match_token(secret)
                .map(|r| r.title)
                .unwrap_or("Plaintext git password");
            // Git logins can push, so this is long-lived write access.
            Finding::new(
                STORED_LOGIN,
                title,
                location,
                Severity::High,
                Lifetime::LongLived,
                Access::Write,
                FIX,
            )
            .with_fingerprint(redact::fingerprint(secret))
        })
        .collect()
}

/// Splits `scheme://user:secret@host/path` into `(host, secret)`. When there
/// is no password, the user part is the secret (`https://TOKEN@host`).
/// Returns `None` for lines without credentials.
fn parse_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    let (_, rest) = line.split_once("://")?;
    let (userinfo, host_and_path) = rest.rsplit_once('@')?;
    let host = host_and_path.split('/').next().unwrap_or("");
    let secret = match userinfo.split_once(':') {
        Some((_, password)) => password,
        None => userinfo,
    };
    if secret.is_empty() || host.is_empty() {
        return None;
    }
    Some((host, secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::fixture_ctx;

    #[test]
    fn parses_lines() {
        assert_eq!(
            parse_line("https://u:p@github.com"),
            Some(("github.com", "p"))
        );
        assert_eq!(
            parse_line("https://tok@gitlab.com/group"),
            Some(("gitlab.com", "tok"))
        );
        assert_eq!(parse_line("https://github.com"), None);
        assert_eq!(parse_line("# comment"), None);
    }

    #[test]
    fn full_fixture() {
        let f = GitCredentialsCheck.run(&fixture_ctx("full"));
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(
            f.iter()
                .all(|f| f.severity == Severity::High && f.access == Access::Write)
        );
        let gh = f
            .iter()
            .find(|f| f.location == "~/.git-credentials (github.com)")
            .unwrap();
        assert_eq!(gh.title, "GitHub personal access token (classic)");
        let other = f
            .iter()
            .find(|f| f.location.contains("git.example.com"))
            .unwrap();
        assert_eq!(other.fingerprint, None);
    }
}
