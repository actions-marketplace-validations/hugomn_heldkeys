//! `npmrc`: registry tokens in `~/.npmrc` and the project's `.npmrc`.
//!
//! An npm token in `.npmrc` usually has publish rights: a hijacked agent could
//! push a malicious version of every package the account owns.

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::checks::display;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::redact;
use crate::rules;

pub struct NpmrcCheck;

const ID: &str = "npmrc";

const REGISTRY_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-NPM-001",
    summary: "npm registry credential in .npmrc",
};

const RULES: &[Rule] = &[REGISTRY_TOKEN];

const FIX: &str = "Use a granular, read-only or automation token scoped to the needed packages, or reference it as ${NPM_TOKEN} only in CI.";

/// Keys (or key suffixes) that hold a registry secret.
const SECRET_KEYS: &[&str] = &["_authToken", "_auth", "_password"];

impl Check for NpmrcCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "npm registry tokens in ~/.npmrc and ./.npmrc (_authToken, _auth, _password)."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let (user, project) = candidate_files(ctx);
        let mut findings = Vec::new();
        if let Some(text) = ctx.read_file(&user) {
            findings.extend(check_text(ctx, &user, &text));
        }
        // The project's .npmrc comes with the repo: read it without
        // following symlinks out of the working directory.
        if let Some(path) = project
            && let Some(text) = ctx.read_project_file(&path)
        {
            findings.extend(check_text(ctx, &path, &text));
        }
        findings
    }
}

/// The user config, and the project's when it is a different file.
fn candidate_files(ctx: &Context) -> (PathBuf, Option<PathBuf>) {
    let user = ctx.path_from_env("NPM_CONFIG_USERCONFIG", ctx.home_path(".npmrc"));
    let project = ctx.cwd.join(".npmrc");
    if project == user {
        (user, None)
    } else {
        (user, Some(project))
    }
}

fn check_text(ctx: &Context, path: &Path, text: &str) -> Vec<Finding> {
    text.lines()
        .filter_map(parse_line)
        .map(|(registry, secret)| {
            let title = rules::match_token(secret)
                .map(|r| r.title)
                .unwrap_or("npm registry credential");
            Finding::new(
                REGISTRY_TOKEN,
                title,
                // Registry keys can carry userinfo (`//user:pw@host/`).
                format!("{} ({})", ctx.display_path(path), display::label(registry)),
                Severity::High,
                Lifetime::LongLived,
                Access::Write,
                FIX,
            )
            .with_fingerprint(redact::fingerprint(secret))
        })
        .collect()
}

/// `//registry.npmjs.org/:_authToken=VALUE` becomes
/// `("//registry.npmjs.org/", VALUE)`. A bare `_authToken=VALUE` applies to
/// the default registry. Values that reference an environment variable
/// (`${NPM_TOKEN}`) are not secrets themselves and are skipped.
fn parse_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    let (key, value) = (key.trim(), rules::trim_value(value));
    let (registry, setting) = match key.rsplit_once(':') {
        Some((registry, setting)) => (registry, setting),
        None => ("default registry", key),
    };
    if !SECRET_KEYS.contains(&setting) || value.is_empty() || value.contains("${") {
        return None;
    }
    Some((registry, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::fixture_ctx;

    #[test]
    fn parses_lines() {
        assert_eq!(
            parse_line("//registry.npmjs.org/:_authToken=abc"),
            Some(("//registry.npmjs.org/", "abc"))
        );
        assert_eq!(
            parse_line("_auth = \"xyz\""),
            Some(("default registry", "xyz"))
        );
        assert_eq!(parse_line("//r/:_authToken=${NPM_TOKEN}"), None);
        assert_eq!(parse_line("registry=https://registry.npmjs.org/"), None);
    }

    #[test]
    fn registry_userinfo_is_not_echoed() {
        let dir = tempfile::tempdir().unwrap();
        crate::checks::testutil::write(
            dir.path(),
            ".npmrc",
            concat!(
                "//eve:FAKEnpmPW0017@registry.example.com/:_authToken=npm_",
                "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0018\n"
            ),
        );
        let f = NpmrcCheck.run(&crate::checks::testutil::ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].location, "~/.npmrc (//registry.example.com/)");
    }

    #[test]
    fn registry_userinfo_with_a_slash_is_not_echoed() {
        let dir = tempfile::tempdir().unwrap();
        crate::checks::testutil::write(
            dir.path(),
            ".npmrc",
            "//u:pa/ssFAKEnpmPW0019@registry.example.com/:_authToken=abcdefghijklmnop\n",
        );
        let f = NpmrcCheck.run(&crate::checks::testutil::ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].location, "~/.npmrc (//registry.example.com/)");
    }

    #[test]
    fn full_fixture() {
        let f = NpmrcCheck.run(&fixture_ctx("full"));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].title, "npm access token");
        assert_eq!(f[0].location, "~/.npmrc (//registry.npmjs.org/)");
        assert!(f[0].fingerprint.as_deref().unwrap().starts_with("npm_"));
    }
}
