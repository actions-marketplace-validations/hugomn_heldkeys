//! `git-helper`: git credential helpers and the GitHub CLI login.
//!
//! A credential helper answers `git credential fill` for any process running
//! as the user, so whatever it stores (usually a token that can push) is
//! reachable even when no file holds it in plaintext. The GitHub CLI keeps its
//! token either in `~/.config/gh/hosts.yml` or in the OS keyring, where
//! `gh auth token` prints it.

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::checks::display;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::ini;
use crate::redact;
use crate::rules;
use crate::yaml;

pub struct GitHelperCheck;

const ID: &str = "git-helper";

const HELPER_STORE: Rule = Rule {
    check: ID,
    id: "HK-GIT-001",
    summary: "Git credential helper that stores logins in plaintext",
};

const HELPER_CACHE: Rule = Rule {
    check: ID,
    id: "HK-GIT-002",
    summary: "Git credential helper that caches logins in memory",
};

const HELPER_GH: Rule = Rule {
    check: ID,
    id: "HK-GIT-003",
    summary: "Git configured to use the GitHub CLI token",
};

const HELPER_OTHER: Rule = Rule {
    check: ID,
    id: "HK-GIT-004",
    summary: "Git credential helper backed by a keychain or other store",
};

const GH_PLAINTEXT: Rule = Rule {
    check: ID,
    id: "HK-GIT-005",
    summary: "GitHub CLI token stored in plaintext hosts.yml",
};

const GH_KEYRING: Rule = Rule {
    check: ID,
    id: "HK-GIT-006",
    summary: "GitHub CLI login with its token in the OS keyring",
};

const RULES: &[Rule] = &[
    HELPER_STORE,
    HELPER_CACHE,
    HELPER_GH,
    HELPER_OTHER,
    GH_PLAINTEXT,
    GH_KEYRING,
];

impl Check for GitHelperCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Git credential helpers in ~/.gitconfig and ~/.config/git/config, and GitHub CLI logins in ~/.config/gh/hosts.yml."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings: Vec<Finding> = gitconfig_paths(ctx)
            .iter()
            .flat_map(|path| helpers_in(ctx, path))
            .collect();
        findings.extend(gh_hosts(ctx));
        findings
    }
}

fn gitconfig_paths(ctx: &Context) -> Vec<PathBuf> {
    vec![
        ctx.home_path(".gitconfig"),
        ctx.config_dir().join("git").join("config"),
    ]
}

/// `helper = ...` entries in `[credential]` and `[credential "<url>"]` sections.
fn helpers_in(ctx: &Context, path: &Path) -> Vec<Finding> {
    let Some(text) = ctx.read_file(path) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    for section in ini::parse(&text) {
        let Some(scope) = credential_scope(&section.name) else {
            continue;
        };
        for (key, helper) in &section.entries {
            // An empty `helper =` resets the list; it is not a helper.
            if key != "helper" || helper.is_empty() {
                continue;
            }
            let shown = match &scope {
                Some(url) => format!("credential {url}"),
                None => "credential".to_string(),
            };
            let location = format!("{} [{shown}]", ctx.display_path(path));
            let scope = scope.as_deref().unwrap_or("all hosts");
            findings.push(helper_finding(helper, scope, location));
        }
    }
    findings
}

/// `Some(None)` for `[credential]` (all hosts), `Some(Some(url))` for
/// `[credential "<url>"]`, `None` for other sections. The URL is shown as
/// `scheme://host` only: people put `user:password@` in it, and the path
/// is not needed to tell which host the helper serves.
fn credential_scope(section: &str) -> Option<Option<String>> {
    if section == "credential" {
        return Some(None);
    }
    let url = section
        .strip_prefix("credential ")?
        .trim()
        .trim_matches('"');
    let shown = display::url_origin(url)
        // A bare host pattern such as `github.com` or `*.example.com`.
        .or_else(|| display::is_host(&url.replace('*', "x")).then(|| url.to_string()))
        .unwrap_or_else(|| "(unparsed URL)".to_string());
    Some(Some(shown))
}

fn helper_finding(helper: &str, scope: &str, location: String) -> Finding {
    let name = helper_name(helper);
    let (rule, title, lifetime, fix) = match name.as_str() {
        "store" => (
            HELPER_STORE,
            "Git credential helper stores plaintext",
            Lifetime::LongLived,
            "Switch to a keychain-backed helper (osxkeychain, libsecret, manager) and delete ~/.git-credentials.",
        ),
        "cache" => (
            HELPER_CACHE,
            "Git credential helper caches logins",
            Lifetime::ShortLived,
            "Lower the cache timeout, or run git credential-cache exit before handing the shell to an agent.",
        ),
        "gh" => (
            HELPER_GH,
            "Git uses the GitHub CLI token",
            Lifetime::LongLived,
            "Run the agent with a separate, fine-grained token instead of your gh login.",
        ),
        _ => (
            HELPER_OTHER,
            "Git credential helper",
            Lifetime::Unknown,
            "Run agents under a user or sandbox without your git logins, or use fine-grained, read-only tokens.",
        ),
    };
    Finding::new(
        rule,
        title,
        location,
        Severity::Medium,
        lifetime,
        Access::Unknown,
        fix,
    )
    .with_detail(format!(
        "helper {name} for {scope}; any process can ask it via git credential fill"
    ))
}

/// `osxkeychain`, `!gh auth git-credential` -> `gh`, `/usr/bin/git-credential-foo` -> `foo`.
/// Only the program name is kept, because helper command lines can carry
/// options, and an inline shell helper (`!f() { echo password=...; }; f`)
/// can be the secret itself, so it is never shown.
fn helper_name(helper: &str) -> String {
    match display::program_name(helper) {
        Some(file) => file
            .strip_prefix("git-credential-")
            .unwrap_or(&file)
            .to_string(),
        None if helper.trim_start().starts_with('!') => "(inline shell command)".to_string(),
        None => "(unrecognised command)".to_string(),
    }
}

/// GitHub CLI logins, from `hosts.yml`. Tokens are either inline
/// (`oauth_token`) or in the keyring, in which case only `user` is present.
fn gh_hosts(ctx: &Context) -> Vec<Finding> {
    let dir = ctx.path_from_env("GH_CONFIG_DIR", ctx.config_dir().join("gh"));
    let path = dir.join("hosts.yml");
    let Some(doc) = crate::checks::read_yaml(ctx, &path) else {
        return Vec::new();
    };
    yaml::entries(&doc)
        .into_iter()
        .map(|(host, entry)| {
            let location = format!("{} ({})", ctx.display_path(&path), display::label(host));
            let token = yaml::str_at(entry, "oauth_token");
            let fix = "Use a fine-grained token with only the repositories and permissions the agent needs, or gh auth logout.";
            match token {
                Some(token) => Finding::new(
                    GH_PLAINTEXT,
                    rules::match_token(token).map(|r| r.title).unwrap_or("GitHub CLI token"),
                    location,
                    Severity::High,
                    Lifetime::LongLived,
                    // gh's default scopes include repo, which can push.
                    Access::Write,
                    fix,
                )
                .with_fingerprint(redact::fingerprint(token))
                .with_detail("GitHub CLI token stored in plaintext"),
                None => Finding::new(
                    GH_KEYRING,
                    "GitHub CLI login (token in OS keyring)",
                    location,
                    Severity::High,
                    Lifetime::LongLived,
                    Access::Write,
                    fix,
                )
                .with_detail("gh auth token prints it to any process running as this user"),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::fixture_ctx;

    #[test]
    fn helper_names() {
        assert_eq!(helper_name("osxkeychain"), "osxkeychain");
        assert_eq!(helper_name("!gh auth git-credential"), "gh");
        assert_eq!(
            helper_name("/usr/lib/git-core/git-credential-libsecret"),
            "libsecret"
        );
        assert_eq!(helper_name("store --file ~/.x"), "store");
        assert_eq!(
            helper_name("!f(){echo${IFS}password=FAKEhelperPW0002;};f"),
            "(inline shell command)"
        );
        assert_eq!(
            helper_name("!f() { echo password=x; }; f"),
            "(inline shell command)"
        );
    }

    #[test]
    fn credential_urls_show_the_host_only() {
        let dir = tempfile::tempdir().unwrap();
        crate::checks::testutil::write(
            dir.path(),
            ".gitconfig",
            "[credential \"https://alice:FAKEgitcfgPW0001@github.example.com/org\"]\n\thelper = store\n[credential \"*.example.com\"]\n\thelper = cache\n[credential]\n\thelper = !f(){echo${IFS}password=FAKEhelperPW0002;};f\n",
        );
        let f = GitHelperCheck.run(&crate::checks::testutil::ctx_with_env(dir.path(), &[]));
        let shown = format!("{f:?}");
        assert!(
            !shown.contains("FAKE") && !shown.contains("alice"),
            "{shown}"
        );
        let locations: Vec<&str> = f.iter().map(|f| f.location.as_str()).collect();
        assert_eq!(
            locations,
            [
                "~/.gitconfig [credential https://github.example.com]",
                "~/.gitconfig [credential *.example.com]",
                "~/.gitconfig [credential]",
            ]
        );
        assert!(
            f[2].detail
                .as_deref()
                .unwrap()
                .starts_with("helper (inline shell command) for all hosts")
        );
    }

    #[test]
    fn full_fixture() {
        let f = GitHelperCheck.run(&fixture_ctx("full"));
        let gh = f
            .iter()
            .find(|f| f.location == "~/.config/gh/hosts.yml (github.com)")
            .unwrap();
        assert_eq!(gh.severity, Severity::High);
        assert!(gh.fingerprint.as_deref().unwrap().starts_with("gho_"));
        assert!(f.iter().any(|f| {
            f.title == "Git credential helper"
                && f.detail
                    .as_deref()
                    .unwrap()
                    .starts_with("helper osxkeychain for all hosts")
        }));
        assert!(
            f.iter()
                .any(|f| f.title == "Git credential helper stores plaintext")
        );
    }

    #[test]
    fn keyring_fixture() {
        let f = GitHelperCheck.run(&fixture_ctx("gh-keyring"));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].title, "GitHub CLI login (token in OS keyring)");
        assert_eq!(f[0].fingerprint, None);
    }
}
