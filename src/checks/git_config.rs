//! `git-config`: credentials written straight into git config files.
//!
//! Besides credential helpers (`git-helper`) and `~/.git-credentials`
//! (`git-credentials`), tokens end up in git config in three common ways:
//!
//! - a URL rewrite, `[url "https://x-access-token:TOKEN@github.com/"]
//!   insteadOf = https://github.com/`, a popular CI and Dockerfile trick;
//! - an `http.<url>.extraheader = AUTHORIZATION: basic ...` header, which
//!   `actions/checkout` writes and many scripts copy;
//! - a remote URL with the token in it, `remote.origin.url =
//!   https://TOKEN@github.com/o/r.git`.
//!
//! git sends them on every fetch and push, and any process that can read the
//! file can copy them. We read `~/.gitconfig`, `$XDG_CONFIG_HOME/git/config`
//! and the working directory's `.git/config`. Findings show the host only;
//! a fingerprint is shown only for tokens of a known format.
//!
//! `heldkeys ci` runs the repository half (`RepoGitConfigCheck`, same id and
//! rules): a CI job's checkout is a working directory like any other, and a
//! token in its remote URL is readable by every step.
//!
//! The repository config comes with the working directory, which whoever
//! wrote the repo controls, so it is only read from inside that directory.
//! A linked worktree or submodule keeps it elsewhere (`.git` is then a file,
//! `gitdir: <dir>`); such a directory is only followed when git's own
//! back-pointer in it names this working directory, which a cloned repo
//! cannot forge. Anything else is reported as not read (Info, `--strict`
//! fails on it).

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::checks::display;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::fsutil;
use crate::ini;
use crate::redact;
use crate::rules;

pub struct GitConfigCheck;

const ID: &str = "git-config";

const URL_REWRITE: Rule = Rule {
    check: ID,
    id: "HK-GITCFG-001",
    summary: "Credential embedded in a git url.<base>.insteadOf rewrite",
};

const EXTRA_HEADER: Rule = Rule {
    check: ID,
    id: "HK-GITCFG-002",
    summary: "Authorization header in git http.extraheader",
};

const REMOTE_URL: Rule = Rule {
    check: ID,
    id: "HK-GITCFG-003",
    summary: "Credential embedded in a git remote URL",
};

const RULES: &[Rule] = &[URL_REWRITE, EXTRA_HEADER, REMOTE_URL];

impl Check for GitConfigCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Tokens written into git config: url.<base>.insteadOf rewrites, http.extraheader and remote URLs in ~/.gitconfig, ~/.config/git/config and ./.git/config."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        for path in [
            ctx.home_path(".gitconfig"),
            ctx.config_dir().join("git").join("config"),
        ] {
            if let Some(text) = ctx.read_file(&path) {
                findings.extend(check_text(ctx, &path, &text, Headers::All));
            }
        }
        findings.extend(repo_findings(ctx, Headers::All));
        findings
    }
}

/// The repository half of `git-config`, for `heldkeys ci`: the working
/// directory's `.git/config` only. Same id and rules as `GitConfigCheck`;
/// the two never run in the same mode.
pub struct RepoGitConfigCheck;

impl Check for RepoGitConfigCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Tokens written into the checkout's ./.git/config: remote URLs, url.<base>.insteadOf rewrites and http.extraheader."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        // In GitHub Actions, `ci-runtime` reports the checkout's
        // AUTHORIZATION extraheader as HK-CI-005; do not report it twice.
        let headers = if ctx.var("GITHUB_ACTIONS") == Some("true") {
            Headers::NotAuthorization
        } else {
            Headers::All
        };
        repo_findings(ctx, headers)
    }
}

/// Which `http.extraheader` values to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Headers {
    All,
    /// Skip `Authorization` headers (reported by `ci-runtime` as HK-CI-005).
    NotAuthorization,
}

fn repo_findings(ctx: &Context, headers: Headers) -> Vec<Finding> {
    match repo_config(ctx) {
        Some((path, text)) => check_text(ctx, &path, &text, headers),
        None => Vec::new(),
    }
}

/// The working directory's repository config. `.git` is usually a
/// directory; in a linked worktree or submodule it is a file that names the
/// real git directory (`gitdir: ...`), whose `commondir` holds the config.
fn repo_config(ctx: &Context) -> Option<(PathBuf, String)> {
    let dot_git = ctx.cwd.join(".git");
    if dot_git.is_dir() {
        let path = dot_git.join("config");
        let text = ctx.read_project_file(&path)?;
        return Some((path, text));
    }
    let pointer = ctx.read_project_file(&dot_git)?;
    let Some(target) = pointer.trim().strip_prefix("gitdir:").map(str::trim) else {
        ctx.note_unreadable(&dot_git, "not a directory or a gitdir: pointer");
        return None;
    };
    let gitdir = ctx.cwd.join(target);
    if fsutil::is_within(&ctx.cwd, &gitdir) {
        // A git directory inside the tree: everything it leads to must stay
        // inside it too.
        let common = match ctx.read_project_file(&gitdir.join("commondir")) {
            Some(c) => gitdir.join(c.trim()),
            None => gitdir,
        };
        let path = common.join("config");
        let text = ctx.read_project_file(&path)?;
        return Some((path, text));
    }
    if !points_back(ctx, &gitdir, &dot_git) {
        ctx.note_unreadable(
            &dot_git,
            "its gitdir: is outside the directory scanned and does not point back to it, so the repository config was not read",
        );
        return None;
    }
    let common = match ctx.read_file_within(&gitdir, &gitdir.join("commondir")) {
        Some(c) => gitdir.join(c.trim()),
        None => gitdir.clone(),
    };
    // A linked worktree's git directory is `<common>/worktrees/<name>`.
    if !fsutil::is_within(&common, &gitdir) {
        ctx.note_unreadable(
            &gitdir.join("commondir"),
            "points to a directory that does not contain this git directory",
        );
        return None;
    }
    let path = common.join("config");
    let text = ctx.read_file_within(&common, &path)?;
    Some((path, text))
}

/// Whether the git directory `gitdir`, outside the working directory, names
/// this working directory as its own: a linked worktree's `gitdir` file holds
/// the path of the worktree's `.git` file, and a submodule's config has
/// `core.worktree` pointing at the submodule. A cloned repo controls neither,
/// so it cannot make us read some other repository's config.
fn points_back(ctx: &Context, gitdir: &Path, dot_git: &Path) -> bool {
    let same = |a: &Path, b: &Path| match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    let read = |name: &str| {
        fsutil::try_read_text_within(gitdir, &gitdir.join(name), fsutil::MAX_FILE_BYTES)
            .ok()
            .flatten()
    };
    if let Some(back) = read("gitdir")
        && same(&gitdir.join(back.trim()), dot_git)
    {
        return true;
    }
    read("config").is_some_and(|text| {
        ini::parse(&text)
            .iter()
            .filter(|s| s.name.eq_ignore_ascii_case("core"))
            .filter_map(|s| s.get("worktree"))
            .any(|worktree| same(&gitdir.join(worktree), &ctx.cwd))
    })
}

fn check_text(ctx: &Context, path: &Path, text: &str, headers: Headers) -> Vec<Finding> {
    let file = ctx.display_path(path);
    let mut findings = Vec::new();
    for section in ini::parse(text) {
        if let Some(base) = subsection(&section.name, "url") {
            if let Some(secret) = url_secret(base) {
                let location = format!("{file} [url {}]", origin(base));
                findings.push(url_finding(
                    URL_REWRITE,
                    "Token in a git URL rewrite",
                    location,
                    &secret,
                    "Remove the credentials from the [url] section, rotate the token, and use a credential helper or gh auth instead.",
                ));
            }
        } else if let Some(url) = subsection(&section.name, "http")
            .or_else(|| (section.name.eq_ignore_ascii_case("http")).then_some(""))
        {
            for (key, value) in &section.entries {
                if key == "extraheader"
                    && !(headers == Headers::NotAuthorization && is_authorization(value))
                    && let Some(f) = header_finding(&file, url, value)
                {
                    findings.push(f);
                }
            }
        } else if let Some(remote) = subsection(&section.name, "remote") {
            for (key, value) in &section.entries {
                if (key == "url" || key == "pushurl")
                    && let Some(secret) = url_secret(value)
                {
                    let location = format!("{file} [remote {}]", display::label(remote));
                    findings.push(
                        url_finding(
                            REMOTE_URL,
                            "Token in a git remote URL",
                            location,
                            &secret,
                            "Run git remote set-url with the URL minus its credentials, rotate the token, and use a credential helper instead.",
                        )
                        .with_detail(format!("{key} points to {} with credentials in the URL", origin(value))),
                    );
                }
            }
        }
    }
    findings
}

/// `url "https://x"` (or the old `url.https://x` form) for `kind` = "url".
fn subsection<'a>(section: &'a str, kind: &str) -> Option<&'a str> {
    let head = section.get(..kind.len())?;
    if !head.eq_ignore_ascii_case(kind) {
        return None;
    }
    let rest = &section[kind.len()..];
    if let Some(quoted) = rest.strip_prefix(' ') {
        return Some(quoted.trim().trim_matches('"'));
    }
    rest.strip_prefix('.').filter(|r| !r.is_empty())
}

/// The secret in a URL's userinfo: the password of `user:password@`, or a
/// bare `TOKEN@` when it is a token of a known format (a bare user name such
/// as `git@` or `alice@` is not a secret). Passwords may hold an unencoded
/// `/` and the separators may be percent-encoded (`redact::find_userinfo`).
fn url_secret(url: &str) -> Option<String> {
    let url = redact::decode_separators(url.trim());
    let authority = url.find("://")? + 3;
    let userinfo = redact::find_userinfo(&url)
        .into_iter()
        .find(|u| u.start == authority)?;
    let userinfo = &url[userinfo.start..userinfo.end];
    let secret = match userinfo.split_once(':') {
        Some((_, password)) => password,
        None if rules::match_token(userinfo).is_some() => userinfo,
        None => return None,
    };
    let placeholder = secret.is_empty() || secret.starts_with('$') || secret.starts_with('<');
    (!placeholder).then(|| secret.to_string())
}

/// An `Authorization` or `Proxy-Authorization` header value.
fn is_authorization(header: &str) -> bool {
    header.split_once(':').is_some_and(|(name, _)| {
        let name = name.trim();
        name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("proxy-authorization")
    })
}

/// `scheme://host` for display, or a fixed text when the URL is too odd to
/// show safely.
fn origin(url: &str) -> String {
    display::url_origin(url).unwrap_or_else(|| "(unparsed URL)".to_string())
}

fn url_finding(rule: Rule, title: &str, location: String, secret: &str, fix: &str) -> Finding {
    let token = rules::match_token(secret);
    Finding::new(
        rule,
        title,
        location,
        Severity::High,
        token.map_or(Lifetime::LongLived, |t| t.lifetime),
        // git sends it on push as well as fetch.
        Access::Write,
        fix,
    )
    .with_fingerprint(redact::fingerprint(secret))
}

/// An `extraheader` that carries a credential: an `Authorization` header, or
/// any header with a token of a known format in it.
fn header_finding(file: &str, url: &str, value: &str) -> Option<Finding> {
    let (_, rest) = value.split_once(':')?;
    let rest = rest.trim();
    let authorization = is_authorization(value);
    let secret = if authorization {
        let (scheme, credential) = rest.split_once(' ').unwrap_or(("", rest));
        let credential = credential.trim();
        if scheme.eq_ignore_ascii_case("basic") {
            // `user:token`, base64-encoded. Only the decoded token is ever
            // matched or fingerprinted; it is never shown.
            base64_decode(credential)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .and_then(|pair| pair.split_once(':').map(|(_, t)| t.to_string()))
                .unwrap_or_default()
        } else {
            credential.to_string()
        }
    } else {
        let found = rules::find_tokens(rest);
        let first = found.first()?;
        rest[first.start..first.end].to_string()
    };
    let token = rules::match_token(&secret);
    let scope = if url.is_empty() {
        "all hosts".to_string()
    } else {
        origin(url)
    };
    let location = if url.is_empty() {
        format!("{file} [http]")
    } else {
        format!("{file} [http {scope}]")
    };
    Some(
        Finding::new(
            EXTRA_HEADER,
            "Auth header in git http.extraheader",
            location,
            Severity::High,
            token.map_or(Lifetime::Unknown, |t| t.lifetime),
            Access::Unknown,
            "Remove it (git config --unset-all http.<url>.extraheader), rotate the token, and use a credential helper instead.",
        )
        .with_fingerprint(redact::fingerprint(&secret))
        .with_detail(format!(
            "git sends this header to {scope} on every fetch and push"
        )),
    )
}

/// Standard base64 (padding optional). `None` if `s` is not base64.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in s.trim().trim_end_matches('=').bytes() {
        let value = ALPHABET.iter().position(|&a| a == c)? as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, write};

    const TOKEN: &str = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000991";

    #[test]
    fn url_secrets() {
        let secret = |url: &str| url_secret(url);
        assert_eq!(secret("https://u:pw@h/x").as_deref(), Some("pw"));
        assert_eq!(
            secret(&format!("https://{TOKEN}@github.com/o/r")).as_deref(),
            Some(TOKEN)
        );
        assert_eq!(secret("https://alice@github.com/o/r"), None);
        assert_eq!(secret("ssh://git@github.com/o/r"), None);
        assert_eq!(secret("https://u:${TOKEN}@h/"), None);
        assert_eq!(secret("https://github.com/o/r"), None);
        // An unencoded `/` in the password, and encoded separators.
        assert_eq!(
            secret("https://u:ab/cdFAKE01@github.com/o/r.git").as_deref(),
            Some("ab/cdFAKE01")
        );
        assert_eq!(
            secret("https://user%3AFAKEpct02@github.com/o/r.git").as_deref(),
            Some("FAKEpct02")
        );
        assert_eq!(
            secret("https://u:FAKE%2Fpct03@github.com/o/r.git").as_deref(),
            Some("FAKE%2Fpct03")
        );
        // A port, then an `@` in the path: no credentials.
        assert_eq!(secret("https://h.example:8443/@scope/r.git"), None);
    }

    #[test]
    fn subsections() {
        assert_eq!(subsection("url \"https://x/\"", "url"), Some("https://x/"));
        assert_eq!(subsection("url.https://x/", "url"), Some("https://x/"));
        assert_eq!(subsection("http", "http"), None);
        assert_eq!(subsection("remote \"origin\"", "remote"), Some("origin"));
        assert_eq!(subsection("remotes", "remote"), None);
    }

    #[test]
    fn base64() {
        assert_eq!(base64_decode("dTpw").unwrap(), b"u:p");
        assert_eq!(base64_decode("dTpwdw==").unwrap(), b"u:pw");
        assert_eq!(base64_decode("not base64!"), None);
    }

    #[test]
    fn global_config() {
        let dir = tempfile::tempdir().unwrap();
        // "x-access-token:<TOKEN>" in base64.
        let basic = "eC1hY2Nlc3MtdG9rZW46Z2hwX0ZBS0VGQUtFRkFLRUZBS0VGQUtFRkFLRUZBS0UwMDA5OTE=";
        write(
            dir.path(),
            ".gitconfig",
            &format!(
                "[url \"https://x-access-token:{TOKEN}@github.com/\"]\n\tinsteadOf = https://github.com/\n[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic {basic}\n[http]\n\textraheader = Authorization: Bearer opaque-secret-value\n[url \"https://github.com/\"]\n\tinsteadOf = gh:\n"
            ),
        );
        let f = GitConfigCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 3, "{f:#?}");
        let rewrite = f.iter().find(|f| f.rule == "HK-GITCFG-001").unwrap();
        assert_eq!(rewrite.location, "~/.gitconfig [url https://github.com]");
        assert_eq!(rewrite.fingerprint.as_deref(), Some("ghp_…991"));
        assert_eq!(rewrite.severity, Severity::High);
        let headers: Vec<&Finding> = f.iter().filter(|f| f.rule == "HK-GITCFG-002").collect();
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers[0].location,
            "~/.gitconfig [http https://github.com]"
        );
        assert_eq!(headers[0].fingerprint.as_deref(), Some("ghp_…991"));
        assert_eq!(headers[1].location, "~/.gitconfig [http]");
        assert_eq!(headers[1].fingerprint, None);
        let all = format!("{f:?}");
        assert!(!all.contains("opaque-secret-value") && !all.contains(TOKEN));
    }

    #[test]
    fn repository_remote() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".git/config",
            &format!(
                "[remote \"origin\"]\n\turl = https://x-access-token:{TOKEN}@github.com/o/r.git\n[remote \"fork\"]\n\turl = https://alice@github.com/alice/r.git\n"
            ),
        );
        let f = GitConfigCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].rule, "HK-GITCFG-003");
        assert_eq!(f[0].location, "~/.git/config [remote origin]");
        assert_eq!(
            f[0].detail.as_deref(),
            Some("url points to https://github.com with credentials in the URL")
        );
    }

    /// `repo/.git/config` with a token, and a linked worktree `wt` whose
    /// `.git` file points at `repo/.git/worktrees/wt`.
    fn worktree(dir: &Path, back_pointer: bool) -> PathBuf {
        let repo = dir.join("main");
        write(
            &repo,
            ".git/config",
            "[remote \"origin\"]\n\turl = https://u:FAKEpw0001xyz@git.example.com/r.git\n",
        );
        write(&repo, ".git/worktrees/wt/commondir", "../..\n");
        let wt = dir.join("wt");
        write(
            &wt,
            ".git",
            &format!("gitdir: {}\n", repo.join(".git/worktrees/wt").display()),
        );
        if back_pointer {
            write(
                &repo,
                ".git/worktrees/wt/gitdir",
                &format!("{}\n", wt.join(".git").display()),
            );
        }
        wt
    }

    #[test]
    fn worktree_pointer_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_env(dir.path(), &[]);
        ctx.cwd = worktree(dir.path(), true);
        let f = GitConfigCheck.run(&ctx);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].fingerprint, None);
        assert!(ctx.take_unreadable().is_empty());
    }

    #[test]
    fn submodule_pointer_file() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("super/sub");
        write(&sub, ".git", "gitdir: ../.git/modules/sub\n");
        write(
            &dir.path().join("super"),
            ".git/modules/sub/config",
            &format!(
                "[core]\n\tworktree = ../../../sub\n[remote \"origin\"]\n\turl = https://x:{TOKEN}@github.com/o/s.git\n"
            ),
        );
        let mut ctx = ctx_with_env(dir.path(), &[]);
        ctx.cwd = sub;
        let f = GitConfigCheck.run(&ctx);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].rule, "HK-GITCFG-003");
    }

    /// A cloned repo cannot point `.git` at another repository's git
    /// directory: without git's back-pointer it is not followed, and that is
    /// reported rather than skipped.
    #[test]
    fn gitdir_outside_the_tree_needs_a_back_pointer() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_env(dir.path(), &[]);
        ctx.cwd = worktree(dir.path(), false);
        assert!(GitConfigCheck.run(&ctx).is_empty());
        let unreadable = ctx.take_unreadable();
        assert_eq!(unreadable.len(), 1, "{unreadable:?}");
        assert!(unreadable[0].0.ends_with("wt/.git"));
        assert!(unreadable[0].1.contains("outside the directory scanned"));
    }

    #[test]
    fn commondir_cannot_leave_the_git_directory_tree() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = ctx_with_env(dir.path(), &[]);
        ctx.cwd = worktree(dir.path(), true);
        // Elsewhere: a repository the worktree does not belong to.
        write(
            &dir.path().join("other"),
            ".git/config",
            &format!("[remote \"origin\"]\n\turl = https://x:{TOKEN}@github.com/o/r.git\n"),
        );
        write(
            &dir.path().join("main"),
            ".git/worktrees/wt/commondir",
            &format!("{}\n", dir.path().join("other/.git").display()),
        );
        assert!(GitConfigCheck.run(&ctx).is_empty());
        let unreadable = ctx.take_unreadable();
        assert_eq!(unreadable.len(), 1, "{unreadable:?}");
        assert!(unreadable[0].0.ends_with("commondir"));
    }

    #[test]
    fn in_tree_gitdir_cannot_lead_out_of_the_tree() {
        let outside = tempfile::tempdir().unwrap();
        write(
            outside.path(),
            "config",
            &format!("[remote \"origin\"]\n\turl = https://x:{TOKEN}@github.com/o/r.git\n"),
        );
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".git", "gitdir: gd\n");
        write(
            dir.path(),
            "gd/commondir",
            &format!("{}\n", outside.path().display()),
        );
        let ctx = ctx_with_env(dir.path(), &[]);
        assert!(GitConfigCheck.run(&ctx).is_empty());
        let unreadable = ctx.take_unreadable();
        assert_eq!(unreadable.len(), 1, "{unreadable:?}");
        assert_eq!(
            unreadable[0].1,
            "symlink leads outside the directory scanned"
        );
    }

    #[test]
    fn remote_url_with_a_slash_in_the_password() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".git/config",
            "[remote \"origin\"]\n\turl = https://u:ab/cdFAKEremote03@github.com/o/r.git\n[remote \"up\"]\n\turl = https://u:FAKE%2Fpct04@github.com/o/r.git\n[url \"https://user:pa/ssFAKEurl02@github.com/\"]\n\tinsteadOf = https://github.com/\n",
        );
        let f = GitConfigCheck.run(&ctx_with_env(dir.path(), &[]));
        let rules: Vec<&str> = f.iter().map(|f| f.rule).collect();
        assert_eq!(
            rules,
            ["HK-GITCFG-003", "HK-GITCFG-003", "HK-GITCFG-001"],
            "{f:#?}"
        );
        assert_eq!(f[2].location, "~/.git/config [url https://github.com]");
        assert_eq!(
            f[0].detail.as_deref(),
            Some("url points to https://github.com with credentials in the URL")
        );
        let all = format!("{f:?}");
        assert!(!all.contains("FAKE"), "{all}");
    }

    /// In `heldkeys ci` the repository config is checked too; inside GitHub
    /// Actions the checkout's AUTHORIZATION header is left to HK-CI-005.
    #[test]
    fn ci_checks_the_repository_config() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".gitconfig",
            &format!(
                "[url \"https://x:{TOKEN}@github.com/\"]\n\tinsteadOf = https://github.com/\n"
            ),
        );
        write(
            dir.path(),
            ".git/config",
            &format!(
                "[remote \"origin\"]\n\turl = https://x-access-token:{TOKEN}@github.com/o/r.git\n[http \"https://github.com/\"]\n\textraheader = AUTHORIZATION: basic eDp5\n"
            ),
        );
        let outside = RepoGitConfigCheck.run(&ctx_with_env(dir.path(), &[]));
        let rules: Vec<&str> = outside.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["HK-GITCFG-003", "HK-GITCFG-002"], "{outside:#?}");
        // Home configs are not part of the CI check.
        assert!(
            outside
                .iter()
                .all(|f| f.location.starts_with("~/.git/config"))
        );
        let actions =
            RepoGitConfigCheck.run(&ctx_with_env(dir.path(), &[("GITHUB_ACTIONS", "true")]));
        let rules: Vec<&str> = actions.iter().map(|f| f.rule).collect();
        assert_eq!(rules, ["HK-GITCFG-003"], "{actions:#?}");
    }
}
