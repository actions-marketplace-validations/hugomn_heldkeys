//! `dotenv`: credentials in `.env*` files under the working directory.
//!
//! Coding agents read project files freely, and `.env` files are where
//! projects keep their secrets. `.gitignore` keeps them out of git, not away
//! from the agent, so we report them even when they are ignored, and we walk
//! ignored directories too (`.vercel/.env.production.local` is a classic).
//! Only a fixed list of heavy dependency directories is pruned, plus a depth
//! and an entry limit that keep the walk fast. Symlinked `.env` files are
//! followed when they stay inside the working directory; one that points
//! outside it is not read (a cloned repo must not be able to make us read
//! files elsewhere) and is reported by `read-errors` instead.

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Finding, Rule, Severity};
use crate::fsutil;
use crate::rules;

pub struct DotenvCheck;

const ID: &str = "dotenv";

const KNOWN_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-DOTENV-001",
    summary: "Token of a known format in a .env file",
};

const BY_NAME: Rule = Rule {
    check: ID,
    id: "HK-DOTENV-002",
    summary: "Credential-named entry with a secret-looking value in a .env file",
};

const RULES: &[Rule] = &[KNOWN_TOKEN, BY_NAME];

/// How deep below the working directory we look. Deep enough for monorepos
/// (`apps/web/.env`), shallow enough to stay fast.
const MAX_DEPTH: usize = 4;
/// Upper bound on directory entries visited, so a huge tree cannot stall the scan.
const MAX_ENTRIES: usize = 20_000;
/// Dependency and VCS directories: big, and never where a project keeps its
/// own `.env`. Everything else is walked, gitignored or not.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "bower_components",
    "target",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
];
/// Name parts that mark a template file (`.env.example`, `.env.sample.local`,
/// `.env.local.template`). Templates are committed on purpose and hold
/// placeholders: only values of a known token format that do not look like
/// filler are reported, one severity level lower, and titled as such.
const TEMPLATE_MARKERS: &[&str] = &[
    "example", "sample", "template", "tmpl", "tpl", "dist", "defaults", "default", "skeleton",
];

impl Check for DotenvCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        ".env* files under the working directory, gitignored ones included (depth 4, skipping dependency directories; only the top level when run from the home directory), that hold credentials."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        // Run from the home directory, a deep walk would visit every project
        // on the machine and mostly hit the entry budget. Look only at the
        // home directory's own .env files there; projects are scanned by
        // running heldkeys inside them (or with --path).
        let max_depth = if same_dir(&ctx.cwd, &ctx.home) {
            0
        } else {
            MAX_DEPTH
        };
        let mut walk = Walk {
            budget: MAX_ENTRIES,
            max_depth,
            files: Vec::new(),
        };
        walk.dir(&ctx.cwd, &ctx.cwd, 0);
        if walk.budget == 0 {
            ctx.note_unreadable(
                &ctx.cwd,
                format!(
                    "stopped looking for .env files after {MAX_ENTRIES} entries, so some were not checked; run heldkeys from a single project or pass --path"
                ),
            );
        }
        walk.files
            .iter()
            .flat_map(|(path, project)| {
                let id = crate::finding::identity(&project.to_string_lossy());
                check_file(ctx, path).into_iter().map(move |mut f| {
                    f.project_id = Some(id);
                    f
                })
            })
            .collect()
    }
}

/// Whether two paths name the same directory, after resolving symlinks.
fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// A bounded, depth-first walk that collects `.env*` files in sorted order,
/// each with the project it belongs to: the closest directory above it with
/// a `.git` (a checkout or a worktree), else the working directory.
struct Walk {
    budget: usize,
    max_depth: usize,
    files: Vec<(PathBuf, PathBuf)>,
}

impl Walk {
    fn dir(&mut self, dir: &Path, project: &Path, depth: usize) {
        let entries = fsutil::list_dir(dir);
        // `.git` is a directory in a checkout and a file in a worktree.
        let project = if entries.iter().any(|p| fsutil::file_name(p) == ".git") {
            dir
        } else {
            project
        };
        for path in entries {
            if self.budget == 0 {
                return;
            }
            self.budget -= 1;
            let name = fsutil::file_name(&path);
            // symlink_metadata: a symlinked directory is never entered (no
            // loops, no walking out of the tree).
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) && depth < self.max_depth {
                    self.dir(&path, project, depth + 1);
                }
            } else if is_dotenv_name(&name) {
                // Symlinks are checked when the file is read: inside the
                // working directory they are followed, outside they are
                // recorded as unreadable. So are FIFOs, sockets and devices
                // with a .env name: the reader records them rather than
                // the walk skipping them silently.
                self.files.push((path, project.to_path_buf()));
            }
        }
    }
}

fn is_dotenv_name(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.")
}

/// `.env.example`, `.env.local.sample`, ...: see `TEMPLATE_MARKERS`.
fn is_template_name(name: &str) -> bool {
    name.split('.')
        .skip(2)
        .any(|part| TEMPLATE_MARKERS.contains(&part.to_ascii_lowercase().as_str()))
}

/// One severity level lower, for a token in a template file. Low stays Low:
/// it is still a credential.
fn lower(severity: Severity) -> Severity {
    match severity {
        Severity::High => Severity::Medium,
        Severity::Medium | Severity::Low => Severity::Low,
        Severity::Info => Severity::Info,
    }
}

fn check_file(ctx: &Context, path: &Path) -> Vec<Finding> {
    let Some(text) = ctx.read_project_file(path) else {
        return Vec::new();
    };
    let name = fsutil::file_name(path);
    let template = is_template_name(&name);
    let display = ctx.display_path(path);
    let mut findings = Vec::new();
    for (n, line) in text.lines().enumerate() {
        match parse_line(line) {
            Line::Skip => {}
            Line::Entry(key, value) => {
                let Some(mut c) = rules::classify_named_value(key, value) else {
                    continue;
                };
                if template {
                    if c.rule_id.is_none() || rules::looks_like_template_placeholder(value) {
                        continue;
                    }
                    c.title = format!("{} in a template file", c.title);
                    c.severity = lower(c.severity);
                }
                let rule = if c.rule_id.is_some() {
                    KNOWN_TOKEN
                } else {
                    BY_NAME
                };
                // A key can itself be a pasted token (`ghp_...=x`).
                let key = crate::checks::display::label(key);
                findings.push(
                    Finding::new(
                        rule,
                        c.title,
                        format!("{display}: {key}"),
                        c.severity,
                        c.lifetime,
                        c.access,
                        format!("Move {key} out of {name} into a secret manager, or run the agent where this file is not readable."),
                    )
                    .with_fingerprint(c.fingerprint)
                    .with_secret(value),
                );
            }
            // Not `KEY=value`: a pasted URL, a bare token, a typo. Only tokens
            // of a known format count here, and the location is the line
            // number, because the line itself may be the secret.
            Line::Other(text) => {
                for m in rules::find_tokens(text) {
                    let token = &text[m.start..m.end];
                    if rules::is_local_dev_url(token)
                        || (template && rules::looks_like_template_placeholder(token))
                    {
                        continue;
                    }
                    let (title, severity) = if template {
                        (
                            format!("{} in a template file", m.rule.title),
                            lower(m.rule.severity),
                        )
                    } else {
                        (m.rule.title.to_string(), m.rule.severity)
                    };
                    findings.push(
                        Finding::new(
                            KNOWN_TOKEN,
                            title,
                            format!("{display}:{}", n + 1),
                            severity,
                            m.rule.lifetime,
                            m.rule.access,
                            format!("Remove line {} from {name} and rotate the credential; keep secrets in a secret manager.", n + 1),
                        )
                        .with_fingerprint(crate::redact::fingerprint(token))
                        .with_secret(token),
                    );
                }
            }
        }
    }
    findings
}

/// One line of a `.env` file.
#[derive(Debug, PartialEq, Eq)]
enum Line<'a> {
    /// Blank or a comment.
    Skip,
    /// `KEY=value` or `export KEY=value`, with a plain variable name.
    Entry(&'a str, &'a str),
    /// Anything else.
    Other(&'a str),
}

fn parse_line(line: &str) -> Line<'_> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Line::Skip;
    }
    let body = line.strip_prefix("export ").unwrap_or(line);
    match body.split_once('=') {
        Some((key, value)) if is_variable_name(key.trim()) => Line::Entry(key.trim(), value),
        _ => Line::Other(line),
    }
}

/// `NAME`, `name.with.dots` or `name-with-dashes`: what dotenv loaders accept
/// as a key. Anything else (a URL, a sentence) is not shown as a key.
fn is_variable_name(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, fixture, write};
    use std::collections::BTreeMap;

    fn project_ctx() -> Context {
        let empty = fixture("empty");
        Context::new(empty.clone(), empty, fixture("project"), BTreeMap::new())
    }

    #[test]
    fn parses_lines() {
        assert_eq!(parse_line("export A=b"), Line::Entry("A", "b"));
        assert_eq!(parse_line("# A=b"), Line::Skip);
        assert_eq!(parse_line("A = \"b\""), Line::Entry("A", " \"b\""));
        assert_eq!(
            parse_line("https://u:p@h/x?api_key=q"),
            Line::Other("https://u:p@h/x?api_key=q")
        );
        assert_eq!(parse_line("1A=b"), Line::Other("1A=b"));
    }

    #[test]
    fn project_fixture() {
        let f = DotenvCheck.run(&project_ctx());
        let locations: Vec<&str> = f.iter().map(|f| f.location.as_str()).collect();
        assert!(
            locations.contains(&"./.env: OPENAI_API_KEY"),
            "{locations:?}"
        );
        assert!(locations.contains(&"./.env: DATABASE_URL"), "{locations:?}");
        assert!(
            locations.contains(&"./.env.local: STRIPE_SECRET_KEY"),
            "{locations:?}"
        );
        assert!(
            locations.contains(&"./apps/web/.env: GITHUB_TOKEN"),
            "{locations:?}"
        );
        // Placeholder in the template is skipped, real-format token is not.
        assert!(
            !locations.contains(&"./.env.example: API_TOKEN"),
            "{locations:?}"
        );
        assert!(
            locations.contains(&"./.env.example: SLACK_BOT_TOKEN"),
            "{locations:?}"
        );
        // Gitignored directories are walked; node_modules is not.
        assert!(
            locations.contains(&"./generated/.env: GITHUB_TOKEN"),
            "{locations:?}"
        );
        assert!(
            !locations.iter().any(|l| l.contains("node_modules")),
            "{locations:?}"
        );
        // Non-secret settings are not reported.
        assert!(
            !locations.iter().any(|l| l.ends_with("NODE_ENV")),
            "{locations:?}"
        );
    }

    #[test]
    fn template_files() {
        assert!(is_template_name(".env.example"));
        assert!(is_template_name(".env.local.sample"));
        assert!(is_template_name(".env.Template"));
        assert!(is_template_name(".env.dist"));
        assert!(!is_template_name(".env"));
        assert!(!is_template_name(".env.production"));
        assert!(!is_template_name(".env.example-app"));

        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".env.example",
            "ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n\
             OPENAI_API_KEY=sk-proj-your-openai-key-goes-here-000\n\
             DATABASE_URL=postgres://postgres:postgres@localhost:5432/app\n\
             REDIS_URL=redis://default:password@127.0.0.1:6379\n\
             JWT_SECRET=supersecretjwtvalue1234\n\
             ADMIN_PASSWORD=password\n\
             STRIPE_SECRET_KEY=sk_test_your_stripe_key_here\n\
             GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000041\n\
             postgres://app:FAKEtplPASSWORD0042@db.internal:5432/app\n",
        );
        let f = DotenvCheck.run(&ctx_with_env(dir.path(), &[]));
        let shown: Vec<(&str, &str, Severity)> = f
            .iter()
            .map(|f| (f.location.as_str(), f.title.as_str(), f.severity))
            .collect();
        assert_eq!(
            shown,
            [
                (
                    "~/.env.example: GITHUB_TOKEN",
                    "GitHub personal access token (classic) in a template file",
                    Severity::Medium
                ),
                (
                    "~/.env.example:9",
                    "Connection string with embedded password in a template file",
                    Severity::Medium
                ),
            ],
            "{f:#?}"
        );
    }

    #[test]
    fn local_dev_database_urls_are_skipped_everywhere() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".env",
            "DATABASE_URL=postgres://postgres:postgres@localhost:5432/app\n\
             postgres://app:app@127.0.0.1/app\n\
             PROD_DATABASE_URL=postgres://app:FAKEprodPW0043@db.internal/app\n",
        );
        let f = DotenvCheck.run(&ctx_with_env(dir.path(), &[]));
        let locations: Vec<&str> = f.iter().map(|f| f.location.as_str()).collect();
        assert_eq!(locations, ["~/.env: PROD_DATABASE_URL"]);
    }

    #[test]
    fn frontend_variables() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "apps/web/.env.local",
            "NEXT_PUBLIC_POSTHOG_KEY=phc_FAKEFAKEFAKEFAKEFAKE0044\n\
             VITE_RECAPTCHA_SITE_KEY=6LcFAKEFAKEFAKEFAKE0045\n\
             NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJGQUtFIn0.eyJzdWIiOiJGQUtFRkFLRUZBS0UifQ.FAKEsig46\n\
             NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJGQUtFIn0.eyJzdWIiOiJGQUtFRkFLRUZBS0UifQ.FAKEsig47\n",
        );
        // The working directory is a project, not the home directory, so
        // the walk goes into apps/web.
        let ctx = Context::new(
            dir.path().to_path_buf(),
            fixture("empty"),
            dir.path().to_path_buf(),
            BTreeMap::new(),
        );
        let f = DotenvCheck.run(&ctx);
        assert_eq!(f.len(), 1, "{f:#?}");
        assert_eq!(f[0].title, "Secret exposed to the frontend bundle");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(
            f[0].location,
            "./apps/web/.env.local: NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"
        );
    }

    #[test]
    fn bare_lines_show_the_line_number_only() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".env",
            "https://bob:FAKEdotenvPW0003@api.example.com/v1?api_key=q8Zr1vLx0pTn4Wm2\nghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000031\nnot a secret\n",
        );
        let f = DotenvCheck.run(&ctx_with_env(dir.path(), &[]));
        let locations: Vec<&str> = f.iter().map(|f| f.location.as_str()).collect();
        assert_eq!(locations, ["~/.env:1", "~/.env:2"], "{f:#?}");
        write(
            dir.path(),
            ".env.local",
            "MY_ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000032_TOKEN=q8Zr1vLx0pTn4Wm2\n",
        );
        let f2 = DotenvCheck.run(&ctx_with_env(dir.path(), &[]));
        assert!(
            f2.iter()
                .any(|f| f.location == "~/.env.local: MY_ghp_…032_TOKEN"),
            "{f2:#?}"
        );
        let all = format!("{f:?}");
        assert!(
            !all.contains("FAKEdotenvPW") && !all.contains("bob"),
            "{all}"
        );
        assert_eq!(f[1].fingerprint.as_deref(), Some("ghp_…031"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_inside_are_followed_outside_are_recorded() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("p");
        write(
            &root.path().join("shared"),
            ".env",
            "OPENAI_API_KEY=sk-proj-FAKEFAKEFAKEFAKEFAKEFAKE0902\n",
        );
        write(
            &project,
            "config/real.env.txt",
            "GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000903\n",
        );
        write(
            &project,
            ".vercel/.env.production.local",
            "STRIPE_SECRET_KEY=sk_live_FAKEFAKEFAKEFAKE0904\n",
        );
        write(&project, ".gitignore", ".vercel\n");
        std::fs::create_dir_all(project.join("apps/web")).unwrap();
        symlink("../../../shared/.env", project.join("apps/web/.env")).unwrap();
        symlink("config/real.env.txt", project.join(".env")).unwrap();
        let empty = fixture("empty");
        let ctx = Context::new(empty.clone(), empty, project.clone(), BTreeMap::new());
        let f = DotenvCheck.run(&ctx);
        let locations: Vec<&str> = f.iter().map(|f| f.location.as_str()).collect();
        assert_eq!(
            locations,
            [
                "./.env: GITHUB_TOKEN",
                "./.vercel/.env.production.local: STRIPE_SECRET_KEY"
            ]
        );
        let problems = ctx.take_unreadable();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert_eq!(problems[0].0, project.join("apps/web/.env"));
        assert_eq!(problems[0].1, "symlink leads outside the directory scanned");
    }

    #[test]
    fn from_the_home_directory_only_the_top_level_is_read() {
        let home = tempfile::tempdir().unwrap();
        write(
            home.path(),
            ".env",
            "GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000951\n",
        );
        write(
            home.path(),
            "code/app/.env",
            "GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000952\n",
        );
        let at_home = Context::new(
            fixture("empty"),
            home.path().to_path_buf(),
            home.path().to_path_buf(),
            BTreeMap::new(),
        );
        let f = DotenvCheck.run(&at_home);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(!f[0].location.contains("code/app"), "{f:?}");

        // From anywhere else, the walk goes into subdirectories as usual.
        let elsewhere = Context::new(
            fixture("empty"),
            fixture("empty"),
            home.path().to_path_buf(),
            BTreeMap::new(),
        );
        assert_eq!(DotenvCheck.run(&elsewhere).len(), 2);
    }
}
