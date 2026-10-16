//! The summary that human-facing reports lead with.
//!
//! A scan of a directory full of checkouts can hold hundreds of findings,
//! most of them the same few secrets copied into many `.env` files. Nobody
//! reads that list. The digest boils it down to what a reader acts on:
//!
//! - **secrets**: distinct credentials, each with every place it was found,
//!   ranked so the ones to fix first come first;
//! - **categories**: how many findings each kind of place holds;
//! - **steps**: a handful of generic actions, by kind of credential rather
//!   than one per variable, ordered by how much each one removes;
//! - **notes**: context facts and files that could not be analysed.
//!
//! It only reorganises findings that `Report::new` already cleaned; it adds
//! no text read from the scanned machine.

use std::collections::{BTreeSet, HashMap};

use crate::finding::{Category, Finding, Severity};
use crate::report::Report;

/// Distinct credentials shown in "Fix these first".
pub const TOP: usize = 10;
/// Most actions shown in "Next steps".
pub const MAX_STEPS: usize = 6;

/// One credential and every place it was found, most important place first.
pub struct Secret<'a> {
    pub places: Vec<&'a Finding>,
}

impl<'a> Secret<'a> {
    /// The place shown for it: machine-wide before project files.
    pub fn first(&self) -> &'a Finding {
        self.places[0]
    }

    pub fn severity(&self) -> Severity {
        self.first().severity
    }

    /// Distinct files (or places without a file) holding it.
    pub fn files(&self) -> usize {
        self.places
            .iter()
            .map(|f| split_location(&f.location).0.unwrap_or(&f.location))
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// True when every copy is in a project file: "in 4 files" rather than
    /// "in 4 places".
    pub fn only_in_files(&self) -> bool {
        self.places.iter().all(|f| f.category.is_project())
    }
}

/// Finding counts for one category.
pub struct CategoryRow {
    pub category: Category,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    /// Distinct files the findings are in.
    pub files: usize,
    /// Distinct projects (git checkouts) the findings are in.
    pub projects: usize,
}

impl CategoryRow {
    pub fn total(&self) -> usize {
        self.high + self.medium + self.low
    }
}

/// See the module documentation.
pub struct Digest<'a> {
    /// Ranked, most urgent first.
    pub secrets: Vec<Secret<'a>>,
    /// In `Category` order; only categories with credentials.
    pub categories: Vec<CategoryRow>,
    /// Info findings, files that could not be analysed first.
    pub notes: Vec<&'a Finding>,
    /// At most `MAX_STEPS`, biggest effect first.
    pub steps: Vec<String>,
}

impl Digest<'_> {
    /// The `TOP` secrets to fix first, in rank order, with at most
    /// `PER_CATEGORY` from one category while others still have some, so
    /// one crowded place (ten kubeconfig users) does not hide the rest.
    pub fn top(&self) -> Vec<&Secret<'_>> {
        const PER_CATEGORY: usize = 3;
        let mut picked: Vec<usize> = Vec::new();
        let mut per: HashMap<Category, usize> = HashMap::new();
        for (i, s) in self.secrets.iter().enumerate() {
            let n = per.entry(s.first().category).or_default();
            if *n < PER_CATEGORY && picked.len() < TOP {
                *n += 1;
                picked.push(i);
            }
        }
        for i in 0..self.secrets.len() {
            if picked.len() >= TOP {
                break;
            }
            if !picked.contains(&i) {
                picked.push(i);
            }
        }
        picked.sort_unstable();
        picked.iter().map(|&i| &self.secrets[i]).collect()
    }

    /// Credentials found in more than one place, most copies first.
    pub fn shared(&self) -> Vec<&Secret<'_>> {
        let mut shared: Vec<&Secret> = self.secrets.iter().filter(|s| s.places.len() > 1).collect();
        shared.sort_by_key(|s| std::cmp::Reverse(s.places.len()));
        shared
    }
}

pub fn digest(report: &Report) -> Digest<'_> {
    let credentials: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.is_credential())
        .collect();
    let secrets = group_secrets(&credentials);
    let mut notes: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| !f.is_credential())
        .collect();
    notes.sort_by_key(|f| !crate::checks::read_errors::is_not_analysed(f));
    Digest {
        steps: steps(&secrets),
        categories: categories(&credentials),
        secrets,
        notes,
    }
}

/// Sort key for a place: most severe, then machine-wide before project
/// files, then long-lived with write access, then by category and location.
pub(crate) fn place_rank(f: &Finding) -> impl Ord + '_ {
    (
        std::cmp::Reverse(f.severity.rank()),
        f.category.is_project(),
        !f.is_long_lived_write(),
        f.category,
        f.location.as_str(),
    )
}

/// Groups findings that hold the same secret (`Finding::secret_key`) and
/// ranks the groups: most severe, machine-wide before project files,
/// long-lived with write access, then the most copies.
fn group_secrets<'a>(credentials: &[&'a Finding]) -> Vec<Secret<'a>> {
    let mut index: HashMap<crate::finding::SecretKey, usize> = HashMap::new();
    let mut secrets: Vec<Secret<'a>> = Vec::new();
    for f in credentials {
        match f.secret_key() {
            Some(key) => match index.get(&key) {
                Some(&i) => secrets[i].places.push(f),
                None => {
                    index.insert(key, secrets.len());
                    secrets.push(Secret { places: vec![f] });
                }
            },
            None => secrets.push(Secret { places: vec![f] }),
        }
    }
    for s in &mut secrets {
        s.places.sort_by(|a, b| place_rank(a).cmp(&place_rank(b)));
    }
    secrets.sort_by(|a, b| secret_rank(a).cmp(&secret_rank(b)));
    secrets
}

/// Most severe first; then machine-wide before project files; then
/// long-lived, then write access; then the most copies; then by place.
fn secret_rank<'a>(s: &Secret<'a>) -> impl Ord + 'a {
    let f = s.first();
    (
        std::cmp::Reverse(f.severity.rank()),
        f.category.is_project(),
        f.lifetime != crate::finding::Lifetime::LongLived,
        f.access != crate::finding::Access::Write,
        std::cmp::Reverse(s.places.len()),
        f.category,
        f.location.as_str(),
    )
}

fn categories(credentials: &[&Finding]) -> Vec<CategoryRow> {
    let mut rows: Vec<CategoryRow> = Vec::new();
    let mut seen: BTreeSet<Category> = BTreeSet::new();
    for f in credentials {
        seen.insert(f.category);
    }
    for category in seen {
        let mine: Vec<&&Finding> = credentials
            .iter()
            .filter(|f| f.category == category)
            .collect();
        let count = |s: Severity| mine.iter().filter(|f| f.severity == s).count();
        rows.push(CategoryRow {
            category,
            high: count(Severity::High),
            medium: count(Severity::Medium),
            low: count(Severity::Low),
            files: mine
                .iter()
                .filter_map(|f| split_location(&f.location).0)
                .collect::<BTreeSet<_>>()
                .len(),
            projects: mine
                .iter()
                .map(|f| f.project_id)
                .collect::<BTreeSet<_>>()
                .len(),
        });
    }
    rows
}

/// What a "Next steps" action is about: a named kind of credential with its
/// own generic wording, or, for checks without one, the findings' own fix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Action {
    Named(&'static str),
    Fix(String),
}

fn action(f: &Finding) -> Action {
    let named = match (f.check, f.rule) {
        ("dotenv", "HK-DOTENV-003") => "dotenv-history",
        ("dotenv", _) => "dotenv",
        ("aws", "HK-AWS-001") => "aws-static",
        ("aws", "HK-AWS-007" | "HK-AWS-008") => "aws-cache",
        ("env", "HK-ENV-003") if f.lifetime == crate::finding::Lifetime::LongLived => "aws-static",
        ("env", _) => "env",
        ("aws", _) => "aws",
        ("gcloud", _) => "gcloud",
        ("azure", _) => "azure",
        ("kube", _) => "kube",
        ("git-credentials", _) => "git-credentials",
        ("netrc", _) => "netrc",
        ("git-helper", _) => "git-helper",
        ("git-config", _) => "git-config",
        ("npmrc", _) => "npmrc",
        ("pypirc", _) => "pypirc",
        ("cargo-credentials", _) => "cargo",
        ("docker", _) => "docker",
        ("ssh-agent", "HK-SSH-002") => "ssh-key",
        ("ssh-agent", _) => "ssh-agent",
        ("mcp", _) => "mcp",
        ("ai-logins", _) => "ai-logins",
        ("cli-logins", _) => "cli-logins",
        ("docker-socket", _) => "docker-socket",
        ("k8s-service-account", _) => "k8s",
        _ => return Action::Fix(f.fix.clone()),
    };
    Action::Named(named)
}

/// How much one action covers.
#[derive(Default)]
struct Reach {
    /// Severity-weighted count of distinct secrets: what fixing it removes.
    weight: usize,
    secrets: usize,
    files: BTreeSet<String>,
    /// Rank of the first secret it covers, to break ties.
    first: usize,
}

fn steps(secrets: &[Secret]) -> Vec<String> {
    let mut reach: HashMap<Action, Reach> = HashMap::new();
    for (rank, secret) in secrets.iter().enumerate() {
        // A secret copied into a .env file and a shell profile takes both
        // actions; within one action it counts once.
        let mut counted: BTreeSet<Action> = BTreeSet::new();
        for f in &secret.places {
            let a = action(f);
            let r = reach.entry(a.clone()).or_insert_with(|| Reach {
                first: rank,
                ..Reach::default()
            });
            if let Some(file) = split_location(&f.location).0 {
                r.files.insert(file.to_string());
            }
            if counted.insert(a) {
                r.secrets += 1;
                r.weight += match f.severity {
                    Severity::High => 9,
                    Severity::Medium => 3,
                    _ => 1,
                };
            }
        }
    }
    let mut ranked: Vec<(Action, Reach)> = reach.into_iter().collect();
    ranked.sort_by(|a, b| b.1.weight.cmp(&a.1.weight).then(a.1.first.cmp(&b.1.first)));
    ranked
        .into_iter()
        .take(MAX_STEPS)
        .map(|(a, r)| step_text(&a, &r))
        .collect()
}

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let key = |a: &Action| match a {
            Action::Named(n) => (0, n.to_string()),
            Action::Fix(f) => (1, f.clone()),
        };
        key(self).cmp(&key(other))
    }
}

fn step_text(action: &Action, r: &Reach) -> String {
    let name = match action {
        Action::Fix(fix) => return fix.clone(),
        Action::Named(name) => *name,
    };
    let n = r.secrets;
    match name {
        "dotenv" => format!(
            "Move secrets out of {} into a secret manager, or run agents where they cannot read them.",
            plural(r.files.len(), ".env file", ".env files")
        ),
        "env" => format!(
            "Remove {} from the shell environment; pass each only to the command that needs it.",
            plural(n, "credential", "credentials")
        ),
        "aws-static" => "Replace static AWS keys with SSO (aws configure sso) or an assumed role, then deactivate them.".to_string(),
        "dotenv-history" => format!(
            "Delete the editor .history folders holding {}, and exclude .env files from the Local History extension.",
            plural(r.files.len(), "copy of a .env file", "copies of .env files")
        ),
        "aws" => "Give agents their own narrowly scoped AWS role, with short sessions.".to_string(),
        "aws-cache" => "Clear cached AWS sessions (~/.aws/cli/cache, awsume --clean) before handing a shell to an agent.".to_string(),
        "gcloud" => "Revoke gcloud logins agents do not need (gcloud auth revoke, gcloud auth application-default revoke).".to_string(),
        "azure" => "Sign out of the Azure CLI where agents run (az logout), or give agents their own identity.".to_string(),
        "kube" => "Give agents a kubeconfig with a namespaced, read-only user, or none at all.".to_string(),
        "git-credentials" => "Delete ~/.git-credentials and use a keychain credential helper.".to_string(),
        "netrc" => "Remove passwords and tokens from ~/.netrc; use a credential helper.".to_string(),
        "git-helper" => "Run agents without your git and GitHub CLI logins, or give them fine-grained, read-only tokens.".to_string(),
        "git-config" => format!(
            "Remove {} from git config (url rewrites, extra headers, remote URLs) and rotate them.",
            plural(n, "token", "tokens")
        ),
        "npmrc" => "Replace npm tokens with granular, read-only ones, or keep them out of ~/.npmrc.".to_string(),
        "pypirc" => "Remove PyPI tokens from ~/.pypirc; publish with trusted publishing instead.".to_string(),
        "cargo" => "Remove the crates.io token (cargo logout); publish from CI with a scoped token.".to_string(),
        "docker" => "Use a Docker credential store, and log out of registries agents do not need.".to_string(),
        "ssh-key" => format!(
            "Add passphrases to {} (ssh-keygen -p -f <file>), or use hardware-backed keys.",
            plural(n, "SSH key", "SSH keys")
        ),
        "ssh-agent" => "Load SSH keys with a time limit (ssh-add -t 1h), or run agents without SSH_AUTH_SOCK.".to_string(),
        "mcp" => format!(
            "Move {} out of MCP configs into the client's secret prompt or a credential helper.",
            plural(n, "token", "tokens")
        ),
        "ai-logins" => format!(
            "Log out of AI tools where other agents run, or give each agent its own scoped key ({}).",
            plural(n, "credential", "credentials")
        ),
        "cli-logins" => format!(
            "Log out of developer platform CLIs agents do not need, or use scoped, expiring tokens ({}).",
            plural(n, "credential", "credentials")
        ),
        "docker-socket" => "Do not expose the Docker socket where agents run.".to_string(),
        "k8s" => "Turn off automountServiceAccountToken for agent pods.".to_string(),
        other => other.to_string(),
    }
}

/// "1 file", "3 files".
pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// Splits a location into the file it names, if any, and what is inside it:
///
/// - `./.env: DATABASE_URL` → (`./.env`, `DATABASE_URL`)
/// - `./.env:12` → (`./.env`, `line 12`)
/// - `~/.aws/credentials [default]` → (`~/.aws/credentials`, `[default]`)
/// - `~/Library/Application Support/Claude/claude_desktop_config.json mcpServers.x env T`
///   → (the path, `mcpServers.x env T`)
/// - `env: GITHUB_TOKEN` → (none, `GITHUB_TOKEN`)
/// - `169.254.169.254:80` → (none, the whole location)
pub fn split_location(location: &str) -> (Option<&str>, std::borrow::Cow<'_, str>) {
    use std::borrow::Cow;
    if let Some(name) = location.strip_prefix("env: ") {
        return (None, Cow::Borrowed(name));
    }
    if !looks_like_path(location) {
        return (None, Cow::Borrowed(location));
    }
    let bytes = location.as_bytes();
    for (i, c) in location.char_indices() {
        let path = &location[..i];
        match c {
            ':' if bytes.get(i + 1) == Some(&b' ') => {
                return (Some(path), Cow::Borrowed(location[i + 2..].trim()));
            }
            ':' if bytes.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                let digits: String = location[i + 1..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                let rest = location[i + 1 + digits.len()..].trim();
                let inside = if rest.is_empty() {
                    format!("line {digits}")
                } else {
                    format!("line {digits} {rest}")
                };
                return (Some(path), Cow::Owned(inside));
            }
            ' ' if ends_a_path(path, &location[i + 1..]) => {
                return (Some(path), Cow::Borrowed(location[i + 1..].trim()));
            }
            _ => {}
        }
    }
    (Some(location), Cow::Borrowed(""))
}

fn looks_like_path(s: &str) -> bool {
    s.starts_with("~/") || s.starts_with("./") || s.starts_with('/') || s.starts_with(".github/")
}

/// Whether a space after `path` ends it: the next word opens a section
/// (`[`, `(`) or names something inside the file, and the path's last part
/// looks like a file name (an extension, a dotfile, or a known name).
fn ends_a_path(path: &str, next: &str) -> bool {
    if next.starts_with(['[', '(']) {
        return true;
    }
    let last = path.rsplit('/').next().unwrap_or(path);
    last.contains('.') || matches!(last, "config" | "credentials" | "token" | "hosts")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Access, Lifetime, TEST_RULE};
    use crate::report::Mode;

    #[test]
    fn locations_split_into_file_and_place() {
        let cases = [
            ("./.env: DATABASE_URL", Some("./.env"), "DATABASE_URL"),
            ("./.env:12", Some("./.env"), "line 12"),
            (
                "~/.aws/credentials [default]",
                Some("~/.aws/credentials"),
                "[default]",
            ),
            (
                "~/.docker/config.json (https://index.docker.io/v1/)",
                Some("~/.docker/config.json"),
                "(https://index.docker.io/v1/)",
            ),
            (
                "~/Library/Application Support/Claude/claude_desktop_config.json mcpServers.github env T",
                Some("~/Library/Application Support/Claude/claude_desktop_config.json"),
                "mcpServers.github env T",
            ),
            (
                "~/.kube/config user prod-admin",
                Some("~/.kube/config"),
                "user prod-admin",
            ),
            ("~/.ssh/id_ed25519", Some("~/.ssh/id_ed25519"), ""),
            (
                ".github/workflows/triage.yml:23 jobs.triage.steps[1] (uses: a/b@v1)",
                Some(".github/workflows/triage.yml"),
                "line 23 jobs.triage.steps[1] (uses: a/b@v1)",
            ),
            ("env: GITHUB_TOKEN", None, "GITHUB_TOKEN"),
            ("169.254.169.254:80", None, "169.254.169.254:80"),
        ];
        for (location, file, inside) in cases {
            let (f, i) = split_location(location);
            assert_eq!((f, i.as_ref()), (file, inside), "{location}");
        }
    }

    fn cred(title: &str, location: &str, check: &'static str, severity: Severity) -> Finding {
        let mut f = Finding::new(
            TEST_RULE,
            title,
            location,
            severity,
            Lifetime::LongLived,
            Access::Write,
            "fix",
        );
        f.check = check;
        f.category = Category::of_check(check);
        f
    }

    #[test]
    fn copies_of_one_secret_are_one_entry_shown_at_its_widest_place() {
        let mut findings = Vec::new();
        for i in 0..4 {
            findings.push(
                cred(
                    "Anthropic API key",
                    &format!("./r{i}/.env: ANTHROPIC_API_KEY"),
                    "dotenv",
                    Severity::High,
                )
                .with_fingerprint(Some("sk-a…KE1".into()))
                .with_secret("sk-ant-FAKE-same-value"),
            );
        }
        findings.push(
            cred(
                "Anthropic API key",
                "env: ANTHROPIC_API_KEY",
                "env",
                Severity::High,
            )
            .with_fingerprint(Some("sk-a…KE1".into()))
            .with_secret("sk-ant-FAKE-same-value"),
        );
        // Same name, different value: a different secret.
        findings.push(
            cred(
                "Possible credential",
                "./r0/.env: ADMIN_SECRET",
                "dotenv",
                Severity::Medium,
            )
            .with_secret("one-value-FAKE-0001"),
        );
        findings.push(
            cred(
                "Possible credential",
                "./r1/.env: ADMIN_SECRET",
                "dotenv",
                Severity::Medium,
            )
            .with_secret("other-value-FAKE-0002"),
        );
        let report = Report::new(Mode::Scan, findings);
        let d = digest(&report);
        assert_eq!(d.secrets.len(), 3);
        assert_eq!(d.secrets[0].places.len(), 5);
        assert_eq!(d.secrets[0].first().location, "env: ANTHROPIC_API_KEY");
        assert_eq!(d.shared().len(), 1);
        assert!(!d.secrets[0].only_in_files());
        assert_eq!(report.findings[0].duplicates, Some(4));
        let dotenv = d
            .categories
            .iter()
            .find(|r| r.category == Category::ProjectEnv)
            .unwrap();
        assert_eq!((dotenv.high, dotenv.medium, dotenv.files), (4, 2, 4));
        assert!(
            d.steps[0].starts_with("Move secrets out of 4 .env files"),
            "{:?}",
            d.steps
        );
    }

    #[test]
    fn machine_wide_credentials_rank_before_project_files() {
        let report = Report::new(
            Mode::Scan,
            vec![
                cred("DB", "./a/.env: DATABASE_URL", "dotenv", Severity::High),
                cred("Key", "~/.aws/credentials [x]", "aws", Severity::High),
                cred("Medium", "~/.npmrc (x)", "npmrc", Severity::Medium),
            ],
        );
        let d = digest(&report);
        let order: Vec<&str> = d.secrets.iter().map(|s| s.first().title.as_str()).collect();
        assert_eq!(order, ["Key", "DB", "Medium"]);
    }
}
