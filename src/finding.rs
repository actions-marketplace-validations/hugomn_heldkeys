//! The data model every check produces and every report consumes.
//!
//! A `Finding` describes one credential (or one context fact) that an agent
//! running here could reach. It never holds a secret value: the only trace of
//! the value is `fingerprint`, built by `redact::fingerprint`.

use std::hash::{BuildHasher, RandomState};
use std::sync::LazyLock;

use serde::Serialize;

/// How bad it is if an agent gets hijacked while this credential is reachable.
///
/// Rule of thumb from the spec:
/// - High: long-lived plus write access, or unknown access on a cloud or SCM credential.
/// - Medium: short-lived write, long-lived read, or an SSH key loaded in an agent.
/// - Low: test-mode keys and read-only tokens with narrow scope.
/// - Info: a context fact, such as the metadata endpoint being reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// All severities, most severe first. Reports group findings in this order.
    pub const ALL: [Severity; 4] = [
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    /// Higher number means more severe. Used for sorting and `--fail-on`.
    pub fn rank(self) -> u8 {
        match self {
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// How long the credential stays valid if it is stolen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lifetime {
    LongLived,
    ShortLived,
    Unknown,
}

impl Lifetime {
    pub fn as_str(self) -> &'static str {
        match self {
            Lifetime::LongLived => "long-lived",
            Lifetime::ShortLived => "short-lived",
            Lifetime::Unknown => "unknown lifetime",
        }
    }
}

/// What the credential lets its holder do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Write,
    Read,
    Unknown,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Write => "write access",
            Access::Read => "read access",
            Access::Unknown => "unknown access",
        }
    }
}

/// A stable rule: one kind of finding a check can produce, e.g. "HK-AWS-001"
/// (a long-lived AWS key in a credentials file). Rule ids never change
/// meaning once released; SARIF and docs pages key on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// The check that produces it, e.g. "aws".
    pub check: &'static str,
    /// Stable id, `HK-<AREA>-<NNN>`.
    pub id: &'static str,
    /// One-line description, used for `checks` output and SARIF rule metadata.
    pub summary: &'static str,
}

/// Where a finding lives, for grouping reports: one per kind of place an
/// agent finds credentials. Derived from the check; the order is the order
/// reports list them in, machine-wide places before project files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Environment,
    CloudCli,
    Git,
    PackageRegistry,
    Ssh,
    Mcp,
    Host,
    CiJob,
    Workflow,
    ProjectEnv,
    RepoFiles,
    NotAnalysed,
    Other,
}

impl Category {
    /// The category of a check's findings.
    pub fn of_check(check: &str) -> Category {
        match check {
            "env" => Category::Environment,
            "aws" | "gcloud" | "azure" | "kube" => Category::CloudCli,
            "netrc" | "git-credentials" | "git-helper" | "git-config" => Category::Git,
            "npmrc" | "pypirc" | "cargo-credentials" | "docker" => Category::PackageRegistry,
            "ssh-agent" => Category::Ssh,
            "mcp" => Category::Mcp,
            "docker-socket" | "k8s-service-account" | "cloud-metadata" => Category::Host,
            "ci-runtime" => Category::CiJob,
            "workflows" => Category::Workflow,
            "dotenv" => Category::ProjectEnv,
            "repo-secrets" => Category::RepoFiles,
            "read-errors" => Category::NotAnalysed,
            _ => Category::Other,
        }
    }

    /// The heading reports show.
    pub fn label(self) -> &'static str {
        match self {
            Category::Environment => "Shell environment",
            Category::CloudCli => "Cloud CLIs (AWS, gcloud, Azure, kube)",
            Category::Git => "Git and GitHub",
            Category::PackageRegistry => "Package registries (npm, PyPI, cargo, Docker)",
            Category::Ssh => "SSH",
            Category::Mcp => "MCP and agent configs",
            Category::Host => "Sandbox and host",
            Category::CiJob => "CI job",
            Category::Workflow => "Workflows",
            Category::ProjectEnv => "Project .env files",
            Category::RepoFiles => "Tracked files",
            Category::NotAnalysed => "Could not analyse",
            Category::Other => "Other",
        }
    }

    /// Files in the working directory, which a repository controls, rather
    /// than machine-wide logins and the environment.
    pub fn is_project(self) -> bool {
        matches!(self, Category::ProjectEnv | Category::RepoFiles)
    }
}

/// The key for `Finding::with_secret`'s in-memory identity: random for each
/// process, so the identity of a value means nothing outside this run.
static IDENTITY_KEY: LazyLock<RandomState> = LazyLock::new(RandomState::new);

/// An opaque, keyed hash of `value` that only tells whether two findings
/// hold the same value. Never printed or serialized.
pub fn identity(value: &str) -> u64 {
    IDENTITY_KEY.hash_one(value)
}

/// One reachable credential, or one context fact (severity `Info`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Id of the check that produced it, e.g. "aws". Stable; used as the SARIF rule id.
    pub check: &'static str,
    /// Stable rule id, e.g. "HK-AWS-001".
    pub rule: &'static str,
    /// Short human title, e.g. "Long-lived AWS access key".
    pub title: String,
    /// Where it lives, e.g. "~/.aws/credentials [default]" or "env: GITHUB_TOKEN".
    pub location: String,
    /// Redacted fingerprint, at most 4 leading + 3 trailing characters.
    pub fingerprint: Option<String>,
    pub severity: Severity,
    pub lifetime: Lifetime,
    pub access: Access,
    /// Extra context (scopes, profile, helper name). Never the secret.
    pub detail: Option<String>,
    /// One-line remediation.
    pub fix: String,
    /// Where it lives, for grouping (see `Category`). Follows `check`.
    pub category: Category,
    /// How many other findings in the report hold the same secret (same
    /// value, or same title and fingerprint). Set by `Report::new`; absent
    /// when there are none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicates: Option<usize>,
    /// `identity` of the secret value, so reports can tell copies of one
    /// secret apart from different secrets without keeping the value. Only
    /// compared in memory: never printed, never serialized.
    #[serde(skip)]
    pub secret_id: Option<u64>,
    /// `identity` of the project (git checkout) a project file belongs to,
    /// for counting projects. Never printed, never serialized.
    #[serde(skip)]
    pub project_id: Option<u64>,
}

impl Finding {
    /// Builds a finding without fingerprint or detail; add those with the
    /// `with_*` helpers. Kept as a plain constructor so every check reads the same.
    pub fn new(
        rule: Rule,
        title: impl Into<String>,
        location: impl Into<String>,
        severity: Severity,
        lifetime: Lifetime,
        access: Access,
        fix: impl Into<String>,
    ) -> Finding {
        Finding {
            check: rule.check,
            rule: rule.id,
            title: title.into(),
            location: location.into(),
            fingerprint: None,
            severity,
            lifetime,
            access,
            detail: None,
            fix: fix.into(),
            category: Category::of_check(rule.check),
            duplicates: None,
            secret_id: None,
            project_id: None,
        }
    }

    /// Records the in-memory identity of the secret value (see `identity`),
    /// so copies of it can be grouped. Surrounding quotes and spaces do not
    /// count.
    pub fn with_secret(mut self, value: &str) -> Finding {
        self.secret_id = Some(identity(crate::rules::trim_value(value)));
        self
    }

    /// Which copies of a secret this finding is one of: the value's identity
    /// when the check recorded it, else the title and fingerprint (two
    /// tokens of one format can share a fingerprint, but rarely a title
    /// too). `None` when neither is known: then it is its own group.
    pub fn secret_key(&self) -> Option<SecretKey> {
        match (self.secret_id, &self.fingerprint) {
            (Some(id), _) => Some(SecretKey::Value(id)),
            (None, Some(fp)) => Some(SecretKey::Fingerprint(self.title.clone(), fp.clone())),
            (None, None) => None,
        }
    }

    pub fn with_fingerprint(mut self, fingerprint: Option<String>) -> Finding {
        self.fingerprint = fingerprint;
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Finding {
        self.detail = Some(detail.into());
        self
    }

    /// True for findings that are actual credentials (everything but `Info`).
    pub fn is_credential(&self) -> bool {
        self.severity != Severity::Info
    }

    /// Long-lived with write access: the worst combination, called out in the summary.
    pub fn is_long_lived_write(&self) -> bool {
        self.lifetime == Lifetime::LongLived && self.access == Access::Write
    }
}

/// See `Finding::secret_key`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecretKey {
    Value(u64),
    Fingerprint(String, String),
}

/// The `--fail-on` threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    None,
    High,
    Medium,
    Low,
    LongLivedWrite,
}

impl FailOn {
    /// Does this finding reach the threshold (and so make the exit code 1)?
    pub fn is_triggered_by(self, finding: &Finding) -> bool {
        match self {
            FailOn::None => false,
            FailOn::High => finding.severity.rank() >= Severity::High.rank(),
            FailOn::Medium => finding.severity.rank() >= Severity::Medium.rank(),
            FailOn::Low => finding.severity.rank() >= Severity::Low.rank(),
            FailOn::LongLivedWrite => finding.is_long_lived_write(),
        }
    }

    pub fn any_triggered(self, findings: &[Finding]) -> bool {
        findings.iter().any(|f| self.is_triggered_by(f))
    }
}

/// Sorts findings for stable output: most severe first, then by check and location.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.check.cmp(b.check))
            .then_with(|| a.location.cmp(&b.location))
            .then_with(|| a.title.cmp(&b.title))
    });
}

/// A rule for unit tests that build findings by hand.
#[cfg(test)]
pub(crate) const TEST_RULE: Rule = Rule {
    check: "test",
    id: "HK-TEST-001",
    summary: "test",
};

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity, lifetime: Lifetime, access: Access) -> Finding {
        Finding::new(TEST_RULE, "t", "l", severity, lifetime, access, "fix")
    }

    #[test]
    fn fail_on_thresholds() {
        let medium = finding(Severity::Medium, Lifetime::ShortLived, Access::Write);
        assert!(!FailOn::None.is_triggered_by(&medium));
        assert!(!FailOn::High.is_triggered_by(&medium));
        assert!(FailOn::Medium.is_triggered_by(&medium));
        assert!(FailOn::Low.is_triggered_by(&medium));
        assert!(!FailOn::LongLivedWrite.is_triggered_by(&medium));

        let info = finding(Severity::Info, Lifetime::Unknown, Access::Unknown);
        assert!(!FailOn::Low.is_triggered_by(&info));
    }

    #[test]
    fn long_lived_write_threshold() {
        let lw = finding(Severity::Low, Lifetime::LongLived, Access::Write);
        assert!(FailOn::LongLivedWrite.is_triggered_by(&lw));
    }

    #[test]
    fn sort_puts_high_first() {
        let mut v = vec![
            finding(Severity::Info, Lifetime::Unknown, Access::Unknown),
            finding(Severity::High, Lifetime::Unknown, Access::Unknown),
            finding(Severity::Low, Lifetime::Unknown, Access::Unknown),
        ];
        sort_findings(&mut v);
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[2].severity, Severity::Info);
    }

    #[test]
    fn serializes_enums_as_kebab_strings() {
        let f = finding(Severity::High, Lifetime::LongLived, Access::Write);
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["severity"], "high");
        assert_eq!(json["lifetime"], "long-lived");
        assert_eq!(json["access"], "write");
        assert_eq!(json["rule"], "HK-TEST-001");
        assert_eq!(json["check"], "test");
        assert_eq!(json["category"], "other");
        assert!(json.get("duplicates").is_none());
    }

    #[test]
    fn the_secret_identity_is_never_serialized() {
        let f = finding(Severity::High, Lifetime::LongLived, Access::Write)
            .with_secret("hunter2hunter2");
        let id = f.secret_id.unwrap();
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains(&id.to_string()), "{json}");
        assert!(
            !json.contains("secret_id") && !json.contains("project_id"),
            "{json}"
        );
        let same = finding(Severity::Low, Lifetime::Unknown, Access::Unknown)
            .with_secret("\"hunter2hunter2\"");
        assert_eq!(f.secret_key(), same.secret_key());
        let other = finding(Severity::High, Lifetime::LongLived, Access::Write)
            .with_secret("hunter3hunter3");
        assert_ne!(f.secret_key(), other.secret_key());
    }

    #[test]
    fn categories_follow_the_check() {
        assert_eq!(Category::of_check("dotenv"), Category::ProjectEnv);
        assert_eq!(Category::of_check("aws"), Category::CloudCli);
        assert!(Category::ProjectEnv.is_project());
        assert!(Category::Environment < Category::ProjectEnv);
    }
}
