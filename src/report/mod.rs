//! Output formats. Every renderer gets the same `Report` and returns a string;
//! `main` decides where it goes (stdout or `--output`).

use crate::finding::{Finding, Severity};
use crate::redact;
use crate::sanitize::sanitize;
use crate::suppress::{By, Change, Suppressed, Suppression};

pub mod digest;
pub mod json;
pub mod markdown;
pub mod sarif;
pub mod text;

/// `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Markdown,
    Sarif,
}

/// Which subcommand produced the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Scan,
    Ci,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Scan => "scan",
            Mode::Ci => "ci",
        }
    }
}

/// Everything a renderer needs.
pub struct Report {
    pub mode: Mode,
    /// Sorted, most severe first (see `finding::sort_findings`).
    pub findings: Vec<Finding>,
    /// The scanned directory as shown to the reader ("~/code"), when
    /// known. Text output names it in its first line and shows paths under
    /// it relative to it.
    pub origin: Option<String>,
    /// Findings an ignore rule or the baseline left out (see `suppress`).
    /// Counted and listed by every format, never part of `--fail-on`.
    pub suppressed: Vec<Suppressed>,
    /// The ignore rules that matched, the baseline used, and warnings.
    pub suppression: Suppression,
}

impl Report {
    /// Builds a report. Every finding passes through `clean_finding` first,
    /// so no renderer ever sees untrusted text as it was read, and gets its
    /// `duplicates` count.
    pub fn new(mode: Mode, findings: Vec<Finding>) -> Report {
        let mut findings: Vec<Finding> = findings.into_iter().map(clean_finding).collect();
        count_duplicates(&mut findings);
        Report {
            mode,
            findings,
            origin: None,
            suppressed: Vec::new(),
            suppression: Suppression::default(),
        }
    }

    /// Names the scanned directory (see `origin`). Cleaned like any finding
    /// text, because a directory name is not ours to trust.
    pub fn with_origin(mut self, origin: &str) -> Report {
        self.origin = Some(redact::scrub(&sanitize(origin)));
        self
    }

    pub fn summary(&self) -> Summary {
        let count = |s: Severity| self.findings.iter().filter(|f| f.severity == s).count();
        let by = |by: By| self.suppressed.iter().filter(|s| s.by == by).count();
        // "ignored by .heldkeys.toml" when that is the only file the
        // matching ignore rules came from, "ignored by config" otherwise.
        let project_only = self
            .suppression
            .hits
            .iter()
            .all(|h| h.ignore.source.trim_start_matches("./") == crate::config::PROJECT_FILE);
        Summary {
            mode: self.mode,
            credentials: self.findings.iter().filter(|f| f.is_credential()).count(),
            workflow_risks: self
                .findings
                .iter()
                .filter(|f| f.is_credential() && f.check == WORKFLOW_CHECK)
                .count(),
            long_lived_write: self
                .findings
                .iter()
                .filter(|f| f.is_credential() && f.is_long_lived_write())
                .count(),
            high: count(Severity::High),
            medium: count(Severity::Medium),
            low: count(Severity::Low),
            info: count(Severity::Info),
            ignored: by(By::Config),
            in_baseline: by(By::Baseline),
            // A file the change under review can edit is named as such, so
            // the verdict itself says who accepted these findings.
            ignored_by: match self.suppression.config_from_change {
                Some(Change::PullRequest) => "a file the pull request can change",
                Some(Change::MergeRequest) => "a file the merge request can change",
                None if project_only => crate::config::PROJECT_FILE,
                None => "config",
            },
            baseline: match self.suppression.baseline_from_change {
                Some(Change::PullRequest) => "a baseline the pull request can change",
                Some(Change::MergeRequest) => "a baseline the merge request can change",
                None => "the baseline",
            },
        }
    }
}

/// Sets each credential's `duplicates`: how many other credentials in the
/// report hold the same secret (`Finding::secret_key`).
pub(crate) fn count_duplicates(findings: &mut [Finding]) {
    let mut counts: std::collections::HashMap<crate::finding::SecretKey, usize> =
        std::collections::HashMap::new();
    for f in findings.iter().filter(|f| f.is_credential()) {
        if let Some(key) = f.secret_key() {
            *counts.entry(key).or_default() += 1;
        }
    }
    for f in findings.iter_mut().filter(|f| f.is_credential()) {
        f.duplicates = f
            .secret_key()
            .and_then(|key| counts.get(&key))
            .filter(|n| **n > 1)
            .map(|n| n - 1);
    }
}

/// The last line of defence between what the checks read and what is
/// printed. Titles, locations, details and fixes can quote files a pull
/// request or a cloned repo controls, so each one is
///
/// 1. made a single line of inert text (`sanitize`: no control characters,
///    no bidi controls, no line that starts a workflow command), then
/// 2. scrubbed of anything that looks like a secret (`redact::scrub`: URL
///    passwords become `***@`, known tokens become their fingerprint).
///
/// A fingerprint that is not in the `abcd…xyz` shape is dropped, and a check
/// or rule id outside `[A-Za-z0-9._-]` (only possible from a remote report)
/// becomes `unknown`, because renderers put ids in links and SARIF rule ids.
fn clean_finding(mut f: Finding) -> Finding {
    let clean = |s: &str| redact::scrub(&sanitize(s));
    f.title = clean(&f.title);
    f.location = clean(&f.location);
    f.fix = clean(&f.fix);
    f.detail = f.detail.as_deref().map(clean);
    f.fingerprint = f
        .fingerprint
        .as_deref()
        .map(sanitize)
        .filter(|fp| redact::is_safe_fingerprint(fp));
    for id in [&mut f.check, &mut f.rule] {
        if !is_safe_id(id) {
            *id = UNKNOWN_ID;
        }
    }
    f.category = crate::finding::Category::of_check(f.check);
    f
}

/// Stands in for a check or rule id that is not safe to print.
pub(crate) const UNKNOWN_ID: &str = "unknown";

/// Ids are short ASCII words such as `aws` or `HK-AWS-001`.
pub(crate) fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The check whose findings are risks in workflow files rather than
/// credentials the job can reach. `ci` mode counts them separately.
const WORKFLOW_CHECK: &str = "workflows";

/// Counts shown in the summary line and the JSON `summary` object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Summary {
    /// Picks the wording of the summary line; not part of the JSON.
    #[serde(skip)]
    pub mode: Mode,
    /// Findings that are not Info. In `scan` mode every one is a credential;
    /// in `ci` mode this includes the `workflow_risks`.
    pub credentials: usize,
    /// Non-Info findings of the `workflows` check (AI agent steps in
    /// workflow files). Always 0 in `scan` mode.
    pub workflow_risks: usize,
    pub long_lived_write: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    /// Findings left out by an ignore rule.
    pub ignored: usize,
    /// Findings left out because the baseline already has them.
    pub in_baseline: usize,
    /// Names where the ignore rules came from, in the summary line.
    #[serde(skip)]
    pub ignored_by: &'static str,
    /// Names the baseline in the summary line.
    #[serde(skip)]
    pub baseline: &'static str,
}

impl Summary {
    /// The one-line verdict.
    ///
    /// `scan`: "7 credentials reachable, 2 long-lived with write access. If a
    /// prompt injection can run one shell command here, it can use all of them."
    ///
    /// `ci`: "3 AI agent workflow risks, 2 credentials reachable in this job."
    /// Workflow findings are risks in the YAML, not credentials, so they are
    /// counted apart from what the running job exposes.
    pub fn line(&self) -> String {
        match self.mode {
            Mode::Scan => self.scan_line(),
            Mode::Ci => self.ci_line(),
        }
    }

    /// " (4 ignored by .heldkeys.toml, 2 in the baseline)", or nothing when
    /// no finding was left out.
    pub fn suppressed_note(&self) -> String {
        let mut parts = Vec::new();
        if self.ignored > 0 {
            parts.push(format!("{} ignored by {}", self.ignored, self.ignored_by));
        }
        if self.in_baseline > 0 {
            parts.push(format!("{} in {}", self.in_baseline, self.baseline));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", parts.join(", "))
        }
    }

    fn ci_line(&self) -> String {
        let job_credentials = self.credentials - self.workflow_risks;
        let note = self.suppressed_note();
        if self.workflow_risks == 0 && job_credentials == 0 {
            return format!(
                "No AI agent workflow risks and no credentials reachable in this job{note}."
            );
        }
        format!(
            "{}, {} reachable in this job{note}.",
            plural(
                self.workflow_risks,
                "AI agent workflow risk",
                "AI agent workflow risks"
            ),
            plural(job_credentials, "credential", "credentials"),
        )
    }

    fn scan_line(&self) -> String {
        let note = self.suppressed_note();
        match self.credentials {
            0 => format!("No credentials reachable from here{note}."),
            1 => format!(
                "1 credential reachable, {} long-lived with write access{note}. If a prompt injection can run one shell command here, it can use it.",
                self.long_lived_write
            ),
            n => format!(
                "{n} credentials reachable, {} long-lived with write access{note}. If a prompt injection can run one shell command here, it can use all of them.",
                self.long_lived_write
            ),
        }
    }
}

/// "1 credential", "0 credentials", "2 credentials".
fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// How text output is laid out. Other formats ignore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextOptions {
    /// ANSI colours.
    pub color: bool,
    /// Line width to fit in, in characters.
    pub width: usize,
    /// `--details`: every finding, grouped by place and file, instead of
    /// the summary.
    pub details: bool,
}

impl TextOptions {
    /// Width when the terminal's is not known.
    pub const DEFAULT_WIDTH: usize = 100;

    /// Plain text at the default width, summary view.
    pub fn plain() -> TextOptions {
        TextOptions {
            color: false,
            width: TextOptions::DEFAULT_WIDTH,
            details: false,
        }
    }

    /// The width to use: `COLUMNS` when it is a sensible number, otherwise
    /// `DEFAULT_WIDTH`. Clamped so a tiny or huge value keeps the layout.
    pub fn width_from(columns: Option<&str>) -> usize {
        columns
            .and_then(|c| c.trim().parse::<usize>().ok())
            .unwrap_or(TextOptions::DEFAULT_WIDTH)
            .clamp(60, 200)
    }
}

/// Renders `report` in `format`. `text` only affects text output.
pub fn render(format: Format, report: &Report, text: &TextOptions) -> Result<String, String> {
    match format {
        Format::Text => Ok(text::render(report, text)),
        Format::Json => Ok(json::render(report)),
        Format::Markdown => markdown::render(report),
        Format::Sarif => sarif::render(report),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Access, Lifetime};

    #[test]
    fn unsafe_fingerprints_are_dropped() {
        let f = Finding::new(
            crate::finding::TEST_RULE,
            "t",
            "l",
            Severity::High,
            Lifetime::LongLived,
            Access::Write,
            "x",
        )
        .with_fingerprint(Some(concat!("AKIA", "IOSFODNN7EXAMPLE").to_string()));
        let r = Report::new(Mode::Scan, vec![f]);
        assert_eq!(r.findings[0].fingerprint, None);
    }

    fn hostile(text: &str) -> Finding {
        Finding::new(
            crate::finding::TEST_RULE,
            text,
            text,
            Severity::High,
            Lifetime::LongLived,
            Access::Write,
            text,
        )
        .with_detail(text)
    }

    fn fields(f: &Finding) -> [&str; 4] {
        [&f.title, &f.location, f.detail.as_deref().unwrap(), &f.fix]
    }

    #[test]
    fn every_text_field_is_sanitized() {
        let r = Report::new(
            Mode::Ci,
            vec![hostile(
                "x\x1b]0;T\x07\x1b[2J\r\n::error::boom\u{202E}\u{9b}",
            )],
        );
        for field in fields(&r.findings[0]) {
            assert_eq!(field, "x?]0;T??[2J??::error::boom??");
        }
        let r = Report::new(Mode::Ci, vec![hostile("::set-output name=x::1")]);
        for field in fields(&r.findings[0]) {
            assert!(field.starts_with("?::"), "{field}");
        }
    }

    #[test]
    fn every_text_field_is_scrubbed() {
        let r = Report::new(
            Mode::Ci,
            vec![hostile(
                "git fetch https://x-access-token:FAKEpw0001@github.com/o/r ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000123",
            )],
        );
        for field in fields(&r.findings[0]) {
            assert_eq!(field, "git fetch https://***@github.com/o/r ghp_…123");
        }
    }

    #[test]
    fn unsafe_ids_are_replaced() {
        let mut f = hostile("t");
        f.rule = "x](https://evil.example)";
        f.check = "aws";
        let r = Report::new(Mode::Scan, vec![f]);
        assert_eq!(r.findings[0].rule, UNKNOWN_ID);
        assert_eq!(r.findings[0].check, "aws");
    }

    #[test]
    fn summary_lines() {
        let mut s = Summary {
            mode: Mode::Scan,
            credentials: 0,
            workflow_risks: 0,
            long_lived_write: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 1,
            ignored: 0,
            in_baseline: 0,
            ignored_by: "config",
            baseline: "the baseline",
        };
        assert_eq!(s.line(), "No credentials reachable from here.");
        s.credentials = 7;
        s.long_lived_write = 2;
        assert_eq!(
            s.line(),
            "7 credentials reachable, 2 long-lived with write access. If a prompt injection can run one shell command here, it can use all of them."
        );
    }

    fn finding(check: &'static str, severity: Severity) -> Finding {
        let mut f = Finding::new(
            crate::finding::TEST_RULE,
            "t",
            "l",
            severity,
            Lifetime::ShortLived,
            Access::Write,
            "x",
        );
        f.check = check;
        f
    }

    #[test]
    fn ci_summary_counts_workflow_risks_apart_from_job_credentials() {
        let line = |findings: Vec<Finding>| Report::new(Mode::Ci, findings).summary().line();
        assert_eq!(
            line(vec![finding("ci-runtime", Severity::Info)]),
            "No AI agent workflow risks and no credentials reachable in this job."
        );
        assert_eq!(
            line(vec![
                finding("workflows", Severity::High),
                finding("workflows", Severity::Medium),
                finding("workflows", Severity::Low),
                finding("ci-runtime", Severity::High),
                finding("repo-secrets", Severity::Medium),
                finding("ci-runtime", Severity::Info),
            ]),
            "3 AI agent workflow risks, 2 credentials reachable in this job."
        );
        assert_eq!(
            line(vec![
                finding("workflows", Severity::High),
                finding("ci-runtime", Severity::Medium),
            ]),
            "1 AI agent workflow risk, 1 credential reachable in this job."
        );
        assert_eq!(
            line(vec![finding("workflows", Severity::Medium)]),
            "1 AI agent workflow risk, 0 credentials reachable in this job."
        );
    }

    #[test]
    fn scan_summary_ignores_the_workflow_split() {
        let r = Report::new(Mode::Scan, vec![finding("env", Severity::High)]);
        assert_eq!(r.summary().workflow_risks, 0);
        assert!(r.summary().line().starts_with("1 credential reachable, "));
    }
}
