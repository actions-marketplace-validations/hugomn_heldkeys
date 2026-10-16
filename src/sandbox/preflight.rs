//! `heldkeys preflight`: a verdict for container entrypoints and sandbox
//! start hooks.
//!
//! The idea is "refuse to start the agent if its sandbox can reach a
//! long-lived write credential". It runs the same local checks as `scan`,
//! then prints one line that starts with PASS or FAIL, so logs stay readable
//! and scripts can `grep` it. The exit code carries the decision: 0 for PASS,
//! 1 for FAIL (and 2 for a usage or runtime error, as everywhere else).

use serde_json::json;

use crate::checks::read_errors;
use crate::finding::{FailOn, Finding};
use crate::report::{self, Report, digest};

/// The outcome of a preflight run.
pub struct Verdict<'a> {
    pub passed: bool,
    pub fail_on: FailOn,
    /// Findings that reach `fail_on`, most severe first.
    pub triggered: Vec<&'a Finding>,
    /// Files that could not be read or parsed. Each one may hide a
    /// credential: with `--strict` they fail the verdict, without it the
    /// PASS line still mentions them.
    pub unreadable: Vec<&'a Finding>,
    pub strict: bool,
    /// All credentials reachable (every finding except Info).
    pub credentials: usize,
    /// " (2 ignored by .heldkeys.toml)" when ignore rules or a baseline left
    /// findings out, so the verdict never hides that it was narrowed.
    pub suppressed_note: String,
}

/// Decides PASS or FAIL for `report` under `fail_on`. With `strict`, anything
/// the checks could not analyse (`read_errors::NOT_ANALYSED_RULES`) fails it too.
pub fn verdict(report: &Report, fail_on: FailOn, strict: bool) -> Verdict<'_> {
    let triggered: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| fail_on.is_triggered_by(f))
        .collect();
    let unreadable: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| read_errors::is_not_analysed(f))
        .collect();
    Verdict {
        passed: triggered.is_empty() && (!strict || unreadable.is_empty()),
        fail_on,
        triggered,
        unreadable,
        strict,
        credentials: report.summary().credentials,
        suppressed_note: report.summary().suppressed_note(),
    }
}

impl Verdict<'_> {
    /// The one-line verdict, e.g.
    /// "heldkeys preflight: FAIL, 3 high-severity credentials reachable (2 long-lived with write access)".
    pub fn line(&self) -> String {
        format!("{}{}", self.verdict_line(), self.suppressed_note)
    }

    fn verdict_line(&self) -> String {
        let prefix = format!("{} preflight:", crate::TOOL_NAME);
        if self.passed {
            let unread = match self.unreadable.len() {
                0 => String::new(),
                n => format!(
                    " ({} could not be read; --strict fails on that)",
                    plural(n, "file")
                ),
            };
            return match self.credentials {
                0 => format!("{prefix} PASS, no credentials reachable{unread}"),
                n => format!(
                    "{prefix} PASS, {} reachable but none reach --fail-on {}{unread}",
                    plural(n, "credential"),
                    fail_on_name(self.fail_on)
                ),
            };
        }
        let n = self.triggered.len();
        if n == 0 {
            let files = plural(self.unreadable.len(), "file");
            return format!("{prefix} FAIL, {files} could not be read (--strict)");
        }
        let what = match self.fail_on {
            FailOn::High => format!("{n} high-severity {}", noun(n, "credential")),
            FailOn::Medium => format!("{} of medium severity or higher", plural(n, "credential")),
            FailOn::Low | FailOn::None => plural(n, "credential"),
            FailOn::LongLivedWrite => format!("{n} long-lived write {}", noun(n, "credential")),
        };
        let long_lived_write = self
            .triggered
            .iter()
            .filter(|f| f.is_long_lived_write())
            .count();
        let note = if long_lived_write > 0 && self.fail_on != FailOn::LongLivedWrite {
            format!(" ({long_lived_write} long-lived with write access)")
        } else {
            String::new()
        };
        let unreadable = if self.strict && !self.unreadable.is_empty() {
            let files = plural(self.unreadable.len(), "file");
            format!("; {files} could not be read (--strict)")
        } else {
            String::new()
        };
        format!("{prefix} FAIL, {what} reachable{note}{unreadable}")
    }
}

/// Reasons listed under a FAIL line without `--details`.
const MAX_REASONS: usize = 10;

/// Text output: the verdict line, then (on FAIL, unless `quiet`) one line
/// per finding that caused it, so the log says what to fix: the first
/// `MAX_REASONS`, most severe first, or all of them with `details`.
pub fn render_text(verdict: &Verdict, quiet: bool, details: bool) -> String {
    let mut out = verdict.line();
    out.push('\n');
    if quiet {
        return out;
    }
    let unreadable: &[&Finding] = if verdict.strict {
        &verdict.unreadable
    } else {
        &[]
    };
    // Most urgent first, as in the scan summary: machine-wide credentials
    // before project files, long-lived write access before the rest.
    let mut triggered: Vec<&&Finding> = verdict.triggered.iter().collect();
    triggered.sort_by(|a, b| digest::place_rank(a).cmp(&digest::place_rank(b)));
    let reasons: Vec<&&Finding> = triggered.into_iter().chain(unreadable).collect();
    let shown = if details {
        reasons.len()
    } else {
        reasons.len().min(MAX_REASONS)
    };
    for f in &reasons[..shown] {
        let fingerprint = f
            .fingerprint
            .as_deref()
            .map(|fp| format!("  {fp}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {}  {}  {}{fingerprint}\n",
            f.severity.as_str().to_uppercase(),
            f.title,
            f.location
        ));
    }
    if shown < reasons.len() {
        out.push_str(&format!(
            "  +{} more (run with --details for all)\n",
            reasons.len() - shown
        ));
    }
    out
}

/// JSON output: the normal `heldkeys/v1` report with a `preflight` object
/// added (fields are only ever added within a schema version).
pub fn render_json(report: &Report, verdict: &Verdict) -> String {
    let mut doc: serde_json::Value =
        serde_json::from_str(&report::json::render(report)).expect("our own JSON parses");
    doc["preflight"] = json!({
        "result": if verdict.passed { "pass" } else { "fail" },
        "fail_on": fail_on_name(verdict.fail_on),
        "triggered": verdict.triggered.len(),
        "unreadable": verdict.unreadable.len(),
        "verdict": verdict.line(),
    });
    let mut out = serde_json::to_string_pretty(&doc).expect("JSON value serializes");
    out.push('\n');
    out
}

/// The `--fail-on` value as typed on the command line.
pub fn fail_on_name(fail_on: FailOn) -> &'static str {
    match fail_on {
        FailOn::None => "none",
        FailOn::High => "high",
        FailOn::Medium => "medium",
        FailOn::Low => "low",
        FailOn::LongLivedWrite => "long-lived-write",
    }
}

fn noun(n: usize, word: &str) -> String {
    if n == 1 {
        word.to_string()
    } else {
        format!("{word}s")
    }
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {}", noun(n, word))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Access, Lifetime, Severity, TEST_RULE};
    use crate::report::Mode;

    fn finding(severity: Severity, lifetime: Lifetime, access: Access) -> Finding {
        Finding::new(
            TEST_RULE, "Token", "env: X", severity, lifetime, access, "fix",
        )
        .with_fingerprint(Some("ghp_…123".to_string()))
    }

    fn report() -> Report {
        Report::new(
            Mode::Scan,
            vec![
                finding(Severity::High, Lifetime::LongLived, Access::Write),
                finding(Severity::High, Lifetime::LongLived, Access::Unknown),
                finding(Severity::Medium, Lifetime::ShortLived, Access::Unknown),
                finding(Severity::Info, Lifetime::Unknown, Access::Unknown),
            ],
        )
    }

    #[test]
    fn fail_lines() {
        let r = report();
        assert_eq!(
            verdict(&r, FailOn::High, false).line(),
            "heldkeys preflight: FAIL, 2 high-severity credentials reachable (1 long-lived with write access)"
        );
        assert_eq!(
            verdict(&r, FailOn::LongLivedWrite, false).line(),
            "heldkeys preflight: FAIL, 1 long-lived write credential reachable"
        );
        assert_eq!(
            verdict(&r, FailOn::Medium, false).line(),
            "heldkeys preflight: FAIL, 3 credentials of medium severity or higher reachable (1 long-lived with write access)"
        );
    }

    #[test]
    fn pass_lines() {
        let r = report();
        let v = verdict(&r, FailOn::None, false);
        assert!(v.passed);
        assert_eq!(
            v.line(),
            "heldkeys preflight: PASS, 3 credentials reachable but none reach --fail-on none"
        );
        let empty = Report::new(Mode::Scan, vec![]);
        assert_eq!(
            verdict(&empty, FailOn::High, false).line(),
            "heldkeys preflight: PASS, no credentials reachable"
        );
    }

    #[test]
    fn strict_fails_on_unreadable_files() {
        let unreadable = Finding::new(
            read_errors::UNREADABLE,
            "File could not be read",
            "~/.kube/config",
            Severity::Info,
            Lifetime::Unknown,
            Access::Unknown,
            "fix",
        );
        let only = Report::new(Mode::Scan, vec![unreadable.clone()]);
        let lenient = verdict(&only, FailOn::High, false);
        assert!(lenient.passed);
        assert_eq!(
            lenient.line(),
            "heldkeys preflight: PASS, no credentials reachable (1 file could not be read; --strict fails on that)"
        );
        assert_eq!(render_text(&lenient, false, false).lines().count(), 1);
        let v = verdict(&only, FailOn::High, true);
        assert!(!v.passed);
        assert_eq!(
            v.line(),
            "heldkeys preflight: FAIL, 1 file could not be read (--strict)"
        );
        assert!(render_text(&v, false, false).contains("File could not be read  ~/.kube/config"));

        let mut findings = report().findings;
        findings.push(unreadable);
        let both = Report::new(Mode::Scan, findings);
        assert_eq!(
            verdict(&both, FailOn::High, true).line(),
            "heldkeys preflight: FAIL, 2 high-severity credentials reachable (1 long-lived with write access); 1 file could not be read (--strict)"
        );
    }

    #[test]
    fn text_lists_what_failed() {
        let r = report();
        let v = verdict(&r, FailOn::High, false);
        let text = render_text(&v, false, false);
        assert_eq!(text.lines().count(), 3, "{text}");
        assert!(
            text.lines()
                .nth(1)
                .unwrap()
                .contains("HIGH  Token  env: X  ghp_…123")
        );
        assert_eq!(render_text(&v, true, false).lines().count(), 1);
    }

    #[test]
    fn reasons_are_capped_without_details() {
        let many: Vec<Finding> = (0..25)
            .map(|_| finding(Severity::High, Lifetime::LongLived, Access::Write))
            .collect();
        let r = Report::new(Mode::Scan, many);
        let v = verdict(&r, FailOn::High, false);
        let text = render_text(&v, false, false);
        assert_eq!(text.lines().count(), 1 + MAX_REASONS + 1, "{text}");
        assert!(
            text.ends_with("  +15 more (run with --details for all)\n"),
            "{text}"
        );
        assert_eq!(render_text(&v, false, true).lines().count(), 26);
    }

    #[test]
    fn json_has_the_preflight_object() {
        let r = report();
        let v = verdict(&r, FailOn::High, false);
        let doc: serde_json::Value = serde_json::from_str(&render_json(&r, &v)).unwrap();
        assert_eq!(doc["schema"], crate::JSON_SCHEMA);
        assert_eq!(doc["preflight"]["result"], "fail");
        assert_eq!(doc["preflight"]["fail_on"], "high");
        assert_eq!(doc["preflight"]["triggered"], 2);
        assert_eq!(doc["findings"].as_array().unwrap().len(), 4);
    }
}
