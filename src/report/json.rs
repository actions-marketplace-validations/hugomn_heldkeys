//! JSON output: a stable, versioned schema (`"schema": "heldkeys/v1"`).
//!
//! Fields are only ever added within a schema version. Renaming or removing a
//! field means a new version.
//!
//! The same document is a baseline (`--baseline`, `--write-baseline`): only
//! `schema`, `origin` and each finding's `rule`, `location`, `fingerprint`,
//! `severity`, `access` and `lifetime` are read back.

use serde::Serialize;

use crate::finding::{Access, Finding, Lifetime, Severity};
use crate::report::{Report, Summary};
use crate::suppress::By;

#[derive(Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct Document<'a> {
    schema: &'static str,
    tool: Tool,
    mode: &'static str,
    /// The scanned directory as shown ("~/workspace"). Baselines use it to
    /// compare locations relative to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<&'a str>,
    summary: Summary,
    findings: &'a [Finding],
    /// Findings left out by an ignore rule or the baseline.
    suppressed: Vec<SuppressedEntry<'a>>,
    /// Warnings about the run, such as ignore rules read from the checkout
    /// of the pull request under review.
    notices: &'a [String],
}

/// One entry of `suppressed`: enough to recognise the finding, and why it
/// was left out. Like every finding, it holds a fingerprint at most.
#[derive(Serialize)]
struct SuppressedEntry<'a> {
    rule: &'a str,
    check: &'a str,
    title: &'a str,
    severity: Severity,
    lifetime: Lifetime,
    access: Access,
    location: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<&'a str>,
    by: By,
    reason: &'a str,
    /// The config or baseline file.
    source: &'a str,
}

pub fn render(report: &Report) -> String {
    let doc = Document {
        schema: crate::JSON_SCHEMA,
        tool: Tool {
            name: crate::TOOL_NAME,
            version: crate::TOOL_VERSION,
        },
        mode: report.mode.as_str(),
        origin: report.origin.as_deref(),
        summary: report.summary(),
        findings: &report.findings,
        suppressed: report
            .suppressed
            .iter()
            .map(|s| SuppressedEntry {
                rule: s.finding.rule,
                check: s.finding.check,
                title: &s.finding.title,
                severity: s.finding.severity,
                lifetime: s.finding.lifetime,
                access: s.finding.access,
                location: &s.finding.location,
                fingerprint: s.finding.fingerprint.as_deref(),
                by: s.by,
                reason: &s.reason,
                source: &s.source,
            })
            .collect(),
        notices: &report.suppression.notices,
    };
    // Serializing plain structs of strings and numbers cannot fail.
    let mut out = serde_json::to_string_pretty(&doc).expect("report serializes");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Access, Lifetime, Severity};
    use crate::report::Mode;

    #[test]
    fn schema_and_fields() {
        let f = Finding::new(
            crate::finding::TEST_RULE,
            "Long-lived AWS access key",
            "~/.aws/credentials [default]",
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            "rotate",
        )
        .with_fingerprint(Some("AKIA…PLE".to_string()));
        let out = render(&Report::new(Mode::Scan, vec![f]));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["schema"], format!("{}/v1", crate::TOOL_NAME));
        assert_eq!(v["mode"], "scan");
        assert_eq!(v["summary"]["credentials"], 1);
        assert_eq!(v["summary"]["high"], 1);
        assert_eq!(v["findings"][0]["check"], "test");
        assert_eq!(v["findings"][0]["rule"], "HK-TEST-001");
        assert_eq!(v["findings"][0]["fingerprint"], "AKIA…PLE");
        assert_eq!(v["findings"][0]["detail"], serde_json::Value::Null);
    }
}
