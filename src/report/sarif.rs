//! SARIF 2.1.0 output, for GitHub code scanning (CI mode).
//!
//! One run. `tool.driver.rules` lists every rule of every check (from
//! `Check::rules()`), each with a link to its docs page; each finding is one
//! result whose `ruleId` is `Finding::rule`. Levels: High = error,
//! Medium = warning, Low and Info = note.
//!
//! Locations: GitHub only shows results that have a file. CI findings start
//! their location with a repo-relative file, optionally with `:line`
//! (`.github/workflows/x.yml:12 jobs...`, `src/config.py:3`,
//! `.github/workflows/x.yml env: AWS_KEY`), which becomes the physical
//! location. Anything else (home-directory files in `scan` mode, `env:` with
//! no workflow known) gets a logical location only.
//!
//! Findings left out by an ignore rule or the baseline are results too, with
//! a `suppressions` entry (kind `external`, status `accepted`, the reason as
//! justification), so code scanning shows them as dismissed rather than
//! fixed, and the reason stays next to them.

use serde_json::{Value, json};

use crate::checks;
use crate::finding::{Finding, Rule, Severity};
use crate::report::Report;
use crate::report::markdown::RULE_DOCS;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/hugomn/heldkeys";

/// Checks whose locations start with a repo-relative file.
const FILE_CHECKS: &[&str] = &["workflows", "repo-secrets", "ci-runtime"];

pub fn render(report: &Report) -> Result<String, String> {
    let rules = all_rules();
    let index = |f: &Finding| rules.iter().position(|r| r.id == f.rule);
    let mut results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| result(f, index(f)))
        .collect();
    for s in &report.suppressed {
        let mut r = result(&s.finding, index(&s.finding));
        r["suppressions"] = json!([{
            "kind": "external",
            "status": "accepted",
            "justification": s.reason,
        }]);
        results.push(r);
    }
    let mut doc = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": crate::TOOL_NAME,
                    "version": crate::TOOL_VERSION,
                    "semanticVersion": crate::TOOL_VERSION,
                    "informationUri": INFORMATION_URI,
                    "rules": rules.iter().map(rule).collect::<Vec<Value>>(),
                }
            },
            "results": results,
        }]
    });
    // Warnings about the run (ignore rules read from the checkout of the
    // pull request under review) as tool notifications, which code scanning
    // shows with the analysis.
    if !report.suppression.notices.is_empty() {
        let notifications: Vec<Value> = report
            .suppression
            .notices
            .iter()
            .map(|n| json!({ "level": "warning", "message": { "text": n } }))
            .collect();
        doc["runs"][0]["invocations"] = json!([{
            "executionSuccessful": true,
            "toolExecutionNotifications": notifications,
        }]);
    }
    let mut out = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    out.push('\n');
    Ok(out)
}

/// Every rule of every check, local and CI, in registry order.
fn all_rules() -> Vec<Rule> {
    checks::all_checks()
        .iter()
        .flat_map(|c| c.rules().iter().copied())
        .collect()
}

fn rule(r: &Rule) -> Value {
    json!({
        "id": r.id,
        "name": r.id.replace('-', ""),
        "shortDescription": { "text": r.summary },
        "fullDescription": { "text": r.summary },
        "helpUri": format!("{RULE_DOCS}/{}.md", r.id),
        "help": { "text": format!("{} See {RULE_DOCS}/{}.md", r.summary, r.id) },
        "properties": { "tags": ["security", r.check] },
    })
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn result(f: &Finding, rule_index: Option<usize>) -> Value {
    let mut message = f.title.clone();
    if let Some(fp) = &f.fingerprint {
        message.push_str(&format!(" ({fp})"));
    }
    if let Some(d) = &f.detail {
        message.push_str(&format!(": {d}"));
    }
    message.push_str(&format!(". Fix: {}", f.fix));

    let logical = json!([{ "fullyQualifiedName": f.location, "kind": "resource" }]);
    let location = match file_location(f) {
        Some((uri, line)) => {
            let mut physical = json!({ "artifactLocation": { "uri": uri } });
            if let Some(line) = line {
                physical["region"] = json!({ "startLine": line });
            }
            json!({ "physicalLocation": physical, "logicalLocations": logical })
        }
        None => json!({ "logicalLocations": logical }),
    };
    let mut result = json!({
        "ruleId": f.rule,
        "level": level(f.severity),
        "message": { "text": message },
        "locations": [location],
        "properties": {
            "check": f.check,
            "severity": f.severity.as_str(),
            "lifetime": f.lifetime.as_str(),
            "access": f.access.as_str(),
        },
    });
    if let Some(i) = rule_index {
        result["ruleIndex"] = json!(i);
    }
    result
}

/// The repo-relative file (and line) a CI finding's location starts with.
pub(crate) fn file_location(f: &Finding) -> Option<(String, Option<u64>)> {
    if !FILE_CHECKS.contains(&f.check) {
        return None;
    }
    let first = f.location.split_whitespace().next()?;
    // "env:" and friends are labels, not files; "~" and "/" are outside the repo.
    if first.ends_with(':') || first.starts_with('~') || first.starts_with('/') {
        return None;
    }
    match first.rsplit_once(':') {
        Some((path, line)) if !line.is_empty() && line.chars().all(|c| c.is_ascii_digit()) => {
            Some((path.to_string(), line.parse().ok()))
        }
        _ if first.contains(':') => None,
        // Without a line number, only something path-shaped is a file
        // ("GitHub Actions", the CI context with no workflow known, is not).
        _ if first.contains('/') || first.contains('.') => Some((first.to_string(), None)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Access, Lifetime, TEST_RULE};
    use crate::report::Mode;

    const WF_RULE: Rule = Rule {
        check: "workflows",
        id: "HK-WF-001",
        summary: "x",
    };

    fn finding(rule: Rule, location: &str, severity: Severity) -> Finding {
        Finding::new(
            rule,
            "Title",
            location,
            severity,
            Lifetime::ShortLived,
            Access::Write,
            "Fix it.",
        )
    }

    fn render_value(findings: Vec<Finding>) -> Value {
        serde_json::from_str(&render(&Report::new(Mode::Ci, findings)).unwrap()).unwrap()
    }

    #[test]
    fn document_shape() {
        let v = render_value(vec![finding(
            WF_RULE,
            ".github/workflows/a.yml:12 jobs.x.steps[0] (uses: a/b@v1)",
            Severity::High,
        )]);
        assert_eq!(v["version"], "2.1.0");
        let driver = &v["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "heldkeys");
        assert_eq!(
            driver["informationUri"],
            "https://github.com/hugomn/heldkeys"
        );
        let rules = driver["rules"].as_array().unwrap();
        let wf1 = rules.iter().position(|r| r["id"] == "HK-WF-001").unwrap();
        assert_eq!(
            rules[wf1]["helpUri"],
            "https://github.com/hugomn/heldkeys/blob/main/docs/rules/HK-WF-001.md"
        );
        assert!(rules.iter().any(|r| r["id"] == "HK-AWS-001"));

        let r = &v["runs"][0]["results"][0];
        assert_eq!(r["ruleId"], "HK-WF-001");
        assert_eq!(r["ruleIndex"], wf1);
        assert_eq!(r["level"], "error");
        let physical = &r["locations"][0]["physicalLocation"];
        assert_eq!(
            physical["artifactLocation"]["uri"],
            ".github/workflows/a.yml"
        );
        assert_eq!(physical["region"]["startLine"], 12);
    }

    #[test]
    fn levels() {
        assert_eq!(level(Severity::High), "error");
        assert_eq!(level(Severity::Medium), "warning");
        assert_eq!(level(Severity::Low), "note");
        assert_eq!(level(Severity::Info), "note");
    }

    #[test]
    fn locations() {
        let loc = |check_rule: Rule, l: &str| file_location(&finding(check_rule, l, Severity::Low));
        assert_eq!(
            loc(WF_RULE, "src/app.py:3"),
            Some(("src/app.py".to_string(), Some(3)))
        );
        assert_eq!(
            loc(WF_RULE, ".github/workflows/a.yml env: X"),
            Some((".github/workflows/a.yml".to_string(), None))
        );
        assert_eq!(loc(WF_RULE, "env: X"), None);
        assert_eq!(loc(WF_RULE, "~/.aws/credentials"), None);
        assert_eq!(loc(WF_RULE, "GitHub Actions"), None);
        assert_eq!(
            loc(WF_RULE, "Makefile:7"),
            Some(("Makefile".to_string(), Some(7)))
        );
        // Local-mode checks never get a physical location.
        assert_eq!(loc(TEST_RULE, "src/app.py:3"), None);
    }

    #[test]
    fn suppressed_findings_are_results_with_suppressions() {
        let mut report = Report::new(
            Mode::Ci,
            vec![
                finding(WF_RULE, ".github/workflows/a.yml:3 jobs.a", Severity::High),
                finding(WF_RULE, ".github/workflows/b.yml:3 jobs.b", Severity::High),
            ],
        );
        let ignore = crate::config::Ignore {
            rule: "HK-WF-001".to_string(),
            path: Some(".github/workflows/b.yml".to_string()),
            location: None,
            reason: "accepted until the rewrite".to_string(),
            expires: None,
            source: "./.heldkeys.toml".to_string(),
        };
        crate::suppress::apply(
            &mut report,
            &[ignore],
            None,
            crate::config::Date::parse("2026-10-16").unwrap(),
        );
        let v: Value = serde_json::from_str(&render(&report).unwrap()).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].get("suppressions").is_none());
        assert_eq!(
            results[1]["suppressions"],
            json!([{ "kind": "external", "status": "accepted", "justification": "accepted until the rewrite" }])
        );
        assert_eq!(results[1]["ruleId"], "HK-WF-001");
        assert_eq!(results[1]["level"], "error");
    }

    #[test]
    fn non_file_findings_get_a_logical_location() {
        let v = render_value(vec![finding(TEST_RULE, "env: X", Severity::Info)]);
        let loc = &v["runs"][0]["results"][0]["locations"][0];
        assert!(loc.get("physicalLocation").is_none());
        assert_eq!(loc["logicalLocations"][0]["fullyQualifiedName"], "env: X");
    }
}
