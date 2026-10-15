//! JSON output: a stable, versioned schema (`"schema": "heldkeys/v1"`).
//!
//! Fields are only ever added within a schema version. Renaming or removing a
//! field means a new version.

use serde::Serialize;

use crate::finding::Finding;
use crate::report::{Report, Summary};

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
    summary: Summary,
    findings: &'a [Finding],
}

pub fn render(report: &Report) -> String {
    let doc = Document {
        schema: crate::JSON_SCHEMA,
        tool: Tool {
            name: crate::TOOL_NAME,
            version: crate::TOOL_VERSION,
        },
        mode: report.mode.as_str(),
        summary: report.summary(),
        findings: &report.findings,
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
