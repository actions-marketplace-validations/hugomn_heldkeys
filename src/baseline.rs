//! Baselines: a previous `--format json` report whose findings are accepted,
//! so CI only fails on findings that are new since.
//!
//! A finding is "in the baseline" when the baseline holds one with the same
//! rule, the same normalised location (relative to the scanned directory,
//! without line numbers, see `suppress::normalise_location`) and the same
//! fingerprint, or no fingerprint on either side, **and** the finding is no
//! worse than it was then: severity no higher, access no wider, lifetime no
//! longer. A finding that got worse in place (a pull request lets anyone
//! trigger an agent the baseline accepted as gated) is reported again, with
//! what it was in the baseline. Secret values play no part: the report never
//! holds them. A rotated token gets a new fingerprint, so it shows up as new,
//! which is the point.
//!
//! The file is the ordinary JSON report (`"schema": "heldkeys/v1"`); both its
//! `findings` and its `suppressed` entries count, and each needs `rule`,
//! `location`, `severity`, `access` and `lifetime`. `--write-baseline`
//! writes one with every finding of the current run.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use crate::finding::{Access, Finding, Lifetime, Severity};
use crate::fsutil;
use crate::suppress::normalise_location;

/// Baselines of big scans grow past the 1 MiB that config files get.
const MAX_BASELINE_BYTES: u64 = 64 * 1024 * 1024;

/// What a finding is matched on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub rule: String,
    pub location: String,
    pub fingerprint: Option<String>,
}

impl Key {
    /// The key of a finding at `location`, reported from `origin` (the
    /// scanned directory as shown, such as `~/workspace`).
    pub fn new(rule: &str, location: &str, fingerprint: Option<&str>, origin: Option<&str>) -> Key {
        Key {
            rule: rule.to_string(),
            location: normalise_location(location, origin),
            fingerprint: fingerprint.map(str::to_string),
        }
    }
}

/// How bad a finding was when the baseline was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exposure {
    pub severity: Severity,
    pub access: Access,
    pub lifetime: Lifetime,
}

impl Exposure {
    pub fn of(f: &Finding) -> Exposure {
        Exposure {
            severity: f.severity,
            access: f.access,
            lifetime: f.lifetime,
        }
    }

    /// True when `now` is no worse than `self` on every axis. Unknown sits
    /// between the two known values: unknown access could be write, an
    /// unknown lifetime could be long.
    pub fn covers(self, now: Exposure) -> bool {
        now.severity.rank() <= self.severity.rank()
            && access_rank(now.access) <= access_rank(self.access)
            && lifetime_rank(now.lifetime) <= lifetime_rank(self.lifetime)
    }

    /// What was different in the baseline, for a finding it no longer
    /// covers: "was medium in the baseline", "was medium, had read access in
    /// the baseline".
    pub fn was(self, now: Exposure) -> String {
        let mut parts = Vec::new();
        if now.severity.rank() > self.severity.rank() {
            parts.push(format!("was {}", self.severity.as_str()));
        }
        if access_rank(now.access) > access_rank(self.access) {
            parts.push(format!("had {}", self.access.as_str()));
        }
        if lifetime_rank(now.lifetime) > lifetime_rank(self.lifetime) {
            parts.push(match self.lifetime {
                Lifetime::ShortLived => "was short-lived".to_string(),
                _ => "had an unknown lifetime".to_string(),
            });
        }
        format!("{} in the baseline", parts.join(", "))
    }
}

fn access_rank(a: Access) -> u8 {
    match a {
        Access::Read => 0,
        Access::Unknown => 1,
        Access::Write => 2,
    }
}

fn lifetime_rank(l: Lifetime) -> u8 {
    match l {
        Lifetime::ShortLived => 0,
        Lifetime::Unknown => 1,
        Lifetime::LongLived => 2,
    }
}

/// What the baseline says about a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not in the baseline: a new finding.
    New,
    /// In the baseline, and no worse: leave it out.
    Covered,
    /// In the baseline, but worse now; the text says how it was
    /// ("was medium in the baseline").
    Worse(String),
}

/// A loaded baseline.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    entries: HashMap<Key, Vec<Exposure>>,
    /// The file, as shown to the reader.
    pub source: String,
}

impl Baseline {
    /// Whether `f`, found from `origin`, is new, covered, or got worse.
    pub fn check(&self, f: &Finding, origin: Option<&str>) -> Verdict {
        let key = Key::new(f.rule, &f.location, f.fingerprint.as_deref(), origin);
        let Some(then) = self.entries.get(&key) else {
            return Verdict::New;
        };
        let now = Exposure::of(f);
        if then.iter().any(|e| e.covers(now)) {
            return Verdict::Covered;
        }
        // Compare against the closest entry: the most severe one.
        let closest = then
            .iter()
            .max_by_key(|e| e.severity.rank())
            .expect("entries are never empty");
        Verdict::Worse(closest.was(now))
    }

    /// Distinct keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Reads a baseline file. Unlike a config file it must exist: the user named it.
pub fn load(path: &Path, shown: &str) -> Result<Baseline, String> {
    let text = match fsutil::try_read_text(path, MAX_BASELINE_BYTES) {
        Ok(Some(text)) => text,
        Ok(None) => return Err(format!("baseline {shown} does not exist")),
        Err(reason) => return Err(format!("cannot read baseline {shown}: {reason}")),
    };
    parse(&text, shown)
}

/// Parses the text of a baseline file.
pub fn parse(text: &str, shown: &str) -> Result<Baseline, String> {
    let doc: Value = serde_json::from_str(text)
        .map_err(|e| format!("baseline {shown} is not valid JSON: {e}"))?;
    if doc["schema"] != crate::JSON_SCHEMA {
        return Err(format!(
            "baseline {shown} is not a {} JSON report (write one with --write-baseline or --format json)",
            crate::TOOL_NAME
        ));
    }
    let origin = doc["origin"].as_str();
    let mut entries: HashMap<Key, Vec<Exposure>> = HashMap::new();
    for list in ["findings", "suppressed"] {
        let Some(items) = doc[list].as_array() else {
            if list == "findings" {
                return Err(format!("baseline {shown} has no `findings` list"));
            }
            continue;
        };
        for (i, entry) in items.iter().enumerate() {
            let bad = |what: &str| {
                format!(
                    "baseline {shown}: {list} entry {} has no valid `{what}`; write the baseline again with --write-baseline",
                    i + 1
                )
            };
            let rule = entry["rule"].as_str().ok_or_else(|| bad("rule"))?;
            let location = entry["location"].as_str().ok_or_else(|| bad("location"))?;
            let exposure = Exposure {
                severity: severity(&entry["severity"]).ok_or_else(|| bad("severity"))?,
                access: access(&entry["access"]).ok_or_else(|| bad("access"))?,
                lifetime: lifetime(&entry["lifetime"]).ok_or_else(|| bad("lifetime"))?,
            };
            entries
                .entry(Key::new(
                    rule,
                    location,
                    entry["fingerprint"].as_str(),
                    origin,
                ))
                .or_default()
                .push(exposure);
        }
    }
    Ok(Baseline {
        entries,
        source: shown.to_string(),
    })
}

fn severity(v: &Value) -> Option<Severity> {
    Severity::ALL
        .into_iter()
        .find(|s| v.as_str() == Some(s.as_str()))
}

/// The JSON spelling (`serde`'s), not `Access::as_str`'s.
fn access(v: &Value) -> Option<Access> {
    match v.as_str()? {
        "write" => Some(Access::Write),
        "read" => Some(Access::Read),
        "unknown" => Some(Access::Unknown),
        _ => None,
    }
}

fn lifetime(v: &Value) -> Option<Lifetime> {
    match v.as_str()? {
        "long-lived" => Some(Lifetime::LongLived),
        "short-lived" => Some(Lifetime::ShortLived),
        "unknown" => Some(Lifetime::Unknown),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Rule;

    fn doc(findings: &str) -> String {
        format!(
            "{{\"schema\": \"{}\", \"origin\": \"~/work\", \"findings\": [{findings}]}}",
            crate::JSON_SCHEMA
        )
    }

    const EXPOSURE: &str = r#""severity": "medium", "access": "read", "lifetime": "short-lived""#;

    fn finding(id: &'static str, location: &str, severity: Severity, access: Access) -> Finding {
        let rule = Rule {
            check: "workflows",
            id,
            summary: "x",
        };
        Finding::new(
            rule,
            "t",
            location,
            severity,
            Lifetime::ShortLived,
            access,
            "f",
        )
    }

    #[test]
    fn keys_ignore_line_numbers_and_the_scanned_directory() {
        let b = parse(
            &doc(&format!(
                r#"{{"rule": "HK-WF-005", "location": ".github/workflows/a.yml:12 jobs.x.steps[0]", {EXPOSURE}}},
                   {{"rule": "HK-DOTENV-001", "location": "~/work/app/.env: KEY", "fingerprint": "sk-a…KE1", {EXPOSURE}}}"#
            )),
            "b.json",
        )
        .unwrap();
        assert_eq!(b.len(), 2);
        let wf = finding(
            "HK-WF-005",
            ".github/workflows/a.yml:40 jobs.x.steps[0]",
            Severity::Medium,
            Access::Read,
        );
        assert_eq!(b.check(&wf, None), Verdict::Covered);
        let env = finding(
            "HK-DOTENV-001",
            "~/elsewhere/app/.env: KEY",
            Severity::Low,
            Access::Read,
        )
        .with_fingerprint(Some("sk-a…KE1".to_string()));
        assert_eq!(b.check(&env, Some("~/elsewhere")), Verdict::Covered);
        // A different fingerprint at the same place is a new secret.
        let rotated = env.clone().with_fingerprint(Some("sk-a…KE2".to_string()));
        assert_eq!(b.check(&rotated, Some("~/elsewhere")), Verdict::New);
        let other_rule = finding(
            "HK-WF-001",
            ".github/workflows/a.yml:12 jobs.x.steps[0]",
            Severity::Medium,
            Access::Read,
        );
        assert_eq!(b.check(&other_rule, None), Verdict::New);
    }

    #[test]
    fn a_finding_that_got_worse_is_not_covered() {
        let b = parse(
            &doc(&format!(
                r#"{{"rule": "HK-WF-001", "location": ".github/workflows/a.yml:3 jobs.a", {EXPOSURE}}}"#
            )),
            "b.json",
        )
        .unwrap();
        let at = |severity, access| {
            finding(
                "HK-WF-001",
                ".github/workflows/a.yml:9 jobs.a",
                severity,
                access,
            )
        };
        assert_eq!(
            b.check(&at(Severity::Low, Access::Read), None),
            Verdict::Covered
        );
        assert_eq!(
            b.check(&at(Severity::High, Access::Read), None),
            Verdict::Worse("was medium in the baseline".to_string())
        );
        assert_eq!(
            b.check(&at(Severity::Medium, Access::Unknown), None),
            Verdict::Worse("had read access in the baseline".to_string())
        );
        assert_eq!(
            b.check(&at(Severity::High, Access::Write), None),
            Verdict::Worse("was medium, had read access in the baseline".to_string())
        );
        let mut longer = at(Severity::Medium, Access::Read);
        longer.lifetime = Lifetime::LongLived;
        assert_eq!(
            b.check(&longer, None),
            Verdict::Worse("was short-lived in the baseline".to_string())
        );
    }

    #[test]
    fn exposure_ordering() {
        let e = |severity, access, lifetime| Exposure {
            severity,
            access,
            lifetime,
        };
        let base = e(Severity::Medium, Access::Unknown, Lifetime::Unknown);
        assert!(base.covers(e(Severity::Medium, Access::Read, Lifetime::ShortLived)));
        assert!(!base.covers(e(Severity::Medium, Access::Write, Lifetime::Unknown)));
        assert!(!base.covers(e(Severity::Medium, Access::Unknown, Lifetime::LongLived)));
        assert!(!base.covers(e(Severity::High, Access::Read, Lifetime::ShortLived)));
    }

    #[test]
    fn suppressed_entries_count_too() {
        let text = format!(
            "{{\"schema\": \"{}\", \"findings\": [], \"suppressed\": [{{\"rule\": \"HK-WF-005\", \"location\": \"x.yml\", \"by\": \"config\", \"reason\": \"r\", {EXPOSURE}}}]}}",
            crate::JSON_SCHEMA
        );
        let f = finding("HK-WF-005", "x.yml", Severity::Medium, Access::Read);
        assert_eq!(parse(&text, "b").unwrap().check(&f, None), Verdict::Covered);
    }

    #[test]
    fn bad_files_are_errors() {
        assert!(parse("nope", "b").unwrap_err().contains("not valid JSON"));
        assert!(
            parse("{\"schema\": \"other/v1\", \"findings\": []}", "b")
                .unwrap_err()
                .contains("is not a heldkeys JSON report")
        );
        assert!(
            parse(&doc("{\"rule\": \"HK-WF-005\"}"), "b")
                .unwrap_err()
                .contains("findings entry 1 has no valid `location`")
        );
        let no_severity = doc(
            r#"{"rule": "HK-WF-005", "location": "x", "access": "read", "lifetime": "unknown"}"#,
        );
        assert!(
            parse(&no_severity, "b")
                .unwrap_err()
                .contains("has no valid `severity`; write the baseline again")
        );
        let missing = format!("{{\"schema\": \"{}\"}}", crate::JSON_SCHEMA);
        assert!(parse(&missing, "b").unwrap_err().contains("no `findings`"));
    }
}
