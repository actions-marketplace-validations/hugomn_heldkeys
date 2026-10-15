//! `netrc`: passwords in `~/.netrc` (or `$NETRC`).
//!
//! curl, git, pip, Heroku and many other tools read `.netrc` automatically, so
//! a password there is usable by any command the agent runs, with no prompt.

use std::path::Path;

use crate::checks::Check;
use crate::checks::display;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::rules;

pub struct NetrcCheck;

const ID: &str = "netrc";

const KNOWN_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-NETRC-001",
    summary: "Token of a known format in ~/.netrc",
};

const PASSWORD: Rule = Rule {
    check: ID,
    id: "HK-NETRC-002",
    summary: "Plaintext password in ~/.netrc",
};

const RULES: &[Rule] = &[KNOWN_TOKEN, PASSWORD];

const FIX: &str =
    "Remove the entry from .netrc; use a credential helper or a short-lived token for that host.";

impl Check for NetrcCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Plaintext passwords and tokens in ~/.netrc, which curl, git and others use automatically."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let path = ctx.path_from_env("NETRC", ctx.home_path(".netrc"));
        let Some(text) = ctx.read_file(&path) else {
            return Vec::new();
        };
        parse(&text)
            .into_iter()
            .map(|entry| finding_for(ctx, &path, &entry))
            .collect()
    }
}

/// One `machine` (or `default`) entry that has a password.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    machine: String,
    password: String,
}

/// Parses netrc tokens. The format is whitespace-separated keyword/value
/// pairs; `machine` or `default` starts a new entry. `macdef` bodies are
/// skipped up to the next entry, which is good enough for finding passwords.
fn parse(text: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut machine: Option<String> = None;
    let mut password: Option<String> = None;
    let mut tokens = text.split_whitespace();
    while let Some(token) = tokens.next() {
        match token {
            "machine" | "default" => {
                push_entry(&mut entries, machine.take(), password.take());
                machine = if token == "default" {
                    Some("default".to_string())
                } else {
                    tokens.next().map(str::to_string)
                };
            }
            "password" => password = tokens.next().map(str::to_string),
            "login" | "account" | "port" => {
                tokens.next();
            }
            _ => {}
        }
    }
    push_entry(&mut entries, machine, password);
    entries
}

fn push_entry(entries: &mut Vec<Entry>, machine: Option<String>, password: Option<String>) {
    if let (Some(machine), Some(password)) = (machine, password)
        && !password.is_empty()
    {
        entries.push(Entry { machine, password });
    }
}

fn finding_for(ctx: &Context, path: &Path, entry: &Entry) -> Finding {
    let location = format!(
        "{} (machine {})",
        ctx.display_path(path),
        shown_machine(entry)
    );
    if let Some(rule) = rules::match_token(&entry.password) {
        return Finding::new(
            KNOWN_TOKEN,
            rule.title,
            location,
            rule.severity,
            rule.lifetime,
            rule.access,
            FIX,
        )
        .with_fingerprint(crate::redact::fingerprint(&entry.password));
    }
    // A password never expires on its own. On a cloud or SCM host the access
    // is unknown but likely broad, which the spec rates High.
    let severity = if rules::is_cloud_or_scm_host(&entry.machine) {
        Severity::High
    } else {
        Severity::Medium
    };
    Finding::new(
        PASSWORD,
        "Plaintext password in .netrc",
        location,
        severity,
        Lifetime::LongLived,
        Access::Unknown,
        FIX,
    )
}

/// The machine name as shown. A malformed file can shift the tokens so that
/// a password lands where the host name should be, so anything that is not
/// plainly a host name (or is the password itself) is not echoed.
fn shown_machine(entry: &Entry) -> &str {
    let machine = entry.machine.as_str();
    if machine == "default" || (display::is_host(machine) && machine != entry.password) {
        machine
    } else {
        "(not a host name)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::fixture_ctx;

    #[test]
    fn parses_entries() {
        let text = "machine a.com login u password p1\nmachine b.com\n  login u\n  password p2\ndefault login x password p3\nmachine nopass.com login x\n";
        let e = parse(text);
        assert_eq!(e.len(), 3);
        assert_eq!(
            e[0],
            Entry {
                machine: "a.com".into(),
                password: "p1".into()
            }
        );
        assert_eq!(e[2].machine, "default");
    }

    #[test]
    fn odd_machine_names_are_not_echoed() {
        let dir = tempfile::tempdir().unwrap();
        crate::checks::testutil::write(
            dir.path(),
            ".netrc",
            "machine FAKEnetrcHost0016:FAKEpw password hunter2hunter2\nmachine samepass password samepass\n",
        );
        let f = NetrcCheck.run(&crate::checks::testutil::ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 2);
        assert!(
            f.iter()
                .all(|f| f.location == "~/.netrc (machine (not a host name))"),
            "{f:?}"
        );
    }

    #[test]
    fn full_fixture() {
        let f = NetrcCheck.run(&fixture_ctx("full"));
        assert_eq!(f.len(), 2, "{f:?}");
        let gh = f
            .iter()
            .find(|f| f.location.contains("api.github.com"))
            .unwrap();
        assert_eq!(gh.severity, Severity::High);
        assert!(gh.fingerprint.as_deref().unwrap().starts_with("ghp_"));
        let other = f
            .iter()
            .find(|f| f.location.contains("ftp.example.com"))
            .unwrap();
        assert_eq!(other.severity, Severity::Medium);
        assert_eq!(other.fingerprint, None);
    }
}
