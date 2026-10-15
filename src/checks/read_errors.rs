//! `read-errors`: files the other checks found but could not read or parse.
//!
//! A check that skips a file it cannot read reports nothing about it, so the
//! scan looks cleaner than it is: a 2 MB `.npmrc`, a kubeconfig that is not
//! valid YAML, a `.env` symlinked out of the project or a credentials file
//! the scan has no permission to read all hide whatever they hold. Checks
//! record such files on the `Context` (`Context::read_file`,
//! `Context::note_unreadable`), and `checks::run_all` turns the records into
//! one Info finding per file after every check has run. `--strict` makes
//! these findings (and the other rules in `NOT_ANALYSED_RULES`) fail the
//! run, for gates that must fail closed.

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};

pub struct ReadErrorsCheck;

const ID: &str = "read-errors";

pub const UNREADABLE: Rule = Rule {
    check: ID,
    id: "HK-READ-001",
    summary: "A file a check looks at exists but could not be read or parsed (context)",
};

const RULES: &[Rule] = &[UNREADABLE];

impl Check for ReadErrorsCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Files the other checks found but could not read or parse (Info; --strict fails on them)."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    /// The findings are produced by `findings`, which `run_all` calls after
    /// every other check, in `scan`, `preflight` and `ci` alike.
    fn run(&self, _ctx: &Context) -> Vec<Finding> {
        Vec::new()
    }
}

/// One Info finding per file recorded on `ctx`, and clears the records.
pub fn findings(ctx: &Context) -> Vec<Finding> {
    ctx.take_unreadable()
        .into_iter()
        .map(|(path, reason)| {
            let shown = ctx.display_path(&path);
            Finding::new(
                UNREADABLE,
                "File could not be read",
                shown.clone(),
                Severity::Info,
                Lifetime::Unknown,
                Access::Unknown,
                "Check this file by hand: anything it holds is missing from this report. --strict fails the run on these.",
            )
            .with_detail(format!("could not read {shown}: {reason}"))
        })
        .collect()
}

/// Rules that mean "heldkeys could not analyse this": a file it could not
/// read or parse (`HK-READ-001`) and a workflow it could not read, parse or
/// follow (`HK-WF-007`). Each may hide a credential or a risk, so `--strict`
/// fails the run on any of them (`scan`, `ci` and `preflight` alike). A new
/// "not analysed" rule belongs in this list.
pub const NOT_ANALYSED_RULES: &[&str] = &[UNREADABLE.id, "HK-WF-007"];

/// True for the findings `--strict` fails on: see `NOT_ANALYSED_RULES`.
pub fn is_not_analysed(finding: &Finding) -> bool {
    NOT_ANALYSED_RULES.contains(&finding.rule)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::ctx_with_env;

    #[test]
    fn records_become_info_findings() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_env(dir.path(), &[]);
        ctx.note_unreadable(&dir.path().join(".kube/config"), "not valid YAML");
        let f = findings(&ctx);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[0].location, "~/.kube/config");
        assert_eq!(
            f[0].detail.as_deref(),
            Some("could not read ~/.kube/config: not valid YAML")
        );
        assert!(is_not_analysed(&f[0]));
        assert!(findings(&ctx).is_empty());
    }
}
