//! `pypirc`: upload credentials in `~/.pypirc`.
//!
//! twine reads this file automatically, so a token here lets the agent upload
//! new releases of the account's packages.

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::ini;
use crate::redact;
use crate::rules;

pub struct PypircCheck;

const ID: &str = "pypirc";

const INDEX_PASSWORD: Rule = Rule {
    check: ID,
    id: "HK-PYPI-001",
    summary: "Package index password or token in ~/.pypirc",
};

const RULES: &[Rule] = &[INDEX_PASSWORD];

impl Check for PypircCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "PyPI and other package index passwords or upload tokens in ~/.pypirc."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let path = ctx.home_path(".pypirc");
        let Some(text) = ctx.read_file(&path) else {
            return Vec::new();
        };
        ini::parse(&text)
            .iter()
            .filter_map(|section| {
                let password = section.get("password")?;
                let title = rules::match_token(password)
                    .map(|r| r.title)
                    .unwrap_or("Package index password");
                Some(
                    Finding::new(
                        INDEX_PASSWORD,
                        title,
                        format!(
                            "{} [{}]",
                            ctx.display_path(&path),
                            crate::checks::display::label(&section.name)
                        ),
                        Severity::High,
                        Lifetime::LongLived,
                        Access::Write,
                        "Use a project-scoped API token, or trusted publishing from CI, instead of an account-wide one.",
                    )
                    .with_fingerprint(redact::fingerprint(password)),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::fixture_ctx;

    #[test]
    fn full_fixture() {
        let f = PypircCheck.run(&fixture_ctx("full"));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].title, "PyPI upload token");
        assert_eq!(f[0].location, "~/.pypirc [pypi]");
    }

    #[test]
    fn empty_home() {
        assert!(PypircCheck.run(&fixture_ctx("empty")).is_empty());
    }
}
