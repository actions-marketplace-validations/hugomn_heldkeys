//! `cargo-credentials`: registry tokens in `~/.cargo/credentials.toml`.
//!
//! `cargo login` stores the crates.io token here in plaintext (unless a
//! credential provider is configured). It can publish new crate versions.

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::ini;
use crate::redact;

pub struct CargoCredentialsCheck;

const ID: &str = "cargo-credentials";

const REGISTRY_TOKEN: Rule = Rule {
    check: ID,
    id: "HK-CARGO-001",
    summary: "Cargo registry token in credentials.toml",
};

const RULES: &[Rule] = &[REGISTRY_TOKEN];

impl Check for CargoCredentialsCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "crates.io and other Cargo registry tokens in ~/.cargo/credentials.toml."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let cargo_home = ctx.path_from_env("CARGO_HOME", ctx.home_path(".cargo"));
        // `credentials` without extension is the pre-1.39 name, still read by cargo.
        ["credentials.toml", "credentials"]
            .iter()
            .map(|name| cargo_home.join(name))
            .flat_map(|path| {
                let text = ctx.read_file(&path).unwrap_or_default();
                // credentials.toml is simple TOML: [registry] or
                // [registries.<name>] sections with a `token = "..."` key,
                // which the INI reader handles.
                ini::parse(&text)
                    .into_iter()
                    .filter_map(|section| {
                        let token = section.get("token")?;
                        Some(
                            Finding::new(
                                REGISTRY_TOKEN,
                                "Cargo registry token",
                                format!(
                                    "{} [{}]",
                                    ctx.display_path(&path),
                                    crate::checks::display::label(&section.name)
                                ),
                                Severity::High,
                                Lifetime::LongLived,
                                Access::Write,
                                "Run cargo logout, or configure a credential provider (cargo:macos-keychain, cargo:libsecret) and a scoped token.",
                            )
                            .with_fingerprint(redact::fingerprint(token)),
                        )
                    })
                    .collect::<Vec<_>>()
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
        let f = CargoCredentialsCheck.run(&fixture_ctx("full"));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].location, "~/.cargo/credentials.toml [registry]");
        assert!(f[0].fingerprint.as_deref().unwrap().starts_with("cio"));
    }

    #[test]
    fn empty_home() {
        assert!(CargoCredentialsCheck.run(&fixture_ctx("empty")).is_empty());
    }
}
