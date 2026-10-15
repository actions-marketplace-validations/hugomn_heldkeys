//! `docker`: registry logins in `~/.docker/config.json` (or `$DOCKER_CONFIG`).
//!
//! `docker login` without a credential helper stores `user:password` base64
//! encoded, which is plaintext for practical purposes. With a helper, the
//! secret lives in the OS keychain, but any process running as the user can
//! still ask the helper for it (`docker-credential-<helper> get`).

use std::path::Path;

use serde_json::Value;

use crate::checks::Check;
use crate::checks::display;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};

pub struct DockerCheck;

const ID: &str = "docker";

const INLINE: Rule = Rule {
    check: ID,
    id: "HK-DOCKER-001",
    summary: "Registry login stored inline in ~/.docker/config.json",
};

const HELPER: Rule = Rule {
    check: ID,
    id: "HK-DOCKER-002",
    summary: "Registry logins retrievable through a Docker credential helper",
};

const RULES: &[Rule] = &[INLINE, HELPER];

impl Check for DockerCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Docker registry logins in ~/.docker/config.json: inline auths and credential helpers."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let dir = ctx.path_from_env("DOCKER_CONFIG", ctx.home_path(".docker"));
        let path = dir.join("config.json");
        let Some(json) = crate::checks::read_json(ctx, &path) else {
            return Vec::new();
        };
        let mut findings = inline_auths(ctx, &path, &json);
        findings.extend(helpers(ctx, &path, &json));
        findings
    }
}

/// Registries with `auth` or `identitytoken` stored right in the file.
fn inline_auths(ctx: &Context, path: &Path, json: &Value) -> Vec<Finding> {
    let Some(auths) = json.get("auths").and_then(Value::as_object) else {
        return Vec::new();
    };
    auths
        .iter()
        .filter(|(_, entry)| has_secret(entry))
        .map(|(registry, _)| {
            Finding::new(
                INLINE,
                "Docker registry credentials (plaintext)",
                format!("{} ({})", ctx.display_path(path), display::label(registry)),
                Severity::High,
                Lifetime::LongLived,
                // A registry login can push images.
                Access::Write,
                "Use a credential helper (credsStore), or a read-only, short-lived registry token for the agent.",
            )
        })
        .collect()
}

fn has_secret(entry: &Value) -> bool {
    ["auth", "identitytoken", "password", "registrytoken"]
        .iter()
        .any(|k| {
            entry
                .get(*k)
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
        })
}

/// `credsStore` and `credHelpers`: secrets kept outside the file but
/// retrievable on demand.
fn helpers(ctx: &Context, path: &Path, json: &Value) -> Vec<Finding> {
    let mut names: Vec<String> = Vec::new();
    if let Some(store) = json.get("credsStore").and_then(Value::as_str) {
        names.push(store.to_string());
    }
    if let Some(map) = json.get("credHelpers").and_then(Value::as_object) {
        for helper in map.values().filter_map(Value::as_str) {
            if !names.iter().any(|n| n == helper) {
                names.push(helper.to_string());
            }
        }
    }
    names
        .into_iter()
        .map(|helper| {
            // A helper name is a program suffix; anything odder is not echoed.
            let (shown, program) = match display::program_name(&helper) {
                Some(name) => (
                    format!("helper {name}"),
                    format!("docker-credential-{name}"),
                ),
                None => ("unrecognised helper".to_string(), "the helper".to_string()),
            };
            Finding::new(
                HELPER,
                "Docker credential helper",
                format!("{} ({shown})", ctx.display_path(path)),
                Severity::Medium,
                Lifetime::Unknown,
                Access::Unknown,
                "Log out of registries the agent does not need (docker logout <registry>).",
            )
            .with_detail(format!(
                "{program} returns stored logins to any process running as this user"
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::fixture_ctx;

    #[test]
    fn full_fixture() {
        let f = DockerCheck.run(&fixture_ctx("full"));
        let inline: Vec<_> = f.iter().filter(|f| f.severity == Severity::High).collect();
        assert_eq!(inline.len(), 1, "{f:?}");
        assert_eq!(
            inline[0].location,
            "~/.docker/config.json (https://index.docker.io/v1/)"
        );
        assert!(f.iter().any(|f| f.title == "Docker credential helper"));
    }

    #[test]
    fn empty_home() {
        assert!(DockerCheck.run(&fixture_ctx("empty")).is_empty());
    }
}
