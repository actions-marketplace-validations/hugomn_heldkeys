//! `azure`: Azure CLI token caches and service principal secrets in `~/.azure`.
//!
//! `az login` keeps refresh tokens in an MSAL cache; `az login --service-principal`
//! keeps the principal's secret in `service_principal_entries.json`. Any
//! process running as the user can use either.

use std::path::Path;

use serde_json::Value;

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};

pub struct AzureCheck;

const ID: &str = "azure";

const REFRESH: Rule = Rule {
    check: ID,
    id: "HK-AZ-001",
    summary: "Azure CLI MSAL cache with refresh tokens",
};

const ACCESS: Rule = Rule {
    check: ID,
    id: "HK-AZ-002",
    summary: "Azure CLI MSAL cache with access tokens only",
};

const ENCRYPTED: Rule = Rule {
    check: ID,
    id: "HK-AZ-003",
    summary: "Azure CLI token cache encrypted for the current user",
};

const LEGACY: Rule = Rule {
    check: ID,
    id: "HK-AZ-004",
    summary: "Pre-MSAL Azure CLI token cache with refresh tokens",
};

const SP_SECRET: Rule = Rule {
    check: ID,
    id: "HK-AZ-005",
    summary: "Azure service principal secret stored by az login",
};

const RULES: &[Rule] = &[REFRESH, ACCESS, ENCRYPTED, LEGACY, SP_SECRET];

impl Check for AzureCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Azure CLI: MSAL token caches (refresh tokens) and service principal secrets in ~/.azure."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let dir = ctx.path_from_env("AZURE_CONFIG_DIR", ctx.home_path(".azure"));
        let mut findings = Vec::new();
        findings.extend(token_cache(ctx, &dir.join("msal_token_cache.json")));
        findings.extend(encrypted_cache(ctx, &dir.join("msal_token_cache.bin")));
        findings.extend(legacy_tokens(ctx, &dir.join("accessTokens.json")));
        findings.extend(service_principals(
            ctx,
            &dir.join("service_principal_entries.json"),
        ));
        findings
    }
}

const LOGOUT_FIX: &str = "Run az logout when done, or give the agent its own AZURE_CONFIG_DIR with a narrowly scoped identity.";

/// Plaintext MSAL cache: count refresh tokens (long-lived) and access tokens.
fn token_cache(ctx: &Context, path: &Path) -> Option<Finding> {
    let json = crate::checks::read_json(ctx, path)?;
    let refresh = count_entries(&json, "RefreshToken");
    let access = count_entries(&json, "AccessToken");
    let location = ctx.display_path(path);
    if refresh > 0 {
        Some(
            Finding::new(
                REFRESH,
                "Azure CLI refresh tokens",
                location,
                Severity::High,
                Lifetime::LongLived,
                Access::Unknown,
                LOGOUT_FIX,
            )
            .with_detail(format!(
                "{refresh} refresh token(s), {access} access token(s)"
            )),
        )
    } else if access > 0 {
        Some(
            Finding::new(
                ACCESS,
                "Azure CLI access tokens",
                location,
                Severity::Medium,
                Lifetime::ShortLived,
                Access::Unknown,
                LOGOUT_FIX,
            )
            .with_detail(format!("{access} access token(s)")),
        )
    } else {
        None
    }
}

/// The encrypted cache is encrypted for the user, so a process running as the
/// user (the agent) can still decrypt and use it through the az CLI.
fn encrypted_cache(ctx: &Context, path: &Path) -> Option<Finding> {
    ctx.file_len(path)?;
    Some(
        Finding::new(
            ENCRYPTED,
            "Encrypted Azure CLI token cache",
            ctx.display_path(path),
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            LOGOUT_FIX,
        )
        .with_detail("encrypted at rest, but usable by any process running as this user"),
    )
}

/// Pre-MSAL Azure CLI versions stored ADAL tokens, including refresh tokens.
fn legacy_tokens(ctx: &Context, path: &Path) -> Option<Finding> {
    let json = crate::checks::read_json(ctx, path)?;
    let count = json
        .as_array()
        .map(|a| a.iter().filter(|e| e.get("refreshToken").is_some()).count())
        .unwrap_or(0);
    if count == 0 {
        return None;
    }
    Some(
        Finding::new(
            LEGACY,
            "Azure CLI legacy refresh tokens",
            ctx.display_path(path),
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            LOGOUT_FIX,
        )
        .with_detail(format!("{count} refresh token(s) in the pre-MSAL cache")),
    )
}

/// Secrets of service principals logged in with `az login --service-principal`.
fn service_principals(ctx: &Context, path: &Path) -> Option<Finding> {
    let json = crate::checks::read_json(ctx, path)?;
    let count = json
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|e| e.get("client_secret").is_some() || e.get("certificate").is_some())
                .count()
        })
        .unwrap_or(0);
    if count == 0 {
        return None;
    }
    Some(
        Finding::new(
            SP_SECRET,
            "Azure service principal secret",
            ctx.display_path(path),
            Severity::High,
            Lifetime::LongLived,
            Access::Unknown,
            "Run az logout to remove stored secrets; prefer managed identity or workload identity federation.",
        )
        .with_detail(format!("{count} service principal(s)")),
    )
}

/// Number of entries in a top-level MSAL section such as "RefreshToken".
fn count_entries(json: &Value, section: &str) -> usize {
    json.get(section)
        .and_then(Value::as_object)
        .map(|o| o.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::fixture_ctx;

    #[test]
    fn full_fixture() {
        let f = AzureCheck.run(&fixture_ctx("full"));
        let cache = f
            .iter()
            .find(|f| f.title == "Azure CLI refresh tokens")
            .expect("cache");
        assert_eq!(
            cache.detail.as_deref(),
            Some("1 refresh token(s), 1 access token(s)")
        );
        assert!(
            f.iter()
                .any(|f| f.title == "Azure service principal secret")
        );
        assert!(f.iter().all(|f| f.fingerprint.is_none()));
    }

    #[test]
    fn empty_home() {
        assert!(AzureCheck.run(&fixture_ctx("empty")).is_empty());
    }
}
