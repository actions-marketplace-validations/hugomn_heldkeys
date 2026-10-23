//! `platform-breaches`: platforms that disclosed, in the same week, that
//! secrets their customers stored with them may have been read. A login or
//! project file for one of them on this machine means there are secrets to
//! rotate on that side too, even though nothing here was compromised.
//!
//! - Railway (21 October 2026): systems storing customer environment
//!   variables were accessed, some decrypted; Railway asks everyone to roll
//!   every variable, API key and private registry credential stored there.
//! - Zeabur (14 to 15 October 2026): the platform database was read, 3.2
//!   million environment variable records and 321,810 accounts; every
//!   credential stored there is to be replaced, all access tokens were
//!   revoked, and the service shuts down on 31 December 2026.
//! - OpenCode Console (around 17 October 2026): a legacy console system was
//!   breached and provider keys linked there may have been exposed, for
//!   1.4% of console users; keys the CLI and desktop app keep locally were
//!   not affected.

use crate::checks::Check;
use crate::checks::incident as inc;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};

pub struct PlatformsCheck;

const ID: &str = "platform-breaches";

pub const RAILWAY: Rule = Rule {
    check: ID,
    id: "HK-BREACH-001",
    summary: "Railway login or project: environment variables stored there may have been read (21 Oct 2026)",
};

pub const ZEABUR: Rule = Rule {
    check: ID,
    id: "HK-BREACH-002",
    summary: "Zeabur login or project: the platform database was read (14 to 15 Oct 2026)",
};

pub const OPENCODE: Rule = Rule {
    check: ID,
    id: "HK-BREACH-003",
    summary: "OpenCode data on disk: provider keys linked in OpenCode Console may be exposed (17 Oct 2026)",
};

const RULES: &[Rule] = &[RAILWAY, ZEABUR, OPENCODE];

impl Check for PlatformsCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Logins and project files of platforms that disclosed a breach of stored secrets: Railway (~/.railway/config.json, railway.json), Zeabur (~/.config/zeabur/cli.yaml, zbpack.json) and OpenCode (auth.json and opencode.db in its data directory)."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        let railway = [
            ctx.home_path(".railway/config.json"),
            ctx.cwd.join("railway.json"),
            ctx.cwd.join("railway.toml"),
        ];
        for path in inc::dedup_paths(railway.to_vec()) {
            if ctx.file_len(&path).is_some() {
                findings.push(
                    Finding::new(
                        RAILWAY,
                        "Secrets stored in Railway need rotation",
                        ctx.display_path(&path),
                        Severity::Medium,
                        Lifetime::Unknown,
                        Access::Unknown,
                        "Roll every environment variable, API key and private registry credential stored in Railway, and review those services' logs for unusual activity (Railway's disclosure of 21 Oct 2026).",
                    )
                    .with_detail("an unauthorised party may have read stored environment variables, some decrypted"),
                );
            }
        }
        let zeabur = [
            ctx.home_path(".config/zeabur/cli.yaml"),
            ctx.config_dir().join("zeabur/cli.yaml"),
            ctx.cwd.join("zbpack.json"),
        ];
        for path in inc::dedup_paths(zeabur.to_vec()) {
            if ctx.file_len(&path).is_some() {
                findings.push(
                    Finding::new(
                        ZEABUR,
                        "Secrets stored on Zeabur need rotation",
                        ctx.display_path(&path),
                        Severity::Medium,
                        Lifetime::Unknown,
                        Access::Unknown,
                        "Revoke and recreate every credential stored in Zeabur variables, sign in again (all access tokens were revoked), and plan the move off Zeabur: it shuts down on 31 Dec 2026.",
                    )
                    .with_detail("the platform database, environment variables included, was read on 14 and 15 Oct 2026"),
                );
            }
        }
        let opencode = [
            ctx.data_dir().join("opencode/auth.json"),
            ctx.data_dir().join("opencode/opencode.db"),
            ctx.home_path(".local/share/opencode/auth.json"),
            ctx.home_path(".local/share/opencode/opencode.db"),
            ctx.config_dir().join("opencode/opencode.db"),
        ];
        for path in inc::dedup_paths(opencode.to_vec()) {
            if ctx.file_len(&path).is_some() {
                findings.push(
                    Finding::new(
                        OPENCODE,
                        "Provider keys linked in OpenCode Console",
                        ctx.display_path(&path),
                        Severity::Low,
                        Lifetime::Unknown,
                        Access::Unknown,
                        "Keys kept locally were not affected; if you linked OpenAI, Anthropic or Google keys in OpenCode Console, revoke and reissue them at the provider and check its usage.",
                    )
                    .with_detail("OpenCode uses this machine; the console breach of 17 Oct 2026 exposed linked provider keys for 1.4% of console users"),
                );
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, write};

    #[test]
    fn each_platform_file_is_one_finding() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".railway/config.json", "{}");
        write(dir.path(), "railway.json", "{}");
        write(dir.path(), ".config/zeabur/cli.yaml", "token: x\n");
        write(dir.path(), ".local/share/opencode/auth.json", "{}");
        write(dir.path(), ".local/share/opencode/opencode.db", "");
        let ctx = ctx_with_env(dir.path(), &[]);
        let findings = PlatformsCheck.run(&ctx);
        let rows: Vec<(&str, &str)> = findings
            .iter()
            .map(|f| (f.rule, f.location.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("HK-BREACH-001", "~/.railway/config.json"),
                ("HK-BREACH-001", "~/railway.json"),
                ("HK-BREACH-002", "~/.config/zeabur/cli.yaml"),
                ("HK-BREACH-003", "~/.local/share/opencode/auth.json"),
                ("HK-BREACH-003", "~/.local/share/opencode/opencode.db"),
            ],
            "{findings:#?}"
        );
        assert!(findings.iter().all(|f| f.title.chars().count() <= 44));
    }

    #[test]
    fn nothing_on_disk_means_nothing_reported() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_env(dir.path(), &[]);
        assert!(PlatformsCheck.run(&ctx).is_empty());
    }
}
