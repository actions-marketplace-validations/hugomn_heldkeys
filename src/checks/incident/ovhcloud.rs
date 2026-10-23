//! `ioc-ovhcloud`: the tampered OVHcloud CLI release binaries of 19 October
//! 2026.
//!
//! A hijacked developer account replaced the release assets of v0.11.0 to
//! v0.15.0 with builds that steal AI tool databases, cloud CLI logins,
//! Docker and Kubernetes configs, SSH keys, `.netrc` and more, between
//! 12:47 and 14:21 UTC. Only downloads made in that window are affected;
//! OVHcloud published the MD5 of each malicious binary, and the stealer
//! leaves an `envchecker-<digits>` directory in the temp directory that it
//! never deletes. 0.16.0 and later are clean.
//!
//! Source: OVHcloud's advisory GHSA-862f-55f5-vmvw. The binary is never
//! run (the advisory says not to); it is hashed.

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::checks::incident as inc;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::fsutil;
use crate::hash;

pub struct OvhcloudCheck;

const ID: &str = "ioc-ovhcloud";

pub const MALICIOUS: Rule = Rule {
    check: ID,
    id: "HK-OVH-001",
    summary: "ovhcloud CLI binary matching a published malicious build (MD5)",
};

pub const AFFECTED: Rule = Rule {
    check: ID,
    id: "HK-OVH-002",
    summary: "ovhcloud CLI from the tampered release range, or installed in the tampering window",
};

pub const ENVCHECKER: Rule = Rule {
    check: ID,
    id: "HK-OVH-003",
    summary: "envchecker working directory left by the OVHcloud CLI stealer",
};

const RULES: &[Rule] = &[MALICIOUS, AFFECTED, ENVCHECKER];

/// MD5 of the five malicious binaries (Darwin arm64 and x86_64, Linux
/// arm64 and x86_64, Windows x86_64), from the advisory's appendix.
const BAD_MD5: &[&str] = &[
    "6f2f086239f3d88eb2750e871901927d",
    "347e65eb7f2d78d1c6872690272a6cc3",
    "01f57206d37c28cf711677f612052913",
    "301bff0b51980b9e76c93633e7cfd3bd",
    "6a3cf153338c416169cda2fe704c8848",
];

/// 2026-10-19 12:47 to 14:21 UTC, as Unix time.
const WINDOW_START: u64 = 1_792_414_020;
const WINDOW_END: u64 = 1_792_419_660;
const WINDOW_TEXT: &str = "19 Oct 2026 between 12:47 and 14:21 UTC";

const ROTATE: &str = "Delete the binary, install ovhcloud-cli 0.16.0 or later, and rotate every credential below: the build copies AI tool databases, cloud logins, Docker and kube configs, SSH keys and .netrc.";

impl Check for OvhcloudCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Indicators of the tampered OVHcloud CLI releases: the ovhcloud binary on PATH and in the usual install places hashed against OVHcloud's list, its version and install time, and envchecker directories in the temp directory."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        for path in candidates(ctx) {
            let md5 = hash::md5_file(&path);
            let modified = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            findings.push(binary_finding(
                ctx,
                &path,
                verdict(&path, md5.as_deref(), modified, BAD_MD5),
            ));
        }
        findings.extend(envchecker_dirs(ctx));
        findings
    }
}

/// Every `ovhcloud` binary in the context's `PATH`, the install script's
/// and Homebrew's locations, each once.
fn candidates(ctx: &Context) -> Vec<PathBuf> {
    let mut paths = inc::which(ctx, "ovhcloud");
    paths.extend(inc::which(ctx, "ovhcloud.exe"));
    if let Some(dir) = ctx.var("XDG_BIN_HOME") {
        paths.push(ctx.resolve(dir).join("ovhcloud"));
    }
    for rel in [".local/bin/ovhcloud", "bin/ovhcloud", "go/bin/ovhcloud"] {
        paths.push(ctx.home_path(rel));
    }
    for abs in [
        "/usr/local/bin/ovhcloud",
        "/opt/homebrew/bin/ovhcloud",
        "/usr/bin/ovhcloud",
    ] {
        paths.push(ctx.root_path(abs));
    }
    for cask in [
        &[
            "opt",
            "homebrew",
            "Caskroom",
            "ovhcloud-cli",
            "*",
            "ovhcloud",
        ],
        &["usr", "local", "Caskroom", "ovhcloud-cli", "*", "ovhcloud"],
    ] {
        paths.extend(inc::expand(&ctx.root, cask.as_slice()));
    }
    inc::dedup_paths(paths.into_iter().filter(|p| fsutil::is_file(p)).collect())
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Malicious,
    InWindow(u64),
    AffectedVersion(String),
    Clean,
    Unreadable,
}

fn verdict(path: &Path, md5: Option<&str>, modified: Option<u64>, bad: &[&str]) -> Verdict {
    let Some(md5) = md5 else {
        return Verdict::Unreadable;
    };
    if bad.contains(&md5) {
        return Verdict::Malicious;
    }
    if let Some(t) = modified
        && (WINDOW_START..=WINDOW_END).contains(&t)
    {
        return Verdict::InWindow(t);
    }
    if let Some(version) = affected_version(path) {
        return Verdict::AffectedVersion(version);
    }
    Verdict::Clean
}

/// `0.11.0` to `0.15.x` when a path segment names the version, as a
/// Homebrew Caskroom path does.
fn affected_version(path: &Path) -> Option<String> {
    let re = regex::Regex::new(r"^v?(0\.1[1-5]\.\d+)$").expect("valid regex");
    path.components()
        .filter_map(|c| c.as_os_str().to_str())
        .find_map(|segment| re.captures(segment).map(|c| c[1].to_string()))
}

fn binary_finding(ctx: &Context, path: &Path, verdict: Verdict) -> Finding {
    let location = ctx.display_path(path);
    match verdict {
        Verdict::Malicious => Finding::new(
            MALICIOUS,
            "ovhcloud CLI is a known malicious build",
            location,
            Severity::High,
            Lifetime::Unknown,
            Access::Unknown,
            ROTATE,
        )
        .with_detail("MD5 matches OVHcloud's list of replaced binaries"),
        Verdict::InWindow(t) => Finding::new(
            AFFECTED,
            "ovhcloud CLI installed in the tampering window",
            location,
            Severity::Medium,
            Lifetime::Unknown,
            Access::Unknown,
            "Reinstall ovhcloud-cli 0.16.0 or later; if this one was downloaded in the window, rotate every credential below.",
        )
        .with_detail(format!(
            "modified {}; MD5 is not in OVHcloud's list, which covers the five release assets",
            inc::utc_time(t)
        )),
        Verdict::AffectedVersion(v) => Finding::new(
            AFFECTED,
            format!("ovhcloud CLI {v} from the affected range"),
            location,
            Severity::Low,
            Lifetime::Unknown,
            Access::Unknown,
            "Update to ovhcloud-cli 0.16.0 or later.",
        )
        .with_detail(format!(
            "MD5 is not in OVHcloud's list; clean unless downloaded on {WINDOW_TEXT}"
        )),
        Verdict::Clean => Finding::new(
            AFFECTED,
            "ovhcloud CLI checked, not a known bad build",
            location,
            Severity::Info,
            Lifetime::Unknown,
            Access::Unknown,
            "Nothing to do; update to 0.16.0 or later if older.",
        )
        .with_detail("MD5 is not in OVHcloud's list and the file was not modified in the window"),
        Verdict::Unreadable => Finding::new(
            AFFECTED,
            "ovhcloud CLI could not be hashed",
            location,
            Severity::Low,
            Lifetime::Unknown,
            Access::Unknown,
            "Check the file by hand against OVHcloud's advisory, or reinstall 0.16.0 or later.",
        )
        .with_detail("unreadable or too large to hash"),
    }
}

/// `envchecker-<9 or 10 digits>` directories in the temp directories.
fn envchecker_dirs(ctx: &Context) -> Vec<Finding> {
    let re = regex::Regex::new(r"^envchecker-\d{9,10}$").expect("valid regex");
    let mut findings = Vec::new();
    for dir in inc::temp_dirs(ctx) {
        for entry in fsutil::list_dir(&dir) {
            if re.is_match(&fsutil::file_name(&entry)) && entry.is_dir() {
                findings.push(
                    Finding::new(
                        ENVCHECKER,
                        "OVHcloud stealer working directory",
                        ctx.display_path(&entry),
                        Severity::High,
                        Lifetime::Unknown,
                        Access::Unknown,
                        ROTATE,
                    )
                    .with_detail(
                        "the malicious build copies what it steals here before uploading it",
                    ),
                );
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, write};

    #[test]
    fn verdicts_in_order_of_certainty() {
        let p = Path::new("/opt/homebrew/Caskroom/ovhcloud-cli/0.14.0/ovhcloud");
        assert_eq!(verdict(p, Some("abc"), None, &["abc"]), Verdict::Malicious);
        assert_eq!(
            verdict(p, Some("abc"), Some(WINDOW_START + 60), &["x"]),
            Verdict::InWindow(WINDOW_START + 60)
        );
        assert_eq!(
            verdict(p, Some("abc"), Some(WINDOW_END + 1), &["x"]),
            Verdict::AffectedVersion("0.14.0".to_string())
        );
        assert_eq!(
            verdict(
                Path::new("/usr/local/bin/ovhcloud"),
                Some("abc"),
                Some(1),
                &["x"]
            ),
            Verdict::Clean
        );
        assert_eq!(verdict(p, None, None, &["x"]), Verdict::Unreadable);
        assert_eq!(
            affected_version(Path::new("/x/ovhcloud-cli/0.16.0/ovhcloud")),
            None
        );
        assert_eq!(
            affected_version(Path::new("/x/v0.11.0/ovhcloud")),
            Some("0.11.0".into())
        );
    }

    #[test]
    fn binaries_are_hashed_and_envchecker_dirs_found() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "bin/ovhcloud", "#!/bin/sh\necho fake\n");
        write(
            dir.path(),
            "opt/homebrew/Caskroom/ovhcloud-cli/0.13.0/ovhcloud",
            "fake 0.13\n",
        );
        std::fs::create_dir_all(dir.path().join("tmp/envchecker-123456789")).unwrap();
        std::fs::create_dir_all(dir.path().join("tmp/envchecker-12")).unwrap();
        write(
            dir.path(),
            "tmp/envchecker-1234567890",
            "a file, not a directory",
        );
        let bin = dir.path().join("bin").display().to_string();
        let ctx = ctx_with_env(dir.path(), &[("PATH", bin.as_str())]);
        let findings = OvhcloudCheck.run(&ctx);
        let summary: Vec<(&str, Severity, &str)> = findings
            .iter()
            .map(|f| (f.rule, f.severity, f.location.as_str()))
            .collect();
        assert_eq!(
            summary,
            [
                ("HK-OVH-002", Severity::Info, "~/bin/ovhcloud"),
                (
                    "HK-OVH-002",
                    Severity::Low,
                    "~/opt/homebrew/Caskroom/ovhcloud-cli/0.13.0/ovhcloud"
                ),
                ("HK-OVH-003", Severity::High, "~/tmp/envchecker-123456789"),
            ],
            "{findings:#?}"
        );
        // A binary whose MD5 is on the list is the real thing.
        let md5 = hash::md5(b"#!/bin/sh\necho fake\n");
        assert_eq!(
            verdict(Path::new("x"), Some(&md5), None, &[md5.as_str()]),
            Verdict::Malicious
        );
    }

    #[test]
    fn nothing_installed_means_nothing_reported() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_env(dir.path(), &[]);
        assert!(OvhcloudCheck.run(&ctx).is_empty());
    }
}
