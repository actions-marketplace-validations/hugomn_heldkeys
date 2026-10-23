//! `ioc-litellm`: the compromised LiteLLM 1.107.0 release of 21 October
//! 2026.
//!
//! The PyPI wheels and the Docker images tagged `v1.107.0`, `latest`,
//! `main-latest` and `main-stable` carried a credential stealer
//! (`cook.pth`, `cook.py`) and a remote code loader (`sitecustomize.py`)
//! that Python runs on every start, whether or not litellm is imported.
//! The stealer takes cloud CLI logins, SSH keys, browser passwords, AI tool
//! logins, `.netrc`, kubeconfigs and the proxy's own database, and leaves
//! marker files behind; the loader forks a detached daemon that holds a
//! lock file and fetches code every hour.
//!
//! Sources: LiteLLM's incident post, SafeDep's and StepSecurity's analyses
//! (see `incident::Set::advisories`). Hashes and names are copied from them.
//! Python is never run here: that is what would trigger the loader.

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::checks::incident as inc;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::fsutil;
use crate::hash;

pub struct LitellmCheck;

const ID: &str = "ioc-litellm";

pub const INSTALLED: Rule = Rule {
    check: ID,
    id: "HK-LITELLM-001",
    summary: "litellm 1.107.0 installed in a Python environment",
};

pub const STEALER_FILE: Rule = Rule {
    check: ID,
    id: "HK-LITELLM-002",
    summary: "LiteLLM stealer or loader file in a site-packages directory",
};

pub const MARKER: Rule = Rule {
    check: ID,
    id: "HK-LITELLM-003",
    summary: "Marker or lock file of the LiteLLM stealer in the temp directory",
};

pub const ENV_FLAG: Rule = Rule {
    check: ID,
    id: "HK-LITELLM-004",
    summary: "PRIVCOLLECT_ACTIVE set in the environment by the LiteLLM stealer",
};

pub const DAEMON: Rule = Rule {
    check: ID,
    id: "HK-LITELLM-005",
    summary: "Detached Python process of the LiteLLM remote code loader",
};

pub const IMAGE: Rule = Rule {
    check: ID,
    id: "HK-LITELLM-006",
    summary: "LiteLLM Docker image with a compromised digest or the v1.107.0 tag",
};

pub const PINNED: Rule = Rule {
    check: ID,
    id: "HK-LITELLM-007",
    summary: "Project requirements or lockfile pin litellm 1.107.0",
};

const RULES: &[Rule] = &[
    INSTALLED,
    STEALER_FILE,
    MARKER,
    ENV_FLAG,
    DAEMON,
    IMAGE,
    PINNED,
];

/// The metadata directory the malicious wheels install.
const DIST_INFO: &str = "litellm-1.107.0.dist-info";

/// The files the wheels drop next to it, with their published SHA-256
/// (Linux and macOS wheels, then the Windows wheel).
const STEALER_FILES: &[(&str, [&str; 2])] = &[
    (
        "cook.pth",
        [
            "7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb",
            "84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d",
        ],
    ),
    (
        "cook.py",
        [
            "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25",
            "03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea",
        ],
    ),
    (
        "sitecustomize.py",
        [
            "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa",
            "b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465",
        ],
    ),
];

/// Written to `/tmp` by the stealer after a successful upload, and by the
/// loader while its daemon runs.
const FIXED_MARKERS: &[(&str, &str)] = &[
    (
        ".pc_once_72129118c59f5636c0bb",
        "LiteLLM stealer upload marker",
    ),
    ("remote_code_loader.lock", "LiteLLM loader lock file"),
];
const LOCK_FILE: &str = "remote_code_loader.lock";
/// Scratch files the stealer leaves in the system temp directory.
const SCRATCH_PREFIXES: &[&str] = &[".pc_sq_", ".pc_e_"];

/// Image index and manifest digests of the compromised images, and the
/// first twelve characters of the two the advisory only gave truncated.
const BAD_DIGESTS: &[&str] = &[
    "1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e",
    "bd1aeee419ea36da9aa2b657288da4101887be468f020ac63d22ba6ed84a3ea5",
];
const BAD_DIGEST_PREFIXES: &[&str] = &["c00f9d92c427", "7b00e91cd2fe"];

const CLEANUP: &str = "Treat this host as compromised: delete cook.pth, cook.py, sitecustomize.py and their __pycache__ entries from every site-packages, kill the detached Python daemon, reinstall litellm==1.106.2 from scratch, then rotate every credential below.";

/// Site-packages directories to look in, as patterns under the home
/// directory (see `inc::expand`).
const HOME_SITE: &[&[&str]] = &[
    &[".local", "lib", "python3*", "site-packages"],
    &["Library", "Python", "3*", "lib", "python", "site-packages"],
];
/// Virtualenv and conda roots under the home directory.
const HOME_VENVS: &[&[&str]] = &[
    &[".venv"],
    &["venv"],
    &[".virtualenvs", "*"],
    &[".local", "share", "virtualenvs", "*"],
    &[".cache", "pypoetry", "virtualenvs", "*"],
    &[".local", "pipx", "venvs", "*"],
    &[".local", "share", "pipx", "venvs", "*"],
    &[".local", "share", "uv", "tools", "*"],
    &[".pyenv", "versions", "*"],
    &["miniconda3"],
    &["anaconda3"],
    &["miniforge3"],
    &["mambaforge"],
    &["miniconda3", "envs", "*"],
    &["anaconda3", "envs", "*"],
    &["miniforge3", "envs", "*"],
    &["mambaforge", "envs", "*"],
    &[".conda", "envs", "*"],
];
/// System-wide site-packages, under the filesystem root.
const ROOT_SITE: &[&[&str]] = &[
    &["usr", "lib", "python3*", "site-packages"],
    &["usr", "lib", "python3*", "dist-packages"],
    &["usr", "local", "lib", "python3*", "site-packages"],
    &["usr", "local", "lib", "python3*", "dist-packages"],
    &["opt", "homebrew", "lib", "python3*", "site-packages"],
    &[
        "Library",
        "Frameworks",
        "Python.framework",
        "Versions",
        "*",
        "lib",
        "python3*",
        "site-packages",
    ],
    &["opt", "conda", "lib", "python3*", "site-packages"],
    &[
        "opt",
        "conda",
        "envs",
        "*",
        "lib",
        "python3*",
        "site-packages",
    ],
];
/// Virtualenvs containers put at the root: `/app/.venv` is where the
/// LiteLLM images install the package.
const ROOT_VENVS: &[&[&str]] = &[
    &["app", ".venv"],
    &["app", "venv"],
    &["venv"],
    &["opt", "venv"],
    &["usr", "src", "app", ".venv"],
];
const VENV_SITE: &[&str] = &["lib", "python3*", "site-packages"];

impl Check for LitellmCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "Indicators of the compromised LiteLLM 1.107.0 release: the installed package and stealer files in site-packages, marker files in /tmp, PRIVCOLLECT_ACTIVE, the loader's daemon, Docker images by digest, and lockfiles pinning 1.107.0."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        for sp in site_packages(ctx) {
            findings.extend(scan_site_packages(ctx, &sp));
        }
        findings.extend(markers(ctx));
        if ctx.env.contains_key("PRIVCOLLECT_ACTIVE") {
            findings.push(
                Finding::new(
                    ENV_FLAG,
                    "LiteLLM stealer flag in the environment",
                    "env: PRIVCOLLECT_ACTIVE",
                    Severity::High,
                    Lifetime::Unknown,
                    Access::Unknown,
                    CLEANUP,
                )
                .with_detail("the stealer sets it so it runs once per process tree"),
            );
        }
        if findings.iter().any(|f| f.rule == MARKER.id) {
            findings.extend(daemons(ctx));
        }
        findings.extend(images(ctx));
        findings.extend(pins(ctx));
        findings
    }
}

/// Every site-packages directory worth looking in: the known places under
/// the home directory and the root, plus the virtualenvs of the project.
fn site_packages(ctx: &Context) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for pattern in HOME_SITE {
        dirs.extend(inc::expand(&ctx.home, pattern));
    }
    for pattern in ROOT_SITE {
        dirs.extend(inc::expand(&ctx.root, pattern));
    }
    let mut venvs = Vec::new();
    for pattern in HOME_VENVS {
        venvs.extend(inc::expand(&ctx.home, pattern));
    }
    for pattern in ROOT_VENVS {
        venvs.extend(inc::expand(&ctx.root, pattern));
    }
    venvs.extend(inc::project_tree(ctx, &|_| false).venvs);
    for venv in venvs {
        dirs.extend(inc::expand(&venv, VENV_SITE));
    }
    inc::dedup_paths(dirs)
}

fn scan_site_packages(ctx: &Context, sp: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    if sp.join(DIST_INFO).exists() {
        findings.push(
            Finding::new(
                INSTALLED,
                "litellm 1.107.0 installed",
                ctx.display_path(sp),
                Severity::High,
                Lifetime::Unknown,
                Access::Unknown,
                CLEANUP,
            )
            .with_detail(format!("{DIST_INFO} present")),
        );
    }
    let has_cook = fsutil::is_file(&sp.join("cook.pth")) || fsutil::is_file(&sp.join("cook.py"));
    for (name, hashes) in STEALER_FILES {
        let path = sp.join(name);
        if !fsutil::is_file(&path) {
            continue;
        }
        let digest = hash::sha256_file(&path);
        let matched = digest.as_deref().is_some_and(|d| hashes.contains(&d));
        // sitecustomize.py is a normal file in some distributions: only the
        // published hash, or the stealer next to it, makes it a finding.
        if *name == "sitecustomize.py" && !matched && !has_cook {
            continue;
        }
        let detail = if matched {
            "SHA-256 matches the published sample".to_string()
        } else {
            "same name and place as the published sample, different SHA-256".to_string()
        };
        findings.push(
            Finding::new(
                STEALER_FILE,
                "LiteLLM stealer file in site-packages",
                ctx.display_path(&path),
                Severity::High,
                Lifetime::Unknown,
                Access::Unknown,
                CLEANUP,
            )
            .with_detail(detail),
        );
    }
    for entry in fsutil::list_dir(&sp.join("__pycache__")) {
        let name = fsutil::file_name(&entry);
        let stealer = name.starts_with("cook.") || (has_cook && name.starts_with("sitecustomize."));
        if stealer && name.ends_with(".pyc") {
            findings.push(
                Finding::new(
                    STEALER_FILE,
                    "Compiled LiteLLM stealer in __pycache__",
                    ctx.display_path(&entry),
                    Severity::High,
                    Lifetime::Unknown,
                    Access::Unknown,
                    CLEANUP,
                )
                .with_detail("bytecode cache of the stealer; the source may have been deleted"),
            );
        }
    }
    findings
}

/// The fixed names in `/tmp`, and the scratch files in every temp directory.
fn markers(ctx: &Context) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (name, title) in FIXED_MARKERS {
        let path = ctx.root_path("/tmp").join(name);
        if path.exists() {
            findings.push(
                Finding::new(
                    MARKER,
                    *title,
                    ctx.display_path(&path),
                    Severity::High,
                    Lifetime::Unknown,
                    Access::Unknown,
                    CLEANUP,
                )
                .with_detail(if *name == LOCK_FILE {
                    "held by the loader's daemon while it runs"
                } else {
                    "written after the stealer uploaded what it collected"
                }),
            );
        }
    }
    for dir in inc::temp_dirs(ctx) {
        for entry in fsutil::list_dir(&dir) {
            let name = fsutil::file_name(&entry);
            if SCRATCH_PREFIXES.iter().any(|p| name.starts_with(p)) {
                findings.push(
                    Finding::new(
                        MARKER,
                        "LiteLLM stealer scratch file",
                        ctx.display_path(&entry),
                        Severity::High,
                        Lifetime::Unknown,
                        Access::Unknown,
                        CLEANUP,
                    )
                    .with_detail("left in the temp directory while collecting"),
                );
            }
        }
    }
    findings
}

/// The loader's daemon: a Python process whose parent is PID 1 and whose
/// working directory is `/`, or whichever process holds the lock file.
/// Through `/proc` where there is one, else `lsof` on the lock file.
fn daemons(ctx: &Context) -> Vec<Finding> {
    let lock = ctx.root_path("/tmp").join(LOCK_FILE);
    let mut pids = proc_daemons(&ctx.root_path("/proc"), &lock);
    if pids.is_empty()
        && lock.exists()
        && let Some(out) = inc::command_output(ctx, "lsof", &["-t", "--", &lock.to_string_lossy()])
    {
        pids.extend(
            out.lines()
                .filter_map(|l| l.trim().parse::<u32>().ok())
                .map(|pid| (pid, "holds the loader lock file".to_string())),
        );
    }
    pids.sort();
    pids.dedup();
    pids.into_iter()
        .map(|(pid, detail)| {
            Finding::new(
                DAEMON,
                "LiteLLM loader daemon running",
                format!("pid {pid}"),
                Severity::High,
                Lifetime::Unknown,
                Access::Unknown,
                "Kill the process before deleting the stealer files (kill -9 <pid>), then follow the LiteLLM advisory and rotate every credential below.",
            )
            .with_detail(detail)
        })
        .collect()
}

/// Reads `/proc/<pid>/stat`, `cwd` and `fd` for every process. `/proc` is
/// read directly: its files are tiny and not under a repository's control.
fn proc_daemons(proc: &Path, lock: &Path) -> Vec<(u32, String)> {
    let mut found = Vec::new();
    for entry in fsutil::list_dir(proc) {
        let Ok(pid) = fsutil::file_name(&entry).parse::<u32>() else {
            continue;
        };
        let Some(stat) = read_small(&entry.join("stat")) else {
            continue;
        };
        let Some((comm, ppid)) = parse_stat(&stat) else {
            continue;
        };
        let cwd = std::fs::read_link(entry.join("cwd")).ok();
        let holds_lock = fsutil::list_dir(&entry.join("fd"))
            .iter()
            .filter_map(|fd| std::fs::read_link(fd).ok())
            .any(|target| target == lock || target.ends_with(Path::new("tmp").join(LOCK_FILE)));
        let detached =
            comm.starts_with("python") && ppid == 1 && cwd.as_deref() == Some(Path::new("/"));
        if holds_lock || detached {
            let command = read_small(&entry.join("cmdline"))
                .map(|c| {
                    c.replace('\0', " ")
                        .trim()
                        .chars()
                        .take(100)
                        .collect::<String>()
                })
                .filter(|c| !c.is_empty())
                .unwrap_or(comm);
            let why = if holds_lock {
                "holds the loader lock file"
            } else {
                "python with parent PID 1 and working directory /"
            };
            found.push((pid, format!("{why}: {command}")));
        }
    }
    found
}

/// `(comm, ppid)` from a `/proc/<pid>/stat` line: `1234 (python3) S 1 ...`.
fn parse_stat(stat: &str) -> Option<(String, u32)> {
    let start = stat.find('(')? + 1;
    let end = stat.rfind(')')?;
    let comm = stat.get(start..end)?.to_string();
    let mut rest = stat.get(end + 1..)?.split_whitespace();
    let _state = rest.next()?;
    let ppid = rest.next()?.parse().ok()?;
    Some((comm, ppid))
}

fn read_small(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(64 * 1024)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// Local Docker images of LiteLLM, by repository digest.
fn images(ctx: &Context) -> Vec<Finding> {
    let Some(out) = inc::command_output(
        ctx,
        "docker",
        &[
            "image",
            "ls",
            "--digests",
            "--no-trunc",
            "--format",
            "{{json .}}",
        ],
    ) else {
        return Vec::new();
    };
    image_findings(&out)
}

fn image_findings(listing: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for line in listing.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let repo = v["Repository"].as_str().unwrap_or_default();
        let tag = v["Tag"].as_str().unwrap_or_default();
        if !repo.to_ascii_lowercase().contains("litellm") {
            continue;
        }
        let digest = v["Digest"]
            .as_str()
            .and_then(|d| d.strip_prefix("sha256:"))
            .unwrap_or_default();
        let bad = BAD_DIGESTS.contains(&digest)
            || (!digest.is_empty() && BAD_DIGEST_PREFIXES.iter().any(|p| digest.starts_with(p)));
        let location = format!(
            "docker image {}:{}",
            crate::checks::display::label(repo),
            crate::checks::display::label(tag)
        );
        if bad {
            findings.push(
                Finding::new(
                    IMAGE,
                    "LiteLLM image with a compromised digest",
                    location,
                    Severity::High,
                    Lifetime::Unknown,
                    Access::Unknown,
                    "Remove the image, rebuild every container that ran it from litellm v1.106.2 pulled by digest, and rotate the secrets those containers held.",
                )
                .with_detail(format!(
                    "digest sha256:{}… is one published for the compromised images",
                    digest.chars().take(12).collect::<String>()
                )),
            );
        } else if tag == "v1.107.0" {
            findings.push(
                Finding::new(
                    IMAGE,
                    "LiteLLM v1.107.0 image of unknown origin",
                    location,
                    Severity::Medium,
                    Lifetime::Unknown,
                    Access::Unknown,
                    "The v1.107.0 tag was published with the stealer: check where this image came from, and prefer v1.106.2 pulled by digest.",
                )
                .with_detail("its digest is not one of the published compromised ones"),
            );
        }
    }
    findings
}

/// Requirements, constraints and lockfiles that pin the bad release.
fn pins(ctx: &Context) -> Vec<Finding> {
    let tree = inc::project_tree(ctx, &is_pin_file);
    let mut findings = Vec::new();
    for path in tree.files {
        let Some(text) = ctx.read_project_file(&path) else {
            continue;
        };
        let name = fsutil::file_name(&path);
        for (line, detail) in find_pins(&name, &text) {
            findings.push(
                Finding::new(
                    PINNED,
                    "Project pins litellm 1.107.0",
                    format!("{}:{line}", ctx.display_path(&path)),
                    Severity::Medium,
                    Lifetime::Unknown,
                    Access::Unknown,
                    "Pin litellm==1.106.2 or a later clean release and reinstall in a fresh environment: PyPI removed 1.107.0, but a cached wheel would still install it.",
                )
                .with_detail(detail),
            );
        }
    }
    findings
}

fn is_pin_file(name: &str) -> bool {
    matches!(
        name,
        "poetry.lock" | "uv.lock" | "pdm.lock" | "Pipfile.lock" | "Pipfile" | "pyproject.toml"
    ) || ((name.starts_with("requirements") || name.starts_with("constraints"))
        && name.ends_with(".txt"))
}

/// `(line number, what was found)` for every pin of 1.107.0 in `text`.
fn find_pins(name: &str, text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    match name {
        "poetry.lock" | "uv.lock" | "pdm.lock" => {
            for (i, line) in lines.iter().enumerate() {
                if line.trim() == "name = \"litellm\"" {
                    for (j, next) in lines.iter().enumerate().skip(i + 1).take(4) {
                        if next.trim() == "version = \"1.107.0\"" {
                            found.push((j + 1, "locked at 1.107.0".to_string()));
                        }
                    }
                }
            }
        }
        "Pipfile.lock" => {
            for (i, line) in lines.iter().enumerate() {
                if line.contains("\"litellm\"") {
                    for (j, next) in lines.iter().enumerate().skip(i + 1).take(6) {
                        if next.contains("\"version\"") && next.contains("1.107.0") {
                            found.push((j + 1, "locked at 1.107.0".to_string()));
                        }
                    }
                }
            }
        }
        _ => {
            let exact = regex::Regex::new(
                r#"(?i)(?:^|[\s"'\[,])litellm(?:\[[^\]]*\])?\s*(?:===?\s*|=\s*"=?=?)1\.107\.0(?:[\s"';,#\]]|$)"#,
            )
            .expect("valid regex");
            for (i, line) in lines.iter().enumerate() {
                let line = line.trim();
                if line.starts_with('#') {
                    continue;
                }
                if exact.is_match(line) {
                    found.push((i + 1, "exact pin ==1.107.0".to_string()));
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::incident::tests::project_ctx;
    use crate::checks::testutil::{ctx_with_env, write};

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule).collect()
    }

    #[test]
    fn installed_package_and_stealer_files_are_found_in_a_project_venv() {
        let dir = tempfile::tempdir().unwrap();
        let sp = "project/.venv/lib/python3.12/site-packages";
        write(dir.path(), "project/.venv/pyvenv.cfg", "home = /usr/bin\n");
        write(
            dir.path(),
            &format!("{sp}/litellm-1.107.0.dist-info/METADATA"),
            "",
        );
        // The real cook.pth is the line `import cook`: its published hash.
        write(dir.path(), &format!("{sp}/cook.pth"), "import cook\n");
        write(
            dir.path(),
            &format!("{sp}/cook.py"),
            "print('not the real one')\n",
        );
        write(dir.path(), &format!("{sp}/sitecustomize.py"), "pass\n");
        write(
            dir.path(),
            &format!("{sp}/__pycache__/cook.cpython-312.pyc"),
            "",
        );
        let ctx = project_ctx(dir.path(), &[]);
        let findings = LitellmCheck.run(&ctx);
        assert_eq!(
            ids(&findings),
            [
                "HK-LITELLM-001",
                "HK-LITELLM-002",
                "HK-LITELLM-002",
                "HK-LITELLM-002",
                "HK-LITELLM-002"
            ],
            "{findings:#?}"
        );
        let pth = findings
            .iter()
            .find(|f| f.location.ends_with("cook.pth"))
            .unwrap();
        assert_eq!(
            pth.detail.as_deref(),
            Some("SHA-256 matches the published sample")
        );
        let py = findings
            .iter()
            .find(|f| f.location.ends_with("cook.py"))
            .unwrap();
        assert!(py.detail.as_deref().unwrap().contains("different SHA-256"));
        assert!(findings.iter().all(|f| f.severity == Severity::High));
        assert!(
            findings
                .iter()
                .all(|f| f.location.starts_with("~/project/.venv/"))
        );
    }

    #[test]
    fn a_plain_sitecustomize_is_not_a_finding() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            ".local/lib/python3.11/site-packages/sitecustomize.py",
            "import sys\n",
        );
        let ctx = ctx_with_env(dir.path(), &[]);
        assert!(LitellmCheck.run(&ctx).is_empty());
    }

    #[test]
    fn markers_env_and_proc_daemon() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "tmp/remote_code_loader.lock", "");
        write(dir.path(), "tmp/.pc_sq_abc", "");
        write(dir.path(), "tmp/unrelated", "");
        // A fake /proc: pid 42 is the daemon, pid 7 a normal shell.
        write(dir.path(), "proc/42/stat", "42 (python3) S 1 42 42 0 -1\n");
        write(dir.path(), "proc/42/cmdline", "python3\0-c\0import x\0");
        std::fs::create_dir_all(dir.path().join("proc/42/fd")).unwrap();
        std::os::unix::fs::symlink("/", dir.path().join("proc/42/cwd")).unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("tmp/remote_code_loader.lock"),
            dir.path().join("proc/42/fd/3"),
        )
        .unwrap();
        write(dir.path(), "proc/7/stat", "7 (zsh) S 1 7 7 0 -1\n");
        std::os::unix::fs::symlink("/", dir.path().join("proc/7/cwd")).unwrap();
        write(dir.path(), "proc/self/stat", "x");
        let ctx = ctx_with_env(dir.path(), &[("PRIVCOLLECT_ACTIVE", "1")]);
        let findings = LitellmCheck.run(&ctx);
        let mut rules = ids(&findings);
        rules.sort();
        assert_eq!(
            rules,
            [
                "HK-LITELLM-003",
                "HK-LITELLM-003",
                "HK-LITELLM-004",
                "HK-LITELLM-005"
            ],
            "{findings:#?}"
        );
        let daemon = findings
            .iter()
            .find(|f| f.rule == "HK-LITELLM-005")
            .unwrap();
        assert_eq!(daemon.location, "pid 42");
        assert!(
            daemon
                .detail
                .as_deref()
                .unwrap()
                .contains("holds the loader lock file")
        );
    }

    #[test]
    fn daemon_search_only_runs_when_a_marker_exists() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "proc/42/stat", "42 (python3) S 1 42 42 0 -1\n");
        std::os::unix::fs::symlink("/", dir.path().join("proc/42/cwd")).unwrap();
        let ctx = ctx_with_env(dir.path(), &[]);
        assert!(LitellmCheck.run(&ctx).is_empty());
    }

    #[test]
    fn stat_lines_with_odd_process_names_parse() {
        assert_eq!(
            parse_stat("12 (my (odd) name) R 1 0"),
            Some(("my (odd) name".to_string(), 1))
        );
        assert_eq!(parse_stat("garbage"), None);
    }

    #[test]
    fn image_listing_is_matched_by_digest_then_tag() {
        let listing = concat!(
            r#"{"Repository":"ghcr.io/berriai/litellm","Tag":"main-latest","Digest":"sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e"}"#,
            "\n",
            r#"{"Repository":"litellm/litellm","Tag":"v1.107.0","Digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#,
            "\n",
            r#"{"Repository":"ghcr.io/berriai/litellm-database","Tag":"latest","Digest":"sha256:c00f9d92c427aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            "\n",
            r#"{"Repository":"litellm/litellm","Tag":"v1.106.2","Digest":"<none>"}"#,
            "\n",
            r#"{"Repository":"postgres","Tag":"16","Digest":"sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e"}"#,
            "\nnot json\n"
        );
        let findings = image_findings(listing);
        assert_eq!(
            findings
                .iter()
                .map(|f| (f.severity, f.location.as_str()))
                .collect::<Vec<_>>(),
            [
                (
                    Severity::High,
                    "docker image ghcr.io/berriai/litellm:main-latest"
                ),
                (Severity::Medium, "docker image litellm/litellm:v1.107.0"),
                (
                    Severity::High,
                    "docker image ghcr.io/berriai/litellm-database:latest"
                ),
            ]
        );
    }

    #[test]
    fn pins_in_every_file_format() {
        let req = "# litellm==1.107.0 (comment)\nlitellm==1.107.0\nlitellm[proxy] == 1.107.0  # x\nlitellm>=1.107.0\nlitellm==1.107.0rc1\nLITELLM===1.107.0\n";
        assert_eq!(
            find_pins("requirements.txt", req)
                .iter()
                .map(|(l, _)| *l)
                .collect::<Vec<_>>(),
            [2, 3, 6]
        );
        let toml = "[project]\ndependencies = [\n  \"litellm==1.107.0\",\n]\n[tool.poetry.dependencies]\nlitellm = \"1.107.0\"\nother = \"==1.107.0\"\n";
        assert_eq!(
            find_pins("pyproject.toml", toml)
                .iter()
                .map(|(l, _)| *l)
                .collect::<Vec<_>>(),
            [3, 6]
        );
        let lock = "[[package]]\nname = \"litellm\"\nversion = \"1.107.0\"\n\n[[package]]\nname = \"other\"\nversion = \"1.107.0\"\n";
        assert_eq!(
            find_pins("uv.lock", lock),
            [(3, "locked at 1.107.0".to_string())]
        );
        let pipfile = "{\n \"default\": {\n  \"litellm\": {\n   \"hashes\": [],\n   \"version\": \"==1.107.0\"\n  }\n }\n}\n";
        assert_eq!(find_pins("Pipfile.lock", pipfile).len(), 1);
        assert!(find_pins("requirements.txt", "litellm==1.106.2\n").is_empty());
    }

    #[test]
    fn pins_are_reported_with_their_line() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "project/api/requirements.txt",
            "fastapi\nlitellm==1.107.0\n",
        );
        let ctx = project_ctx(dir.path(), &[]);
        let findings = LitellmCheck.run(&ctx);
        assert_eq!(ids(&findings), ["HK-LITELLM-007"]);
        assert_eq!(findings[0].location, "~/project/api/requirements.txt:2");
        assert_eq!(findings[0].severity, Severity::Medium);
    }
}
