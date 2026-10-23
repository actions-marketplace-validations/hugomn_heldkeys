//! The checks behind `heldkeys incident <set>`: indicators of a named wave
//! of supply-chain compromises, run next to the normal credential
//! inventory. One file per kind of indicator; `black_october` lists the set.
//!
//! Like every check these only read. Three of them also run a program:
//! `docker image ls`, `php --version`, `node --version` and `lsof`, each
//! with an empty environment but `PATH`, and a timeout. None of them ever
//! runs `python`: the LiteLLM loader lives in `sitecustomize.py`, which the
//! interpreter imports on start, so running Python to ask it where its
//! site-packages are would run the malware.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::checks::Check;
use crate::context::Context;
use crate::fsutil;

pub mod litellm;
pub mod ovhcloud;
pub mod platforms;
pub mod runtimes;

/// The checks of `heldkeys incident black-october`.
pub fn black_october() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(litellm::LitellmCheck),
        Box::new(ovhcloud::OvhcloudCheck),
        Box::new(runtimes::RuntimesCheck),
        Box::new(platforms::PlatformsCheck),
    ]
}

/// Every incident check of every set, each id once. For listings of rules.
pub fn all() -> Vec<Box<dyn Check>> {
    black_october()
}

/// Where the system and the user's tools put temporary files: `$TMPDIR`,
/// `/tmp` and `/var/tmp`, each once.
pub(crate) fn temp_dirs(ctx: &Context) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = ctx.var("TMPDIR") {
        dirs.push(ctx.resolve(dir));
    }
    dirs.push(ctx.root_path("/tmp"));
    dirs.push(ctx.root_path("/var/tmp"));
    dedup_paths(dirs)
}

/// Keeps the first of every path that names the same place (symlinks
/// resolved when the path exists).
pub(crate) fn dedup_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::BTreeSet::new();
    paths
        .into_iter()
        .filter(|p| seen.insert(std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())))
        .collect()
}

/// Most entries one pattern may expand to, so a home directory with
/// thousands of virtualenvs does not turn the scan into a crawl.
const MAX_EXPANSIONS: usize = 200;

/// Existing paths matching `pattern` under `base`: each segment is a
/// literal name, `*` for any entry, or `name*` for entries starting with
/// `name`. No symlinks are resolved; a later read decides what to do with
/// them.
pub(crate) fn expand(base: &Path, pattern: &[&str]) -> Vec<PathBuf> {
    let mut current = vec![base.to_path_buf()];
    for segment in pattern {
        let mut next = Vec::new();
        for dir in &current {
            if let Some(prefix) = segment.strip_suffix('*') {
                for entry in fsutil::list_dir(dir) {
                    if fsutil::file_name(&entry).starts_with(prefix) {
                        next.push(entry);
                    }
                    if next.len() >= MAX_EXPANSIONS {
                        break;
                    }
                }
            } else {
                let path = dir.join(segment);
                if path.exists() {
                    next.push(path);
                }
            }
            if next.len() >= MAX_EXPANSIONS {
                break;
            }
        }
        current = next;
        if current.is_empty() {
            break;
        }
    }
    current
}

/// `name` in every directory of `PATH`, as the context sees it.
pub(crate) fn which(ctx: &Context, name: &str) -> Vec<PathBuf> {
    let Some(path) = ctx.var("PATH") else {
        return Vec::new();
    };
    let found: Vec<PathBuf> = path
        .split(':')
        .filter(|dir| !dir.is_empty())
        .map(|dir| ctx.resolve(dir).join(name))
        .filter(|p| fsutil::is_file(p))
        .collect();
    dedup_paths(found)
}

/// Directories never walked for project files: dependency trees and build
/// output, which are large and hold nothing a project pins or runs.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "bower_components",
    "target",
    "vendor",
    "__pycache__",
    ".tox",
    ".cache",
    "dist",
    "build",
];
/// How deep under the working directory project files are looked for.
const MAX_DEPTH: usize = 4;
/// Most directory entries looked at in one walk.
const MAX_ENTRIES: usize = 4_000;

/// Files and virtualenvs found under the working directory.
pub(crate) struct ProjectTree {
    /// Files whose name `keep` accepted, sorted.
    pub files: Vec<PathBuf>,
    /// Directories holding a `pyvenv.cfg` (not walked into).
    pub venvs: Vec<PathBuf>,
}

/// A bounded walk of the working directory: `MAX_DEPTH` levels, at most
/// `MAX_ENTRIES` entries, skipping `SKIP_DIRS`. Run from the home directory
/// it only looks at the top level, like the `.env` walk does.
pub(crate) fn project_tree(ctx: &Context, keep: &dyn Fn(&str) -> bool) -> ProjectTree {
    let same = |a: &Path, b: &Path| {
        std::fs::canonicalize(a).ok() == std::fs::canonicalize(b).ok() && a.exists()
    };
    let max_depth = if same(&ctx.cwd, &ctx.home) {
        1
    } else {
        MAX_DEPTH
    };
    let mut tree = ProjectTree {
        files: Vec::new(),
        venvs: Vec::new(),
    };
    let mut budget = MAX_ENTRIES;
    walk(&ctx.cwd, 1, max_depth, &mut budget, keep, &mut tree);
    tree.files.sort();
    tree.venvs.sort();
    tree
}

fn walk(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    budget: &mut usize,
    keep: &dyn Fn(&str) -> bool,
    tree: &mut ProjectTree,
) {
    for entry in fsutil::list_dir(dir) {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let name = fsutil::file_name(&entry);
        // Symlinked directories are not followed: a project cannot point
        // the walk at the rest of the disk.
        let meta = match std::fs::symlink_metadata(&entry) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            if fsutil::is_file(&entry.join("pyvenv.cfg")) {
                tree.venvs.push(entry);
            } else if !SKIP_DIRS.contains(&name.as_str()) && depth < max_depth {
                walk(&entry, depth + 1, max_depth, budget, keep, tree);
            }
        } else if keep(&name) {
            tree.files.push(entry);
        }
    }
}

/// How long a program may run before it is killed.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
/// Most output kept from a program.
const MAX_OUTPUT: u64 = 1024 * 1024;

/// Runs `program` from the context's `PATH` with `args` and an otherwise
/// empty environment (plus `HOME` and the Docker client variables), and
/// returns its stdout. `None` when there is no `PATH`, the program is not
/// there, fails, or takes longer than `COMMAND_TIMEOUT`.
pub(crate) fn command_output(ctx: &Context, program: &str, args: &[&str]) -> Option<String> {
    debug_assert!(
        !program.starts_with("python"),
        "never run Python here: its startup imports sitecustomize.py"
    );
    let path = ctx.var("PATH")?;
    if which(ctx, program).is_empty() {
        return None;
    }
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", path)
        .env("HOME", &ctx.home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for var in [
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
    ] {
        if let Some(value) = ctx.var(var) {
            command.env(var, value);
        }
    }
    let mut child = command.spawn().ok()?;
    let stdout = child.stdout.take()?;
    // Read on a thread, so a program that prints more than the pipe holds
    // still finishes, and the timeout below is the only wait.
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        let _ = stdout.take(MAX_OUTPUT).read_to_string(&mut out);
        out
    });
    let started = Instant::now();
    let finished = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if started.elapsed() < COMMAND_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    let out = reader.join().ok()?;
    finished.then_some(out)
}

/// The first `X.Y.Z` in `text`, such as `8.4.26` in "PHP 8.4.26 (cli)" or
/// `22.23.3` in "v22.23.3".
pub(crate) fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let re = regex::Regex::new(r"(\d+)\.(\d+)\.(\d+)").expect("valid regex");
    let caps = re.captures(text)?;
    Some((
        caps[1].parse().ok()?,
        caps[2].parse().ok()?,
        caps[3].parse().ok()?,
    ))
}

/// A Unix time as `2026-10-19 13:02 UTC`.
pub(crate) fn utc_time(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hour, minute) = (rem / 3600, (rem % 3600) / 60);
    // Civil-from-days (Howard Hinnant), valid for every date after 1970.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hour:02}:{minute:02} UTC")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, write};

    #[test]
    fn patterns_expand_to_existing_entries_only() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".venv/lib/python3.12/site-packages/x", "");
        write(dir.path(), ".venv/lib/python3.9/site-packages/x", "");
        write(dir.path(), ".venv/lib/pythonX/site-packages/x", "");
        let found = expand(dir.path(), &[".venv", "lib", "python3*", "site-packages"]);
        let names: Vec<String> = found
            .iter()
            .map(|p| {
                p.parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into()
            })
            .collect();
        assert_eq!(names, ["python3.12", "python3.9"]);
        assert!(expand(dir.path(), &["nope", "*"]).is_empty());
    }

    /// A context whose working directory is `<dir>/project`, so the walk
    /// goes deeper than the single level it allows for a home directory.
    pub(crate) fn project_ctx(dir: &Path, env: &[(&str, &str)]) -> Context {
        let mut ctx = ctx_with_env(dir, env);
        ctx.cwd = dir.join("project");
        std::fs::create_dir_all(&ctx.cwd).unwrap();
        ctx
    }

    #[test]
    fn project_tree_skips_dependency_dirs_and_notes_venvs() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "project/requirements.txt", "");
        write(dir.path(), "project/api/requirements-dev.txt", "");
        write(dir.path(), "project/node_modules/pkg/requirements.txt", "");
        write(dir.path(), "project/.venv/pyvenv.cfg", "");
        write(dir.path(), "project/.venv/lib/requirements.txt", "");
        write(dir.path(), "project/a/b/c/d/e/requirements.txt", "");
        let ctx = project_ctx(dir.path(), &[]);
        let tree = project_tree(&ctx, &|name| name.starts_with("requirements"));
        let rel = |p: &PathBuf| p.strip_prefix(&ctx.cwd).unwrap().display().to_string();
        assert_eq!(
            tree.files.iter().map(rel).collect::<Vec<_>>(),
            ["api/requirements-dev.txt", "requirements.txt"]
        );
        assert_eq!(tree.venvs.iter().map(rel).collect::<Vec<_>>(), [".venv"]);
        // From the home directory only the top level is looked at.
        write(dir.path(), "deep/requirements.txt", "");
        write(dir.path(), "requirements.txt", "");
        let home = ctx_with_env(dir.path(), &[]);
        let tree = project_tree(&home, &|name| name.starts_with("requirements"));
        assert_eq!(tree.files.len(), 1, "{:?}", tree.files);
    }

    #[test]
    fn versions_and_times() {
        assert_eq!(
            parse_version("PHP 8.4.26 (cli) (built: ...)"),
            Some((8, 4, 26))
        );
        assert_eq!(parse_version("v22.23.3\n"), Some((22, 23, 3)));
        assert_eq!(parse_version("22-slim"), None);
        assert_eq!(utc_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_time(1_792_414_020), "2026-10-19 12:47 UTC");
        assert_eq!(utc_time(1_792_419_660), "2026-10-19 14:21 UTC");
    }

    #[test]
    fn commands_need_a_path_and_never_python() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_env(dir.path(), &[]);
        assert_eq!(command_output(&ctx, "docker", &["--version"]), None);
        assert!(which(&ctx, "docker").is_empty());
    }

    #[test]
    fn temp_dirs_are_listed_once() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("tmp")).unwrap();
        let tmp = dir.path().join("tmp").display().to_string();
        let ctx = ctx_with_env(dir.path(), &[("TMPDIR", tmp.as_str())]);
        let dirs = temp_dirs(&ctx);
        assert_eq!(dirs.len(), 2, "{dirs:?}");
    }
}
