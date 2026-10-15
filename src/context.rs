//! Everything a check is allowed to know about the place it runs in.
//!
//! Checks never call `std::env::var` or look up the real home directory
//! themselves. They read `Context`, which `main` builds once from the process
//! (or tests build from a fixture). That is what makes it safe to test every
//! check against a fake home with a controlled environment.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::path::{Path, PathBuf};

use crate::fsutil;

/// Environment variable that turns off the single network probe
/// (`cloud-metadata`). Integration tests set it.
pub const NO_NET_VAR: &str = "HELDKEYS_NO_NET";

#[derive(Debug, Clone)]
pub struct Context {
    /// The filesystem root for system-wide paths such as `/var/run/docker.sock`
    /// and the Kubernetes service account token. "/" in real runs; tests point
    /// it at a fixture so they never touch the real filesystem.
    pub root: PathBuf,
    /// The home directory to inspect (`--home` or the real one).
    pub home: PathBuf,
    /// The working directory (`--path` or the real one). `dotenv` and the CI
    /// checks look here.
    pub cwd: PathBuf,
    /// The environment as the agent would see it.
    pub env: BTreeMap<String, String>,
    /// `--deep`: allow network calls to a credential's own issuer.
    pub deep: bool,
    /// `ci --repo-secrets`: scan tracked files for tokens.
    pub repo_secrets: bool,
    /// Files a check found but could not read or parse, with the reason,
    /// keyed by path so a file read by two checks is reported once. The
    /// `read-errors` check turns them into Info findings after every other
    /// check has run, so a scan never passes silently over a file it skipped
    /// (`--strict` fails on them). A `RefCell` because checks only get
    /// `&Context`.
    unreadable: RefCell<BTreeMap<PathBuf, String>>,
    /// Every path a check asked to read through this context, found or not.
    /// Lets tests enumerate the files the checks look at.
    paths_read: RefCell<BTreeSet<PathBuf>>,
}

impl Context {
    /// A context with the given root, home, cwd and environment, and every
    /// option off.
    pub fn new(
        root: PathBuf,
        home: PathBuf,
        cwd: PathBuf,
        env: BTreeMap<String, String>,
    ) -> Context {
        Context {
            root,
            home,
            cwd,
            env,
            deep: false,
            repo_secrets: false,
            unreadable: RefCell::new(BTreeMap::new()),
            paths_read: RefCell::new(BTreeSet::new()),
        }
    }

    /// Builds the context from the running process. `root`, `home` and `cwd`
    /// override the real ones when given.
    pub fn from_process(
        root: Option<PathBuf>,
        home: Option<PathBuf>,
        cwd: Option<PathBuf>,
    ) -> Result<Context, String> {
        let root = root.unwrap_or_else(|| PathBuf::from("/"));
        if !root.is_dir() {
            return Err(format!("root {} is not a directory", root.display()));
        }
        // std::env::home_dir is no longer deprecated (Rust 1.86+) and does
        // what we need, so we do not pull in the `dirs` crate for it.
        let home = resolve_home(home, std::env::home_dir())?;
        let cwd = match cwd {
            Some(c) => c,
            None => std::env::current_dir().map_err(|e| format!("cannot read cwd: {e}"))?,
        };
        if !cwd.is_dir() {
            return Err(format!("path {} is not a directory", cwd.display()));
        }
        // Non-UTF-8 variables are kept, lossily, so they can still be matched by name.
        let env = std::env::vars_os()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect();
        Ok(Context::new(root, home, cwd, env))
    }

    /// A non-empty environment variable.
    pub fn var(&self, name: &str) -> Option<&str> {
        self.env
            .get(name)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    /// A system-wide absolute path such as "/var/run/docker.sock", under `root`.
    pub fn root_path(&self, absolute: &str) -> PathBuf {
        self.root.join(absolute.trim_start_matches('/'))
    }

    /// `home/relative`.
    pub fn home_path(&self, relative: &str) -> PathBuf {
        self.home.join(relative)
    }

    /// `$XDG_CONFIG_HOME`, or `~/.config`. Tools such as gh, gcloud and git use
    /// this location on every Unix, including macOS.
    pub fn config_dir(&self) -> PathBuf {
        match self.var("XDG_CONFIG_HOME") {
            Some(dir) => self.resolve(dir),
            None => self.home_path(".config"),
        }
    }

    /// The path in environment variable `var` if set (tools let users move
    /// their config this way), otherwise `default`.
    pub fn path_from_env(&self, var: &str, default: PathBuf) -> PathBuf {
        match self.var(var) {
            Some(p) => self.resolve(p),
            None => default,
        }
    }

    /// Resolves a path from the environment: `~/` means our home, relative
    /// paths are relative to the working directory.
    pub fn resolve(&self, path: &str) -> PathBuf {
        if let Some(rest) = path.strip_prefix("~/") {
            return self.home.join(rest);
        }
        let p = Path::new(path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.cwd.join(p)
        }
    }

    /// How a path is shown in findings: `~/...` under home, `./...` under the
    /// working directory, otherwise as is. Keeps output short and avoids
    /// printing the user's account name.
    pub fn display_path(&self, path: &Path) -> String {
        if let Ok(rest) = path.strip_prefix(&self.home) {
            return format!("~/{}", rest.display());
        }
        if let Ok(rest) = path.strip_prefix(&self.cwd) {
            return format!("./{}", rest.display());
        }
        path.display().to_string()
    }

    /// Reads a home-level or system config file (symlinks followed, except
    /// into /proc and /sys). `None` if it is missing or could not be read;
    /// in the second case the reason is recorded for the `read-errors` check.
    pub fn read_file(&self, path: &Path) -> Option<String> {
        self.read_file_limited(path, fsutil::MAX_FILE_BYTES)
    }

    /// `read_file` with a caller-chosen size limit.
    pub fn read_file_limited(&self, path: &Path, limit: u64) -> Option<String> {
        self.recorded(path, fsutil::try_read_text(path, limit))
    }

    /// Reads a file in the working directory, which a cloned repository
    /// controls: symlinks that lead out of the working directory are refused
    /// (and recorded), so a repo cannot point us at files elsewhere.
    pub fn read_project_file(&self, path: &Path) -> Option<String> {
        let result = fsutil::try_read_text_within(&self.cwd, path, fsutil::MAX_FILE_BYTES);
        self.recorded(path, result)
    }

    /// Reads a file that must stay inside `root` (a git directory, a CI
    /// runner's temp dir): symlinks that lead out of it are refused and
    /// recorded, like any other file that exists but cannot be read.
    pub fn read_file_within(&self, root: &Path, path: &Path) -> Option<String> {
        let result = fsutil::try_read_text_within(root, path, fsutil::MAX_FILE_BYTES);
        self.recorded(path, result)
    }

    /// The first `limit` bytes of a file, for checks that only need a header.
    /// Unlike the other readers it does not record failures: the caller
    /// decides, because a directory listing can hold sockets and other files
    /// that are not worth a report.
    pub fn try_read_head(
        &self,
        path: &Path,
        limit: u64,
    ) -> Result<Option<String>, fsutil::Unreadable> {
        self.paths_read.borrow_mut().insert(path.to_path_buf());
        fsutil::try_read_head(path, limit)
    }

    /// The size of a file whose presence is the finding (an encrypted token
    /// cache, a credentials database): `None` if it is missing. Something
    /// that is there but is not a regular file is recorded for `read-errors`,
    /// since it may stand in for the credential.
    pub fn file_len(&self, path: &Path) -> Option<u64> {
        self.paths_read.borrow_mut().insert(path.to_path_buf());
        match fsutil::try_file_len(path) {
            Ok(len) => len,
            Err(reason) => {
                self.note_unreadable(path, reason);
                None
            }
        }
    }

    /// Every path a check asked to read so far, found or not, sorted.
    pub fn paths_read(&self) -> Vec<PathBuf> {
        self.paths_read.borrow().iter().cloned().collect()
    }

    fn recorded(
        &self,
        path: &Path,
        result: Result<Option<String>, fsutil::Unreadable>,
    ) -> Option<String> {
        self.paths_read.borrow_mut().insert(path.to_path_buf());
        match result {
            Ok(text) => text,
            Err(reason) => {
                self.note_unreadable(path, reason);
                None
            }
        }
    }

    /// Records that `path` exists but could not be used, for example because
    /// it is not valid JSON. Reported as an Info finding by `read-errors`.
    pub fn note_unreadable(&self, path: &Path, reason: impl Display) {
        self.unreadable
            .borrow_mut()
            .entry(path.to_path_buf())
            .or_insert_with(|| reason.to_string());
    }

    /// The files recorded by `note_unreadable` so far, sorted by path, and
    /// forgets them.
    pub fn take_unreadable(&self) -> Vec<(PathBuf, String)> {
        std::mem::take(&mut *self.unreadable.borrow_mut())
            .into_iter()
            .collect()
    }

    /// Whether the `cloud-metadata` TCP probe may run. Never in unit tests,
    /// and never when `HELDKEYS_NO_NET=1`.
    pub fn network_allowed(&self) -> bool {
        !cfg!(test) && self.var(NO_NET_VAR) != Some("1")
    }
}

/// The home directory to scan.
///
/// An explicit `--home` must exist: a typo there should not silently scan
/// nothing. Without one we take the OS's answer even if the directory does
/// not exist, and fall back to "/" when there is no answer at all. Minimal
/// containers and sandboxes often run without `HOME` or a passwd entry
/// (Docker uses "/" then), and `preflight` has to work there; a missing home
/// just means nothing is found under it.
fn resolve_home(explicit: Option<PathBuf>, from_os: Option<PathBuf>) -> Result<PathBuf, String> {
    match explicit {
        Some(h) if h.is_dir() => Ok(h),
        Some(h) => Err(format!("home directory {} does not exist", h.display())),
        None => Ok(from_os
            .filter(|h| !h.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from("/"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        let mut env = BTreeMap::new();
        env.insert("KUBECONFIG".to_string(), "~/k/config".to_string());
        env.insert("EMPTY".to_string(), String::new());
        Context::new(
            PathBuf::from("/r"),
            PathBuf::from("/h"),
            PathBuf::from("/w"),
            env,
        )
    }

    #[test]
    fn display_paths() {
        let c = ctx();
        assert_eq!(
            c.display_path(Path::new("/h/.aws/credentials")),
            "~/.aws/credentials"
        );
        assert_eq!(c.display_path(Path::new("/w/.env")), "./.env");
        assert_eq!(c.display_path(Path::new("/etc/x")), "/etc/x");
    }

    #[test]
    fn env_paths() {
        let c = ctx();
        assert_eq!(
            c.path_from_env("KUBECONFIG", PathBuf::from("/d")),
            PathBuf::from("/h/k/config")
        );
        assert_eq!(
            c.path_from_env("NOPE", PathBuf::from("/d")),
            PathBuf::from("/d")
        );
        assert_eq!(c.var("EMPTY"), None);
        assert_eq!(c.resolve("rel/x"), PathBuf::from("/w/rel/x"));
        assert_eq!(c.root_path("/var/run/x"), PathBuf::from("/r/var/run/x"));
    }

    #[test]
    fn home_without_an_os_answer() {
        assert_eq!(resolve_home(None, None).unwrap(), PathBuf::from("/"));
        assert_eq!(
            resolve_home(None, Some(PathBuf::new())).unwrap(),
            PathBuf::from("/")
        );
        // An implicit home that does not exist is scanned (and is empty).
        assert_eq!(
            resolve_home(None, Some(PathBuf::from("/nonexistent-home"))).unwrap(),
            PathBuf::from("/nonexistent-home")
        );
        // An explicit one must exist.
        assert!(resolve_home(Some(PathBuf::from("/nonexistent-home")), None).is_err());
    }

    #[test]
    fn unreadable_files_are_recorded_once() {
        let dir = tempfile::tempdir().unwrap();
        let c = Context::new(
            dir.path().to_path_buf(),
            dir.path().to_path_buf(),
            dir.path().to_path_buf(),
            BTreeMap::new(),
        );
        assert_eq!(c.read_file(&dir.path().join("missing")), None);
        assert!(c.take_unreadable().is_empty());
        // A directory where a file is expected.
        assert_eq!(c.read_file(dir.path()), None);
        c.note_unreadable(dir.path(), "second reason");
        let problems = c.take_unreadable();
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].1, "not a regular file");
        assert!(c.take_unreadable().is_empty());
    }

    #[test]
    fn no_network_in_unit_tests() {
        assert!(!ctx().network_allowed());
    }
}
