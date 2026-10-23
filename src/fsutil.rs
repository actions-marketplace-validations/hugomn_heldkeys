//! Small, read-only file helpers shared by the checks.
//!
//! Every file read in heldkeys goes through `open_regular`, so there is one
//! place that enforces "regular files only, and not huge ones":
//!
//! - The file is opened first and the open handle is checked (`fstat`), not
//!   the path, so a path swapped between the check and the read cannot slip a
//!   FIFO or a device past us. On Unix it is opened with `O_NONBLOCK`, so
//!   opening a FIFO returns at once instead of waiting for a writer; the
//!   flag changes nothing for regular files.
//! - At most `limit + 1` bytes are ever read, so a file that lies about its
//!   size (`/proc` files report 0) cannot make us read without end.
//! - Files under `/proc` and `/sys` are refused: they are not config files,
//!   and a symlink to `/proc/self/environ` would report our own environment
//!   as if it were a file.
//!
//! Paths inside a repository or project directory are read with
//! `try_read_text_within`, which also refuses symlinks that lead out of that
//! directory: a cloned repo must not be able to make us read (and report on)
//! files elsewhere on the machine. Home-level configs may be symlinks
//! anywhere, because dotfile managers put them in other directories.

use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Credential and config files are small. Anything bigger than this is not
/// what we are looking for, and reading it would slow the scan down.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Why a file that exists could not be read. Shown to the user as
/// "could not read <path>: <reason>".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreadable {
    /// A directory, FIFO, socket or device where a file was expected.
    NotAFile,
    /// Larger than the size limit for this kind of file.
    TooLarge { limit: u64 },
    /// A symlink that resolves outside the directory being scanned.
    OutsideTree,
    /// Under `/proc` or `/sys`.
    SystemFile,
    /// The operating system refused (permissions, I/O error).
    Io(String),
}

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unreadable::NotAFile => write!(f, "not a regular file"),
            Unreadable::TooLarge { limit } => write!(f, "larger than {}", human_size(*limit)),
            Unreadable::OutsideTree => write!(f, "symlink leads outside the directory scanned"),
            Unreadable::SystemFile => write!(f, "resolves into /proc or /sys"),
            Unreadable::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Reads a regular file as text (invalid UTF-8 replaced), or `None` if it is
/// missing, not a regular file, unreadable, or larger than `MAX_FILE_BYTES`.
pub fn read_text(path: &Path) -> Option<String> {
    try_read_text(path, MAX_FILE_BYTES).ok().flatten()
}

/// Like `read_text`, with a caller-chosen size limit. For the few config
/// files that legitimately grow past `MAX_FILE_BYTES`, such as Claude Code's
/// `~/.claude.json`, which also keeps per-project history.
pub fn read_text_limited(path: &Path, limit: u64) -> Option<String> {
    try_read_text(path, limit).ok().flatten()
}

/// Reads a file the way `read_text_limited` does, but says why it failed:
/// `Ok(None)` if the file does not exist (nothing to report), `Err` if it
/// exists and could not be read. Symlinks are followed, except into `/proc`
/// and `/sys`. For home-level and system configs.
pub fn try_read_text(path: &Path, limit: u64) -> Result<Option<String>, Unreadable> {
    let Some(target) = resolve(path)? else {
        return Ok(None);
    };
    read_resolved(&target, limit).map(Some)
}

/// Reads `path`, which must be inside `root`, refusing symlinks (anywhere in
/// the path) that resolve outside `root`. For files in a repository or
/// project directory, which whoever wrote the repo controls. `Ok(None)` if
/// the file does not exist.
pub fn try_read_text_within(
    root: &Path,
    path: &Path,
    limit: u64,
) -> Result<Option<String>, Unreadable> {
    let Some(target) = resolve(path)? else {
        return Ok(None);
    };
    if !is_within(root, &target) {
        return Err(Unreadable::OutsideTree);
    }
    read_resolved(&target, limit).map(Some)
}

/// `try_read_text_within` with the default size limit, `None` on any failure.
pub fn read_text_within(root: &Path, path: &Path) -> Option<String> {
    try_read_text_within(root, path, MAX_FILE_BYTES)
        .ok()
        .flatten()
}

/// True if `path` (after resolving symlinks) is inside `root` (also
/// resolved). False if either does not exist.
pub fn is_within(root: &Path, path: &Path) -> bool {
    match (fs::canonicalize(root), fs::canonicalize(path)) {
        (Ok(root), Ok(path)) => path.starts_with(root),
        _ => false,
    }
}

/// Reads at most `limit` bytes from the start of a regular file. Used where
/// only a header matters (SSH private keys), so we never load more than needed.
pub fn read_head(path: &Path, limit: u64) -> Option<String> {
    try_read_head(path, limit).ok().flatten()
}

/// `read_head`, saying why it failed: `Ok(None)` if the file does not exist,
/// `Err` if it exists and could not be read.
pub fn try_read_head(path: &Path, limit: u64) -> Result<Option<String>, Unreadable> {
    let Some(target) = resolve(path)? else {
        return Ok(None);
    };
    let file = open_regular(&target)?;
    let mut buf = Vec::new();
    file.take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| Unreadable::Io(e.kind().to_string()))?;
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// The size of a regular file, without opening it: `Ok(None)` if nothing is
/// there, `Err(NotAFile)` for a directory, FIFO, socket or device. For checks
/// that only need to know a file is present (a permission-less file still
/// counts as present).
pub fn try_file_len(path: &Path) -> Result<Option<u64>, Unreadable> {
    let Some(target) = resolve(path)? else {
        return Ok(None);
    };
    let meta = fs::metadata(&target).map_err(|e| Unreadable::Io(e.kind().to_string()))?;
    if meta.is_file() {
        Ok(Some(meta.len()))
    } else {
        Err(Unreadable::NotAFile)
    }
}

/// The real path behind `path`, or `None` if nothing is there. Refuses
/// `/proc` and `/sys`.
fn resolve(path: &Path) -> Result<Option<PathBuf>, Unreadable> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Unreadable::Io(e.kind().to_string())),
        Ok(_) => {}
    }
    let target = match fs::canonicalize(path) {
        Ok(t) => t,
        // A dangling symlink: nothing to read.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Unreadable::Io(e.kind().to_string())),
    };
    if is_system_path(&target) {
        return Err(Unreadable::SystemFile);
    }
    Ok(Some(target))
}

fn is_system_path(path: &Path) -> bool {
    path.starts_with("/proc") || path.starts_with("/sys")
}

/// Opens `path` and checks, on the open handle, that it is a regular file.
pub(crate) fn open_regular(path: &Path) -> Result<fs::File, Unreadable> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A FIFO would otherwise block the open until someone writes to it.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| Unreadable::Io(e.kind().to_string()))?;
    let meta = file
        .metadata()
        .map_err(|e| Unreadable::Io(e.kind().to_string()))?;
    if !meta.is_file() {
        return Err(Unreadable::NotAFile);
    }
    Ok(file)
}

fn read_resolved(path: &Path, limit: u64) -> Result<String, Unreadable> {
    let file = open_regular(path)?;
    // The size on disk is a cheap first check; the bounded read below is the
    // one that counts, because some files report a size of 0.
    if file.metadata().map(|m| m.len()).unwrap_or(0) > limit {
        return Err(Unreadable::TooLarge { limit });
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| Unreadable::Io(e.kind().to_string()))?;
    if bytes.len() as u64 > limit {
        return Err(Unreadable::TooLarge { limit });
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn human_size(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else {
        format!("{bytes} bytes")
    }
}

/// True if `path` is a regular file (following symlinks).
pub fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

/// Entries of a directory, sorted by name for stable output. Empty if the
/// directory does not exist or cannot be read.
pub fn list_dir(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
        Err(_) => Vec::new(),
    };
    entries.sort();
    entries
}

/// Name of the last path component, or "" if there is none.
pub fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope");
        assert_eq!(try_read_text(&path, 10), Ok(None));
        assert_eq!(try_read_text_within(dir.path(), &path, 10), Ok(None));
    }

    #[test]
    fn size_limit_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        fs::write(&path, "0123456789").unwrap();
        assert_eq!(
            try_read_text(&path, 10).unwrap().as_deref(),
            Some("0123456789")
        );
        assert_eq!(
            try_read_text(&path, 9),
            Err(Unreadable::TooLarge { limit: 9 })
        );
        assert_eq!(read_head(&path, 4).as_deref(), Some("0123"));
    }

    #[test]
    fn directories_are_not_files() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(try_read_text(dir.path(), 10), Err(Unreadable::NotAFile));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_leaving_the_tree_are_refused() {
        let outside = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "x").unwrap();
        fs::write(root.path().join("inside"), "y").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("out")).unwrap();
        std::os::unix::fs::symlink(root.path().join("inside"), root.path().join("in")).unwrap();
        assert_eq!(
            try_read_text_within(root.path(), &root.path().join("out"), 10),
            Err(Unreadable::OutsideTree)
        );
        assert_eq!(
            read_text_within(root.path(), &root.path().join("in")).as_deref(),
            Some("y")
        );
        // Home-level reads follow symlinks anywhere.
        assert_eq!(read_text(&root.path().join("out")).as_deref(), Some("x"));
    }

    #[cfg(unix)]
    #[test]
    fn fifos_do_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(try_read_text(&fifo, 10), Err(Unreadable::NotAFile));
        assert_eq!(read_head(&fifo, 10), None);
    }

    #[cfg(unix)]
    #[test]
    fn proc_and_sys_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("environ");
        std::os::unix::fs::symlink("/proc/self/environ", &link).unwrap();
        // On Linux the target exists and is refused; elsewhere it is missing.
        let result = try_read_text(&link, MAX_FILE_BYTES);
        assert!(
            matches!(result, Err(Unreadable::SystemFile) | Ok(None)),
            "{result:?}"
        );
        assert!(is_system_path(Path::new("/sys/kernel/x")));
        assert!(!is_system_path(Path::new("/processes")));
    }
}
