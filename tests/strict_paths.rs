//! `preflight --strict` fails closed on every credential file the local
//! checks read: put a FIFO, or a file nobody may read, where the file should
//! be, and the verdict must be FAIL.
//!
//! The list of paths is not written out by hand, so it cannot rot: the
//! checks run once against an empty home and report every path they asked
//! for (`Context::paths_read`). Files that are only found by listing a
//! directory are added explicitly.

#![cfg(unix)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use common::run_in;
use heldkeys::checks;
use heldkeys::context::Context;

/// Files found by listing a directory, which an empty home does not show.
const LISTED: &[&str] = &[
    ".aws/sso/cache/session.json",
    ".aws/cli/cache/role.json",
    ".ssh/id_ed25519",
    ".ssh/deploy_key",
];

/// In `~/.ssh` sockets and other non-files are normal (ControlMaster), so
/// only default key names count when they are not regular files; any other
/// name counts when it is a file that cannot be read.
fn applies(relative: &Path, kind: Kind) -> bool {
    match kind {
        Kind::NoPermission => true,
        Kind::Fifo => relative != Path::new(".ssh/deploy_key"),
    }
}

/// Every file under `home` that the local checks read, relative to it.
fn credential_paths(home: &Path, cwd: &Path) -> Vec<PathBuf> {
    let ctx = Context::new(
        home.to_path_buf(),
        home.to_path_buf(),
        cwd.to_path_buf(),
        BTreeMap::new(),
    );
    checks::run_all(&checks::local_checks(), &ctx);
    let mut paths: Vec<PathBuf> = ctx
        .paths_read()
        .into_iter()
        .filter_map(|p| p.strip_prefix(home).ok().map(Path::to_path_buf))
        .collect();
    paths.extend(LISTED.iter().map(PathBuf::from));
    paths.sort();
    paths.dedup();
    paths
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Fifo,
    NoPermission,
}

fn plant(home: &Path, relative: &Path, kind: Kind) {
    let path = home.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    match kind {
        Kind::Fifo => {
            let status = std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap();
            assert!(status.success());
        }
        Kind::NoPermission => {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&path, "x\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
    }
}

#[test]
fn strict_preflight_fails_on_every_unreadable_credential_path() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().join("cwd");
    let empty = tmp.path().join("empty");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&empty).unwrap();

    let baseline = run_in(&empty, &cwd, &["preflight", "--strict"], &[]);
    assert_eq!(baseline.code, 0, "{}", baseline.stdout);

    let paths = credential_paths(&empty, &cwd);
    for expected in [".aws/credentials", ".claude.json", ".cursor/mcp.json"] {
        assert!(
            paths.contains(&PathBuf::from(expected)),
            "{expected} missing from {paths:?}"
        );
    }
    assert!(paths.len() > 30, "{paths:?}");

    // root ignores file permissions, so that half only means something
    // for an ordinary user.
    let kinds: &[Kind] = if unsafe { libc::geteuid() } == 0 {
        &[Kind::Fifo]
    } else {
        &[Kind::Fifo, Kind::NoPermission]
    };
    for relative in &paths {
        for &kind in kinds.iter().filter(|&&k| applies(relative, k)) {
            let home = tempfile::tempdir().unwrap();
            plant(home.path(), relative, kind);
            let out = run_in(home.path(), &cwd, &["preflight", "--strict"], &[]);
            assert_eq!(
                out.code,
                1,
                "{} as {kind:?}: {}",
                relative.display(),
                out.stdout
            );
            assert!(
                out.stdout.starts_with("heldkeys preflight: FAIL"),
                "{} as {kind:?}: {}",
                relative.display(),
                out.stdout
            );
        }
    }
}
