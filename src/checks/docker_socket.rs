//! `docker-socket`: a Docker daemon socket the agent can talk to.
//!
//! Whoever can talk to the Docker daemon can start a privileged container that
//! mounts the host's filesystem, so access to the socket is root on the host.
//! Agent sandboxes often mount it in for convenience.
//!
//! "Accessible" is tested by opening a Unix socket connection and closing it
//! straight away. Nothing is sent. This is local IPC, not a network call.

use std::path::{Path, PathBuf};

use crate::checks::Check;
use crate::context::Context;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};

pub struct DockerSocketCheck;

const ID: &str = "docker-socket";

const SOCKET: Rule = Rule {
    check: ID,
    id: "HK-SOCK-001",
    summary: "Docker daemon socket reachable by this user",
};

const RULES: &[Rule] = &[SOCKET];

impl Check for DockerSocketCheck {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "A Docker daemon socket (/var/run/docker.sock, $DOCKER_HOST, rootless or Docker Desktop) that this user can connect to."
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut seen: Vec<PathBuf> = Vec::new();
        let mut findings = Vec::new();
        for path in candidate_sockets(ctx) {
            // The same socket is often reachable through several paths
            // (Docker Desktop links /var/run/docker.sock to ~/.docker/run).
            let real = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            if seen.contains(&real) || !can_connect(&path) {
                continue;
            }
            seen.push(real);
            findings.push(
                Finding::new(
                    SOCKET,
                    "Docker daemon socket is accessible",
                    ctx.display_path(&path),
                    Severity::High,
                    Lifetime::LongLived,
                    Access::Write,
                    "Do not mount the Docker socket into agent sandboxes; use rootless Docker or a separate build service.",
                )
                .with_detail("access to the Docker socket is root on the host"),
            );
        }
        findings
    }
}

/// Where a Docker socket usually lives, all resolved under `ctx.root` or
/// `ctx.home` so tests can point them at a fixture.
fn candidate_sockets(ctx: &Context) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = ctx
        .var("DOCKER_HOST")
        .and_then(|h| h.strip_prefix("unix://"))
    {
        paths.push(ctx.root_path(path));
    }
    paths.push(ctx.root_path("/var/run/docker.sock"));
    paths.push(ctx.root_path("/run/docker.sock"));
    if let Some(runtime) = ctx.var("XDG_RUNTIME_DIR") {
        // Rootless Docker.
        paths.push(ctx.root_path(runtime).join("docker.sock"));
    }
    // Docker Desktop on macOS.
    paths.push(ctx.home_path(".docker/run/docker.sock"));
    paths
}

#[cfg(unix)]
fn can_connect(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    let is_socket = std::fs::metadata(path)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false);
    // Connect and drop immediately: no bytes are written.
    is_socket && std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(not(unix))]
fn can_connect(_path: &Path) -> bool {
    // Windows named pipes are out of scope for v0.1.
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::checks::testutil::{ctx_with_env, fixture_ctx};
    use std::os::unix::net::UnixListener;

    #[test]
    fn listening_socket_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/run")).unwrap();
        let _listener = UnixListener::bind(dir.path().join("var/run/docker.sock")).unwrap();
        let f = DockerSocketCheck.run(&ctx_with_env(dir.path(), &[]));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].fingerprint.is_none());
    }

    #[test]
    fn docker_host_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let _listener = UnixListener::bind(dir.path().join("d.sock")).unwrap();
        let f = DockerSocketCheck.run(&ctx_with_env(
            dir.path(),
            &[("DOCKER_HOST", "unix:///d.sock")],
        ));
        assert_eq!(f.len(), 1, "{f:?}");
    }

    #[test]
    fn plain_file_is_not_a_socket() {
        let dir = tempfile::tempdir().unwrap();
        crate::checks::testutil::write(dir.path(), "var/run/docker.sock", "");
        assert!(
            DockerSocketCheck
                .run(&ctx_with_env(dir.path(), &[]))
                .is_empty()
        );
    }

    #[test]
    fn empty_fixture() {
        assert!(DockerSocketCheck.run(&fixture_ctx("empty")).is_empty());
    }
}
