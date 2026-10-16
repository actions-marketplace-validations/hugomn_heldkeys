//! `heldkeys scan --docker <container>` and `heldkeys scan --kube <pod>`.
//!
//! Steps, all through `docker` or `kubectl` on PATH:
//!
//! 1. Find the target's OS and CPU (`uname -sm` inside it, or the image or
//!    node metadata when the image has no `uname`). Only Linux is supported.
//! 2. Check that the binary we are about to copy is a Linux binary for that
//!    CPU. Usually this binary is a macOS or glibc build, so `--binary` points
//!    at a static musl build instead (see docs/building.md).
//! 3. Copy it to `/tmp/heldkeys-<random>` in the target. If the copy fails,
//!    remove whatever part of the file it may have written.
//! 4. Run it there with `--remove-self scan --format json --fail-on none`.
//!    `--remove-self` makes the copy delete its own file before it does
//!    anything else, so once it has started, nothing this side does (or
//!    fails to do, because it was killed) can leave it behind.
//! 5. `rm -f` the copy, whatever happened in step 4, for a copy that never
//!    started (a `noexec` /tmp, a missing loader). SIGINT and SIGTERM stop
//!    steps 3 and 4 early but still let this step run.
//! 6. Parse the JSON back into findings, so the caller renders them locally
//!    in any format and applies `--fail-on` here.
//!
//! What can still leave the file behind: this process being killed with
//! SIGKILL (or the machine dying) between the end of the copy and the start
//! of the copied binary, a binary that cannot start in an image without
//! `rm`, and a non-root Docker container whose runtime refuses the root
//! `rm` (see `Target::remove` and docs/sandboxes.md).
//!
//! Every command is built with `Command` and explicit arguments, never a
//! shell string, so names cannot inject shell syntax.
//!
//! The target may be hostile. Every command is killed after
//! `COMMAND_TIMEOUT`, its output is capped (`MAX_STDOUT`, `MAX_STDERR`), and
//! every string read back from it (uname output, stderr, the JSON report)
//! goes through `sanitize` before it can reach our stdout or stderr.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::checks;
use crate::finding::{Access, Finding, Lifetime, Rule, Severity};
use crate::report;
use crate::sandbox::elf::{self, Arch};
use crate::sanitize::sanitize;

/// How long one docker or kubectl command may run before it is killed. The
/// scan itself takes well under a second; copying the binary into a pod over
/// a slow API server is the longest step.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
/// Most stdout read from one command. A JSON report is a few KiB; anything
/// past this is an error, not a report.
const MAX_STDOUT: usize = 16 * 1024 * 1024;
/// Most stderr read from one command; only its start is shown.
const MAX_STDERR: usize = 64 * 1024;
/// Characters of a target's stderr shown in an error message.
const STDERR_SHOWN: usize = 500;
/// Characters of other target-supplied text (uname output, an unknown
/// severity) shown in an error message.
const VALUE_SHOWN: usize = 80;

/// The hidden flag that makes heldkeys delete its own executable file as the
/// first thing it does. Passed to the copy run in the target; `main` acts on
/// it before parsing any other argument.
pub const REMOVE_SELF_FLAG: &str = "--remove-self";

/// Whether `args` (the arguments after the program name) contain
/// `--remove-self`, before any `--`.
pub fn wants_remove_self(args: impl IntoIterator<Item = OsString>) -> bool {
    args.into_iter()
        .take_while(|a| a != "--")
        .any(|a| a == REMOVE_SELF_FLAG)
}

/// Deletes the file of the running executable. Linux and macOS let a running
/// program unlink its own file: the process keeps running from memory, and
/// the file is gone from the directory at once.
pub fn remove_self() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this binary: {e}"))?;
    std::fs::remove_file(&exe).map_err(|e| format!("cannot remove {}: {e}", exe.display()))
}

/// Where to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Docker {
        container: String,
    },
    Kube {
        pod: String,
        namespace: Option<String>,
        container: Option<String>,
    },
}

/// What came back from a remote scan.
pub struct RemoteScan {
    pub findings: Vec<Finding>,
    /// Non-fatal problems to show the user, such as a copy we could not remove.
    pub warnings: Vec<String>,
}

impl Target {
    /// How the target is named in messages.
    pub fn describe(&self) -> String {
        match self {
            Target::Docker { container } => format!("docker container {container}"),
            Target::Kube {
                pod,
                namespace,
                container,
            } => {
                let mut s = format!("pod {pod}");
                if let Some(ns) = namespace {
                    s.push_str(&format!(" in namespace {ns}"));
                }
                if let Some(c) = container {
                    s.push_str(&format!(", container {c}"));
                }
                s
            }
        }
    }

    /// Rejects names that docker or kubectl could read as a flag or as a
    /// `name:path` copy spec. Container, pod, namespace and container names
    /// are letters, digits, `.`, `_` and `-`, starting with a letter or digit.
    pub fn validate(&self) -> Result<(), String> {
        let names: Vec<(&str, &str)> = match self {
            Target::Docker { container } => vec![("container", container)],
            Target::Kube {
                pod,
                namespace,
                container,
            } => {
                let mut v = vec![("pod", pod.as_str())];
                if let Some(ns) = namespace {
                    v.push(("namespace", ns));
                }
                if let Some(c) = container {
                    v.push(("container", c));
                }
                v
            }
        };
        for (what, name) in names {
            let valid = name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
            if !valid {
                return Err(format!("invalid {what} name {name:?}"));
            }
        }
        Ok(())
    }

    /// `kubectl` flags that select the pod's namespace, placed before the verb.
    fn kube_prefix(namespace: &Option<String>) -> Vec<String> {
        match namespace {
            Some(ns) => vec!["-n".into(), ns.clone()],
            None => Vec::new(),
        }
    }

    /// Runs `args` inside the target:
    /// `docker exec <container> <args>` or
    /// `kubectl [-n ns] exec <pod> [-c container] -- <args>`.
    pub fn exec(&self, args: &[&str]) -> Command {
        match self {
            Target::Docker { container } => {
                let mut cmd = Command::new("docker");
                cmd.arg("exec").arg(container).args(args);
                cmd
            }
            Target::Kube {
                pod,
                namespace,
                container,
            } => {
                let mut cmd = Command::new("kubectl");
                cmd.args(Self::kube_prefix(namespace)).arg("exec").arg(pod);
                if let Some(c) = container {
                    cmd.arg("-c").arg(c);
                }
                cmd.arg("--").args(args);
                cmd
            }
        }
    }

    /// Copies a local file into the target:
    /// `docker cp <local> <container>:<remote>` or
    /// `kubectl [-n ns] cp <local> <pod>:<remote> [-c container]`.
    pub fn copy(&self, local: &Path, remote: &str) -> Command {
        match self {
            Target::Docker { container } => {
                let mut cmd = Command::new("docker");
                cmd.arg("cp")
                    .arg(local)
                    .arg(format!("{container}:{remote}"));
                cmd
            }
            Target::Kube {
                pod,
                namespace,
                container,
            } => {
                let mut cmd = Command::new("kubectl");
                cmd.args(Self::kube_prefix(namespace))
                    .arg("cp")
                    .arg(local)
                    .arg(format!("{pod}:{remote}"));
                if let Some(c) = container {
                    cmd.arg("-c").arg(c);
                }
                cmd
            }
        }
    }

    /// Removes the copy at exactly `remote` (never a pattern):
    /// `docker exec -u 0 <container> rm -f <remote>` or
    /// `kubectl [-n ns] exec <pod> [-c container] -- rm -f <remote>`.
    ///
    /// `docker cp` creates the file owned by root, and /tmp is normally
    /// sticky, so in a container that runs as another user only root may
    /// delete it. `kubectl cp` writes it as the container's own user.
    pub fn remove(&self, remote: &str) -> Command {
        match self {
            Target::Docker { container } => {
                let mut cmd = Command::new("docker");
                cmd.args(["exec", "-u", "0"])
                    .arg(container)
                    .args(["rm", "-f", remote]);
                cmd
            }
            Target::Kube { .. } => self.exec(&["rm", "-f", remote]),
        }
    }

    /// Commands that read the target's platform from metadata, for images
    /// without `uname` (distroless, scratch). Each step's output is the next
    /// step's last argument; the final output is `os/arch`.
    fn platform_from_metadata(&self) -> Vec<Command> {
        match self {
            Target::Docker { container } => {
                let mut image = Command::new("docker");
                image
                    .args(["inspect", "--format", "{{.Image}}"])
                    .arg(container);
                let mut platform = Command::new("docker");
                platform.args(["image", "inspect", "--format", "{{.Os}}/{{.Architecture}}"]);
                vec![image, platform]
            }
            Target::Kube { pod, namespace, .. } => {
                let mut node = Command::new("kubectl");
                node.args(Self::kube_prefix(namespace))
                    .args(["get", "pod"])
                    .arg(pod)
                    .args(["-o", "jsonpath={.spec.nodeName}"]);
                let mut platform = Command::new("kubectl");
                platform.args([
                    "get",
                    "-o",
                    "jsonpath={.status.nodeInfo.operatingSystem}/{.status.nodeInfo.architecture}",
                    "node",
                ]);
                vec![node, platform]
            }
        }
    }
}

/// The commands a remote run is made of. `Target` builds `docker` and
/// `kubectl` commands; the tests build local stand-ins.
trait Runner {
    fn copy(&self, local: &Path, remote: &str) -> Command;
    fn exec(&self, args: &[&str]) -> Command;
    fn remove(&self, remote: &str) -> Command;
    fn describe(&self) -> String;
}

impl Runner for Target {
    fn copy(&self, local: &Path, remote: &str) -> Command {
        Target::copy(self, local, remote)
    }
    fn exec(&self, args: &[&str]) -> Command {
        Target::exec(self, args)
    }
    fn remove(&self, remote: &str) -> Command {
        Target::remove(self, remote)
    }
    fn describe(&self) -> String {
        Target::describe(self)
    }
}

/// Scans inside `target` with `binary` (or this executable), passing
/// `scan_args` (such as `--deep`) through to the remote scan.
///
/// Errors and warnings are sanitized once more here, so no message built
/// from the target's output can carry a control character to the terminal.
pub fn scan(
    target: &Target,
    binary: Option<&Path>,
    scan_args: &[String],
) -> Result<RemoteScan, String> {
    let mut result = scan_unsanitized(target, binary, scan_args).map_err(|e| sanitize(&e))?;
    for warning in &mut result.warnings {
        *warning = sanitize(warning);
    }
    Ok(result)
}

fn scan_unsanitized(
    target: &Target,
    binary: Option<&Path>,
    scan_args: &[String],
) -> Result<RemoteScan, String> {
    target.validate()?;
    let binary: PathBuf = match binary {
        Some(b) => b.to_path_buf(),
        None => std::env::current_exe().map_err(|e| format!("cannot find this binary: {e}"))?,
    };
    let explicit = binary_is_explicit(&binary);
    // Fail fast, before touching the target, if the binary cannot run on
    // any Linux target at all.
    let info =
        elf::inspect_file(&binary).ok_or_else(|| not_linux_message(&binary, None, explicit))?;

    let arch = detect_arch(target)?;
    let mut warnings = Vec::new();
    if info.arch != Some(arch) {
        return Err(not_linux_message(&binary, Some(arch), explicit));
    }
    if !info.is_static {
        warnings.push(format!(
            "{} is dynamically linked and may not start in minimal images; a static musl build (docs/building.md) runs anywhere",
            binary.display()
        ));
    }

    let remote_path = format!("/tmp/{}-{}", crate::TOOL_NAME, random_suffix());
    let output = copy_run_remove(
        target,
        &binary,
        &remote_path,
        scan_args,
        LIMITS,
        &mut warnings,
    )?;
    let findings = parse_report(&output)?;
    Ok(RemoteScan { findings, warnings })
}

/// The arguments that run the copy at `remote_path` in the target.
fn remote_argv<'a>(remote_path: &'a str, scan_args: &'a [String]) -> Vec<&'a str> {
    let mut args = vec![
        remote_path,
        REMOVE_SELF_FLAG,
        "scan",
        "--format",
        "json",
        "--fail-on",
        "none",
    ];
    args.extend(scan_args.iter().map(String::as_str));
    args
}

/// Copies `binary` to `remote_path` in the target, runs it there and removes
/// it again, returning the run's stdout.
///
/// The copy deletes itself when it starts (`--remove-self`); the `rm -f`
/// afterwards covers a copy that failed partway or never started. While this
/// runs, SIGINT and SIGTERM stop the copy or the run instead of this process,
/// so the `rm -f` still happens (a second signal exits at once).
fn copy_run_remove(
    target: &impl Runner,
    binary: &Path,
    remote_path: &str,
    scan_args: &[String],
    limits: Limits,
    warnings: &mut Vec<String>,
) -> Result<String, String> {
    let _signals = interrupt::Guard::install();
    let step = Limits {
        stop_on_signal: true,
        ..limits
    };
    if let Err(copy) = run_limited(
        target.copy(binary, remote_path),
        "copying heldkeys into the target",
        step,
    ) {
        if !copy.started {
            // docker or kubectl did not start, so nothing was written.
            return Err(copy.message);
        }
        // A copy that failed partway may have left part of the file.
        return Err(match remove(target, remote_path, limits) {
            Ok(()) => copy.message,
            Err(e) => format!(
                "{}; {remote_path} may be left in the {}, and removing it failed: {e}",
                copy.message,
                target.describe()
            ),
        });
    }

    let output = run_limited(
        target.exec(&remote_argv(remote_path, scan_args)),
        "running heldkeys in the target",
        step,
    )
    .map_err(|e| with_older_binary_hint(e.message));

    // Also when the run failed: the copy may never have started.
    let removed = remove(target, remote_path, limits);
    if interrupt::received() {
        let note = match &removed {
            Ok(()) => format!("removed {remote_path} from the {}", target.describe()),
            Err(e) => format!(
                "{remote_path} may be left in the {}: {e}",
                target.describe()
            ),
        };
        return Err(format!("interrupted; {note}"));
    }
    match (output, removed) {
        (Ok(out), Ok(())) => Ok(out),
        (Ok(out), Err(e)) => {
            // The copy ran, so it most likely deleted itself on start (an
            // image without `rm`, or a runtime that refuses `exec -u 0`).
            warnings.push(format!(
                "could not confirm that {remote_path} is gone from the {}: the copy deletes itself when it starts, and the rm -f afterwards failed: {e}",
                target.describe()
            ));
            Ok(out)
        }
        (Err(run), Ok(())) => Err(run),
        (Err(run), Err(e)) => Err(format!(
            "{run}; {remote_path} may be left in the {}, and removing it failed: {e}",
            target.describe()
        )),
    }
}

/// `rm -f <remote_path>` in the target (as root in Docker, see
/// `Target::remove`). A first SIGINT or SIGTERM does not stop it (a second
/// exits heldkeys); the timeout does.
fn remove(target: &impl Runner, remote_path: &str, limits: Limits) -> Result<(), String> {
    run_limited(target.remove(remote_path), "removing the copy", limits)
        .map(drop)
        .map_err(|e| e.message)
}

/// Adds a hint when the error comes from a `--binary` older than
/// `--remove-self`, which rejects the flag.
fn with_older_binary_hint(message: String) -> String {
    if message.contains(REMOVE_SELF_FLAG) {
        format!(
            "{message} (a --binary build older than 0.2.1 does not know {REMOVE_SELF_FLAG}; copy a build of this version)"
        )
    } else {
        message
    }
}

/// `--binary` given by the user, or the running executable?
fn binary_is_explicit(binary: &Path) -> bool {
    std::env::current_exe()
        .map(|exe| exe != binary)
        .unwrap_or(true)
}

/// The message for a binary that cannot run in the target, telling the user
/// what to pass instead.
fn not_linux_message(binary: &Path, arch: Option<Arch>, explicit: bool) -> String {
    let which = if explicit {
        format!("{} is not", binary.display())
    } else {
        format!("this heldkeys ({}) is not", binary.display())
    };
    match arch {
        Some(arch) => format!(
            "{which} a Linux {a} binary, and the target runs Linux {a}. Pass --binary <path> to a Linux {a} build, for example target/{t}/release/heldkeys (see docs/building.md).",
            a = arch.as_str(),
            t = arch.musl_target()
        ),
        None => format!(
            "{which} a Linux binary, and --docker/--kube copy it into a Linux target. Pass --binary <path> to a Linux build for the target's CPU, for example target/x86_64-unknown-linux-musl/release/heldkeys (see docs/building.md)."
        ),
    }
}

/// The target's CPU, which must run Linux.
fn detect_arch(target: &Target) -> Result<Arch, String> {
    let platform = match run(
        target.exec(&["uname", "-sm"]),
        "running uname in the target",
    ) {
        Ok(out) => parse_uname(&out),
        Err(uname_error) => platform_from_metadata(target).map_err(|_| {
            format!(
                "cannot tell the target's CPU: {uname_error}. Is the {} running?",
                target.describe()
            )
        })?,
    };
    let (os, arch) = platform?;
    if !os.eq_ignore_ascii_case("linux") {
        return Err(format!(
            "the {} runs {os}; only Linux targets are supported",
            target.describe()
        ));
    }
    Arch::parse(&arch).ok_or_else(|| {
        format!(
            "the {} runs on {arch}; static builds exist for x86_64 and aarch64 only",
            target.describe()
        )
    })
}

/// `os/arch` from image or node metadata.
fn platform_from_metadata(target: &Target) -> Result<Result<(String, String), String>, String> {
    let mut last = String::new();
    for (i, mut cmd) in target.platform_from_metadata().into_iter().enumerate() {
        if i > 0 {
            cmd.arg(&last);
        }
        last = run(cmd, "reading the target's platform")?
            .trim()
            .to_string();
    }
    Ok(parse_platform(&last))
}

/// `uname -sm` output, e.g. "Linux x86_64". Both parts come from the
/// target and end up in messages, so they are sanitized and shortened.
fn parse_uname(out: &str) -> Result<(String, String), String> {
    let mut parts = out.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some(os), Some(arch)) => Ok((shown(os, VALUE_SHOWN), shown(arch, VALUE_SHOWN))),
        _ => Err(format!(
            "unexpected uname output \"{}\"",
            shown(out.trim(), VALUE_SHOWN)
        )),
    }
}

/// `os/arch`, e.g. "linux/amd64".
fn parse_platform(out: &str) -> Result<(String, String), String> {
    match out.trim().split_once('/') {
        Some((os, arch)) if !os.is_empty() && !arch.is_empty() => {
            Ok((shown(os, VALUE_SHOWN), shown(arch, VALUE_SHOWN)))
        }
        _ => Err(format!(
            "unexpected platform \"{}\"",
            shown(out.trim(), VALUE_SHOWN)
        )),
    }
}

/// Target-supplied text as it may appear in a message: sanitized and cut to
/// `max` characters.
fn shown(s: &str, max: usize) -> String {
    let s = sanitize(s);
    if s.chars().count() <= max {
        return s;
    }
    let mut cut: String = s.chars().take(max).collect();
    cut.push('…');
    cut
}

/// Bounds on one command: how long it may run and how much output is kept.
#[derive(Debug, Clone, Copy)]
struct Limits {
    timeout: Duration,
    max_stdout: usize,
    max_stderr: usize,
    /// Stop the command when SIGINT or SIGTERM arrives (see `interrupt`).
    stop_on_signal: bool,
}

const LIMITS: Limits = Limits {
    timeout: COMMAND_TIMEOUT,
    max_stdout: MAX_STDOUT,
    max_stderr: MAX_STDERR,
    stop_on_signal: false,
};

/// Why a command failed.
#[derive(Debug)]
struct RunError {
    message: String,
    /// The command started, so it may have done part of its work.
    started: bool,
}

impl RunError {
    fn started(message: String) -> RunError {
        RunError {
            message,
            started: true,
        }
    }
}

/// Runs a command with no stdin and returns its stdout, or an error with
/// its (shortened, sanitized) stderr.
fn run(cmd: Command, what: &str) -> Result<String, String> {
    run_limited(cmd, what, LIMITS).map_err(|e| e.message)
}

/// `run` with explicit limits. The child's stdout and stderr are read on
/// their own threads (so neither pipe can fill up and stall it) while this
/// thread waits for it to exit, and kills it at the deadline.
fn run_limited(mut cmd: Command, what: &str, limits: Limits) -> Result<String, RunError> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| RunError {
            message: match e.kind() {
                std::io::ErrorKind::NotFound => format!("{what}: {program} is not on PATH"),
                _ => format!("{what}: cannot run {program}: {e}"),
            },
            started: false,
        })?;
    let stdout = read_capped(child.stdout.take(), limits.max_stdout);
    let stderr = read_capped(child.stderr.take(), limits.max_stderr);
    let status = wait_until(
        &mut child,
        Instant::now() + limits.timeout,
        limits.stop_on_signal,
    )
    .map_err(|e| RunError::started(format!("{what}: waiting for {program}: {e}")))?;
    let Some(status) = status else {
        // The readers are left behind: a grandchild may still hold the pipes.
        return Err(RunError::started(
            if limits.stop_on_signal && interrupt::received() {
                format!("{what}: interrupted, {program} was stopped")
            } else {
                format!(
                    "{what}: {program} did not finish within {} seconds and was stopped",
                    limits.timeout.as_secs()
                )
            },
        ));
    };
    let (stdout, stdout_cut) = stdout.join().unwrap_or_default();
    let (stderr, _) = stderr.join().unwrap_or_default();
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return Err(RunError::started(format!(
            "{what} failed ({status}): {}",
            shown(stderr.trim(), STDERR_SHOWN)
        )));
    }
    if stdout_cut {
        return Err(RunError::started(format!(
            "{what}: {program} wrote more than {} bytes",
            limits.max_stdout
        )));
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Reads up to `limit` bytes from `pipe` on a new thread. Anything past the
/// limit is read and dropped, so the child never blocks on a full pipe; the
/// flag says whether that happened.
fn read_capped<R: Read + Send + 'static>(
    pipe: Option<R>,
    limit: usize,
) -> JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let Some(mut pipe) = pipe else {
            return (Vec::new(), false);
        };
        let mut kept = Vec::new();
        let _ = (&mut pipe).take(limit as u64).read_to_end(&mut kept);
        let dropped = std::io::copy(&mut pipe, &mut std::io::sink()).unwrap_or(0) > 0;
        (kept, dropped)
    })
}

/// Waits for `child` to exit, or kills it at `deadline` (or, with
/// `stop_on_signal`, when SIGINT or SIGTERM arrived) and returns `None`.
fn wait_until(
    child: &mut Child,
    deadline: Instant,
    stop_on_signal: bool,
) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline || (stop_on_signal && interrupt::received()) {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// SIGINT and SIGTERM during a remote run: instead of killing this process
/// (and with it the `rm -f` of the copy), they set a flag that stops the
/// running command. A second signal exits at once, for when the cleanup
/// itself hangs. SIGKILL cannot be caught; see the module docs.
#[cfg(unix)]
mod interrupt {
    use std::sync::atomic::{AtomicBool, Ordering};

    static RECEIVED: AtomicBool = AtomicBool::new(false);
    const SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGTERM];

    extern "C" fn on_signal(_: libc::c_int) {
        if RECEIVED.swap(true, Ordering::SeqCst) {
            // SAFETY: _exit is async-signal-safe.
            unsafe { libc::_exit(130) };
        }
    }

    /// Catches the signals while alive; puts the previous handlers back on drop.
    pub struct Guard {
        previous: [libc::sighandler_t; 2],
    }

    impl Guard {
        pub fn install() -> Guard {
            RECEIVED.store(false, Ordering::SeqCst);
            let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            // SAFETY: the handler only touches an atomic and calls _exit.
            let previous = SIGNALS.map(|sig| unsafe { libc::signal(sig, handler) });
            for (sig, prev) in SIGNALS.into_iter().zip(previous) {
                if prev == libc::SIG_IGN {
                    // Ignored by whoever started us (nohup): keep it that way.
                    // SAFETY: restoring a handler the process already had.
                    unsafe { libc::signal(sig, libc::SIG_IGN) };
                }
            }
            Guard { previous }
        }
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            for (sig, prev) in SIGNALS.into_iter().zip(self.previous) {
                // SAFETY: restoring a handler the process already had.
                unsafe { libc::signal(sig, prev) };
            }
        }
    }

    /// Whether SIGINT or SIGTERM arrived since the last `Guard::install`.
    pub fn received() -> bool {
        RECEIVED.load(Ordering::SeqCst)
    }
}

#[cfg(not(unix))]
mod interrupt {
    pub struct Guard;

    impl Guard {
        pub fn install() -> Guard {
            Guard
        }
    }

    pub fn received() -> bool {
        false
    }
}

/// A hard-to-guess suffix for the temporary file name. `RandomState` is
/// seeded from the OS's random source, so no extra crate is needed.
fn random_suffix() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.write_u128(nanos);
    hasher.write_u32(std::process::id());
    format!("{:016x}", hasher.finish())
}

/// Parses a `heldkeys/v1` JSON report back into findings.
///
/// The JSON comes from inside a container that may be hostile, so strings
/// are sanitized (no terminal escapes, no bidi controls), and `Report::new`
/// later sanitizes and scrubs them again and drops any fingerprint that is
/// not in the safe `abcd…xyz` shape.
pub fn parse_report(text: &str) -> Result<Vec<Finding>, String> {
    let doc: Value = serde_json::from_str(text)
        .map_err(|e| format!("the target did not return a heldkeys JSON report: {e}"))?;
    if doc["schema"] != crate::JSON_SCHEMA {
        return Err(format!(
            "the target returned schema {}, expected {}",
            shown(&doc["schema"].to_string(), VALUE_SHOWN),
            crate::JSON_SCHEMA
        ));
    }
    doc["findings"]
        .as_array()
        .ok_or("the target's report has no findings list")?
        .iter()
        .map(finding_from_json)
        .collect()
}

fn finding_from_json(v: &Value) -> Result<Finding, String> {
    let text = |key: &str| -> Result<String, String> {
        v[key]
            .as_str()
            .map(sanitize)
            .ok_or_else(|| format!("a finding without {key} in the target's report"))
    };
    let optional = |key: &str| v[key].as_str().map(sanitize);
    let severity = match v["severity"].as_str() {
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        Some("low") => Severity::Low,
        Some("info") => Severity::Info,
        other => {
            return Err(format!(
                "unknown severity \"{}\" in the target's report",
                shown(other.unwrap_or_default(), VALUE_SHOWN)
            ));
        }
    };
    let lifetime = match v["lifetime"].as_str() {
        Some("long-lived") => Lifetime::LongLived,
        Some("short-lived") => Lifetime::ShortLived,
        _ => Lifetime::Unknown,
    };
    let access = match v["access"].as_str() {
        Some("write") => Access::Write,
        Some("read") => Access::Read,
        _ => Access::Unknown,
    };
    let rule = Rule {
        check: known_id(&text("check")?),
        id: known_id(&text("rule")?),
        summary: "",
    };
    let mut finding = Finding::new(
        rule,
        text("title")?,
        text("location")?,
        severity,
        lifetime,
        access,
        text("fix")?,
    )
    .with_fingerprint(optional("fingerprint"));
    if let Some(detail) = optional("detail") {
        finding = finding.with_detail(detail);
    }
    Ok(finding)
}

/// `Finding` keeps check and rule ids as `&'static str`. Ids this binary
/// knows map to its own constants. A newer binary in the target may report
/// ids we do not know; leaking those few short strings for the life of a
/// one-shot process is simpler than changing the data model. An id that is
/// not a short ASCII word is not kept at all.
fn known_id(id: &str) -> &'static str {
    if !report::is_safe_id(id) {
        return report::UNKNOWN_ID;
    }
    let all = checks::local_checks()
        .into_iter()
        .chain(checks::ci_checks())
        .collect::<Vec<_>>();
    for check in &all {
        if check.id() == id {
            return check.id();
        }
        if let Some(rule) = check.rules().iter().find(|r| r.id == id) {
            return rule.id;
        }
    }
    Box::leak(id.to_string().into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Mode, Report};

    fn argv(cmd: &Command) -> Vec<String> {
        std::iter::once(cmd.get_program())
            .chain(cmd.get_args())
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    fn docker() -> Target {
        Target::Docker {
            container: "agent-box".into(),
        }
    }

    fn kube(namespace: bool, container: bool) -> Target {
        Target::Kube {
            pod: "agent-7f9c".into(),
            namespace: namespace.then(|| "sandbox".to_string()),
            container: container.then(|| "agent".to_string()),
        }
    }

    #[test]
    fn docker_commands() {
        let t = docker();
        assert_eq!(
            argv(&t.copy(Path::new("/opt/heldkeys"), "/tmp/heldkeys-ab12")),
            [
                "docker",
                "cp",
                "/opt/heldkeys",
                "agent-box:/tmp/heldkeys-ab12"
            ]
        );
        assert_eq!(
            argv(&t.exec(&["/tmp/heldkeys-ab12", "scan", "--format", "json"])),
            [
                "docker",
                "exec",
                "agent-box",
                "/tmp/heldkeys-ab12",
                "scan",
                "--format",
                "json"
            ]
        );
        // As root: the file `docker cp` made is root's, in a sticky /tmp.
        assert_eq!(
            argv(&t.remove("/tmp/heldkeys-ab12")),
            [
                "docker",
                "exec",
                "-u",
                "0",
                "agent-box",
                "rm",
                "-f",
                "/tmp/heldkeys-ab12"
            ]
        );
        let meta: Vec<Vec<String>> = t.platform_from_metadata().iter().map(argv).collect();
        assert_eq!(
            meta[0],
            ["docker", "inspect", "--format", "{{.Image}}", "agent-box"]
        );
        assert_eq!(
            meta[1],
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Os}}/{{.Architecture}}"
            ]
        );
    }

    #[test]
    fn kube_commands() {
        let t = kube(true, true);
        assert_eq!(
            argv(&t.copy(Path::new("/opt/heldkeys"), "/tmp/heldkeys-ab12")),
            [
                "kubectl",
                "-n",
                "sandbox",
                "cp",
                "/opt/heldkeys",
                "agent-7f9c:/tmp/heldkeys-ab12",
                "-c",
                "agent"
            ]
        );
        // As the container's user, who owns what `kubectl cp` wrote.
        assert_eq!(
            argv(&t.remove("/tmp/heldkeys-ab12")),
            [
                "kubectl",
                "-n",
                "sandbox",
                "exec",
                "agent-7f9c",
                "-c",
                "agent",
                "--",
                "rm",
                "-f",
                "/tmp/heldkeys-ab12"
            ]
        );
        let bare = kube(false, false);
        assert_eq!(
            argv(&bare.exec(&["uname", "-sm"])),
            ["kubectl", "exec", "agent-7f9c", "--", "uname", "-sm"]
        );
        let meta: Vec<Vec<String>> = t.platform_from_metadata().iter().map(argv).collect();
        assert_eq!(
            meta[0],
            [
                "kubectl",
                "-n",
                "sandbox",
                "get",
                "pod",
                "agent-7f9c",
                "-o",
                "jsonpath={.spec.nodeName}"
            ]
        );
    }

    #[test]
    fn names_that_look_like_flags_are_rejected() {
        assert!(docker().validate().is_ok());
        assert!(kube(true, true).validate().is_ok());
        for bad in ["-it", "", "a:b", "a b", "a/b", "x;rm"] {
            let t = Target::Docker {
                container: bad.into(),
            };
            assert!(t.validate().is_err(), "{bad:?}");
        }
        let t = Target::Kube {
            pod: "p".into(),
            namespace: Some("--all".into()),
            container: None,
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn describe() {
        assert_eq!(docker().describe(), "docker container agent-box");
        assert_eq!(
            kube(true, true).describe(),
            "pod agent-7f9c in namespace sandbox, container agent"
        );
    }

    #[test]
    fn platforms() {
        assert_eq!(
            parse_uname("Linux x86_64\n").unwrap(),
            ("Linux".to_string(), "x86_64".to_string())
        );
        assert!(parse_uname("").is_err());
        assert_eq!(
            parse_platform("linux/arm64\n").unwrap(),
            ("linux".to_string(), "arm64".to_string())
        );
        assert!(parse_platform("/").is_err());
    }

    #[test]
    fn binary_messages_name_the_fix() {
        let m = not_linux_message(Path::new("/x/heldkeys"), Some(Arch::Aarch64), true);
        assert!(m.contains("--binary"), "{m}");
        assert!(m.contains("aarch64-unknown-linux-musl"), "{m}");
        let m = not_linux_message(Path::new("/x/heldkeys"), None, false);
        assert!(
            m.starts_with("this heldkeys (/x/heldkeys) is not a Linux binary"),
            "{m}"
        );
    }

    #[test]
    fn non_linux_binary_fails_before_any_command_runs() {
        // A file that is not ELF: scan must stop before calling docker.
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("heldkeys");
        std::fs::write(&fake, b"#!/bin/sh\n").unwrap();
        let err = scan(&docker(), Some(&fake), &[]).err().unwrap();
        assert!(err.contains("is not a Linux binary"), "{err}");
    }

    #[test]
    fn random_suffixes_differ() {
        assert_ne!(random_suffix(), random_suffix());
        assert_eq!(random_suffix().len(), 16);
    }

    #[test]
    fn json_round_trip() {
        let findings = vec![
            Finding::new(
                Rule {
                    check: "aws",
                    id: "HK-AWS-001",
                    summary: "",
                },
                "Long-lived AWS access key",
                "~/.aws/credentials [default]",
                Severity::High,
                Lifetime::LongLived,
                Access::Unknown,
                "Rotate it.",
            )
            .with_fingerprint(Some("AKIA…PLE".to_string())),
            Finding::new(
                Rule {
                    check: "mcp",
                    id: "HK-MCP-003",
                    summary: "",
                },
                "Project-level MCP config",
                "./.mcp.json",
                Severity::Info,
                Lifetime::Unknown,
                Access::Unknown,
                "Review.",
            )
            .with_detail("Claude Code: 1 server(s) (db); runs uvx"),
            Finding::new(
                Rule {
                    check: "env",
                    id: "HK-ENV-001",
                    summary: "",
                },
                "npm access token",
                "env: NPM_TOKEN",
                Severity::Medium,
                Lifetime::ShortLived,
                Access::Write,
                "Remove it.",
            ),
        ];
        let json = report::json::render(&Report::new(Mode::Scan, findings.clone()));
        let back = parse_report(&json).unwrap();
        assert_eq!(back, findings);
    }

    #[test]
    fn hostile_reports_are_contained() {
        let json = r#"{"schema":"heldkeys/v1","findings":[{"check":"future-check","rule":"HK-NEW-001",
            "title":"Evil\u001b[2J","location":"x","fingerprint":"AKIAIOSFODNN7EXAMPLE",
            "severity":"high","lifetime":"long-lived","access":"write","detail":null,"fix":"f"}]}"#;
        let back = parse_report(json).unwrap();
        assert_eq!(back[0].title, "Evil?[2J");
        assert_eq!(back[0].rule, "HK-NEW-001");
        // Report::new drops a fingerprint that is not in the safe shape.
        let report = Report::new(Mode::Scan, back);
        assert_eq!(report.findings[0].fingerprint, None);

        assert!(parse_report("not json").is_err());
        assert!(parse_report(r#"{"schema":"other/v9","findings":[]}"#).is_err());
        assert!(
            parse_report(r#"{"schema":"heldkeys/v1","findings":[{"severity":"bad"}]}"#).is_err()
        );
    }

    #[test]
    fn hostile_ids_and_values_are_not_kept() {
        let json = r#"{"schema":"heldkeys/v1","findings":[{"check":"a\u001b]0;x","rule":"x](https://evil.example)",
            "title":"t","location":"l","fingerprint":null,
            "severity":"high","lifetime":"long-lived","access":"write","detail":"d\u202Ee","fix":"f"}]}"#;
        let back = parse_report(json).unwrap();
        assert_eq!(back[0].check, report::UNKNOWN_ID);
        assert_eq!(back[0].rule, report::UNKNOWN_ID);
        assert_eq!(back[0].detail.as_deref(), Some("d?e"));

        let bad_severity =
            "{\"schema\":\"heldkeys/v1\",\"findings\":[{\"severity\":\"\\u001b[2J\\u202e\"}]}";
        let err = parse_report(bad_severity).err().unwrap();
        assert!(
            !err.contains('\u{1b}') && !err.contains('\u{202e}'),
            "{err:?}"
        );
        let err = parse_report("{\"schema\":\"\\u001b[31mx\\u202e\",\"findings\":[]}")
            .err()
            .unwrap();
        assert!(!err.contains('\u{202e}'), "{err:?}");
    }

    #[test]
    fn uname_output_is_sanitized() {
        let (os, arch) = parse_uname("Lin\u{1b}[2Jux x86\u{202E}_64").unwrap();
        assert_eq!((os.as_str(), arch.as_str()), ("Lin?[2Jux", "x86?_64"));
        let err = parse_uname("\u{1b}]0;title\u{7}").err().unwrap();
        assert!(!err.contains('\u{1b}') && !err.contains('\u{7}'), "{err:?}");
        let err = parse_platform(&"x".repeat(10_000)).err().unwrap();
        assert!(err.len() < 200, "{}", err.len());
    }

    #[cfg(unix)]
    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(script);
        cmd
    }

    #[cfg(unix)]
    #[test]
    fn commands_are_stopped_at_the_timeout() {
        let limits = Limits {
            timeout: Duration::from_millis(300),
            ..LIMITS
        };
        let started = Instant::now();
        let err = run_limited(sh("sleep 20"), "sleeping", limits)
            .err()
            .unwrap()
            .message;
        assert!(err.contains("did not finish within"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[cfg(unix)]
    #[test]
    fn output_is_capped() {
        let limits = Limits {
            max_stdout: 1024,
            max_stderr: 16,
            ..LIMITS
        };
        let err = run_limited(sh("head -c 100000 /dev/zero"), "flooding", limits)
            .err()
            .unwrap()
            .message;
        assert!(err.contains("wrote more than 1024 bytes"), "{err}");
        assert_eq!(
            run_limited(sh("printf ok"), "printing", limits).unwrap(),
            "ok"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stderr_is_sanitized() {
        let err = run_limited(
            sh(r"printf '\033[2J\033]0;t\007bad\n::error::x\n' >&2; exit 3"),
            "failing",
            LIMITS,
        )
        .err()
        .unwrap()
        .message;
        assert!(err.starts_with("failing failed ("), "{err}");
        for bad in ['\u{1b}', '\u{7}', '\n', '\r'] {
            assert!(!err.contains(bad), "{err:?}");
        }
        assert!(err.contains("bad?::error::x"), "{err:?}");
    }
    #[test]
    fn the_copy_is_run_with_remove_self() {
        let scan_args = vec!["--deep".to_string()];
        assert_eq!(
            remote_argv("/tmp/heldkeys-ab12", &scan_args),
            [
                "/tmp/heldkeys-ab12",
                "--remove-self",
                "scan",
                "--format",
                "json",
                "--fail-on",
                "none",
                "--deep"
            ]
        );
        assert_eq!(
            argv(&docker().exec(&remote_argv("/tmp/heldkeys-ab12", &[]))),
            [
                "docker",
                "exec",
                "agent-box",
                "/tmp/heldkeys-ab12",
                "--remove-self",
                "scan",
                "--format",
                "json",
                "--fail-on",
                "none"
            ]
        );
    }

    #[test]
    fn remove_self_is_recognised_before_double_dash_only() {
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(wants_remove_self(args(&["--remove-self", "scan"])));
        assert!(wants_remove_self(args(&[
            "scan",
            "--format",
            "json",
            "--remove-self"
        ])));
        assert!(!wants_remove_self(args(&["scan", "--format", "json"])));
        assert!(!wants_remove_self(args(&["--", "--remove-self"])));
        assert!(!wants_remove_self(args(&["--remove-selfish"])));
    }

    #[test]
    fn older_binaries_get_a_hint() {
        let m = with_older_binary_hint(
            "running heldkeys in the target failed (exit status: 2): error: unexpected argument '--remove-self' found".into(),
        );
        assert!(m.ends_with("copy a build of this version)"), "{m}");
        assert_eq!(with_older_binary_hint("other".into()), "other");
    }

    /// A stand-in target that is this machine: "remote" paths are files in
    /// a temp dir, `copy` runs `copy_script` with the local and remote paths
    /// as $1 and $2, and `exec` logs its argv to `log`, then runs it (or, for
    /// `rm` with `rm_fails`, fails). Only /bin/sh, never docker or kubectl.
    #[cfg(unix)]
    struct Local {
        log: PathBuf,
        copy_program: &'static str,
        copy_script: &'static str,
        rm_fails: bool,
    }

    #[cfg(unix)]
    impl Local {
        fn new(dir: &Path, copy_script: &'static str) -> Local {
            Local {
                log: dir.join("exec.log"),
                copy_program: "/bin/sh",
                copy_script,
                rm_fails: false,
            }
        }

        fn execs(&self) -> Vec<String> {
            std::fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .map(String::from)
                .collect()
        }
    }

    #[cfg(unix)]
    impl Runner for Local {
        fn copy(&self, local: &Path, remote: &str) -> Command {
            let mut cmd = Command::new(self.copy_program);
            cmd.arg("-c")
                .arg(self.copy_script)
                .arg("sh")
                .arg(local)
                .arg(remote);
            cmd
        }
        fn exec(&self, args: &[&str]) -> Command {
            let mut cmd = sh(r#"printf '%s\n' "$*" >> "$LOG"
                if [ "$1" = rm ] && [ -n "$RM_FAILS" ]; then echo 'rm: not found' >&2; exit 127; fi
                exec "$@""#);
            cmd.arg("sh").args(args).env("LOG", &self.log);
            if self.rm_fails {
                cmd.env("RM_FAILS", "1");
            }
            cmd
        }
        fn remove(&self, remote: &str) -> Command {
            self.exec(&["rm", "-f", remote])
        }
        fn describe(&self) -> String {
            "test target".into()
        }
    }

    /// `copy_run_remove` installs process-wide signal handlers: one test at
    /// a time.
    #[cfg(unix)]
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    fn copy_run_remove_locally(
        target: &Local,
        remote: &Path,
    ) -> (Result<String, String>, Vec<String>) {
        use std::os::unix::fs::PermissionsExt;
        // The "binary" prints its arguments, which become the run's stdout.
        let binary = target.log.with_file_name("fake-heldkeys");
        std::fs::write(&binary, "#!/bin/sh\necho \"$@\"\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let mut warnings = Vec::new();
        let result = copy_run_remove(
            target,
            &binary,
            remote.to_str().unwrap(),
            &[],
            LIMITS,
            &mut warnings,
        );
        (result, warnings)
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_copy_is_still_removed() {
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("heldkeys-ab12");
        // The copy writes part of the file, then fails.
        let target = Local::new(
            dir.path(),
            r#"printf partial > "$2"; echo 'broken pipe' >&2; exit 1"#,
        );
        let (result, _) = copy_run_remove_locally(&target, &remote);
        let err = result.err().unwrap();
        assert!(
            err.starts_with("copying heldkeys into the target failed"),
            "{err}"
        );
        assert!(!err.contains("may be left"), "{err}");
        assert_eq!(target.execs(), [format!("rm -f {}", remote.display())]);
        assert!(!remote.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_copy_that_cannot_be_removed_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("heldkeys-ab12");
        let mut target = Local::new(dir.path(), r#"printf partial > "$2"; exit 1"#);
        target.rm_fails = true;
        let (result, _) = copy_run_remove_locally(&target, &remote);
        let err = result.err().unwrap();
        assert!(
            err.contains("may be left in the test target, and removing it failed")
                && err.contains("rm: not found"),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_copy_tool_that_does_not_start_needs_no_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("heldkeys-ab12");
        let mut target = Local::new(dir.path(), "");
        target.copy_program = "/nonexistent/docker";
        let (result, _) = copy_run_remove_locally(&target, &remote);
        assert!(result.err().unwrap().contains("is not on PATH"));
        assert!(target.execs().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_copy_is_removed_after_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("heldkeys-ab12");
        let target = Local::new(dir.path(), r#"cp "$1" "$2""#);
        let (result, warnings) = copy_run_remove_locally(&target, &remote);
        let path = remote.display();
        assert_eq!(
            result.unwrap(),
            "--remove-self scan --format json --fail-on none\n"
        );
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            target.execs(),
            [
                format!("{path} --remove-self scan --format json --fail-on none"),
                format!("rm -f {path}")
            ]
        );
        assert!(!remote.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_rm_after_a_run_is_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("heldkeys-ab12");
        let mut target = Local::new(dir.path(), r#"cp "$1" "$2""#);
        target.rm_fails = true;
        let (result, warnings) = copy_run_remove_locally(&target, &remote);
        assert!(result.is_ok());
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("could not confirm that") && warnings[0].contains("rm: not found"),
            "{warnings:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_signal_during_the_copy_still_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let remote = dir.path().join("heldkeys-ab12");
        // The copy writes part of the file, then this test process gets
        // SIGTERM (as from `kill` or Ctrl-C) while the copy is still going.
        let target = Local::new(
            dir.path(),
            r#"printf partial > "$2"; kill -TERM "$PPID"; exec sleep 20"#,
        );
        let started = Instant::now();
        let (result, _) = copy_run_remove_locally(&target, &remote);
        let err = result.err().unwrap();
        assert!(err.contains("interrupted"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(target.execs(), [format!("rm -f {}", remote.display())]);
        assert!(!remote.exists());
    }
}
