//! `heldkeys scan --docker <container>` and `heldkeys scan --kube <pod>`.
//!
//! Steps, all through `docker` or `kubectl` on PATH:
//!
//! 1. Find the target's OS and CPU (`uname -sm` inside it, or the image or
//!    node metadata when the image has no `uname`). Only Linux is supported.
//! 2. Check that the binary we are about to copy is a Linux binary for that
//!    CPU. Usually this binary is a macOS or glibc build, so `--binary` points
//!    at a static musl build instead (see docs/building.md).
//! 3. Copy it to `/tmp/heldkeys-<random>` in the target.
//! 4. Run it there with `scan --format json --fail-on none`.
//! 5. Remove the copy, whatever happened in step 4.
//! 6. Parse the JSON back into findings, so the caller renders them locally
//!    in any format and applies `--fail-on` here.
//!
//! Every command is built with `Command` and explicit arguments, never a
//! shell string, so names cannot inject shell syntax.
//!
//! The target may be hostile. Every command is killed after
//! `COMMAND_TIMEOUT`, its output is capped (`MAX_STDOUT`, `MAX_STDERR`), and
//! every string read back from it (uname output, stderr, the JSON report)
//! goes through `sanitize` before it can reach our stdout or stderr.

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
    run(
        target.copy(&binary, &remote_path),
        "copying heldkeys into the target",
    )?;

    let mut args = vec![
        remote_path.as_str(),
        "scan",
        "--format",
        "json",
        "--fail-on",
        "none",
    ];
    args.extend(scan_args.iter().map(String::as_str));
    let output = run(target.exec(&args), "running heldkeys in the target");

    // Always clean up, even when the run failed.
    if let Err(e) = run(
        target.exec(&["rm", "-f", &remote_path]),
        "removing the copy",
    ) {
        warnings.push(format!(
            "could not remove {remote_path} from the {}: {e}",
            target.describe()
        ));
    }

    let findings = parse_report(&output?)?;
    Ok(RemoteScan { findings, warnings })
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
}

const LIMITS: Limits = Limits {
    timeout: COMMAND_TIMEOUT,
    max_stdout: MAX_STDOUT,
    max_stderr: MAX_STDERR,
};

/// Runs a command with no stdin and returns its stdout, or an error with
/// its (shortened, sanitized) stderr.
fn run(cmd: Command, what: &str) -> Result<String, String> {
    run_limited(cmd, what, LIMITS)
}

/// `run` with explicit limits. The child's stdout and stderr are read on
/// their own threads (so neither pipe can fill up and stall it) while this
/// thread waits for it to exit, and kills it at the deadline.
fn run_limited(mut cmd: Command, what: &str, limits: Limits) -> Result<String, String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => format!("{what}: {program} is not on PATH"),
            _ => format!("{what}: cannot run {program}: {e}"),
        })?;
    let stdout = read_capped(child.stdout.take(), limits.max_stdout);
    let stderr = read_capped(child.stderr.take(), limits.max_stderr);
    let status = wait_until(&mut child, Instant::now() + limits.timeout)
        .map_err(|e| format!("{what}: waiting for {program}: {e}"))?;
    let Some(status) = status else {
        // The readers are left behind: a grandchild may still hold the pipes.
        return Err(format!(
            "{what}: {program} did not finish within {} seconds and was stopped",
            limits.timeout.as_secs()
        ));
    };
    let (stdout, stdout_cut) = stdout.join().unwrap_or_default();
    let (stderr, _) = stderr.join().unwrap_or_default();
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return Err(format!(
            "{what} failed ({status}): {}",
            shown(stderr.trim(), STDERR_SHOWN)
        ));
    }
    if stdout_cut {
        return Err(format!(
            "{what}: {program} wrote more than {} bytes",
            limits.max_stdout
        ));
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

/// Waits for `child` to exit, or kills it at `deadline` and returns `None`.
fn wait_until(child: &mut Child, deadline: Instant) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(20));
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
        assert_eq!(
            argv(&t.exec(&["rm", "-f", "/tmp/heldkeys-ab12"])),
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
            .unwrap();
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
            .unwrap();
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
        .unwrap();
        assert!(err.starts_with("failing failed ("), "{err}");
        for bad in ['\u{1b}', '\u{7}', '\n', '\r'] {
            assert!(!err.contains(bad), "{err:?}");
        }
        assert!(err.contains("bad?::error::x"), "{err:?}");
    }
}
