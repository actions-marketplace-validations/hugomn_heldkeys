//! Running heldkeys where the agent runs.
//!
//! Sandboxes change what is visible: a container sees its own environment,
//! mounts and service account, not the host's. So the scan has to happen
//! inside the sandbox, and these modules make that easy:
//!
//! - `preflight`: the one-line PASS/FAIL verdict for container entrypoints and
//!   sandbox start hooks (`heldkeys preflight --fail-on high`).
//! - `remote`: `heldkeys scan --docker <container>` and `--kube <pod>`, which
//!   copy this binary into a running container or pod, run it there, read its
//!   JSON report back and remove the copy. These are the only code paths that
//!   touch anything outside this process, and only because the user named the
//!   target explicitly.
//! - `elf`: just enough ELF parsing to tell whether a binary can run in a
//!   Linux target before we copy it there.

pub mod elf;
pub mod preflight;
pub mod remote;
