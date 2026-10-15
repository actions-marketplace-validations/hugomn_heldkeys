//! heldkeys: which credentials could a hijacked AI agent use from here?
//!
//! The binary (`main.rs`) parses flags and wires these modules together:
//!
//! - `context`: what the checks may look at (home, cwd, environment).
//! - `checks`: one file per kind of exposure, all implementing `Check`.
//! - `rules` and `redact`: what a credential looks like, and how much of it
//!   may be shown (never more than 4 leading + 3 trailing characters).
//! - `sanitize`: keeps terminal escapes, bidi controls and workflow commands
//!   from untrusted files out of every output.
//! - `finding`: the data model.
//! - `report`: text, JSON, Markdown and SARIF output.
//! - `sandbox`: `preflight`, and running the binary inside a container or pod.
//! - `jsonc`, `toml_subset`, `ini`, `yaml`: small readers for config formats.

pub mod checks;
pub mod context;
pub mod finding;
pub mod fsutil;
pub mod ini;
pub mod jsonc;
pub mod redact;
pub mod report;
pub mod rules;
pub mod sandbox;
pub mod sanitize;
pub mod toml_subset;
pub mod yaml;

/// The tool's name, taken from Cargo.toml so a rename touches one place.
pub const TOOL_NAME: &str = env!("CARGO_PKG_NAME");
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Version tag of the JSON output, e.g. "heldkeys/v1".
pub const JSON_SCHEMA: &str = concat!(env!("CARGO_PKG_NAME"), "/v1");
