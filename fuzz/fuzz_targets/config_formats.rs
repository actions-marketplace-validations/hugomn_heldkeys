//! The small readers for config formats found in a home directory or a
//! project: TOML (`.heldkeys.toml`, credentials files), JSON with comments
//! (MCP configs), INI (cloud CLI credentials), plus the ignore-rule and
//! baseline parsers built on them.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = heldkeys::toml_subset::parse(text);
        let _ = heldkeys::jsonc::parse(text);
        let _ = heldkeys::ini::parse(text);
        let _ = heldkeys::config::parse(text, "fuzz");
        let _ = heldkeys::baseline::parse(text, "fuzz");
    }
});
