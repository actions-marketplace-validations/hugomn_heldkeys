//! The YAML reader behind workflow, kubeconfig and config parsing. It must
//! return None or an error for any input, never panic or blow up on aliases.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = heldkeys::yaml::load(text);
        let _ = heldkeys::yaml::load_checked(text);
    }
});
