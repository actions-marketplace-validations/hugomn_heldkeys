//! The JSON report a container or pod sends back to `--docker` and `--kube`.
//! The remote side is untrusted, so the parser must reject anything odd
//! without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = heldkeys::sandbox::remote::parse_report(text);
    }
});
