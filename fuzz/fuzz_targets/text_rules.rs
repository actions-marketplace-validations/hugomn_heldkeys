//! Token rules, redaction and output sanitising on arbitrary text: the code
//! that decides what counts as a credential and what may be printed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = heldkeys::rules::find_tokens(text);
        let _ = heldkeys::rules::match_token(text);
        let _ = heldkeys::rules::looks_like_placeholder(text);
        let _ = heldkeys::redact::scrub(text);
        let _ = heldkeys::redact::find_userinfo(text);
        let _ = heldkeys::redact::decode_separators(text);
        let _ = heldkeys::redact::fingerprint(text);
        let _ = heldkeys::sanitize::sanitize(text);
        let _ = heldkeys::sanitize::clip(text);
    }
});
