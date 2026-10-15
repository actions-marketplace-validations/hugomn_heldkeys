//! Making names from config files safe to show in a finding.
//!
//! Locations and details quote things like section names, registry keys,
//! user names and helper commands. Those usually are not secrets, but people
//! paste credentials into them (`[credential "https://alice:pw@host"]`,
//! `//user:pw@registry/`, `helper = !f() { echo password=...; }; f`). The
//! report layer has its own last-resort scrub; these helpers make sure the
//! checks never hand it a secret in the first place.

use std::path::Path;

use crate::redact;
use crate::rules;

/// Removes the `user:password@` part from every URL in `s`, including
/// passwords with an unencoded `/`, `?` or `@` in them and encoded colons
/// (`redact::find_userinfo`).
pub fn strip_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for u in redact::find_userinfo(s) {
        out.push_str(&s[last..u.start]);
        last = u.end + 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Replaces every token of a known format in `s` by its fingerprint, or by
/// `***` when it has none.
pub fn mask_tokens(s: &str) -> String {
    let mut out = String::new();
    let mut last = 0;
    for m in rules::find_tokens(s) {
        out.push_str(&s[last..m.start]);
        let token = &s[m.start..m.end];
        out.push_str(&redact::fingerprint(token).unwrap_or_else(|| "***".to_string()));
        last = m.end;
    }
    out.push_str(&s[last..]);
    out
}

/// A name from a config file, safe to show: no URL userinfo, no tokens and
/// no control characters.
pub fn label(s: &str) -> String {
    mask_tokens(&strip_userinfo(s))
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// `scheme://host[:port]` of a URL, without userinfo, path or query. `None`
/// if it does not look like a URL with a plausible host.
pub fn url_origin(url: &str) -> Option<String> {
    let url = strip_userinfo(url.trim());
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    {
        return None;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    is_host(host).then(|| format!("{scheme}://{host}"))
}

/// A host name or address, optionally with a numeric port (`host:8080`,
/// `[::1]:8080`), and not a token of a known format.
pub fn is_host(s: &str) -> bool {
    let (name, port) = match s.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((ip, port)) if ip.chars().all(|c| c.is_ascii_hexdigit() || c == ':') => {
                ("ipv6", port)
            }
            _ => return false,
        },
        None => match s.rsplit_once(':') {
            Some((name, _)) => (name, &s[name.len()..]),
            None => (s, ""),
        },
    };
    let port_ok = port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    !name.is_empty()
        && s.len() <= 255
        && port_ok
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
        && rules::find_tokens(s).is_empty()
}

/// The program a command line runs, as a bare file name (`/usr/bin/aws
/// --profile x` gives `aws`), or `None` if the first word does not look like
/// a program name. Arguments are never shown: they can carry secrets, and an
/// inline shell snippet (`!f() { echo password=...; }; f`) can be a secret.
pub fn program_name(command: &str) -> Option<String> {
    let command = command.trim().trim_start_matches('!');
    // A quoted program path may contain spaces: "/opt/my tool/bin/x" args.
    let first = match command.chars().next() {
        Some(q @ ('"' | '\'')) => command[1..].split(q).next()?,
        _ => command.split_whitespace().next()?,
    };
    let name = Path::new(first).file_name()?.to_string_lossy().into_owned();
    let plausible = name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
        && rules::find_tokens(&name).is_empty();
    plausible.then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userinfo_is_removed() {
        assert_eq!(
            strip_userinfo("https://alice:pw@github.example.com/x"),
            "https://github.example.com/x"
        );
        assert_eq!(
            strip_userinfo("//eve:pw@registry.example.com/"),
            "//registry.example.com/"
        );
        assert_eq!(strip_userinfo("a https://t@h b"), "a https://h b");
        assert_eq!(strip_userinfo("no url here"), "no url here");
        // Passwords with an unencoded `/`, and an encoded colon.
        assert_eq!(
            strip_userinfo("https://user:pa/ssFAKEcred01@host.example.com"),
            "https://host.example.com"
        );
        assert_eq!(
            strip_userinfo("//u:pa/ssFAKEnpm05@registry.example.com/"),
            "//registry.example.com/"
        );
        assert_eq!(
            strip_userinfo("https://user%3AFAKEpct03@host.example.com/x"),
            "https://host.example.com/x"
        );
        assert_eq!(
            strip_userinfo("https://registry.npmjs.org:443/@scope/pkg"),
            "https://registry.npmjs.org:443/@scope/pkg"
        );
    }

    #[test]
    fn tokens_are_masked() {
        assert_eq!(
            mask_tokens("name ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKE000123 end"),
            "name ghp_…123 end"
        );
        assert_eq!(label("x\u{1b}[31m"), "x?[31m");
    }

    #[test]
    fn origins() {
        assert_eq!(
            url_origin("https://x-access-token:tok@github.com/o/r.git").as_deref(),
            Some("https://github.com")
        );
        assert_eq!(
            url_origin("http://h.example:8080?a=b").as_deref(),
            Some("http://h.example:8080")
        );
        assert_eq!(url_origin("not a url"), None);
        assert_eq!(
            url_origin("https://u:ab/cdFAKEremote03@github.com/o/r.git").as_deref(),
            Some("https://github.com")
        );
        assert_eq!(
            url_origin("https://[::1]:8443/x").as_deref(),
            Some("https://[::1]:8443")
        );
        assert!(!is_host("host:FAKEpw"));
        assert!(is_host("h.example:22"));
        assert_eq!(url_origin("https://bad host/"), None);
    }

    #[test]
    fn program_names() {
        assert_eq!(program_name("/usr/bin/aws --x y").as_deref(), Some("aws"));
        assert_eq!(
            program_name("!gh auth git-credential").as_deref(),
            Some("gh")
        );
        assert_eq!(
            program_name("\"/opt/my tool/bin/x\" y").as_deref(),
            Some("x")
        );
        assert_eq!(program_name("!f(){echo${IFS}password=pw;};f"), None);
        assert_eq!(program_name("tool:secret"), None);
        assert_eq!(program_name(""), None);
    }
}
