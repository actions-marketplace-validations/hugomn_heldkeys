// The copy of tests/fixtures that every test reads. Included with include!
// by the integration tests (tests/common/mod.rs) and by the unit tests
// (src/checks/mod.rs), so paths are spelled out in full.
//
// Fake credentials in tests/fixtures are committed as `{{fake:PREFIX|REST}}`,
// so secret scanners run on this repository do not flag test data. The copy
// has every marker replaced by `PREFIXREST`. It is written once per content
// hash under the system temp directory, and moved into place in one rename,
// so test processes running in parallel share it safely.

/// The root of the copy of tests/fixtures, with every marker resolved.
pub fn fixtures_root() -> std::path::PathBuf {
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures");
        materialise_fixtures(&src)
    })
    .clone()
}

/// Replaces every `{{fake:...}}` marker in `text` with its value, dropping
/// the `|` that separates a token's public prefix from the rest.
pub fn resolve_fake_markers(text: &str) -> String {
    const OPEN: &str = "{{fake:";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(OPEN) {
        out.push_str(&rest[..start]);
        let after = &rest[start + OPEN.len()..];
        let end = after.find("}}").expect("unterminated {{fake: marker");
        out.extend(after[..end].chars().filter(|&c| c != '|'));
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

fn materialise_fixtures(src: &std::path::Path) -> std::path::PathBuf {
    use std::hash::{Hash, Hasher};

    let mut entries = Vec::new();
    collect_fixture_entries(src, src, &mut entries);
    entries.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for (rel, is_dir) in &entries {
        rel.hash(&mut hasher);
        if !is_dir {
            std::fs::read(src.join(rel)).unwrap().hash(&mut hasher);
        }
    }
    let hash = hasher.finish();

    // Canonical, because on macOS the temp directory is behind a symlink
    // (/var -> /private/var) and some checks resolve paths.
    let base = std::env::temp_dir().canonicalize().unwrap();
    let dir = base.join(format!("heldkeys-fixtures-{hash:016x}"));
    if dir.is_dir() {
        return dir;
    }
    let tmp = base.join(format!(
        "heldkeys-fixtures-{hash:016x}.{}.tmp",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    for (rel, is_dir) in &entries {
        let target = tmp.join(rel);
        if *is_dir {
            std::fs::create_dir_all(&target).unwrap();
            continue;
        }
        let bytes = std::fs::read(src.join(rel)).unwrap();
        let bytes = match String::from_utf8(bytes) {
            Ok(text) => resolve_fake_markers(&text).into_bytes(),
            Err(e) => e.into_bytes(),
        };
        std::fs::write(&target, bytes).unwrap();
    }
    // Another process may have won the race; its copy is identical.
    if std::fs::rename(&tmp, &dir).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    assert!(dir.is_dir(), "could not create {}", dir.display());
    dir
}

/// Every directory and file under `dir`, relative to `root`, directories
/// first so they exist before their files are written.
fn collect_fixture_entries(
    root: &std::path::Path,
    dir: &std::path::Path,
    out: &mut Vec<(std::path::PathBuf, bool)>,
) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let rel = path.strip_prefix(root).unwrap().to_path_buf();
        if path.is_dir() {
            out.push((rel, true));
            collect_fixture_entries(root, &path, out);
        } else {
            out.push((rel, false));
        }
    }
}
