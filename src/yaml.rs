//! YAML loading, kept in one place so the parser crate can be swapped easily.
//!
//! Crate choice: `serde_yaml` is deprecated and archived by its author (2024).
//! Its forks either keep the transpiled-C `unsafe-libyaml` core
//! (`serde_yaml_ng`, `serde_norway`) or have had soundness and maintenance
//! problems (`serde_yml`). We only read config trees (kubeconfig, gh
//! `hosts.yml`, GitHub workflows) and never need serde mapping, so we use
//! `yaml-rust2`: maintained, pure safe Rust, YAML 1.2. YAML 1.2 matters for
//! workflows: the key `on:` stays the string "on" instead of turning into the
//! boolean `true` as it does under YAML 1.1. `saphyr` (same maintainers) is the
//! newer successor, but its API is still changing.

use std::collections::BTreeMap;

use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::Marker;

pub use yaml_rust2::Yaml;

/// Parses the first document of `text`, or `None` if it is not valid YAML
/// or is over the size budget (see `load_checked`).
pub fn load(text: &str) -> Option<Yaml> {
    load_checked(text).ok()
}

/// Most aliases (`*name`) a file may use. Real workflows and kubeconfigs use
/// a handful at most.
pub const MAX_ALIASES: usize = 100;
/// Most nodes a file may have once every alias is expanded.
pub const MAX_NODES: usize = 50_000;
/// Most bytes of scalar text a file may hold once every alias is expanded.
/// Files are read up to 1 MiB, so only alias expansion can get near this.
pub const MAX_EXPANDED_BYTES: usize = 8 * 1024 * 1024;
/// Deepest nesting of mappings and sequences.
pub const MAX_DEPTH: usize = 64;

/// Parses the first document of `text`, or says why not.
///
/// `yaml-rust2` expands every alias into a full copy of its anchor, so a
/// 1 KB file of nested aliases ("billion laughs") can expand to gigabytes,
/// and so can a few aliases to one long anchored string. Workflow files come
/// from pull requests, so before building the tree we run the parser once
/// over the event stream, which costs memory in proportion to the text only,
/// and refuse files that would expand past `MAX_NODES` nodes or
/// `MAX_EXPANDED_BYTES` bytes of scalar text, use more than `MAX_ALIASES`
/// aliases, or nest deeper than `MAX_DEPTH`. The loader builds every
/// document in the stream, so the budget covers the whole stream, and each
/// document counts as a node: a file of many small documents is bounded too.
pub fn load_checked(text: &str) -> Result<Yaml, String> {
    let mut budget = Budget::default();
    Parser::new_from_str(text)
        .load(&mut budget, true)
        .map_err(|e| format!("not valid YAML: {e}"))?;
    if let Some(problem) = budget.exceeded {
        return Err(problem);
    }
    yaml_rust2::YamlLoader::load_from_str(text)
        .map_err(|e| format!("not valid YAML: {e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| "empty YAML document".to_string())
}

/// Expanded size of a node: how many nodes and how many bytes of scalar text
/// (keys included) it stands for once aliases are expanded.
#[derive(Clone, Copy, Default)]
struct Size {
    nodes: usize,
    bytes: usize,
}

impl Size {
    fn add(&mut self, other: Size) {
        self.nodes = self.nodes.saturating_add(other.nodes);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }
}

/// Counts what the YAML tree would contain once aliases are expanded. Each
/// open collection keeps its expanded size so far; when an anchored node
/// ends, its size is remembered, and an alias to it adds that size again.
/// A merge key (`<<: *base`) is an ordinary key with an alias value here, so
/// the merged mapping is counted at its full size like any other alias.
#[derive(Default)]
struct Budget {
    /// Expanded size of each anchored node, by anchor id. The parser numbers
    /// anchors across the whole stream, so ids from different documents never
    /// collide.
    anchored: std::collections::HashMap<usize, Size>,
    /// Open collections: (anchor id, expanded size so far).
    open: Vec<(usize, Size)>,
    aliases: usize,
    /// Expanded size seen so far, in the whole stream.
    total: Size,
    exceeded: Option<String>,
}

impl Budget {
    /// `size` more expanded nodes and bytes were seen.
    fn count(&mut self, size: Size) {
        self.total.add(size);
        if self.total.nodes > MAX_NODES {
            self.exceed(format!(
                "YAML expands to more than {MAX_NODES} nodes (alias bomb?); not analysed"
            ));
        }
        if self.total.bytes > MAX_EXPANDED_BYTES {
            self.exceed(format!(
                "YAML expands to more than {} MiB of text (alias bomb?); not analysed",
                MAX_EXPANDED_BYTES / (1024 * 1024)
            ));
        }
    }

    /// A node of expanded `size` ended, anchored as `anchor` (0 = none).
    fn finish(&mut self, anchor: usize, size: Size) {
        if anchor != 0 {
            self.anchored.insert(anchor, size);
        }
        if let Some((_, parent)) = self.open.last_mut() {
            parent.add(size);
        }
    }

    /// Keeps the first problem found.
    fn exceed(&mut self, problem: String) {
        if self.exceeded.is_none() {
            self.exceeded = Some(problem);
        }
    }
}

impl MarkedEventReceiver for Budget {
    fn on_event(&mut self, ev: Event, _mark: Marker) {
        const ONE_NODE: Size = Size { nodes: 1, bytes: 0 };
        match ev {
            Event::DocumentStart => self.count(ONE_NODE),
            Event::Scalar(value, _, anchor, _) => {
                let size = Size {
                    nodes: 1,
                    bytes: value.len(),
                };
                self.count(size);
                self.finish(anchor, size);
            }
            Event::Alias(id) => {
                self.aliases += 1;
                if self.aliases > MAX_ALIASES {
                    self.exceed(format!(
                        "YAML uses more than {MAX_ALIASES} aliases; not analysed"
                    ));
                }
                let size = self.anchored.get(&id).copied().unwrap_or(ONE_NODE);
                self.count(size);
                self.finish(0, size);
            }
            Event::SequenceStart(anchor, _) | Event::MappingStart(anchor, _) => {
                self.count(ONE_NODE);
                self.open.push((anchor, ONE_NODE));
                if self.open.len() > MAX_DEPTH {
                    self.exceed(format!(
                        "YAML nests deeper than {MAX_DEPTH} levels; not analysed"
                    ));
                }
            }
            Event::SequenceEnd | Event::MappingEnd => {
                if let Some((anchor, size)) = self.open.pop() {
                    self.finish(anchor, size);
                }
            }
            _ => {}
        }
    }
}

/// `node[key]` as a string, if it is a non-empty string.
pub fn str_at<'a>(node: &'a Yaml, key: &str) -> Option<&'a str> {
    node[key].as_str().filter(|s| !s.is_empty())
}

/// `node[key]` as a list, or an empty slice.
pub fn list_at<'a>(node: &'a Yaml, key: &str) -> &'a [Yaml] {
    node[key].as_vec().map(Vec::as_slice).unwrap_or(&[])
}

/// True if `node[key]` exists (is not missing or null).
pub fn has(node: &Yaml, key: &str) -> bool {
    !node[key].is_badvalue() && !node[key].is_null()
}

/// The `(key, value)` pairs of a mapping whose keys are strings.
pub fn entries(node: &Yaml) -> Vec<(&str, &Yaml)> {
    match node.as_hash() {
        Some(hash) => hash
            .iter()
            .filter_map(|(k, v)| k.as_str().map(|k| (k, v)))
            .collect(),
        None => Vec::new(),
    }
}

/// Line numbers (1-based) of the nodes in the first document of `text`,
/// keyed by a dotted path such as `jobs.build.steps[2]` or
/// `jobs.build.steps[2].uses`. A mapping value is recorded at the line of its
/// key. Used to give findings a `file:line` location; `Yaml` itself does not
/// keep positions. Returns an empty map if the text is not valid YAML.
pub fn line_index(text: &str) -> BTreeMap<String, usize> {
    let mut index = LineIndex::default();
    if Parser::new_from_str(text).load(&mut index, false).is_err() {
        return BTreeMap::new();
    }
    index.lines
}

/// Where the parser is: inside a mapping (waiting for a key, or for the value
/// of `key`) or inside a sequence (at item `next`).
enum Frame {
    Map { path: String, key: Option<String> },
    Seq { path: String, next: usize },
}

#[derive(Default)]
struct LineIndex {
    frames: Vec<Frame>,
    lines: BTreeMap<String, usize>,
}

impl LineIndex {
    /// A node starts here. Returns its path, or `None` if it is a mapping key.
    fn start_node(&mut self, scalar: Option<&str>, line: usize) -> Option<String> {
        match self.frames.last_mut() {
            None => Some(String::new()),
            Some(Frame::Map { path, key }) => match key {
                None => {
                    // Keys that are not plain strings (rare) get a placeholder.
                    let k = scalar.unwrap_or("?").to_string();
                    let full = join(path, &k);
                    self.lines.entry(full).or_insert(line);
                    *key = Some(k);
                    None
                }
                Some(k) => Some(join(path, k)),
            },
            Some(Frame::Seq { path, next }) => {
                let full = format!("{path}[{next}]");
                self.lines.entry(full.clone()).or_insert(line);
                Some(full)
            }
        }
    }

    /// A value node ended: the parent moves on to its next key or item.
    fn end_node(&mut self) {
        match self.frames.last_mut() {
            Some(Frame::Map { key, .. }) => *key = None,
            Some(Frame::Seq { next, .. }) => *next += 1,
            None => {}
        }
    }
}

impl MarkedEventReceiver for LineIndex {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        let line = mark.line();
        match ev {
            Event::Scalar(value, ..) => {
                if self.start_node(Some(&value), line).is_some() {
                    self.end_node();
                }
            }
            Event::Alias(_) => {
                if self.start_node(None, line).is_some() {
                    self.end_node();
                }
            }
            Event::MappingStart(..) | Event::SequenceStart(..) => {
                let is_map = matches!(ev, Event::MappingStart(..));
                // A collection used as a mapping key gets a placeholder path.
                let path = self
                    .start_node(None, line)
                    .unwrap_or_else(|| "?".to_string());
                self.frames.push(if is_map {
                    Frame::Map { path, key: None }
                } else {
                    Frame::Seq { path, next: 0 }
                });
            }
            Event::MappingEnd | Event::SequenceEnd => {
                self.frames.pop();
                self.end_node();
            }
            _ => {}
        }
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{path}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_key_stays_a_string() {
        let doc = load("on:\n  push: {}\n").unwrap();
        assert!(has(&doc, "on"));
    }

    #[test]
    fn helpers() {
        let doc = load("a: x\nb: [1, 2]\nc:\n  d: e\n").unwrap();
        assert_eq!(str_at(&doc, "a"), Some("x"));
        assert_eq!(list_at(&doc, "b").len(), 2);
        assert_eq!(entries(&doc["c"]).len(), 1);
        assert!(!has(&doc, "missing"));
        assert!(load(": : :\n  - [").is_none());
    }

    /// `levels` levels of `&aN [*aN-1 x10]`: 10^levels strings once expanded.
    fn alias_bomb(levels: usize) -> String {
        let mut text = String::from(
            "on: issue_comment\na0: &a0 [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n",
        );
        for i in 1..=levels {
            let items = vec![format!("*a{}", i - 1); 10].join(",");
            text.push_str(&format!("a{i}: &a{i} [{items}]\n"));
        }
        text.push_str(&format!("jobs:\n  j:\n    env: *a{levels}\n"));
        text
    }

    #[test]
    fn alias_bombs_are_refused_before_expansion() {
        // 4 levels: 40 aliases, but 10^5 strings once expanded.
        let err = load_checked(&alias_bomb(4)).unwrap_err();
        assert!(err.contains("expands to more than"), "{err}");
        // 6 levels would take gigabytes; it must fail fast instead.
        assert!(load_checked(&alias_bomb(6)).is_err());
        assert!(load(&alias_bomb(6)).is_none());
        // A couple of ordinary anchors are fine.
        let ok = "base: &b {runs-on: x}\njobs:\n  a: *b\n  b: *b\n";
        assert!(load_checked(ok).is_ok());
    }

    #[test]
    fn too_many_aliases_or_too_deep() {
        let mut many = String::from("a: &a x\nl:\n");
        for _ in 0..=MAX_ALIASES {
            many.push_str("  - *a\n");
        }
        assert!(load_checked(&many).unwrap_err().contains("aliases"));
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert!(load_checked(&deep).unwrap_err().contains("deeper"));
        let fine = format!("{}{}", "[".repeat(10), "]".repeat(10));
        assert!(load_checked(&fine).is_ok());
    }

    #[test]
    fn a_bomb_in_a_later_document_is_refused_too() {
        let text = format!("a: 1\n---\n{}", alias_bomb(6));
        assert!(load_checked(&text).is_err());
    }

    /// One anchored string of `len` bytes, then `levels` levels of ten
    /// aliases each: `len * 10^levels` bytes once expanded, few nodes.
    fn long_string_bomb(len: usize, levels: usize) -> String {
        let mut text = format!("on: issue_comment\na0: &a0 \"{}\"\n", "A".repeat(len));
        for i in 1..=levels {
            let items = vec![format!("*a{}", i - 1); 10].join(",");
            text.push_str(&format!("a{i}: &a{i} [{items}]\n"));
        }
        text.push_str(&format!("jobs:\n  j:\n    env: {{X: *a{levels}}}\n"));
        text
    }

    #[test]
    fn long_anchored_strings_are_refused_by_expanded_size() {
        // 100 KB anchored string, 30 aliases, 1,111 nodes: 100 MB expanded.
        let started = std::time::Instant::now();
        let err = load_checked(&long_string_bomb(100_000, 3)).unwrap_err();
        assert!(err.contains("MiB of text"), "{err}");
        let err = load_checked(&long_string_bomb(100_000, 4)).unwrap_err();
        assert!(err.contains("MiB of text"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        // 100 KB x 10 = 1 MB expanded is fine.
        assert!(load_checked(&long_string_bomb(100_000, 1)).is_ok());
    }

    #[test]
    fn many_aliases_to_a_long_string_add_up() {
        // 90 aliases, no nesting: 90 x 100 KB = 9 MB expanded.
        let mut text = format!("a: &a \"{}\"\nl:\n", "B".repeat(100_000));
        for _ in 0..90 {
            text.push_str("  - *a\n");
        }
        assert!(load_checked(&text).unwrap_err().contains("MiB of text"));
    }

    #[test]
    fn merge_keys_count_at_their_full_size() {
        // `<<: *m` is kept as an ordinary key whose value is a copy of the
        // anchored mapping, so it counts like any alias.
        let mut text = format!("m0: &m0 {{k: \"{}\"}}\n", "C".repeat(100_000));
        for i in 1..=3 {
            let keys: Vec<String> = (0..10).map(|n| format!("k{n}: *m{}", i - 1)).collect();
            text.push_str(&format!(
                "m{i}: &m{i} {{<<: *m{}, {}}}\n",
                i - 1,
                keys.join(", ")
            ));
        }
        text.push_str("jobs:\n  j:\n    <<: *m3\n");
        assert!(load_checked(&text).unwrap_err().contains("MiB of text"));
        // A plain merge key still loads.
        let ok = "base: &b {runs-on: x}\njobs:\n  a:\n    <<: *b\n    steps: []\n";
        let doc = load_checked(ok).unwrap();
        assert!(has(&doc["jobs"]["a"], "<<"));
    }

    #[test]
    fn many_small_documents_are_bounded() {
        // Each document is tiny and under every limit on its own; the budget
        // is for the whole stream.
        let doc = "a: &a [x, x, x, x, x, x, x, x, x, x]\nb: [*a, *a, *a, *a, *a]\n";
        let mut text = String::new();
        for _ in 0..30 {
            text.push_str("---\n");
            text.push_str(doc);
        }
        assert!(load_checked(&text).unwrap_err().contains("aliases"));
        let empty = "---\n".repeat(MAX_NODES + 1);
        assert!(load_checked(&empty).unwrap_err().contains("nodes"));
        assert!(load_checked(&"---\na: 1\n".repeat(100)).is_ok());
    }

    #[test]
    fn line_numbers_of_nodes() {
        let text = "on: push\njobs:\n  build:\n    steps:\n      - uses: a/b@v1\n      - name: x\n        run: |\n          echo hi\n      - {uses: c/d@v2}\n";
        let lines = line_index(text);
        assert_eq!(lines["on"], 1);
        assert_eq!(lines["jobs.build"], 3);
        assert_eq!(lines["jobs.build.steps[0]"], 5);
        assert_eq!(lines["jobs.build.steps[0].uses"], 5);
        assert_eq!(lines["jobs.build.steps[1]"], 6);
        assert_eq!(lines["jobs.build.steps[1].run"], 7);
        assert_eq!(lines["jobs.build.steps[2]"], 9);
        assert!(line_index("a: [").is_empty());
    }
}
