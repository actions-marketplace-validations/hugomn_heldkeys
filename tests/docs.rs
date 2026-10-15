//! Documentation stays in step with the code: every rule the binary declares
//! has a page and a row in the rules index.

use std::path::{Path, PathBuf};

use heldkeys::checks;

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `(check id, rule id, summary)` for every rule of every check.
fn declared_rules() -> Vec<(&'static str, &'static str, &'static str)> {
    checks::all_checks()
        .into_iter()
        .flat_map(|c| {
            let id = c.id();
            c.rules()
                .iter()
                .map(move |r| (id, r.id, r.summary))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn every_rule_has_a_page_and_an_index_row() {
    let rules_dir: PathBuf = repo().join("docs/rules");
    let index = read(&rules_dir.join("README.md"));
    let mut problems = Vec::new();
    for (check, id, summary) in declared_rules() {
        let page = rules_dir.join(format!("{id}.md"));
        if !page.is_file() {
            problems.push(format!("{id}: no docs/rules/{id}.md"));
            continue;
        }
        let title = read(&page).lines().next().unwrap_or("").to_string();
        if title != format!("# {id}: {summary}") {
            problems.push(format!(
                "{id}: page title is {title:?}, expected \"# {id}: {summary}\""
            ));
        }
        let row = format!("| [{id}]({id}.md) | `{check}` | {summary} |");
        if !index.contains(&row) {
            problems.push(format!("{id}: docs/rules/README.md has no row {row:?}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn readme_rules_tables_list_every_rule() {
    let readme = read(&repo().join("README.md"));
    let mut problems = Vec::new();
    let declared = declared_rules();
    for (check, id, summary) in &declared {
        let row = format!("| [{id}](docs/rules/{id}.md) | `{check}` | {summary} |");
        if !readme.contains(&row) {
            problems.push(format!("{id}: README.md has no row {row:?}"));
        }
    }
    // No row for a rule the binary no longer declares.
    let row_id = regex::Regex::new(r"(?m)^\| \[(HK-[A-Z0-9]+-\d+)\]\(docs/rules/").unwrap();
    for cap in row_id.captures_iter(&readme) {
        let id = &cap[1];
        if !declared.iter().any(|(_, d, _)| *d == id) {
            problems.push(format!(
                "{id}: README.md lists a rule the binary does not declare"
            ));
        }
    }
    // The counts in the collapsed headings. A check that runs in both modes
    // (`git-config`) is listed once, with the local rules.
    let local = checks::local_checks();
    let count = |checks: &[Box<dyn checks::Check>]| -> usize {
        checks.iter().map(|c| c.rules().len()).sum()
    };
    let ci_only: Vec<Box<dyn checks::Check>> = checks::ci_checks()
        .into_iter()
        .filter(|c| !local.iter().any(|l| l.id() == c.id()))
        .collect();
    for (label, n) in [
        ("Local rules", count(&local)),
        ("CI rules", count(&ci_only)),
    ] {
        let heading = format!("<b>{label}</b> ({n})");
        if !readme.contains(&heading) {
            problems.push(format!("README.md has no heading {heading:?}"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Markdown files whose relative links must resolve.
fn markdown_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = [
        "README.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "SPEC.md",
    ]
    .iter()
    .map(|f| repo().join(f))
    .collect();
    let mut dirs = vec![repo().join("docs"), repo().join("skill")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "md") {
                files.push(path);
            }
        }
    }
    files
}

/// The text a reader sees: no HTML comments, no fenced code blocks.
fn visible_text(markdown: &str) -> String {
    let comments = regex::Regex::new(r"(?s)<!--.*?-->").unwrap();
    let without_comments = comments.replace_all(markdown, "");
    let mut out = String::new();
    let mut in_fence = false;
    for line in without_comments.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// GitHub's anchor for a heading: lowercase, punctuation dropped, spaces to hyphens.
fn heading_anchors(markdown: &str) -> Vec<String> {
    visible_text(markdown)
        .lines()
        .filter_map(|l| l.strip_prefix('#'))
        .map(|h| {
            h.trim_start_matches('#')
                .trim()
                .to_lowercase()
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
                .map(|c| if c == ' ' { '-' } else { c })
                .collect()
        })
        .collect()
}

#[test]
fn relative_links_resolve() {
    let link = regex::Regex::new(r#"\]\(([^)\s]+)\)|(?:src|href)="([^"]+)""#).unwrap();
    let mut problems = Vec::new();
    for file in markdown_files() {
        let text = read(&file);
        for cap in link.captures_iter(&visible_text(&text)) {
            let target = cap.get(1).or(cap.get(2)).unwrap().as_str();
            if target.contains("://") || target.starts_with("mailto:") {
                continue;
            }
            let (path, anchor) = target.split_once('#').unwrap_or((target, ""));
            let resolved = if path.is_empty() {
                file.clone()
            } else {
                file.parent().unwrap().join(path)
            };
            let shown = file.strip_prefix(repo()).unwrap().display().to_string();
            if !resolved.exists() {
                problems.push(format!("{shown}: {target} does not exist"));
                continue;
            }
            let is_markdown = resolved.extension().is_some_and(|e| e == "md");
            if !anchor.is_empty()
                && is_markdown
                && !heading_anchors(&read(&resolved))
                    .iter()
                    .any(|a| a == anchor)
            {
                problems.push(format!("{shown}: no heading for #{anchor} in {target}"));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
