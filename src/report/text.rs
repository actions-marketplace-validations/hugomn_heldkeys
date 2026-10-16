//! Text output for terminals.
//!
//! The default view is a short summary:
//!
//! ```text
//! heldkeys: 13 credentials reachable from ~/code/app (4 long-lived with write access)
//!
//! Fix these first
//!   HIGH    Long-lived AWS access key   ~/.aws/credentials [default]   AKIA…PLE
//!   HIGH    Anthropic API key           ./api/.env: ANTHROPI…          sk-a…KE1  ×2
//!
//! Where they are                                   high  medium   low
//!   Cloud CLIs (AWS, gcloud, Azure, kube)             1       2     -
//!   Project .env files                                2       4     -  6 in 3 files across 2 repos
//!
//! Same secret in several places
//!   Anthropic API key sk-a…KE1 in 2 files (./api/.env, +1)
//!
//! Next steps
//!   1. Move secrets out of 3 .env files into a secret manager, or run agents where ...
//! ```
//!
//! followed by a pointer to `--details` and the summary line, which stays
//! the last line so scripts that read it keep working.
//!
//! `--details` lists every finding, grouped by category and then by file:
//! each file path is printed once, its findings indented under it with
//! title, place and fingerprint, and the rest (lifetime, access, detail)
//! after them or, when the line would be too long, on dimmed lines below.
//!
//! Findings an ignore rule or the baseline left out are never hidden: an
//! "Ignored" section lists every ignore rule that matched, with its reason
//! and file, and with `--details` every finding it left out.
//!
//! Lines fit `TextOptions::width`. Paths are cut in the middle when they do
//! not fit (`~/code/acme…/apps/web/.env`); fingerprints never are.

use owo_colors::{OwoColorize, Style};

use crate::finding::{Category, Finding, Severity};
use crate::report::digest::{self, Digest, plural, split_location};
use crate::report::{Mode, Report, TextOptions};

/// Widest the title column gets in `--details`.
const MAX_TITLE_WIDTH: usize = 40;
/// Widest the title column gets in "Fix these first", where the location
/// needs the room more.
const MAX_TOP_TITLE_WIDTH: usize = 36;
/// Widest the location column gets in "Fix these first": a longer one is
/// cut in the middle rather than pushing every fingerprint to the right.
const MAX_TOP_LOCATION_WIDTH: usize = 50;
/// Marks text that was cut.
const CUT: char = '…';
/// "Same secret in several places" lines in the summary.
const MAX_SHARED: usize = 5;
/// Notes (Info findings) in the summary.
const MAX_NOTES: usize = 3;

pub fn render(report: &Report, opts: &TextOptions) -> String {
    let summary = report.summary();
    if report.findings.is_empty() {
        if !has_ignored(report) {
            return format!("{}\n", summary.line());
        }
        let mut out = Out {
            text: String::new(),
            opts: *opts,
        };
        ignored(&mut out, report);
        out.blank();
        for line in fit_sentences(&summary.line(), opts.width) {
            out.line(&paint(&line, Style::new().bold(), opts.color));
        }
        return out.text.trim_start_matches('\n').to_string();
    }
    let digest = digest::digest(report);
    let mut out = Out {
        text: String::new(),
        opts: *opts,
    };
    out.line(&paint(
        &header(report, opts.width),
        Style::new().bold(),
        opts.color,
    ));
    if opts.details {
        details(&mut out, report, &digest);
    } else {
        overview(&mut out, report, &digest);
    }
    for line in fit_sentences(&summary.line(), opts.width) {
        out.line(&paint(&line, Style::new().bold(), opts.color));
    }
    out.text
}

/// The summary line, or, when it is wider than `width`, its sentences on
/// lines of their own.
fn fit_sentences(line: &str, width: usize) -> Vec<String> {
    if line.chars().count() <= width {
        return vec![line.to_string()];
    }
    line.split_inclusive(". ")
        .map(|s| s.trim().to_string())
        .collect()
}

/// Accumulates lines.
struct Out {
    text: String,
    opts: TextOptions,
}

impl Out {
    fn line(&mut self, line: &str) {
        self.text.push_str(line.trim_end());
        self.text.push('\n');
    }

    fn blank(&mut self) {
        self.text.push('\n');
    }

    fn heading(&mut self, text: &str) {
        self.blank();
        let styled = paint(text, Style::new().bold().underline(), self.opts.color);
        self.line(&styled);
    }

    fn dim(&self, text: &str) -> String {
        paint(text, Style::new().dimmed(), self.opts.color)
    }

    /// `text` word-wrapped to the width: the first line after `first`, the
    /// others after `indent` spaces.
    fn wrapped(&mut self, first: &str, indent: usize, text: &str, dim: bool) {
        let width = self.opts.width.saturating_sub(indent).max(20);
        for (i, part) in wrap(text, width).iter().enumerate() {
            let lead = if i == 0 {
                first.to_string()
            } else {
                " ".repeat(indent)
            };
            let part = if dim { self.dim(part) } else { part.clone() };
            self.line(&format!("{lead}{part}"));
        }
    }
}

/// "heldkeys: 13 credentials reachable from ~/code/app (4 long-lived with
/// write access)", or the CI verdict.
fn header(report: &Report, width: usize) -> String {
    let s = report.summary();
    match report.mode {
        Mode::Ci => format!(
            "{} ci: {}",
            crate::TOOL_NAME,
            s.line().trim_end_matches('.')
        ),
        Mode::Scan => {
            let lead = format!(
                "{}: {} reachable from ",
                crate::TOOL_NAME,
                plural(s.credentials, "credential", "credentials")
            );
            let mut tail = format!(" ({} long-lived with write access)", s.long_lived_write);
            // On a narrow terminal the count gives way; the last line has it too.
            if lead.chars().count() + tail.chars().count() + 12 > width {
                tail.clear();
            }
            let room = width
                .saturating_sub(lead.chars().count() + tail.chars().count())
                .max(12);
            let origin = middle_truncate(report.origin.as_deref().unwrap_or("here"), room);
            format!("{lead}{origin}{tail}")
        }
    }
}

/// The default view.
fn overview(out: &mut Out, report: &Report, digest: &Digest) {
    let opts = out.opts;
    if !digest.secrets.is_empty() {
        out.heading("Fix these first");
        let top: Vec<Row> = digest
            .top()
            .iter()
            .map(|s| Row::of(report, s.first(), s.places.len()))
            .collect();
        for line in rows(&top, opts) {
            out.line(&line);
        }
        let more = digest.secrets.len().saturating_sub(digest::TOP);
        if more > 0 {
            let note = format!(
                "  +{more} more {}, see --details",
                if more == 1 {
                    "credential"
                } else {
                    "credentials"
                }
            );
            out.line(&out.dim(&note));
        }
        where_they_are(out, digest);
        shared(out, report, digest, MAX_SHARED);
    }
    notes(out, report, digest, MAX_NOTES);
    next_steps(out, digest);
    ignored(out, report);
    out.blank();
    let command = match report.mode {
        Mode::Scan => crate::TOOL_NAME.to_string(),
        Mode::Ci => format!("{} ci", crate::TOOL_NAME),
    };
    // Info findings are notes (files that could not be read, job context),
    // not credentials, so they are counted apart from the summary's total.
    let notes = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();
    let rest = report.findings.len() - notes;
    let what = match (rest, notes) {
        (_, 0) => plural(rest, "finding", "findings"),
        (0, _) => plural(notes, "note", "notes"),
        _ => format!(
            "{} and {}",
            plural(rest, "finding", "findings"),
            plural(notes, "note", "notes")
        ),
    };
    let pointer = format!("Run `{command} --details` for all {what}, or `--format json`.");
    let lines = if pointer.chars().count() <= opts.width {
        vec![pointer]
    } else {
        pointer
            .split_inclusive(", ")
            .map(|s| s.trim().to_string())
            .collect()
    };
    for line in lines {
        out.line(&out.dim(&line));
    }
}

/// "Where they are": findings per category, with severity counts.
fn where_they_are(out: &mut Out, digest: &Digest) {
    const HEADING: &str = "Where they are";
    let label_width = digest
        .categories
        .iter()
        .map(|r| r.category.label().chars().count())
        .max()
        .unwrap_or(0)
        .max(HEADING.len() - 2);
    let cell = |n: usize| {
        if n == 0 {
            format!("{:>8}", "-")
        } else {
            format!("{n:>8}")
        }
    };
    out.heading(&format!(
        "{}{:>8}{:>8}{:>8}",
        pad(HEADING, label_width + 2),
        "high",
        "medium",
        "low"
    ));
    for row in &digest.categories {
        let mut line = format!(
            "  {}{}{}{}",
            pad(row.category.label(), label_width),
            cell(row.high),
            cell(row.medium),
            cell(row.low)
        );
        if row.category == Category::ProjectEnv {
            let mut note = format!("{} in {}", row.total(), plural(row.files, "file", "files"));
            if row.projects > 1 {
                note.push_str(&format!(" across {} repos", row.projects));
            }
            if line.chars().count() + 2 + note.chars().count() <= out.opts.width {
                line = format!("{line}  {}", out.dim(&note));
            } else {
                out.line(&line);
                line = format!("    {}", out.dim(&note));
            }
        }
        out.line(&line);
    }
}

/// "Same secret in several places", at most `max` lines.
fn shared(out: &mut Out, report: &Report, digest: &Digest, max: usize) {
    let shared = digest.shared();
    if shared.is_empty() {
        return;
    }
    out.heading("Same secret in several places");
    for secret in shared.iter().take(max) {
        let first = secret.first();
        let (file, inside) = split_location(&first.location);
        let id = match &first.fingerprint {
            Some(fp) => fp.clone(),
            None => inside.to_string(),
        };
        let n = secret.places.len();
        let unit = if secret.only_in_files() {
            plural(secret.files(), "file", "files")
        } else {
            plural(n, "place", "places")
        };
        let lead = format!("  {} {} in {unit} (", first.title, id);
        let tail = format!(", +{})", n - 1);
        let room = out
            .opts
            .width
            .saturating_sub(lead.chars().count() + tail.chars().count())
            .max(12);
        let place = shown_location(report, file.unwrap_or(&first.location));
        out.line(&format!("{lead}{}{tail}", middle_truncate(&place, room)));
    }
    if shared.len() > max {
        let note = format!(
            "  +{} more shared, see --details",
            plural(shared.len() - max, "secret", "secrets")
        );
        out.line(&out.dim(&note));
    }
}

/// Info findings: files that could not be analysed first.
fn notes(out: &mut Out, report: &Report, digest: &Digest, max: usize) {
    if digest.notes.is_empty() {
        return;
    }
    out.heading("Notes");
    for note in digest.notes.iter().take(max) {
        let text = match &note.detail {
            Some(d) if note.rule == crate::checks::read_errors::UNREADABLE.id => d.clone(),
            Some(d) => format!(
                "{}: {} ({d})",
                note.title,
                shown_location(report, &note.location)
            ),
            None => format!("{}: {}", note.title, shown_location(report, &note.location)),
        };
        out.wrapped("  ", 4, &text, false);
    }
    if digest.notes.len() > max {
        let note = format!(
            "  +{} more, see --details",
            plural(digest.notes.len() - max, "note", "notes")
        );
        out.line(&out.dim(&note));
    }
}

fn next_steps(out: &mut Out, digest: &Digest) {
    if digest.steps.is_empty() {
        return;
    }
    out.heading("Next steps");
    for (i, step) in digest.steps.iter().enumerate() {
        out.wrapped(&format!("  {}. ", i + 1), 5, step, false);
    }
}

/// `--details`: every finding, by category, then by file.
fn details(out: &mut Out, report: &Report, digest: &Digest) {
    let opts = out.opts;
    let mut categories: Vec<Category> = report.findings.iter().map(|f| f.category).collect();
    categories.sort();
    categories.dedup();
    for category in categories {
        let mine: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.category == category)
            .collect();
        let counts: Vec<String> = Severity::ALL
            .iter()
            .filter_map(|s| {
                let n = mine.iter().filter(|f| f.severity == *s).count();
                (n > 0).then(|| format!("{n} {}", s.as_str()))
            })
            .collect();
        out.heading(category.label());
        out.line(&out.dim(&format!("  {}", counts.join(", "))));
        // Findings without a file first (environment variables, endpoints),
        // then one block per file, in path order.
        let mut files: Vec<Option<String>> = mine
            .iter()
            .map(|f| {
                split_location(&f.location)
                    .0
                    .map(|p| shown_location(report, p))
            })
            .collect();
        files.sort();
        files.dedup();
        for file in files {
            let mut group: Vec<&&Finding> = mine
                .iter()
                .filter(|f| {
                    split_location(&f.location)
                        .0
                        .map(|p| shown_location(report, p))
                        == file
                })
                .collect();
            group.sort_by_key(|f| std::cmp::Reverse(f.severity.rank()));
            // Titles line up within a file, so each block is as narrow as it can be.
            let title_width = column(
                group.iter().map(|f| f.title.chars().count()),
                MAX_TITLE_WIDTH.min(opts.width * 2 / 5),
            );
            if let Some(path) = &file {
                let path = middle_truncate(path, opts.width.saturating_sub(2));
                out.line(&format!(
                    "  {}",
                    paint(&path, Style::new().bold(), opts.color)
                ));
            }
            for f in group {
                detail_lines(out, f, title_width);
            }
        }
    }
    let shared = digest.shared();
    if !shared.is_empty() {
        shared_all(out, report, digest);
    }
    next_steps(out, digest);
    ignored(out, report);
    out.blank();
}

/// Every shared secret, for `--details`.
fn shared_all(out: &mut Out, report: &Report, digest: &Digest) {
    shared(out, report, digest, usize::MAX);
}

/// Whether there is anything for the "Ignored" section.
fn has_ignored(report: &Report) -> bool {
    !report.suppressed.is_empty() || !report.suppression.notices.is_empty()
}

/// "Ignored": how many findings each source left out, every ignore rule
/// that matched (rule, path, count, reason, file, expiry), warnings about
/// where the rules came from, and with `--details` every finding left out.
/// A reviewer sees an ignore that a pull request added here.
fn ignored(out: &mut Out, report: &Report) {
    if !has_ignored(report) {
        return;
    }
    out.heading("Ignored");
    if let Some(line) = ignored_counts(report) {
        out.wrapped("  ", 4, &line, false);
    }
    for hit in &report.suppression.hits {
        let ig = &hit.ignore;
        let mut text = ig.rule.clone();
        if let Some(path) = &ig.path {
            text.push_str(&format!(" at {path}"));
        }
        if let Some(location) = &ig.location {
            text.push_str(&format!(" at exactly {location}"));
        }
        text.push_str(&format!(
            ": {}; {} ({}",
            plural(hit.findings, "finding", "findings"),
            ig.reason,
            ig.source
        ));
        if let Some(day) = ig.expires {
            text.push_str(&format!(", expires {day}"));
        }
        text.push(')');
        out.wrapped("  ", 4, &text, false);
    }
    for notice in &report.suppression.notices {
        out.wrapped("  ", 4, &format!("Warning: {notice}"), false);
    }
    if !out.opts.details {
        return;
    }
    // One line per finding (severity, title, location cut to fit,
    // fingerprint), then the rule and the reason, dimmed.
    let opts = out.opts;
    for s in &report.suppressed {
        let f = &s.finding;
        let fingerprint = f
            .fingerprint
            .as_deref()
            .map(|fp| format!("  {fp}"))
            .unwrap_or_default();
        let (title, _) = fit_title(&f.title, MAX_TITLE_WIDTH.min(opts.width * 2 / 5));
        let lead = format!("    {}{title}  ", pad(tag(f.severity), 8));
        let room = opts
            .width
            .saturating_sub(lead.chars().count() + fingerprint.chars().count())
            .max(16);
        let location = fit_location(&shown_location(report, &f.location), room);
        out.line(&format!("{lead}{location}{fingerprint}"));
        out.wrapped(
            &" ".repeat(12),
            12,
            &format!("{}: {}", f.rule, s.reason),
            true,
        );
    }
}

/// "3 findings ignored by ./.heldkeys.toml, 2 in the baseline base.json".
pub(crate) fn ignored_counts(report: &Report) -> Option<String> {
    let mut parts = Vec::new();
    let by_config = report
        .suppressed
        .iter()
        .filter(|s| s.by == crate::suppress::By::Config)
        .count();
    if by_config > 0 {
        let mut sources: Vec<&str> = report
            .suppression
            .hits
            .iter()
            .map(|h| h.ignore.source.as_str())
            .collect();
        sources.dedup();
        parts.push(format!(
            "{} ignored by {}",
            plural(by_config, "finding", "findings"),
            sources.join(" and ")
        ));
    }
    let in_baseline = report.suppressed.len() - by_config;
    if in_baseline > 0 {
        let file = report.suppression.baseline.as_deref().unwrap_or("");
        let what = if parts.is_empty() {
            plural(in_baseline, "finding", "findings")
        } else {
            in_baseline.to_string()
        };
        parts.push(format!("{what} in the baseline {file}"));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// One finding in `--details`: `    HIGH    Title  place  fp  ×2  (facts; detail)`.
fn detail_lines(out: &mut Out, f: &Finding, title_width: usize) {
    let opts = out.opts;
    const INDENT: usize = 4 + 8;
    const MIN_INSIDE: usize = 16;
    let fingerprint = f.fingerprint.clone().unwrap_or_default();
    let copies = f
        .duplicates
        .map(|n| format!("×{}", n + 1))
        .unwrap_or_default();
    let others = INDENT
        + 2
        + if fingerprint.is_empty() {
            0
        } else {
            2 + fingerprint.chars().count()
        }
        + if copies.is_empty() {
            0
        } else {
            2 + copies.chars().count()
        };
    // A narrow terminal takes room from the title before the place.
    let title_width = title_width.min(opts.width.saturating_sub(others + MIN_INSIDE).max(12));
    let (title, moved) = fit_title(&f.title, title_width);
    let (_, inside) = split_location(&f.location);
    let mut facts = format!("{}, {}", f.lifetime.as_str(), f.access.as_str());
    if f.severity == Severity::Info {
        facts.clear();
    }
    for extra in [moved, f.detail.clone()].into_iter().flatten() {
        if facts.is_empty() {
            facts = extra;
        } else {
            facts = format!("{facts}; {extra}");
        }
    }
    let room = opts
        .width
        .saturating_sub(others + title_width)
        .max(MIN_INSIDE);
    let inside = middle_truncate(&inside, room);
    let mut plain = format!(
        "    {}{}",
        pad(tag(f.severity), 8),
        pad(&title, title_width)
    );
    let mut line = format!(
        "    {}{}",
        paint(
            &pad(tag(f.severity), 8),
            severity_style(f.severity),
            opts.color
        ),
        paint(&pad(&title, title_width), Style::new().bold(), opts.color)
    );
    for (text, style) in [
        (inside.as_str(), Style::new()),
        (fingerprint.as_str(), Style::new().cyan()),
        (copies.as_str(), Style::new().dimmed()),
    ] {
        if !text.is_empty() {
            plain.push_str(&format!("  {text}"));
            line.push_str(&format!("  {}", paint(text, style, opts.color)));
        }
    }
    let note = format!("({facts})");
    if facts.is_empty() {
        out.line(&line);
    } else if plain.trim_end().chars().count() + 2 + note.chars().count() <= opts.width {
        out.line(&format!("{}  {}", line.trim_end(), out.dim(&note)));
    } else {
        out.line(&line);
        out.wrapped(&" ".repeat(INDENT), INDENT, &facts, true);
    }
}

/// A row of "Fix these first".
struct Row {
    severity: Severity,
    title: String,
    location: String,
    fingerprint: String,
    copies: String,
}

impl Row {
    fn of(report: &Report, f: &Finding, places: usize) -> Row {
        Row {
            severity: f.severity,
            title: f.title.clone(),
            location: shown_location(report, &f.location),
            fingerprint: f.fingerprint.clone().unwrap_or_default(),
            copies: if places > 1 {
                format!("×{places}")
            } else {
                String::new()
            },
        }
    }
}

/// Aligned "Fix these first" lines: severity, title, location (cut in the
/// middle to fit), fingerprint, number of copies.
fn rows(rows: &[Row], opts: TextOptions) -> Vec<String> {
    let mut title_width = column(
        rows.iter().map(|r| r.title.chars().count()),
        MAX_TOP_TITLE_WIDTH.min(opts.width * 2 / 5),
    );
    let fp_width = column(rows.iter().map(|r| r.fingerprint.chars().count()), 64);
    let copies_width = column(rows.iter().map(|r| r.copies.chars().count()), 64);
    let others = 2
        + 8
        + 2
        + if fp_width > 0 { 2 + fp_width } else { 0 }
        + if copies_width > 0 {
            2 + copies_width
        } else {
            0
        };
    // A narrow terminal takes room from the title before the location.
    const MIN_LOCATION: usize = 16;
    let spare = opts.width.saturating_sub(others + MIN_LOCATION);
    if title_width > spare {
        title_width = spare.max(12);
    }
    let fixed = others + title_width;
    let location_width = column(
        rows.iter().map(|r| r.location.chars().count()),
        opts.width
            .saturating_sub(fixed)
            .clamp(16, MAX_TOP_LOCATION_WIDTH),
    );
    rows.iter()
        .map(|r| {
            let (title, _) = fit_title(&r.title, title_width);
            let location = fit_location(&r.location, location_width);
            let mut line = format!(
                "  {}{}  {}",
                paint(
                    &pad(tag(r.severity), 8),
                    severity_style(r.severity),
                    opts.color
                ),
                paint(&pad(&title, title_width), Style::new().bold(), opts.color),
                pad(&location, location_width),
            );
            if fp_width > 0 {
                line.push_str(&format!(
                    "  {}",
                    paint(
                        &pad(&r.fingerprint, fp_width),
                        Style::new().cyan(),
                        opts.color
                    )
                ));
            }
            if copies_width > 0 {
                line.push_str(&format!(
                    "  {}",
                    paint(&r.copies, Style::new().dimmed(), opts.color)
                ));
            }
            line
        })
        .collect()
}

fn tag(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// A location as shown: under the scanned directory, relative to it
/// (`./shop/.env` rather than `~/code/shop/.env`), unless that
/// directory is the home directory or the root, where `~/` reads better.
fn shown_location(report: &Report, location: &str) -> String {
    if let Some(origin) = report.origin.as_deref()
        && !matches!(origin, "~" | "/" | "")
        && let Some(rest) = location.strip_prefix(origin)
        && let Some(rest) = rest.strip_prefix('/')
    {
        return format!("./{rest}");
    }
    location.to_string()
}

/// Fits a location in `max` characters. A short file path stays whole and
/// the middle of the place in it goes (`~/.docker/config.json (https:…/v1/)`);
/// a long path loses its middle first, so the place in the file (a
/// variable, a profile) stays whole (`~/code…/api/.env: OPENAI_API_KEY`).
fn fit_location(location: &str, max: usize) -> String {
    if location.chars().count() <= max {
        return location.to_string();
    }
    if let (Some(file), _) = split_location(location)
        && let Some(rest) = location.strip_prefix(file)
        && !rest.is_empty()
    {
        // A workflow step that does not fit keeps its line and the action it
        // uses (`triage.yml:23 claude-code-action@v1`); the job and step
        // index are in --details.
        if let Some(step) = compact_step(rest) {
            let step_len = step.chars().count();
            if file.chars().count() + step_len <= max {
                return format!("{file}{step}");
            }
            let short = short_path(file);
            if short.chars().count() + step_len <= max {
                return format!("{short}{step}");
            }
        }
        let file_len = file.chars().count();
        if file_len <= max * 2 / 3 && max - file_len >= 8 {
            return format!("{file}{}", middle_truncate(rest, max - file_len));
        }
        let room = max.saturating_sub(rest.chars().count());
        if room >= 12 {
            return format!("{}{rest}", middle_truncate(file, room));
        }
        let file = middle_truncate(file, max * 2 / 3);
        let rest_room = max.saturating_sub(file.chars().count());
        if rest_room >= 8 {
            return format!("{file}{}", middle_truncate(rest, rest_room));
        }
    }
    middle_truncate(location, max)
}

/// `:23 jobs.triage.steps[1] (uses: anthropics/claude-code-action@v1)`
/// becomes `:23 claude-code-action@v1`. Anything else gives `None`.
fn compact_step(rest: &str) -> Option<String> {
    let after_colon = rest.strip_prefix(':')?;
    let (line, tail) = after_colon.split_once(' ')?;
    if line.is_empty() || !line.chars().all(|c| c.is_ascii_digit()) || !tail.starts_with("jobs.") {
        return None;
    }
    let uses = tail.split_once(" (uses: ")?.1.strip_suffix(')')?;
    let action = uses.rsplit('/').next().filter(|a| !a.is_empty())?;
    Some(format!(":{line} {action}"))
}

/// `.github/workflows/triage.yml` becomes `.github/…/triage.yml`: the first
/// and last parts of a path with directories in between.
fn short_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() < 3 {
        return path.to_string();
    }
    format!("{}/{CUT}/{}", parts[0], parts[parts.len() - 1])
}

/// Cuts `text` to `max` characters by replacing its middle with `…`,
/// keeping more of the end, where file names and variable names are.
fn middle_truncate(text: &str, max: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max {
        return text.to_string();
    }
    if max < 2 {
        return CUT.to_string();
    }
    let keep = max - 1;
    let head = keep / 3;
    let tail = keep - head;
    let start: String = chars[..head].iter().collect();
    let end: String = chars[chars.len() - tail..].iter().collect();
    format!("{start}{CUT}{end}")
}

/// Splits `text` into lines of at most `width` characters at spaces. A word
/// longer than the width (a path, a fingerprint) is kept whole on its own
/// line. A word that could read as a CI workflow command at the start of a
/// line (`::`, `##[`) is never moved to the start of one: the line gets
/// longer instead.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in text.split(' ').filter(|w| !w.is_empty()) {
        let len = current.chars().count();
        let may_start_a_line = !word.starts_with([':', '#']);
        if len > 0 && len + 1 + word.chars().count() > width && may_start_a_line {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() || lines.is_empty() {
        lines.push(current);
    }
    lines
}

/// The widest value, but never more than `max`.
fn column(widths: impl Iterator<Item = usize>, max: usize) -> usize {
    widths.max().unwrap_or(0).min(max)
}

/// Pads `text` with spaces to `width` characters (never cuts it).
fn pad(text: &str, width: usize) -> String {
    let len = text.chars().count();
    format!("{text}{}", " ".repeat(width.saturating_sub(len)))
}

/// Makes a title fit in `max` characters. Returns the title to show and,
/// if one was split off, the trailing parenthetical (without parentheses),
/// which the caller may print elsewhere.
///
/// "Google user refresh token (application default credentials)" becomes
/// "Google user refresh token" plus "application default credentials".
/// A title without a usable parenthetical is cut at the last word that fits
/// and ends in "…".
fn fit_title(title: &str, max: usize) -> (String, Option<String>) {
    if title.chars().count() <= max {
        return (title.to_string(), None);
    }
    if let Some(open) = title.rfind(" (")
        && title.ends_with(')')
    {
        let head = &title[..open];
        let inner = &title[open + 2..title.len() - 1];
        if !head.is_empty() && !inner.is_empty() {
            let (head, _) = fit_title(head, max);
            return (head, Some(inner.to_string()));
        }
    }
    (cut_at_word(title, max), None)
}

/// Cuts `text` to at most `max` characters, ending at a word boundary,
/// followed by `CUT`.
fn cut_at_word(text: &str, max: usize) -> String {
    let room = max.saturating_sub(1);
    let prefix: String = text.chars().take(room).collect();
    let next_is_break = text.chars().nth(room).is_none_or(|c| c == ' ');
    let kept = if next_is_break {
        prefix.as_str()
    } else {
        // Drop the partial last word, unless the title is a single long word.
        match prefix.rfind(' ') {
            Some(i) if i > 0 => &prefix[..i],
            _ => prefix.as_str(),
        }
    };
    format!("{}{CUT}", kept.trim_end_matches([' ', ',', ';', ':', '(']))
}

fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::High => Style::new().red().bold(),
        Severity::Medium => Style::new().yellow().bold(),
        Severity::Low => Style::new().blue().bold(),
        Severity::Info => Style::new().dimmed().bold(),
    }
}

/// Applies `style` only when colour is on, so plain output has no escape codes.
fn paint(text: &str, style: Style, color: bool) -> String {
    if color && !text.is_empty() {
        text.style(style).to_string()
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Access, Lifetime};

    fn finding(title: &str, location: &str, severity: Severity) -> Finding {
        Finding::new(
            crate::finding::TEST_RULE,
            title,
            location,
            severity,
            Lifetime::LongLived,
            Access::Unknown,
            "Fix it.",
        )
    }

    fn sample() -> Report {
        let mut aws = Finding::new(
            crate::finding::TEST_RULE,
            "Long-lived AWS access key",
            "~/.aws/credentials [default]",
            Severity::High,
            Lifetime::LongLived,
            Access::Write,
            "Rotate it.",
        )
        .with_fingerprint(Some("AKIA…PLE".into()));
        aws.check = "aws";
        let mut meta = Finding::new(
            crate::finding::TEST_RULE,
            "Cloud metadata endpoint is reachable",
            "169.254.169.254:80",
            Severity::Info,
            Lifetime::ShortLived,
            Access::Unknown,
            "Block it.",
        );
        meta.check = "cloud-metadata";
        Report::new(Mode::Scan, vec![aws, meta])
    }

    fn plain() -> TextOptions {
        TextOptions::plain()
    }

    fn details() -> TextOptions {
        TextOptions {
            details: true,
            ..TextOptions::plain()
        }
    }

    #[test]
    fn summary_view() {
        let out = render(&sample().with_origin("~"), &plain());
        assert!(
            out.starts_with(
                "heldkeys: 1 credential reachable from ~ (1 long-lived with write access)\n"
            ),
            "{out}"
        );
        assert!(out.contains("\nFix these first\n"), "{out}");
        assert!(
            out.contains(
                "  HIGH    Long-lived AWS access key  ~/.aws/credentials [default]  AKIA…PLE\n"
            ),
            "{out}"
        );
        assert!(
            out.contains("  Cloud CLIs (AWS, gcloud, Azure, kube)       1       -       -\n"),
            "{out}"
        );
        assert!(
            out.contains("Cloud metadata endpoint is reachable: 169.254.169.254:80"),
            "{out}"
        );
        assert!(
            out.contains("Run `heldkeys --details` for all 1 finding and 1 note"),
            "{out}"
        );
        assert!(out.ends_with("1 credential reachable, 1 long-lived with write access.\nIf a prompt injection can run one shell command here, it can use it.\n"), "{out}");
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn details_view() {
        let out = render(&sample(), &details());
        assert!(out.contains("\nCloud CLIs (AWS, gcloud, Azure, kube)\n  1 high\n  ~/.aws/credentials\n    HIGH    Long-lived AWS access key  [default]  AKIA…PLE  (long-lived, write access)\n"), "{out}");
        assert!(out.contains("\nSandbox and host\n  1 info\n    INFO    Cloud metadata endpoint is reachable  169.254.169.254:80\n"), "{out}");
        assert!(out.contains("Next steps\n"), "{out}");
    }

    #[test]
    fn colour_output_has_escapes_and_the_same_text() {
        let strip = |s: &str| -> String {
            let re = regex::Regex::new("\u{1b}\\[[0-9;]*m").unwrap();
            re.replace_all(s, "").into_owned()
        };
        for opts in [plain(), details()] {
            let colour = TextOptions {
                color: true,
                ..opts
            };
            let out = render(&sample(), &colour);
            assert!(out.contains('\u{1b}'));
            assert_eq!(strip(&out), render(&sample(), &opts));
        }
    }

    #[test]
    fn empty_report() {
        let out = render(&Report::new(Mode::Scan, vec![]), &plain());
        assert_eq!(out, "No credentials reachable from here.\n");
    }

    #[test]
    fn paths_under_the_scanned_directory_are_relative() {
        let report = Report::new(
            Mode::Scan,
            vec![finding("Token", "~/code/app/.env: TOKEN", Severity::High)],
        )
        .with_origin("~/code");
        assert_eq!(shown_location(&report, "~/code/app/.env"), "./app/.env");
        assert_eq!(shown_location(&report, "~/code2/x"), "~/code2/x");
        assert_eq!(shown_location(&report, "~/.npmrc"), "~/.npmrc");
        let home = Report::new(Mode::Scan, vec![]).with_origin("~");
        assert_eq!(shown_location(&home, "~/.npmrc"), "~/.npmrc");
    }

    #[test]
    fn long_lines_fit_the_width() {
        let long = format!(
            "~/{}/apps/web/.env: SOME_VERY_LONG_VARIABLE_NAME",
            "x".repeat(150)
        );
        let report = Report::new(
            Mode::Scan,
            vec![
                finding(
                    "Google user refresh token (application default credentials)",
                    &long,
                    Severity::High,
                )
                .with_fingerprint(Some("ghp_…001".into()))
                .with_detail("a long detail ".repeat(20)),
            ],
        );
        for opts in [plain(), details()] {
            for width in [60, 100, 120] {
                let opts = TextOptions { width, ..opts };
                let out = render(&report, &opts);
                for line in out.lines().filter(|l| !l.contains("prompt injection")) {
                    assert!(line.chars().count() <= width, "{width}: {line}");
                }
                assert!(
                    out.contains("ghp_…001"),
                    "fingerprints are never cut: {out}"
                );
            }
        }
    }

    #[test]
    fn locations_keep_their_most_useful_parts() {
        assert_eq!(
            fit_location(
                "~/projects/acme/storefront-wt-12/apps/api/.env: ANTHROPIC_API_KEY",
                50
            ),
            "~/projects…-wt-12/apps/api/.env: ANTHROPIC_API_KEY"
        );
        let step = fit_location(
            ".github/workflows/triage.yml:23 jobs.triage.steps[1] (uses: anthropics/claude-code-action@v1)",
            50,
        );
        assert_eq!(step, ".github/…/triage.yml:23 claude-code-action@v1");
        let wide = fit_location(
            ".github/workflows/triage.yml:23 jobs.triage.steps[1] (uses: anthropics/claude-code-action@v1)",
            60,
        );
        assert_eq!(
            wide,
            ".github/workflows/triage.yml:23 claude-code-action@v1"
        );
    }

    #[test]
    fn middle_truncation() {
        assert_eq!(middle_truncate("short", 10), "short");
        let cut = middle_truncate("~/projects/acme/storefront-worktree/apps/web/.env", 30);
        assert_eq!(cut.chars().count(), 30);
        assert!(
            cut.starts_with("~/project") && cut.ends_with("apps/web/.env"),
            "{cut}"
        );
    }

    #[test]
    fn wrapping() {
        assert_eq!(wrap("a bb ccc dddd", 6), ["a bb", "ccc", "dddd"]);
        assert_eq!(
            wrap("averyveryverylongword x", 5),
            ["averyveryverylongword", "x"]
        );
        assert_eq!(wrap("", 5), [""]);
        assert_eq!(wrap("aaaa ::error::x b", 5), ["aaaa ::error::x", "b"]);
    }

    #[test]
    fn fit_title_cases() {
        assert_eq!(fit_title("Short title", 20), ("Short title".into(), None));
        assert_eq!(
            fit_title("Azure CLI token cache (encrypted for this user)", 30),
            (
                "Azure CLI token cache".into(),
                Some("encrypted for this user".into())
            )
        );
        assert_eq!(
            fit_title("Git credential helper caches logins in memory", 30),
            ("Git credential helper caches…".into(), None)
        );
        assert_eq!(
            fit_title("Supercalifragilisticexpialidocious", 10),
            ("Supercali…".into(), None)
        );
        for (title, max) in [
            ("Git credential helper caches logins in memory", 12),
            ("a (b)", 3),
            ("Kubernetes bearer token (from file)", 16),
        ] {
            let (shown, _) = fit_title(title, max);
            assert!(shown.chars().count() <= max, "{title}: {shown}");
        }
    }
}
