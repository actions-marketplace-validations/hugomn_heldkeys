//! Command-line entry point: parse flags, build the context, run the checks,
//! render the report, pick the exit code.
//!
//! Exit codes: 0 = nothing reached `--fail-on`, 1 = something did,
//! 2 = usage or runtime error.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use heldkeys::checks::{self, Check, read_errors};
use heldkeys::config::{self, Date, Ignore};
use heldkeys::context::Context;
use heldkeys::finding::FailOn;
use heldkeys::report::{self, Format, Mode, Report};
use heldkeys::sandbox::{preflight, remote};
use heldkeys::{baseline, suppress};

#[derive(Parser)]
#[command(
    name = heldkeys::TOOL_NAME,
    version,
    about = "Which credentials could a hijacked AI agent use from here?",
    long_about = "Lists every credential reachable from this shell, sandbox or CI job, how dangerous each one is, and how to shrink the list. Read-only; never prints a secret; no network calls except one TCP connect to the cloud metadata address."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Scan this machine or container as the agent sees it (the default).
    Scan(ScanArgs),
    /// Inside CI: runtime exposure plus static analysis of workflows.
    Ci(CiArgs),
    /// List all checks and what each one looks at.
    Checks,
    /// One-line PASS/FAIL verdict for container entrypoints and sandbox start
    /// hooks; exits 1 when a finding reaches --fail-on (default: high).
    Preflight,
}

#[derive(Args, Default)]
#[command(group(ArgGroup::new("target").args(["docker", "kube"])))]
struct ScanArgs {
    /// Reserved for upcoming checks that ask a credential's own issuer about it (for example a
    /// token's scopes). No check uses it yet: today it changes nothing.
    #[arg(long)]
    deep: bool,
    /// Scan inside this running Docker container: copies a Linux heldkeys in, runs it, removes it.
    #[arg(long, value_name = "CONTAINER")]
    docker: Option<String>,
    /// Scan inside this Kubernetes pod, the same way, through kubectl cp and exec.
    #[arg(long, value_name = "POD")]
    kube: Option<String>,
    /// Namespace of the --kube pod.
    #[arg(short = 'n', long, value_name = "NAMESPACE", requires = "kube")]
    namespace: Option<String>,
    /// Container in the --kube pod.
    #[arg(short = 'c', long, value_name = "CONTAINER", requires = "kube")]
    container: Option<String>,
    /// Linux heldkeys binary to copy into the --docker/--kube target, when this
    /// one is not a Linux build for the target's CPU (see docs/building.md).
    #[arg(long, value_name = "PATH", requires = "target")]
    binary: Option<PathBuf>,
}

#[derive(Args, Default)]
struct CiArgs {
    /// Also scan tracked files on the current branch for tokens.
    #[arg(long)]
    repo_secrets: bool,
}

/// Flags accepted before or after the subcommand.
#[derive(Args)]
struct CommonArgs {
    /// Output format.
    #[arg(long, value_enum, default_value = "text", global = true)]
    format: FormatArg,
    /// Write the report to this file instead of stdout (the summary line still goes to stdout).
    #[arg(long, global = true, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Exit with 1 when a finding reaches this level [default: none for scan, high for ci and preflight].
    #[arg(long, value_enum, global = true)]
    fail_on: Option<FailOnArg>,
    /// Treat DIR as the home directory (for tests, or another user's profile).
    #[arg(long, global = true, value_name = "DIR")]
    home: Option<PathBuf>,
    /// Treat DIR as the working directory (where .env files and workflows are looked for).
    #[arg(long, global = true, value_name = "DIR")]
    path: Option<PathBuf>,
    /// Treat DIR as the filesystem root for system paths such as /var/run/docker.sock (for tests).
    #[arg(long, global = true, value_name = "DIR", hide = true)]
    root: Option<PathBuf>,
    /// Disable colours (also honoured: NO_COLOR).
    #[arg(long, global = true)]
    no_color: bool,
    /// Print only the summary line.
    #[arg(long, global = true)]
    quiet: bool,
    /// List every finding, grouped by where it is, instead of the summary (text output).
    #[arg(long, short = 'v', global = true, conflicts_with = "quiet")]
    details: bool,
    /// Fail closed: also exit 1 when something could not be analysed: a file a check looks at
    /// exists but could not be read or parsed (HK-READ-001), or a workflow could not be
    /// analysed (HK-WF-007). Either may hide a credential or a risk.
    #[arg(long, global = true)]
    strict: bool,
    /// Read ignore rules from FILE only, instead of .heldkeys.toml in --path (and, for local
    /// scans, ~/.config/heldkeys/config.toml).
    #[arg(long, global = true, value_name = "FILE", conflicts_with = "no_config")]
    config: Option<PathBuf>,
    /// Read no config file: no ignore rules.
    #[arg(long, global = true)]
    no_config: bool,
    /// Leave out findings already in FILE, a previous --format json report or --write-baseline
    /// file. New findings still count for --fail-on.
    #[arg(long, global = true, value_name = "FILE")]
    baseline: Option<PathBuf>,
    /// Write every finding of this run to FILE as a baseline (the --format json report).
    #[arg(long, global = true, value_name = "FILE")]
    write_baseline: Option<PathBuf>,
    /// Apply no ignore rules and no baseline: report everything.
    #[arg(long, global = true)]
    no_ignore: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum FormatArg {
    Text,
    Json,
    Markdown,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOnArg {
    None,
    High,
    Medium,
    Low,
    LongLivedWrite,
}

fn main() -> ExitCode {
    // clap exits with code 2 on usage errors, matching our contract.
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{}: error: {message}", heldkeys::TOOL_NAME);
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let common = cli.common;
    let (mode, deep, repo_secrets) = match cli.command {
        None => (Mode::Scan, false, false),
        Some(Command::Scan(args)) if args.docker.is_some() || args.kube.is_some() => {
            return remote_scan(&args, &common);
        }
        Some(Command::Scan(args)) => (Mode::Scan, args.deep, false),
        Some(Command::Ci(args)) => (Mode::Ci, false, args.repo_secrets),
        Some(Command::Checks) => return list_checks(&common),
        Some(Command::Preflight) => return run_preflight(&common),
    };

    let mut ctx = context(&common)?;
    ctx.deep = deep;
    ctx.repo_secrets = repo_secrets;

    let checks = match mode {
        Mode::Scan => checks::local_checks(),
        Mode::Ci => checks::ci_checks(),
    };
    let report = Report::new(mode, checks::run_all(&checks, &ctx)).with_origin(&origin(&ctx));
    let report = suppress_findings(report, &common, Some(&ctx), mode)?;
    emit(&report, &common, ctx.env.contains_key("NO_COLOR"))?;
    let default = match mode {
        Mode::Scan => FailOn::None,
        Mode::Ci => FailOn::High,
    };
    Ok(exit_code(
        fail_on(common.fail_on, default),
        common.strict,
        &report,
    ))
}

fn context(common: &CommonArgs) -> Result<Context, String> {
    Context::from_process(
        common.root.clone(),
        common.home.clone(),
        common.path.clone(),
    )
}

/// The scanned directory as the reader knows it: `~` for the home
/// directory, `~/workspace` under it, the full path elsewhere.
fn origin(ctx: &Context) -> String {
    match ctx.cwd.strip_prefix(&ctx.home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => ctx.cwd.display().to_string(),
    }
}

/// Prints the report (or writes it to `--output`), honouring `--quiet`.
fn emit(report: &Report, common: &CommonArgs, no_color_env: bool) -> Result<(), String> {
    let summary_line = report.summary().line();
    let mut text = text_options(common, false);
    if let Some(path) = &common.output {
        // The file never gets colour codes.
        let rendered = report::render(format(common.format), report, &text)?;
        write_file(path, &rendered)?;
        println!("{summary_line}");
    } else if common.quiet {
        println!("{summary_line}");
    } else {
        text.color = use_color(common, no_color_env);
        print_stdout(&report::render(format(common.format), report, &text)?)?;
    }
    Ok(())
}

/// Layout of text output: `--details`, and the width from `COLUMNS`.
fn text_options(common: &CommonArgs, color: bool) -> report::TextOptions {
    report::TextOptions {
        color,
        width: report::TextOptions::width_from(std::env::var("COLUMNS").ok().as_deref()),
        details: common.details,
    }
}

/// 1 when a finding reaches `fail_on`, or, with `--strict`, when something
/// could not be analysed (`read_errors::NOT_ANALYSED_RULES`); 0 otherwise.
fn exit_code(fail_on: FailOn, strict: bool, report: &Report) -> ExitCode {
    let unreadable = strict && report.findings.iter().any(read_errors::is_not_analysed);
    if fail_on.any_triggered(&report.findings) || unreadable {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// `heldkeys preflight`: the local scan, reduced to a PASS/FAIL line.
///
/// With `--format json`, stdout is the JSON report (with a `preflight`
/// object) and the verdict line goes to stderr, so a sandbox can parse
/// stdout and still log the verdict.
fn run_preflight(common: &CommonArgs) -> Result<ExitCode, String> {
    let json = match common.format {
        FormatArg::Text => false,
        FormatArg::Json => true,
        _ => return Err("preflight supports --format text or json".to_string()),
    };
    let ctx = context(common)?;
    let report = Report::new(Mode::Scan, checks::run_all(&checks::local_checks(), &ctx))
        .with_origin(&origin(&ctx));
    let report = suppress_findings(report, common, Some(&ctx), Mode::Scan)?;
    let verdict = preflight::verdict(
        &report,
        fail_on(common.fail_on, FailOn::High),
        common.strict,
    );
    let body = if json {
        preflight::render_json(&report, &verdict)
    } else {
        preflight::render_text(&verdict, common.quiet, common.details)
    };
    if let Some(path) = &common.output {
        write_file(path, &body)?;
        println!("{}", verdict.line());
    } else {
        print_stdout(&body)?;
        if json {
            eprintln!("{}", verdict.line());
        }
    }
    Ok(if verdict.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// `heldkeys scan --docker <container>` / `--kube <pod>`: run the scan inside
/// the target, then render and apply `--fail-on` here.
fn remote_scan(args: &ScanArgs, common: &CommonArgs) -> Result<ExitCode, String> {
    let target = match (&args.docker, &args.kube) {
        (Some(container), _) => remote::Target::Docker {
            container: container.clone(),
        },
        (None, Some(pod)) => remote::Target::Kube {
            pod: pod.clone(),
            namespace: args.namespace.clone(),
            container: args.container.clone(),
        },
        (None, None) => unreachable!("only called with a target"),
    };
    // --home and --path name directories inside the target.
    let mut forward = Vec::new();
    if args.deep {
        forward.push("--deep".to_string());
    }
    for (flag, value) in [("--home", &common.home), ("--path", &common.path)] {
        if let Some(dir) = value {
            forward.push(flag.to_string());
            forward.push(dir.to_string_lossy().into_owned());
        }
    }
    let result = remote::scan(&target, args.binary.as_deref(), &forward)?;
    for warning in &result.warnings {
        eprintln!("{}: warning: {warning}", heldkeys::TOOL_NAME);
    }
    let report = Report::new(Mode::Scan, result.findings);
    let report = suppress_findings(report, common, None, Mode::Scan)?;
    emit(&report, common, std::env::var_os("NO_COLOR").is_some())?;
    Ok(exit_code(
        fail_on(common.fail_on, FailOn::None),
        common.strict,
        &report,
    ))
}

/// Writes `--write-baseline`, then applies the ignore rules and the
/// `--baseline` (unless `--no-ignore`): what they cover moves to
/// `report.suppressed`, counted and listed, out of `--fail-on`'s reach.
///
/// `ctx` is `None` for `--docker`/`--kube` scans, whose `--path` is inside
/// the target: only an explicit `--config` applies there.
fn suppress_findings(
    mut report: Report,
    common: &CommonArgs,
    ctx: Option<&Context>,
    mode: Mode,
) -> Result<Report, String> {
    let (ignores, checkout_config) = if common.no_ignore {
        (Vec::new(), None)
    } else {
        load_ignores(common, ctx, mode)?
    };
    let baseline = match &common.baseline {
        Some(path) if !common.no_ignore => Some(baseline::load(path, &shown_path(path, ctx))?),
        _ => None,
    };
    // Every finding of this run, before any is left out, so refreshing a
    // baseline keeps what the old one accepted.
    if let Some(path) = &common.write_baseline {
        write_file(path, &report::json::render(&report))?;
    }
    let today = Date::today();
    for ig in ignores.iter().filter(|i| i.is_expired(today)) {
        eprintln!(
            "{}: warning: {}: the ignore rule for {} expired on {}; its findings are reported again",
            heldkeys::TOOL_NAME,
            ig.source,
            ig.rule,
            ig.expires.map(|d| d.to_string()).unwrap_or_default(),
        );
    }
    suppress::apply(&mut report, &ignores, baseline.as_ref(), today);

    // In the CI run of a pull or merge request, files in the checkout are
    // the change's own: say so in every format and on stderr, and name them
    // as such in the summary line.
    if mode == Mode::Ci
        && let Some(ctx) = ctx
        && let Some((change, run)) = suppress::untrusted_change(|name| ctx.var(name))
    {
        let baseline_file = match (&common.baseline, &baseline) {
            (Some(path), Some(b)) if suppress::in_checkout(&ctx.cwd, path) => {
                Some(b.source.as_str())
            }
            _ => None,
        };
        let s = &mut report.suppression;
        s.config_from_change = checkout_config.is_some().then_some(change);
        s.baseline_from_change = baseline_file.is_some().then_some(change);
        s.notices =
            suppress::checkout_notices(change, &run, checkout_config.as_deref(), baseline_file);
        for notice in &s.notices {
            eprintln!("{}: warning: {notice}", heldkeys::TOOL_NAME);
        }
    }
    Ok(report)
}

/// The ignore rules for this run, and the config file's name when ignore
/// rules came from the scanned checkout (see `suppress::in_checkout`).
///
/// `--no-config`: none. `--config FILE`: that file only, which must exist.
/// Otherwise `.heldkeys.toml` in the scanned directory, if there, plus
/// `~/.config/heldkeys/config.toml` for local scans (not in `ci`, where the
/// home directory is the runner's).
fn load_ignores(
    common: &CommonArgs,
    ctx: Option<&Context>,
    mode: Mode,
) -> Result<(Vec<Ignore>, Option<String>), String> {
    if common.no_config {
        return Ok((Vec::new(), None));
    }
    if let Some(path) = &common.config {
        let shown = shown_path(path, ctx);
        let ignores = config::load(path, &shown, None)?
            .ok_or_else(|| format!("config file {shown} does not exist"))?;
        let from_checkout = ctx
            .filter(|ctx| !ignores.is_empty() && suppress::in_checkout(&ctx.cwd, path))
            .map(|_| shown);
        return Ok((ignores, from_checkout));
    }
    let Some(ctx) = ctx else {
        return Ok((Vec::new(), None));
    };
    let mut ignores = Vec::new();
    let mut from_checkout = None;
    let shown = format!("./{}", config::PROJECT_FILE);
    let project = ctx.cwd.join(config::PROJECT_FILE);
    if let Some(found) = config::load(&project, &shown, Some(&ctx.cwd))? {
        if !found.is_empty() {
            from_checkout = Some(shown);
        }
        ignores.extend(found);
    }
    if mode == Mode::Scan {
        let user = ctx.config_dir().join(config::USER_FILE);
        if let Some(found) = config::load(&user, &ctx.display_path(&user), None)? {
            ignores.extend(found);
        }
    }
    Ok((ignores, from_checkout))
}

/// A path named on the command line, as reports show it.
fn shown_path(path: &std::path::Path, ctx: Option<&Context>) -> String {
    let shown = match ctx {
        Some(ctx) => ctx.display_path(path),
        None => path.display().to_string(),
    };
    heldkeys::sanitize::clip(&heldkeys::sanitize::sanitize(&shown))
}

fn write_file(path: &std::path::Path, contents: &str) -> Result<(), String> {
    std::fs::write(path, contents).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// `heldkeys checks`: a plain list, or JSON with `--format json`.
fn list_checks(common: &CommonArgs) -> Result<ExitCode, String> {
    let groups: [(&str, Vec<Box<dyn Check>>); 2] = [
        ("scan", checks::local_checks()),
        ("ci", checks::ci_checks()),
    ];
    let out = match common.format {
        FormatArg::Json => {
            let list: Vec<serde_json::Value> = groups
                .iter()
                .flat_map(|(mode, checks)| {
                    checks.iter().map(move |c| {
                        let rules: Vec<serde_json::Value> = c
                            .rules()
                            .iter()
                            .map(|r| serde_json::json!({ "id": r.id, "summary": r.summary }))
                            .collect();
                        serde_json::json!({
                            "id": c.id(),
                            "mode": mode,
                            "description": c.describe(),
                            "rules": rules,
                        })
                    })
                })
                .collect();
            serde_json::to_string_pretty(&list).map_err(|e| e.to_string())? + "\n"
        }
        _ => {
            let mut out = String::new();
            for (mode, checks) in &groups {
                out.push_str(&format!("{mode}:\n"));
                for c in checks {
                    out.push_str(&format!("  {:<20} {}\n", c.id(), c.describe()));
                    for rule in c.rules() {
                        out.push_str(&format!("      {:<16} {}\n", rule.id, rule.summary));
                    }
                }
            }
            out
        }
    };
    print_stdout(&out)?;
    Ok(ExitCode::SUCCESS)
}

/// Writes to stdout, treating a closed pipe (`| head`) as success.
fn print_stdout(text: &str) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(text.as_bytes())
        .and_then(|_| stdout.flush())
    {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
            Err(format!("cannot write output: {e}"))
        }
        _ => Ok(()),
    }
}

/// Colour only for text on a terminal, unless `--no-color` or `NO_COLOR` says otherwise.
fn use_color(common: &CommonArgs, no_color_env: bool) -> bool {
    !common.no_color
        && !no_color_env
        && matches!(common.format, FormatArg::Text)
        && std::io::stdout().is_terminal()
}

fn format(arg: FormatArg) -> Format {
    match arg {
        FormatArg::Text => Format::Text,
        FormatArg::Json => Format::Json,
        FormatArg::Markdown => Format::Markdown,
        FormatArg::Sarif => Format::Sarif,
    }
}

/// `--fail-on` if given, else the subcommand's default: `scan` never fails
/// by default, `ci` and `preflight` fail on High.
fn fail_on(arg: Option<FailOnArg>, default: FailOn) -> FailOn {
    match arg {
        Some(FailOnArg::None) => FailOn::None,
        Some(FailOnArg::High) => FailOn::High,
        Some(FailOnArg::Medium) => FailOn::Medium,
        Some(FailOnArg::Low) => FailOn::Low,
        Some(FailOnArg::LongLivedWrite) => FailOn::LongLivedWrite,
        None => default,
    }
}
