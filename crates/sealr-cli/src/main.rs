mod machine;

use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, ColorChoice, Parser, Subcommand};
use sealr::{
    ApplyOptions, Finding, FindingCode, LinuxWorker, Outcome, Policy, PolicyDocumentV12, Request,
    SevenZInterpretationProfile, Source, TarBzip2InterpretationProfile,
    TarGnuLongNameInterpretationProfile, TarGzipInterpretationProfile, TarInterpretationProfile,
    TarPaxInterpretationProfile, TarXzInterpretationProfile, TarZstdInterpretationProfile,
    ZipInterpretationProfile, apply_supervised, apply_with_options,
};
use serde::Serialize;

const AFTER_HELP: &str = "\
Formats:
  zip, zip64
  tar-ustar, tar-pax
  tar-gnu-longname
  tar-gzip-ustar
  tar-gzip-pax
  tar-gzip-gnu-longname
  tar-zstd-ustar, tar-xz-ustar
  tar-bzip2-ustar
  7z-copy

Examples:
  sealr download.zip
      check only, write nothing
  sealr download.zip --dest ./pkg
      admit into a new directory
  sealr src.tar.gz --format tar-gzip-ustar
      pick the exact TAR format

The archive is admitted through one interpretation.
After admission, do not reopen the archive: consume the
materialized --dest tree, or a VerifiedArchive from the
library, and never parse the original bytes again. The
original archive is not an authority; a second parser is
where interpretations disagree.
";

#[derive(Parser, Debug)]
#[command(
    name = "sealr",
    version,
    about = "Admit an untrusted archive into a new directory, or refuse it, with a receipt.",
    after_help = AFTER_HELP,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
    /// Archive file
    archive: Option<PathBuf>,
    /// Exact container interpretation to apply
    #[arg(long, value_parser = parse_cli_format, default_value = "zip")]
    format: CliFormat,
    /// Materialize into a new directory below an existing parent
    #[arg(long)]
    dest: Option<PathBuf>,
    /// Use the exact packaged Linux worker bound by this manifest
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    worker_manifest: Option<PathBuf>,
    /// Write the view JSON to this exact new file instead of stdout
    #[arg(long, value_name = "NEW_FILE")]
    view: Option<PathBuf>,
    /// Write the receipt JSON to this exact new file instead of stderr
    #[arg(long, value_name = "NEW_FILE")]
    receipt: Option<PathBuf>,
    /// Validate and use this exact JSON policy document instead of the
    /// format's default policy
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,
    /// Write the canonical RFC 8785 evidence lineage to the --view and
    /// --receipt files, whose bytes are exactly the digested bytes
    #[arg(long, requires = "view", requires = "receipt")]
    canonical: bool,
    /// Print the view and receipt JSON even when both streams are terminals
    #[arg(long)]
    json: bool,
    /// Print one sealr.command-result.v1 document on stdout
    #[arg(long)]
    machine: bool,
    /// Color the terminal summary. auto follows the terminal and NO_COLOR
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Interpret and verify without writing any member file
    Inspect {
        #[command(flatten)]
        common: CommonArgs,
    },
    /// Interpret, verify, and publish the tree into a new destination
    Materialize {
        #[command(flatten)]
        common: CommonArgs,
        /// Materialize into a new directory below an existing parent
        #[arg(long)]
        dest: PathBuf,
    },
}

#[derive(Args, Debug)]
struct CommonArgs {
    /// Archive file
    archive: PathBuf,
    /// Exact container interpretation to apply
    #[arg(long, value_parser = parse_cli_format, default_value = "zip")]
    format: CliFormat,
    /// Use the exact packaged Linux worker bound by this manifest
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    worker_manifest: Option<PathBuf>,
    /// Write the view JSON to this exact new file instead of stdout
    #[arg(long, value_name = "NEW_FILE")]
    view: Option<PathBuf>,
    /// Write the receipt JSON to this exact new file instead of stderr
    #[arg(long, value_name = "NEW_FILE")]
    receipt: Option<PathBuf>,
    /// Validate and use this exact JSON policy document instead of the
    /// format's default policy
    #[arg(long, value_name = "FILE")]
    policy: Option<PathBuf>,
    /// Write the canonical RFC 8785 evidence lineage to the --view and
    /// --receipt files, whose bytes are exactly the digested bytes
    #[arg(long, requires = "view", requires = "receipt")]
    canonical: bool,
    /// Print the view and receipt JSON even when both streams are terminals
    #[arg(long)]
    json: bool,
    /// Print one sealr.command-result.v1 document on stdout
    #[arg(long)]
    machine: bool,
    /// Color the terminal summary. auto follows the terminal and NO_COLOR
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

/// One resolved invocation shape shared by the compatibility form and both
/// subcommands, so every form runs the identical pipeline.
struct ResolvedInvocation {
    archive: PathBuf,
    format: CliFormat,
    dest: Option<PathBuf>,
    worker_manifest: Option<PathBuf>,
    view: Option<PathBuf>,
    receipt: Option<PathBuf>,
    policy: Option<PathBuf>,
    canonical: bool,
    json: bool,
    machine: bool,
    color: ColorChoice,
}

fn resolve(cli: Cli) -> Result<ResolvedInvocation, String> {
    match cli.command {
        Some(CliCommand::Inspect { common }) => Ok(ResolvedInvocation {
            archive: common.archive,
            format: common.format,
            dest: None,
            worker_manifest: common.worker_manifest,
            view: common.view,
            receipt: common.receipt,
            policy: common.policy,
            canonical: common.canonical,
            json: common.json,
            machine: common.machine,
            color: common.color,
        }),
        Some(CliCommand::Materialize { common, dest }) => Ok(ResolvedInvocation {
            archive: common.archive,
            format: common.format,
            dest: Some(dest),
            worker_manifest: common.worker_manifest,
            view: common.view,
            receipt: common.receipt,
            policy: common.policy,
            canonical: common.canonical,
            json: common.json,
            machine: common.machine,
            color: common.color,
        }),
        None => {
            let Some(archive) = cli.archive else {
                return Err("an archive path or a subcommand is required".to_owned());
            };
            Ok(ResolvedInvocation {
                archive,
                format: cli.format,
                dest: cli.dest,
                worker_manifest: cli.worker_manifest,
                view: cli.view,
                receipt: cli.receipt,
                policy: cli.policy,
                canonical: cli.canonical,
                json: cli.json,
                machine: cli.machine,
                color: cli.color,
            })
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CliFormat {
    Zip,
    Zip64,
    TarUstar,
    TarGzipUstar,
    TarPax,
    TarGnuLongName,
    TarGzipPax,
    TarGzipGnuLongName,
    TarZstdUstar,
    TarXzUstar,
    TarBzip2Ustar,
    SevenZCopy,
}

fn parse_cli_format(raw: &str) -> Result<CliFormat, String> {
    match raw {
        "zip" => Ok(CliFormat::Zip),
        "zip64" => Ok(CliFormat::Zip64),
        "tar-ustar" => Ok(CliFormat::TarUstar),
        "tar-gzip-ustar" => Ok(CliFormat::TarGzipUstar),
        "tar-pax" => Ok(CliFormat::TarPax),
        "tar-gnu-longname" => Ok(CliFormat::TarGnuLongName),
        "tar-gzip-pax" => Ok(CliFormat::TarGzipPax),
        "tar-gzip-gnu-longname" => Ok(CliFormat::TarGzipGnuLongName),
        "tar-zstd-ustar" => Ok(CliFormat::TarZstdUstar),
        "tar-xz-ustar" => Ok(CliFormat::TarXzUstar),
        "tar-bzip2-ustar" => Ok(CliFormat::TarBzip2Ustar),
        "7z-copy" => Ok(CliFormat::SevenZCopy),
        other => Err(unknown_format_message(other)),
    }
}

fn unknown_format_message(raw: &str) -> String {
    let gzip_tar = raw == "tar-gz"
        || raw == "tgz"
        || raw == "tar.gz"
        || raw == ".tar.gz"
        || raw.contains("gzip")
        || raw.contains("tar.gz");
    if gzip_tar {
        format!(
            "{raw} is not a sealr format. See formats: sealr --help. gzip TAR formats: tar-gzip-ustar, tar-gzip-pax, tar-gzip-gnu-longname"
        )
    } else {
        format!("{raw} is not a sealr format. See formats: sealr --help")
    }
}

struct SetupFailure {
    category: &'static str,
    exit: u8,
    code: &'static str,
    finding_code: Option<&'static str>,
    detail: String,
}

fn mode_requests(cli: &Cli) -> (bool, bool, bool) {
    match &cli.command {
        Some(CliCommand::Inspect { common } | CliCommand::Materialize { common, .. }) => {
            (common.machine, common.json, common.canonical)
        }
        None => (cli.machine, cli.json, cli.canonical),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (machine, json, canonical) = mode_requests(&cli);
    if machine && (json || canonical) {
        return report_setup(
            machine,
            SetupFailure {
                category: "usage",
                exit: 2,
                code: "usage.incompatible_flags",
                finding_code: None,
                detail: "--machine cannot be combined with --json or --canonical".to_owned(),
            },
        );
    }
    let invocation = match resolve(cli) {
        Ok(invocation) => invocation,
        Err(message) => {
            return report_setup(
                machine,
                SetupFailure {
                    category: "usage",
                    exit: 2,
                    code: "usage.archive_required",
                    finding_code: None,
                    detail: message,
                },
            );
        }
    };
    let caller_policy = match invocation.policy.as_deref().map(load_policy).transpose() {
        Ok(policy) => policy,
        Err(failure) => return report_setup(invocation.machine, failure),
    };
    let (default_policy, options) = match invocation.format {
        CliFormat::Zip => (Policy::default_v1(), ApplyOptions::new()),
        CliFormat::Zip64 => (
            Policy::default_v3(),
            ApplyOptions::new()
                .with_interpretation_profile(ZipInterpretationProfile::Zip64StrictAsciiV1),
        ),
        CliFormat::TarUstar => (
            Policy::default_v2(),
            ApplyOptions::new()
                .with_tar_interpretation_profile(TarInterpretationProfile::UstarPortableV1),
        ),
        CliFormat::TarGzipUstar => (
            Policy::default_v4(),
            ApplyOptions::new().with_tar_gzip_interpretation_profile(
                TarGzipInterpretationProfile::UstarPortableV1,
            ),
        ),
        CliFormat::TarPax => (
            Policy::default_v5(),
            ApplyOptions::new()
                .with_tar_pax_interpretation_profile(TarPaxInterpretationProfile::PortableV1),
        ),
        CliFormat::TarGnuLongName => (
            Policy::default_v6(),
            ApplyOptions::new().with_tar_gnu_longname_interpretation_profile(
                TarGnuLongNameInterpretationProfile::PortableV1,
            ),
        ),
        CliFormat::TarGzipPax => (
            Policy::default_v7(),
            ApplyOptions::new()
                .with_tar_gzip_interpretation_profile(TarGzipInterpretationProfile::PaxPortableV1),
        ),
        CliFormat::TarGzipGnuLongName => (
            Policy::default_v7(),
            ApplyOptions::new().with_tar_gzip_interpretation_profile(
                TarGzipInterpretationProfile::GnuLongNamePortableV1,
            ),
        ),
        CliFormat::TarZstdUstar => (
            Policy::default_v8(),
            ApplyOptions::new().with_tar_zstd_interpretation_profile(
                TarZstdInterpretationProfile::UstarPortableV1,
            ),
        ),
        CliFormat::TarXzUstar => (
            Policy::default_v9(),
            ApplyOptions::new()
                .with_tar_xz_interpretation_profile(TarXzInterpretationProfile::UstarPortableV1),
        ),
        CliFormat::TarBzip2Ustar => (
            Policy::default_v10(),
            ApplyOptions::new().with_tar_bzip2_interpretation_profile(
                TarBzip2InterpretationProfile::UstarPortableV1,
            ),
        ),
        CliFormat::SevenZCopy => (
            Policy::default_v11(),
            ApplyOptions::new()
                .with_sevenz_interpretation_profile(SevenZInterpretationProfile::CopyPortableV1),
        ),
    };
    let policy = caller_policy.unwrap_or(default_policy);
    let request = Request {
        source: Source::Path(&invocation.archive),
        policy: &policy,
        dest: invocation.dest.as_deref(),
    };
    let worker = match invocation.worker_manifest.as_deref() {
        Some(manifest) => match LinuxWorker::load_from_manifest(manifest) {
            Ok(worker) => Some(worker),
            Err(error) => {
                return report_setup(
                    invocation.machine,
                    SetupFailure {
                        category: "worker",
                        exit: 1,
                        code: machine::worker_code(error.kind()),
                        finding_code: None,
                        detail: format!("supervised execution failed: {error}"),
                    },
                );
            }
        },
        None => None,
    };
    // Output destinations are claimed before any evaluation or materialization
    // effect, and an existing file is never overwritten. A refusal after a
    // partial claim discards the claim so the filesystem is unchanged.
    let view_output = match ClaimedOutput::claim("view", invocation.view.as_deref()) {
        Ok(claimed) => claimed,
        Err(detail) => {
            return report_setup(
                invocation.machine,
                SetupFailure {
                    category: "output",
                    exit: 1,
                    code: "output.view_exists",
                    finding_code: None,
                    detail,
                },
            );
        }
    };
    let receipt_output = match ClaimedOutput::claim("receipt", invocation.receipt.as_deref()) {
        Ok(claimed) => claimed,
        Err(detail) => {
            if let Some(view) = view_output {
                view.discard();
            }
            return report_setup(
                invocation.machine,
                SetupFailure {
                    category: "output",
                    exit: 1,
                    code: "output.receipt_exists",
                    finding_code: None,
                    detail,
                },
            );
        }
    };
    let out = if let Some(worker) = worker.as_ref() {
        match apply_supervised(request, &options, worker) {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(view) = view_output {
                    view.discard();
                }
                if let Some(receipt) = receipt_output {
                    receipt.discard();
                }
                return report_setup(
                    invocation.machine,
                    SetupFailure {
                        category: "worker",
                        exit: 1,
                        code: machine::worker_code(error.kind()),
                        finding_code: None,
                        detail: format!("supervised execution failed: {error}"),
                    },
                );
            }
        }
    } else {
        apply_with_options(request, &options)
    };
    if invocation.canonical {
        let view_claimed = view_output.expect("clap requires --view with --canonical");
        let receipt_claimed = receipt_output.expect("clap requires --receipt with --canonical");
        let evidence = match out.canonical_evidence() {
            Ok(evidence) => evidence,
            Err(finding) => {
                eprintln!(
                    "sealr: canonical evidence emission failed: {}: {}",
                    finding.code.as_str(),
                    finding.detail
                );
                view_claimed.discard();
                receipt_claimed.discard();
                return ExitCode::FAILURE;
            }
        };
        let exit = out.cli_exit_code();
        let mut view_file = view_claimed.into_file();
        let mut receipt_file = receipt_claimed.into_file();
        if view_file.write_all(&evidence.view_bytes).is_err()
            || receipt_file.write_all(&evidence.receipt_bytes).is_err()
        {
            eprintln!("sealr: canonical evidence files were not completely written");
            drop(view_file);
            drop(receipt_file);
            let _ = std::fs::remove_file(invocation.view.as_deref().expect("view path"));
            let _ = std::fs::remove_file(invocation.receipt.as_deref().expect("receipt path"));
            return ExitCode::FAILURE;
        }
        return ExitCode::from(exit);
    }
    if invocation.machine {
        return finish_machine(&out, view_output, receipt_output);
    }
    let stdout_is_tty = io::stdout().is_terminal();
    let stderr_is_tty = io::stderr().is_terminal();
    if use_tty_summary(
        stderr_is_tty,
        invocation.view.is_some(),
        invocation.receipt.is_some(),
        invocation.json,
        false,
        invocation.color,
    ) {
        let summary = format_summary(&SummaryRequest {
            exit_class: out.cli_exit_code(),
            wrote: out.view.wrote,
            member_count: out.view.members.len(),
            findings: &out.view.findings,
            dest: invocation.dest.as_deref(),
            content_tree: content_tree_preview(&out),
            stderr_is_tty,
            color: summary_color(invocation.color, stderr_is_tty, &color_env()),
        });
        if io::stderr().write_all(summary.as_bytes()).is_err() {
            return ExitCode::FAILURE;
        }
        if !stdout_is_tty {
            let mut view_writer: Box<dyn Write> = Box::new(io::stdout().lock());
            if write_json(&mut view_writer, &out.view).is_err() {
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::from(out.cli_exit_code());
    }
    let mut view_writer: Box<dyn Write> = match view_output {
        Some(claimed) => Box::new(claimed.into_file()),
        None => Box::new(io::stdout().lock()),
    };
    let mut receipt_writer: Box<dyn Write> = match receipt_output {
        Some(claimed) => Box::new(claimed.into_file()),
        None => Box::new(io::stderr().lock()),
    };
    write_outputs(
        &mut view_writer,
        &mut receipt_writer,
        &out.view,
        &out.receipt,
        out.cli_exit_code(),
    )
}

/// Read, parse, and validate one JSON policy document, or explain exactly
/// why it was refused. A refused policy never reaches evaluation.
fn load_policy(path: &Path) -> Result<Policy, SetupFailure> {
    const MAX_POLICY_BYTES: u64 = 1024 * 1024;
    let refuse =
        |code: &'static str, finding_code: Option<&'static str>, detail: String| SetupFailure {
            category: "policy",
            exit: 2,
            code,
            finding_code,
            detail,
        };
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(refuse(
                "policy.unreadable",
                None,
                format!("policy file {} was not readable: {error}", path.display()),
            ));
        }
    };
    if metadata.len() > MAX_POLICY_BYTES {
        return Err(refuse(
            "policy.too_large",
            None,
            format!(
                "policy file {} of {} bytes exceeds the {MAX_POLICY_BYTES}-byte bound",
                path.display(),
                metadata.len()
            ),
        ));
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(refuse(
                "policy.unreadable",
                None,
                format!("policy file {} was not readable: {error}", path.display()),
            ));
        }
    };
    let document: PolicyDocumentV12 = match serde_json::from_slice(&bytes) {
        Ok(document) => document,
        Err(error) => {
            return Err(refuse(
                "policy.invalid_json",
                None,
                format!(
                    "policy file {} is not one valid policy document: {error}",
                    path.display()
                ),
            ));
        }
    };
    let validated = match document.validate() {
        Ok(validated) => validated,
        Err(finding) => {
            let code = finding.code.as_str();
            return Err(refuse(
                "policy.refused",
                Some(code),
                format!(
                    "policy file {} was refused: {}: {}",
                    path.display(),
                    code,
                    finding.detail
                ),
            ));
        }
    };
    Ok(validated.into_policy())
}

/// An output file this process created itself and may therefore remove again.
struct ClaimedOutput {
    path: PathBuf,
    file: File,
}

impl ClaimedOutput {
    fn claim(label: &str, path: Option<&Path>) -> Result<Option<Self>, String> {
        let Some(path) = path else {
            return Ok(None);
        };
        match File::create_new(path) {
            Ok(file) => Ok(Some(Self {
                path: path.to_path_buf(),
                file,
            })),
            Err(error) => Err(format!(
                "{label} output file {} was not created: {error}",
                path.display()
            )),
        }
    }

    fn discard(self) {
        let Self { path, file } = self;
        drop(file);
        let _ = std::fs::remove_file(&path);
    }

    fn into_file(self) -> File {
        self.file
    }
}

/// Human summary when stderr is a terminal, or when `--color always` asks for
/// the colored line even though stderr is redirected. A view file, a receipt
/// file, `--json`, or `--machine` keeps the evidence streams.
fn use_tty_summary(
    stderr_is_tty: bool,
    view_file: bool,
    receipt_file: bool,
    json: bool,
    machine: bool,
    color: ColorChoice,
) -> bool {
    if view_file || receipt_file || json || machine {
        return false;
    }
    stderr_is_tty || color == ColorChoice::Always
}

struct ColorEnv {
    no_color: bool,
    clicolor_force: bool,
    clicolor_off: bool,
    term_dumb: bool,
}

fn color_env() -> ColorEnv {
    let nonempty = |name: &str| {
        std::env::var(name)
            .ok()
            .is_some_and(|value| !value.is_empty())
    };
    ColorEnv {
        no_color: nonempty("NO_COLOR"),
        clicolor_force: std::env::var("CLICOLOR_FORCE")
            .ok()
            .is_some_and(|value| !value.is_empty() && value != "0"),
        clicolor_off: std::env::var("CLICOLOR").ok().as_deref() == Some("0"),
        term_dumb: std::env::var("TERM").ok().as_deref() == Some("dumb"),
    }
}

/// `--color always` ignores the environment. On `auto`, a non-empty `NO_COLOR`
/// wins over `CLICOLOR_FORCE`. `CLICOLOR_FORCE` then wins over `CLICOLOR=0`
/// and `TERM=dumb`. Otherwise color follows the stderr terminal.
fn summary_color(choice: ColorChoice, stderr_is_tty: bool, env: &ColorEnv) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            if env.no_color {
                false
            } else if env.clicolor_force {
                true
            } else if env.term_dumb || env.clicolor_off {
                false
            } else {
                stderr_is_tty
            }
        }
    }
}

struct SummaryRequest<'a> {
    exit_class: u8,
    wrote: bool,
    member_count: usize,
    findings: &'a [Finding],
    dest: Option<&'a Path>,
    content_tree: Option<String>,
    stderr_is_tty: bool,
    color: bool,
}

fn paint_span(enabled: bool, code: &str, text: &str) -> String {
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

fn terminal_text(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect()
}

fn cap_member(text: &str) -> String {
    let clean = terminal_text(text);
    if clean.chars().count() <= 120 {
        return clean;
    }
    let mut out: String = clean.chars().take(117).collect();
    out.push_str("...");
    out
}

fn count_phrase(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

fn append_more(text: &mut String, count: usize) {
    if count > 1 {
        let extra = count - 1;
        text.push_str(&format!(" (+{extra} more; --json for all)"));
    }
}

/// First 16 hex digits of a `sealrTreeV1` content identity. Later tree
/// versions and unavailable identities stay quiet. The preview is unsigned.
fn content_tree_preview(out: &Outcome) -> Option<String> {
    let value = serde_json::to_value(&out.receipt.identities.content).ok()?;
    let hex = value.get("sealrTreeV1")?.as_str()?;
    if hex.len() >= 16 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(hex[..16].to_owned())
    } else {
        None
    }
}

fn format_summary(request: &SummaryRequest<'_>) -> String {
    let color = request.color;
    let mut line = if request.exit_class == 0 {
        let effect = if request.wrote {
            match request.dest {
                Some(dest) => format!("wrote {}", terminal_text(&dest.display().to_string())),
                None => "wrote".to_owned(),
            }
        } else {
            "nothing written (use --dest DIR to materialize)".to_owned()
        };
        format!(
            "{}: {}, {}, {effect}",
            paint_span(color, "32", "allowed"),
            count_phrase(request.member_count, "member", "members"),
            count_phrase(request.findings.len(), "finding", "findings"),
        )
    } else {
        let (word, kind_code) = if request.exit_class == 3 {
            ("not written", "33")
        } else {
            ("rejected", "31")
        };
        let verdict = paint_span(color, kind_code, word);
        match request.findings.first() {
            None => verdict,
            Some(finding)
                if request.exit_class == 3 && finding.code == FindingCode::MaterializeExists =>
            {
                let mut text = format!(
                    "{verdict}: {} ({})",
                    paint_span(color, "1", finding.code.as_str()),
                    paint_span(
                        color,
                        "2",
                        "destination already exists; sealr never replaces"
                    ),
                );
                text.push_str(". Choose a new --dest path.");
                append_more(&mut text, request.findings.len());
                text
            }
            Some(finding) => refusal_clause(color, &verdict, finding, request.findings.len()),
        }
    };
    if request.exit_class == 0
        && request.wrote
        && request.stderr_is_tty
        && let Some(hex) = &request.content_tree
    {
        line.push('\n');
        let tree = format!("content tree {hex} (preview identity, unsigned)");
        line.push_str(&paint_span(color, "2", &tree));
    }
    line.push('\n');
    line
}

fn refusal_clause(color: bool, verdict: &str, finding: &Finding, finding_count: usize) -> String {
    let mut text = format!(
        "{verdict}: {}",
        paint_span(color, "1", finding.code.as_str())
    );
    if let Some(member) = finding.member.as_deref() {
        text.push_str(" member ");
        text.push_str(&cap_member(member));
    }
    if let Some(hint) = &finding.hint {
        let inner = if finding.member.is_some() {
            terminal_text(&hint.observed)
        } else {
            format!("observed {}", terminal_text(&hint.observed))
        };
        text.push_str(" (");
        text.push_str(&paint_span(color, "2", &inner));
        text.push(')');
        if !hint.formats.is_empty() {
            text.push_str(". ");
            text.push_str(&paint_span(color, "1", "Try:"));
            text.push_str(" --format ");
            text.push_str(&hint.formats.join(" | "));
        }
    } else {
        text.push_str(" (");
        text.push_str(&paint_span(color, "2", &terminal_text(&finding.detail)));
        text.push(')');
    }
    append_more(&mut text, finding_count);
    text
}

fn report_setup(machine: bool, failure: SetupFailure) -> ExitCode {
    if !machine {
        eprintln!("sealr: {}", failure.detail);
        return ExitCode::from(failure.exit);
    }
    let output = match failure.code {
        "output.view_exists" => machine::OutputDelivery::failed("view"),
        "output.receipt_exists" => machine::OutputDelivery::failed("receipt"),
        _ => machine::OutputDelivery::not_requested(),
    };
    let document = machine::setup_result(
        failure.category,
        failure.exit,
        machine::FailureResult {
            code: failure.code,
            finding_code: failure.finding_code,
            detail: failure.detail,
        },
        output,
    );
    if write_json(&mut io::stdout().lock(), &document).is_err() {
        eprintln!("sealr: command result was not written to stdout");
        return ExitCode::FAILURE;
    }
    ExitCode::from(failure.exit)
}

fn finish_machine(
    out: &Outcome,
    view_output: Option<ClaimedOutput>,
    receipt_output: Option<ClaimedOutput>,
) -> ExitCode {
    let semantic_exit = out.cli_exit_code();
    let committed = out.view.wrote;
    let mut failed_stage: Option<&'static str> = None;
    if let Some(claimed) = view_output
        && !write_claimed_json(claimed, &out.view)
    {
        failed_stage = Some("view");
    }
    if failed_stage.is_none() {
        if let Some(claimed) = receipt_output
            && !write_claimed_json(claimed, &out.receipt)
        {
            failed_stage = Some("receipt");
        }
    } else if let Some(claimed) = receipt_output {
        claimed.discard();
    }
    let process_exit = if failed_stage.is_some() {
        1
    } else {
        semantic_exit
    };
    let output = match failed_stage {
        Some(stage) => machine::OutputDelivery::failed(stage),
        None => machine::OutputDelivery::delivered(),
    };
    let mut document = machine::semantic_result(out, output, process_exit);
    if let Some(stage) = failed_stage {
        document.failure = Some(machine::FailureResult {
            code: "output.write_failed",
            finding_code: None,
            detail: format!("{stage} output was not completely written"),
        });
    }
    if write_json(&mut io::stdout().lock(), &document).is_err() {
        if committed {
            eprintln!(
                "sealr: command result was not written to stdout after a committed destination. The destination was not rolled back. Do not retry the write blindly."
            );
        } else {
            eprintln!("sealr: command result was not written to stdout");
        }
        return ExitCode::FAILURE;
    }
    if let Some(stage) = failed_stage {
        if committed {
            eprintln!(
                "sealr: {stage} output was not completely written after a committed destination. The destination was not rolled back. Do not retry the write blindly."
            );
        } else {
            eprintln!("sealr: {stage} output was not completely written");
        }
        return ExitCode::FAILURE;
    }
    ExitCode::from(semantic_exit)
}

fn write_claimed_json(claimed: ClaimedOutput, value: &impl Serialize) -> bool {
    let path = claimed.path.clone();
    let mut file = claimed.into_file();
    if write_json(&mut file, value).is_ok() {
        true
    } else {
        drop(file);
        let _ = std::fs::remove_file(&path);
        false
    }
}

fn write_json(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")
}

fn write_outputs(
    view_writer: &mut impl Write,
    receipt_writer: &mut impl Write,
    view: &impl Serialize,
    receipt: &impl Serialize,
    semantic_exit_code: u8,
) -> ExitCode {
    let view_result = write_json(view_writer, view);
    let receipt_result = write_json(receipt_writer, receipt);
    if view_result.is_err() || receipt_result.is_err() {
        ExitCode::FAILURE
    } else {
        ExitCode::from(semantic_exit_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use sealr::{FindingCode, FindingHint};

    struct ClosedWriter;

    impl Write for ClosedWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn failed_view_stream_does_not_suppress_the_receipt() {
        let mut view = ClosedWriter;
        let mut receipt = Vec::new();

        let exit = write_outputs(
            &mut view,
            &mut receipt,
            &serde_json::json!({ "schema": "sealr.view.v1" }),
            &serde_json::json!({ "schema": "sealr.receipt.v2" }),
            0,
        );

        assert_eq!(exit, ExitCode::FAILURE);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&receipt).unwrap(),
            serde_json::json!({ "schema": "sealr.receipt.v2" })
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn line(
        exit_class: u8,
        wrote: bool,
        members: usize,
        findings: &[Finding],
        dest: Option<&Path>,
        tree: Option<&str>,
        stderr_is_tty: bool,
        color: bool,
    ) -> String {
        format_summary(&SummaryRequest {
            exit_class,
            wrote,
            member_count: members,
            findings,
            dest,
            content_tree: tree.map(str::to_owned),
            stderr_is_tty,
            color,
        })
    }

    #[test]
    fn tty_summary_follows_stderr_and_color_always() {
        assert!(use_tty_summary(
            true,
            false,
            false,
            false,
            false,
            ColorChoice::Auto
        ));
        assert!(!use_tty_summary(
            false,
            false,
            false,
            false,
            false,
            ColorChoice::Auto
        ));
        assert!(use_tty_summary(
            false,
            false,
            false,
            false,
            false,
            ColorChoice::Always
        ));
        assert!(!use_tty_summary(
            true,
            true,
            false,
            false,
            false,
            ColorChoice::Always
        ));
        assert!(!use_tty_summary(
            true,
            false,
            true,
            false,
            false,
            ColorChoice::Auto
        ));
        assert!(!use_tty_summary(
            true,
            false,
            false,
            true,
            false,
            ColorChoice::Auto
        ));
        assert!(!use_tty_summary(
            true,
            false,
            false,
            false,
            true,
            ColorChoice::Always
        ));
    }

    #[test]
    fn summary_color_follows_choice_then_environment() {
        let plain = ColorEnv {
            no_color: false,
            clicolor_force: false,
            clicolor_off: false,
            term_dumb: false,
        };
        assert!(summary_color(ColorChoice::Always, false, &plain));
        assert!(!summary_color(ColorChoice::Never, true, &plain));
        assert!(summary_color(ColorChoice::Auto, true, &plain));
        assert!(!summary_color(ColorChoice::Auto, false, &plain));

        let no_color = ColorEnv {
            no_color: true,
            clicolor_force: true,
            clicolor_off: false,
            term_dumb: false,
        };
        assert!(!summary_color(ColorChoice::Auto, true, &no_color));
        assert!(summary_color(ColorChoice::Always, false, &no_color));

        let forced = ColorEnv {
            no_color: false,
            clicolor_force: true,
            clicolor_off: true,
            term_dumb: true,
        };
        assert!(summary_color(ColorChoice::Auto, false, &forced));

        let dumb = ColorEnv {
            no_color: false,
            clicolor_force: false,
            clicolor_off: false,
            term_dumb: true,
        };
        assert!(!summary_color(ColorChoice::Auto, true, &dumb));
        let off = ColorEnv {
            clicolor_off: true,
            ..dumb
        };
        assert!(!summary_color(ColorChoice::Auto, true, &off));
    }

    #[test]
    fn summary_lines_name_the_verdict_member_and_next_step() {
        let hinted = Finding::error(FindingCode::FormatMagic, "gzip magic is not 1f 8b")
            .with_hint(FindingHint::new("xz stream", ["tar-xz-ustar"]));
        assert_eq!(
            line(2, false, 0, &[hinted], None, None, true, false),
            "rejected: format.magic (observed xz stream). Try: --format tar-xz-ustar\n"
        );

        let sibling = Finding::error(
            FindingCode::TarFeatureUnsupported,
            "PAX extended header (ustar typeflag 0x78)",
        )
        .on("link")
        .with_hint(FindingHint::new("PAX extended header", ["tar-gzip-pax"]));
        assert_eq!(
            line(2, false, 0, &[sibling], None, None, true, false),
            "rejected: tar.feature_unsupported member link (PAX extended header). Try: --format tar-gzip-pax\n"
        );

        let path = Finding::error(FindingCode::PathDotDot, "parent component").on("./../x");
        assert_eq!(
            line(2, false, 0, &[path], None, None, true, false),
            "rejected: path.dotdot member ./../x (parent component)\n"
        );

        let first = Finding::error(FindingCode::PathDotDot, "parent component").on("../a");
        let extra = [
            first,
            Finding::error(FindingCode::PathEmpty, "empty"),
            Finding::error(FindingCode::PathEmpty, "empty"),
            Finding::error(FindingCode::PathEmpty, "empty"),
        ];
        assert_eq!(
            line(2, false, 0, &extra, None, None, true, false),
            "rejected: path.dotdot member ../a (parent component) (+3 more; --json for all)\n"
        );

        assert_eq!(
            line(0, false, 1, &[], None, None, true, false),
            "allowed: 1 member, 0 findings, nothing written (use --dest DIR to materialize)\n"
        );
        assert_eq!(
            line(
                0,
                false,
                2,
                &[Finding::error(FindingCode::PathEmpty, "empty")],
                None,
                None,
                true,
                false
            ),
            "allowed: 2 members, 1 finding, nothing written (use --dest DIR to materialize)\n"
        );
        assert_eq!(
            line(
                0,
                true,
                2,
                &[],
                Some(Path::new("/tmp/out")),
                None,
                true,
                false
            ),
            "allowed: 2 members, 0 findings, wrote /tmp/out\n"
        );
        assert_eq!(
            line(
                0,
                true,
                1,
                &[],
                Some(Path::new("/tmp/out")),
                Some("850eb7fb25938114"),
                true,
                false
            ),
            "allowed: 1 member, 0 findings, wrote /tmp/out\ncontent tree 850eb7fb25938114 (preview identity, unsigned)\n"
        );
        assert_eq!(
            line(
                0,
                true,
                1,
                &[],
                Some(Path::new("/tmp/out")),
                Some("850eb7fb25938114"),
                false,
                false
            ),
            "allowed: 1 member, 0 findings, wrote /tmp/out\n",
            "a redirected summary omits the preview line"
        );
        assert_eq!(
            line(
                2,
                false,
                0,
                &[],
                None,
                Some("850eb7fb25938114"),
                true,
                false
            ),
            "rejected\n"
        );

        let exists = Finding::error(
            FindingCode::MaterializeExists,
            "destination already exists; replacement is not implemented",
        );
        assert_eq!(
            line(
                3,
                false,
                1,
                &[exists],
                Some(Path::new("exists")),
                None,
                true,
                false
            ),
            "not written: materialize.exists (destination already exists; sealr never replaces). Choose a new --dest path.\n"
        );
    }

    #[test]
    fn summary_color_paints_only_the_named_spans() {
        let exists = Finding::error(
            FindingCode::MaterializeExists,
            "destination already exists; replacement is not implemented",
        );
        let colored = line(3, false, 1, &[exists], None, None, true, true);
        assert!(colored.starts_with("\x1b[33mnot written\x1b[0m: \x1b[1mmaterialize.exists\x1b[0m (\x1b[2mdestination already exists; sealr never replaces\x1b[0m)."));
        assert!(!colored.contains("\x1b[38"));
        assert!(!colored.contains("\x1b[35"));

        let hinted = Finding::error(FindingCode::FormatMagic, "gzip magic is not 1f 8b")
            .with_hint(FindingHint::new("xz stream", ["tar-xz-ustar"]));
        let rejected = line(2, false, 0, &[hinted], None, None, true, true);
        assert!(rejected.contains("\x1b[31mrejected\x1b[0m"));
        assert!(rejected.contains("\x1b[1mformat.magic\x1b[0m"));
        assert!(rejected.contains("\x1b[2mobserved xz stream\x1b[0m"));
        assert!(rejected.contains("\x1b[1mTry:\x1b[0m --format tar-xz-ustar\n"));

        let allowed = line(
            0,
            true,
            1,
            &[],
            Some(Path::new("/tmp/out")),
            Some("850eb7fb25938114"),
            true,
            true,
        );
        assert!(
            allowed.starts_with("\x1b[32mallowed\x1b[0m: 1 member, 0 findings, wrote /tmp/out\n")
        );
        assert!(allowed.contains(
            "\x1b[2mcontent tree 850eb7fb25938114 (preview identity, unsigned)\x1b[0m\n"
        ));
    }

    #[test]
    fn summary_strips_terminal_controls_from_displayed_text() {
        let path = Finding::error(FindingCode::PathInvalidChar, "bad\nname").on("a\u{1b}[31mb");
        let rendered = line(2, false, 0, &[path], None, None, true, false);
        assert_eq!(
            rendered,
            "rejected: path.invalid_char member a?[31mb (bad?name)\n"
        );
        assert_eq!(rendered.matches('\n').count(), 1);
        let long = "x".repeat(130);
        let long_finding = Finding::error(FindingCode::PathDepth, "deep").on(long);
        let rendered = line(2, false, 0, &[long_finding], None, None, true, false);
        assert!(rendered.contains(&format!("{}...", "x".repeat(117))));
        assert!(!rendered.contains(&"x".repeat(118)));
    }

    #[test]
    fn help_is_ascii_and_keeps_format_names_on_one_line() {
        let formats = [
            "zip",
            "zip64",
            "tar-ustar",
            "tar-pax",
            "tar-gnu-longname",
            "tar-gzip-ustar",
            "tar-gzip-pax",
            "tar-gzip-gnu-longname",
            "tar-zstd-ustar",
            "tar-xz-ustar",
            "tar-bzip2-ustar",
            "7z-copy",
        ];
        for width in [60_usize, 80, 100] {
            let mut command = Cli::command().term_width(width);
            let mut buffer = Vec::new();
            command.write_long_help(&mut buffer).unwrap();
            let text = String::from_utf8(buffer).unwrap();
            assert!(text.is_ascii(), "{text}");
            assert!(text.contains("do not reopen the archive"));
            assert!(text.contains("not an authority"));
            assert!(text.contains("Admit an untrusted archive"));
            for name in formats {
                assert!(
                    text.lines().any(|line| line.contains(name)),
                    "{name} missing or split at width {width}:\n{text}"
                );
            }
            for line in text.lines() {
                assert!(
                    line.chars().count() <= width,
                    "line exceeds {width}: {line}"
                );
            }
        }
    }
}
