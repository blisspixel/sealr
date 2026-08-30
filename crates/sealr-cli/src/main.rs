use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use sealr::{
    apply_supervised, apply_with_options, ApplyOptions, LinuxWorker, Policy, PolicyDocument,
    Request, SevenZInterpretationProfile, Source, TarBzip2InterpretationProfile,
    TarGnuLongNameInterpretationProfile, TarGzipInterpretationProfile, TarInterpretationProfile,
    TarPaxInterpretationProfile, TarXzInterpretationProfile, TarZstdInterpretationProfile,
    ZipInterpretationProfile,
};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "sealr",
    version,
    about = "Untrusted archive × policy → (materialize | reject) × receipt × view",
    after_help = "The archive is admitted through exactly one interpretation. After admission, do \
                  not reopen the archive: consume the materialized --dest tree, or a VerifiedArchive \
                  from the library, and never parse the original bytes again. The original archive \
                  is not an authority; a second parser is where interpretations disagree.",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
    /// Archive file
    archive: Option<PathBuf>,
    /// Exact container interpretation to apply
    #[arg(long, value_enum, default_value_t = CliFormat::Zip)]
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
    #[arg(long, value_enum, default_value_t = CliFormat::Zip)]
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
            })
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliFormat {
    Zip,
    Zip64,
    TarUstar,
    TarGzipUstar,
    TarPax,
    #[value(name = "tar-gnu-longname")]
    TarGnuLongName,
    #[value(name = "tar-gzip-pax")]
    TarGzipPax,
    #[value(name = "tar-gzip-gnu-longname")]
    TarGzipGnuLongName,
    TarZstdUstar,
    TarXzUstar,
    TarBzip2Ustar,
    #[value(name = "7z-copy")]
    SevenZCopy,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let invocation = match resolve(cli) {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("sealr: {message}");
            return ExitCode::from(2);
        }
    };
    let caller_policy = match invocation.policy.as_deref().map(load_policy).transpose() {
        Ok(policy) => policy,
        Err(message) => {
            eprintln!("sealr: {message}");
            return ExitCode::from(2);
        }
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
                eprintln!("sealr: supervised execution failed: {error}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };
    // Output destinations are claimed before any evaluation or materialization
    // effect, and an existing file is never overwritten. A refusal after a
    // partial claim discards the claim so the filesystem is unchanged.
    let view_output = match ClaimedOutput::claim("view", invocation.view.as_deref()) {
        Ok(claimed) => claimed,
        Err(exit) => return exit,
    };
    let receipt_output = match ClaimedOutput::claim("receipt", invocation.receipt.as_deref()) {
        Ok(claimed) => claimed,
        Err(exit) => {
            if let Some(view) = view_output {
                view.discard();
            }
            return exit;
        }
    };
    let out = if let Some(worker) = worker.as_ref() {
        match apply_supervised(request, &options, worker) {
            Ok(outcome) => outcome,
            Err(error) => {
                eprintln!("sealr: supervised execution failed: {error}");
                if let Some(view) = view_output {
                    view.discard();
                }
                if let Some(receipt) = receipt_output {
                    receipt.discard();
                }
                return ExitCode::FAILURE;
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
fn load_policy(path: &Path) -> Result<Policy, String> {
    const MAX_POLICY_BYTES: u64 = 1024 * 1024;
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("policy file {} was not readable: {error}", path.display()))?;
    if metadata.len() > MAX_POLICY_BYTES {
        return Err(format!(
            "policy file {} of {} bytes exceeds the {MAX_POLICY_BYTES}-byte bound",
            path.display(),
            metadata.len()
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("policy file {} was not readable: {error}", path.display()))?;
    let document: PolicyDocument = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "policy file {} is not one valid policy document: {error}",
            path.display()
        )
    })?;
    let validated = document.validate().map_err(|finding| {
        format!(
            "policy file {} was refused: {}: {}",
            path.display(),
            finding.code.as_str(),
            finding.detail
        )
    })?;
    Ok(validated.into_policy())
}

/// An output file this process created itself and may therefore remove again.
struct ClaimedOutput {
    path: PathBuf,
    file: File,
}

impl ClaimedOutput {
    fn claim(label: &str, path: Option<&Path>) -> Result<Option<Self>, ExitCode> {
        let Some(path) = path else {
            return Ok(None);
        };
        match File::create_new(path) {
            Ok(file) => Ok(Some(Self {
                path: path.to_path_buf(),
                file,
            })),
            Err(error) => {
                eprintln!(
                    "sealr: {label} output file {} was not created: {error}",
                    path.display()
                );
                Err(ExitCode::FAILURE)
            }
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
}
