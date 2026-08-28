use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use sealr::{
    apply_supervised, apply_with_options, ApplyOptions, LinuxWorker, Policy, Request, Source,
    TarGzipInterpretationProfile, TarInterpretationProfile, TarPaxInterpretationProfile,
    ZipInterpretationProfile,
};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "sealr",
    version,
    about = "Untrusted archive × policy → (materialize | reject) × receipt × view"
)]
struct Cli {
    /// Archive file
    archive: PathBuf,
    /// Exact container interpretation to apply
    #[arg(long, value_enum, default_value_t = CliFormat::Zip)]
    format: CliFormat,
    /// Materialize into a new directory below an existing parent
    #[arg(long)]
    dest: Option<PathBuf>,
    /// Use the exact packaged Linux worker bound by this manifest
    #[arg(long, value_name = "ABSOLUTE_PATH")]
    worker_manifest: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliFormat {
    Zip,
    Zip64,
    TarUstar,
    TarGzipUstar,
    TarPax,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (policy, options) = match cli.format {
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
    };
    let request = Request {
        source: Source::Path(&cli.archive),
        policy: &policy,
        dest: cli.dest.as_deref(),
    };
    let out = if let Some(manifest) = cli.worker_manifest.as_deref() {
        let worker = match LinuxWorker::load_from_manifest(manifest) {
            Ok(worker) => worker,
            Err(error) => {
                eprintln!("sealr: supervised execution failed: {error}");
                return ExitCode::FAILURE;
            }
        };
        match apply_supervised(request, &options, &worker) {
            Ok(outcome) => outcome,
            Err(error) => {
                eprintln!("sealr: supervised execution failed: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        apply_with_options(request, &options)
    };
    write_outputs(
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
        &out.view,
        &out.receipt,
        out.cli_exit_code(),
    )
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
