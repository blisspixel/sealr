use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use sealr::{apply, Policy, Request, Source};
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
    /// Materialize into a new directory below an existing parent
    #[arg(long)]
    dest: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let policy = Policy::default_v1();
    let out = apply(Request {
        source: Source::Path(&cli.archive),
        policy: &policy,
        dest: cli.dest.as_deref(),
    });
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
