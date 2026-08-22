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
    if let Err(error) = write_json(&mut io::stdout().lock(), &out.view) {
        let _ = writeln!(io::stderr().lock(), "sealr: write view: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = write_json(&mut io::stderr().lock(), &out.receipt) {
        let _ = writeln!(io::stderr().lock(), "sealr: write receipt: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::from(out.cli_exit_code())
}

fn write_json(writer: &mut impl Write, value: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *writer, value).map_err(io::Error::other)?;
    writer.write_all(b"\n")
}
