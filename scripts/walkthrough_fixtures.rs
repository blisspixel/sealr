use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(not(test))]
use std::env;
#[cfg(not(test))]
use std::process::ExitCode;

pub const ALLOWED_NAME: &str = "allowed.zip";
pub const REJECTED_NAME: &str = "rejected-parent-path.zip";
pub const CONFIG_PATH: &str = "bundle/config.json";
pub const HELLO_PATH: &str = "bundle/hello.txt";
pub const REJECTED_PATH: &str = "../outside.txt";
pub const CONFIG_BYTES: &[u8] = b"{\"safe\":true}\n";
pub const HELLO_BYTES: &[u8] = b"hello from sealr\n";
pub const REJECTED_BYTES: &[u8] = b"must not escape\n";

#[derive(Clone, Debug)]
pub struct FixturePaths {
    pub allowed: PathBuf,
    pub rejected: PathBuf,
}

struct Entry<'a> {
    name: &'a str,
    data: &'a [u8],
}

struct CentralEntry<'a> {
    entry: Entry<'a>,
    crc32: u32,
    local_offset: u32,
}

pub fn generate(output_dir: &Path) -> io::Result<FixturePaths> {
    fs::create_dir_all(output_dir)?;
    let allowed = output_dir.join(ALLOWED_NAME);
    let rejected = output_dir.join(REJECTED_NAME);

    fs::write(
        &allowed,
        make_stored_zip(&[
            Entry {
                name: CONFIG_PATH,
                data: CONFIG_BYTES,
            },
            Entry {
                name: HELLO_PATH,
                data: HELLO_BYTES,
            },
        ])?,
    )?;
    fs::write(
        &rejected,
        make_stored_zip(&[Entry {
            name: REJECTED_PATH,
            data: REJECTED_BYTES,
        }])?,
    )?;

    Ok(FixturePaths { allowed, rejected })
}

fn make_stored_zip(entries: &[Entry<'_>]) -> io::Result<Vec<u8>> {
    let mut archive = Vec::new();
    let mut central = Vec::with_capacity(entries.len());

    for entry in entries {
        let name = entry.name.as_bytes();
        let name_len = u16::try_from(name.len()).map_err(|_| invalid("member name too long"))?;
        let size = u32::try_from(entry.data.len()).map_err(|_| invalid("member too large"))?;
        let local_offset =
            u32::try_from(archive.len()).map_err(|_| invalid("archive offset too large"))?;
        let crc32 = crc32(entry.data);

        push_u32(&mut archive, 0x0403_4b50);
        push_u16(&mut archive, 20);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0x0021);
        push_u32(&mut archive, crc32);
        push_u32(&mut archive, size);
        push_u32(&mut archive, size);
        push_u16(&mut archive, name_len);
        push_u16(&mut archive, 0);
        archive.extend_from_slice(name);
        archive.extend_from_slice(entry.data);

        central.push(CentralEntry {
            entry: Entry {
                name: entry.name,
                data: entry.data,
            },
            crc32,
            local_offset,
        });
    }

    let central_offset =
        u32::try_from(archive.len()).map_err(|_| invalid("central offset too large"))?;
    for item in &central {
        let name = item.entry.name.as_bytes();
        let name_len = u16::try_from(name.len()).map_err(|_| invalid("member name too long"))?;
        let size = u32::try_from(item.entry.data.len()).map_err(|_| invalid("member too large"))?;

        push_u32(&mut archive, 0x0201_4b50);
        push_u16(&mut archive, 0x0314);
        push_u16(&mut archive, 20);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0x0021);
        push_u32(&mut archive, item.crc32);
        push_u32(&mut archive, size);
        push_u32(&mut archive, size);
        push_u16(&mut archive, name_len);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u16(&mut archive, 0);
        push_u32(&mut archive, 0o100644_u32 << 16);
        push_u32(&mut archive, item.local_offset);
        archive.extend_from_slice(name);
    }

    let central_size = u32::try_from(archive.len())
        .map_err(|_| invalid("central directory too large"))?
        .checked_sub(central_offset)
        .ok_or_else(|| invalid("central directory underflow"))?;
    let entry_count =
        u16::try_from(central.len()).map_err(|_| invalid("too many archive members"))?;

    push_u32(&mut archive, 0x0605_4b50);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, entry_count);
    push_u16(&mut archive, entry_count);
    push_u32(&mut archive, central_size);
    push_u32(&mut archive, central_offset);
    push_u16(&mut archive, 0);

    Ok(archive)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn invalid(detail: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

#[cfg(not(test))]
fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .and_then(|value| PathBuf::from(value).file_name().map(|name| name.to_owned()))
        .unwrap_or_else(|| "walkthrough-fixtures".into());
    let Some(output_dir) = arguments.next() else {
        eprintln!(
            "usage: {} <output-directory>",
            Path::new(&program).display()
        );
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!(
            "usage: {} <output-directory>",
            Path::new(&program).display()
        );
        return ExitCode::from(2);
    }

    match generate(Path::new(&output_dir)) {
        Ok(paths) => {
            println!("{}", paths.allowed.display());
            println!("{}", paths.rejected.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("walkthrough fixture generation failed: {error}");
            ExitCode::FAILURE
        }
    }
}
