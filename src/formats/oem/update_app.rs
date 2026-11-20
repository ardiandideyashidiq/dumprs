//! Extractor for Huawei `UPDATE.APP` firmware packages.
//!
//! The format is a sequence of 4-byte-aligned entries, each prefixed by a
//! `55 AA 5A A5` magic and a fixed-layout header. The layout mirrors DumprX's
//! `splituapp.py`.

use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::info;

const MAGIC: [u8; 4] = [0x55, 0xAA, 0x5A, 0xA5];
const MIN_HEADER_SIZE: u32 = 98;

fn read_u32_le(file: &mut File) -> Result<u32> {
    let mut bytes = [0u8; 4];
    file.read_exact(&mut bytes)
        .context("truncated UPDATE.APP header")?;
    Ok(u32::from_le_bytes(bytes))
}

/// Keep only printable ASCII, lowercase it, and strip path separators so a
/// firmware-supplied name cannot escape the output directory.
fn sanitize_name(raw: &[u8; 16]) -> String {
    let name: String = raw
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ')
        .map(|&b| b.to_ascii_lowercase() as char)
        .collect();
    let name = name.trim().replace(['/', '\\'], "_");
    if name.is_empty() {
        "unknown".to_string()
    } else {
        name
    }
}

fn copy_exact(input: &mut File, output: &mut File, mut remaining: u64) -> Result<u64> {
    let mut buf = vec![0u8; 256 * 1024];
    let mut copied = 0u64;
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = input
            .read(&mut buf[..want])
            .context("reading UPDATE.APP payload")?;
        if n == 0 {
            bail!("UPDATE.APP payload ended {remaining} bytes early");
        }
        output
            .write_all(&buf[..n])
            .context("writing extracted image")?;
        remaining -= n as u64;
        copied += n as u64;
    }
    Ok(copied)
}

/// Split a Huawei `UPDATE.APP` into one `.img` per entry, written into
/// `output_dir`.
///
/// # Errors
///
/// Returns an error when the source cannot be read, a header is truncated or
/// declares an impossible size, or an output image cannot be written.
pub fn extract_update_app(source: &Path, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;
    let mut input =
        File::open(source).with_context(|| format!("Failed to open {}", source.display()))?;

    let mut magic = [0u8; 4];
    let mut extracted = 0usize;
    loop {
        let read = input.read(&mut magic).context("reading UPDATE.APP magic")?;
        if read < MAGIC.len() {
            break;
        }
        if magic != MAGIC {
            continue;
        }

        let header_size = read_u32_le(&mut input)?;
        if header_size < MIN_HEADER_SIZE {
            bail!("invalid UPDATE.APP header size {header_size}");
        }
        input
            .seek(SeekFrom::Current(16))
            .context("seeking UPDATE.APP header")?;
        let file_size = read_u32_le(&mut input)?;
        input
            .seek(SeekFrom::Current(32))
            .context("seeking UPDATE.APP name")?;

        let mut raw_name = [0u8; 16];
        input
            .read_exact(&mut raw_name)
            .context("reading UPDATE.APP name")?;
        input
            .seek(SeekFrom::Current(22))
            .context("seeking UPDATE.APP CRC")?;
        input
            .seek(SeekFrom::Current(i64::from(header_size - MIN_HEADER_SIZE)))
            .context("seeking past UPDATE.APP CRC")?;

        let name = sanitize_name(&raw_name);
        let out_path = output_dir.join(format!("{name}.img"));
        let mut out = File::create(&out_path)
            .with_context(|| format!("Failed to create {}", out_path.display()))?;
        let written = copy_exact(&mut input, &mut out, u64::from(file_size))?;
        info!(name = %name, size = written, "update_app.entry.extracted");
        extracted += 1;

        let position = input
            .stream_position()
            .context("reading UPDATE.APP position")?;
        let padding = (4 - (position % 4) as u32) % 4;
        input
            .seek(SeekFrom::Current(i64::from(padding)))
            .context("aligning UPDATE.APP entries")?;
    }

    info!(entries = extracted, "update_app.extracted");
    Ok(())
}
