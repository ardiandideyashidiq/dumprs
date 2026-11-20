//! Extractor for Nokia/Sharp `.nb0` firmware containers.
//!
//! Layout from `nb0_extractor.py`: a little-endian file count, then one
//! 64-byte header per file (offset, size, two unused words, 48-byte name),
//! followed by the payloads concatenated at `4 + 64 * count`.

use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::info;

fn read_u32_le(file: &mut File) -> Result<u32> {
    let mut bytes = [0u8; 4];
    file.read_exact(&mut bytes)
        .context("truncated nb0 header")?;
    Ok(u32::from_le_bytes(bytes))
}

/// Extract every payload of an `.nb0` container into `output_dir`.
///
/// # Errors
///
/// Returns an error when the header is inconsistent, a name is empty or
/// unsafe, a payload is truncated, or an output file cannot be written.
pub fn extract_nb0(source: &Path, output_dir: &Path) -> Result<()> {
    let mut input =
        File::open(source).with_context(|| format!("Failed to open {}", source.display()))?;
    let count = read_u32_le(&mut input)?;
    let file_len = input.metadata().context("reading nb0 metadata")?.len();
    if u64::from(count) > file_len / 64 {
        bail!("invalid nb0 file: count {count} exceeds file length");
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    let mut headers = Vec::with_capacity(count as usize);
    let mut previous_offset = 0u32;
    for index in 0..count {
        let mut raw = [0u8; 64];
        input
            .read_exact(&mut raw)
            .context("reading nb0 entry header")?;
        let offset = u32::from_le_bytes(raw[..4].try_into().expect("64-byte header"));
        let size = u32::from_le_bytes(raw[4..8].try_into().expect("64-byte header"));
        if offset < previous_offset {
            bail!("invalid nb0 file: entries are not ordered");
        }
        previous_offset = offset;

        let name_bytes = &raw[16..64];
        let name = name_bytes
            .iter()
            .take_while(|&&b| b != 0 && b != b' ')
            .copied()
            .collect::<Vec<_>>();
        if name.is_empty() {
            bail!("nb0 entry {index} has an empty name");
        }
        let name = String::from_utf8_lossy(&name).replace(['/', '\\'], "_");
        headers.push((name, size));
    }

    let data_start = 4u64 + 64 * u64::from(count);
    input
        .seek(SeekFrom::Start(data_start))
        .context("seeking to nb0 payloads")?;

    let mut buf = vec![0u8; 256 * 1024];
    for (name, size) in headers {
        let out_path = output_dir.join(&name);
        let mut out = File::create(&out_path)
            .with_context(|| format!("Failed to create {}", out_path.display()))?;
        let mut remaining = size as u64;
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            let n = input
                .read(&mut buf[..want])
                .context("reading nb0 payload")?;
            if n == 0 {
                bail!("nb0 payload for {name} ended {remaining} bytes early");
            }
            out.write_all(&buf[..n]).context("writing nb0 payload")?;
            remaining -= n as u64;
        }
        info!(name = %name, size, "nb0.entry.extracted");
    }

    Ok(())
}
