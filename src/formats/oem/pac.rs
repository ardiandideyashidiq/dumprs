//! Extractor for Spreadtrum/Unisoc `.pac` firmware packages.
//!
//! Layout from the public-domain `pacExtractor.py`: a 2124-byte packet
//! header, an array of 2580-byte file headers at `partitionsListStart`, then
//! the payloads at per-entry data offsets.

use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::info;

const PAC_HEADER_SIZE: usize = 2124;
const FILE_HEADER_SIZE: usize = 2580;

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .with_context(|| format!("PAC header truncated at {offset}"))?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("4-byte slice")))
}

fn utf16_string(bytes: &[u8]) -> String {
    let (pairs, _) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .replace(['/', '\\'], "_")
}

/// Extract every file of a `.pac` package into `output_dir`.
///
/// CRC verification is intentionally not performed: DumprX does not pass the
/// reference tool's `-c` flag either.
///
/// # Errors
///
/// Returns an error when the version or declared size is unsupported, a file
/// header is malformed, or a payload is truncated.
pub fn extract_pac(source: &Path, output_dir: &Path) -> Result<()> {
    let mut input =
        File::open(source).with_context(|| format!("Failed to open {}", source.display()))?;
    let file_len = input.metadata().context("reading PAC metadata")?.len();
    if file_len < PAC_HEADER_SIZE as u64 {
        bail!("file is too small to be a PAC firmware");
    }

    let mut header = [0u8; PAC_HEADER_SIZE];
    input
        .read_exact(&mut header)
        .context("reading PAC header")?;
    let version = utf16_string(&header[0..44]);
    if version != "BP_R1.0.0" && version != "BP_R2.0.1" {
        bail!("unsupported PAC version {version}");
    }
    let declared = (u64::from(read_u32(&header, 44)?) << 32) | u64::from(read_u32(&header, 48)?);
    if declared != file_len {
        bail!("PAC declared size {declared} does not match file length {file_len}");
    }
    let count = read_u32(&header, 1076)? as usize;
    let list_start = u64::from(read_u32(&header, 1080)?);
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    input
        .seek(SeekFrom::Start(list_start))
        .context("seeking to PAC file headers")?;
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let mut raw = [0u8; FILE_HEADER_SIZE];
        input
            .read_exact(&mut raw)
            .context("reading PAC file header")?;
        if read_u32(&raw, 0)? != FILE_HEADER_SIZE as u32 {
            bail!("unknown PAC file header format at entry {index}");
        }
        let name = utf16_string(&raw[516..1028]);
        if name.is_empty() {
            bail!("PAC entry {index} has an empty file name");
        }
        let size = (u64::from(read_u32(&raw, 1532)?) << 32) | u64::from(read_u32(&raw, 1540)?);
        let offset = (u64::from(read_u32(&raw, 1536)?) << 32) | u64::from(read_u32(&raw, 1552)?);
        if offset.checked_add(size).is_none_or(|end| end > file_len) {
            bail!("PAC entry {name} data range exceeds file length");
        }
        entries.push((name, offset, size));
    }

    let mut buf = vec![0u8; 256 * 1024];
    for (name, offset, size) in entries {
        if size == 0 {
            continue;
        }
        input
            .seek(SeekFrom::Start(offset))
            .context("seeking PAC payload")?;
        let out_path = output_dir.join(&name);
        let mut out = File::create(&out_path)
            .with_context(|| format!("Failed to create {}", out_path.display()))?;
        let mut remaining = size;
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            let n = input
                .read(&mut buf[..want])
                .context("reading PAC payload")?;
            if n == 0 {
                bail!("PAC payload for {name} ended {remaining} bytes early");
            }
            out.write_all(&buf[..n]).context("writing PAC payload")?;
            remaining -= n as u64;
        }
        info!(name = %name, size, "pac.entry.extracted");
    }

    Ok(())
}
