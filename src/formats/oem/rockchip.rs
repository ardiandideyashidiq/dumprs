//! Extractor for Rockchip `update.img` firmware packages.
//!
//! Layout from `rkafp.h`: a 2048-byte `RKAF` header with up to 16 partition
//! records, then the payloads and a trailing RKCRC checksum.

#[path = "rockchip_crc.rs"]
mod crc_table;

use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::{info, warn};

const HEADER_SIZE: usize = 2048;
const PART_SIZE: usize = 112;
const MAX_PARTS: usize = 16;

pub fn rkcrc(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &byte in data {
        crc = (crc << 8) ^ crc_table::RKCRC_TABLE[((crc >> 24) ^ u32::from(byte)) as usize];
    }
    crc
}

fn field(bytes: &[u8], offset: usize, len: usize) -> &[u8] {
    bytes.get(offset..offset + len).unwrap_or_default()
}

fn c_string(bytes: &[u8]) -> String {
    let text = bytes
        .iter()
        .take_while(|&&b| b != 0)
        .copied()
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&text).into_owned()
}

/// Keep the relative directory structure but reject traversal components.
fn safe_path(value: &str) -> String {
    value
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/")
}

fn u32le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(field(bytes, offset, 4).try_into().unwrap_or_default())
}

/// Extract every partition of a Rockchip `update.img` into `output_dir`.
///
/// # Errors
///
/// Returns an error when the magic or CRC is invalid, the header is
/// truncated, or a partition cannot be written.
pub fn extract_rockchip_update(source: &Path, output_dir: &Path) -> Result<()> {
    let data = fs::read(source).with_context(|| format!("Failed to read {}", source.display()))?;
    if data.len() < HEADER_SIZE + 4 {
        bail!("file is too small to be a Rockchip update.img");
    }
    if field(&data, 0, 4) != b"RKAF" {
        bail!("invalid Rockchip update.img magic");
    }
    let declared = u32le(&data, 4) as usize;
    if declared + 4 > data.len() {
        bail!("Rockchip declared length exceeds file size");
    }
    let expected = u32::from_le_bytes(
        data[declared..declared + 4]
            .try_into()
            .context("Rockchip CRC missing")?,
    );
    let actual = rkcrc(&data[..declared]);
    if actual != expected {
        bail!("Rockchip CRC mismatch: expected {expected:#x}, got {actual:#x}");
    }

    let count = u32le(&data, 136) as usize;
    if count > MAX_PARTS {
        bail!("Rockchip header declares {count} partitions, maximum is {MAX_PARTS}");
    }
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    let mut file = File::open(source).context("reopening Rockchip image")?;
    for index in 0..count {
        let base = 140 + index * PART_SIZE;
        let name = c_string(field(&data, base, 32));
        let fullpath = c_string(field(&data, base + 32, 60));
        let mut offset = u32le(&data, base + 96) as u64;
        let mut length = u32le(&data, base + 108) as u64;
        if fullpath == "SELF" || fullpath == "RESERVED" {
            info!(name = %name, "rockchip.part.skipped");
            continue;
        }
        if field(&data, base, 9) == b"parameter" {
            offset += 8;
            length = length.saturating_sub(12);
        }
        let end = offset.saturating_add(length);
        if end > declared as u64 {
            bail!("Rockchip partition {name} exceeds declared length");
        }
        file.seek(SeekFrom::Start(offset))
            .context("seeking Rockchip partition")?;
        let relative = safe_path(if fullpath.is_empty() {
            &name
        } else {
            &fullpath
        });
        if relative.is_empty() {
            bail!("Rockchip partition {name} has an empty output path");
        }
        let out_path = output_dir.join(relative);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let mut out = File::create(&out_path)
            .with_context(|| format!("Failed to create {}", out_path.display()))?;
        let mut remaining = length;
        let mut buf = vec![0u8; 256 * 1024];
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            let read = file
                .read(&mut buf[..want])
                .context("reading Rockchip partition")?;
            if read == 0 {
                bail!("Rockchip partition {name} ended early");
            }
            out.write_all(&buf[..read])
                .context("writing Rockchip partition")?;
            remaining -= read as u64;
        }
        info!(name = %name, size = length, "rockchip.part.extracted");
    }

    if count == 0 {
        warn!("Rockchip update.img declares no partitions");
    }
    Ok(())
}
