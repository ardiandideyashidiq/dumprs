//! Extractor for Sony Xperia `.sin` firmware containers (v3 ADDR/LZ4A blocks).
//!
//! Layout (big-endian) from the published SIN structure analysis: a versioned
//! `SIN` header, an `MMCF`/`GPTP` data header, then a list of block headers.
//! `ADDR` blocks are copied verbatim; `LZ4A` blocks hold raw LZ4 data.

use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;
use tracing::info;

const SIN_HEADER_BASE: usize = 0x18;
const RSA_SIGNATURE: usize = 0x100;
const ADDR_HEADER: usize = 0x44;
const LZ4A_HEADER: usize = 0x54;

fn be_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        data.get(offset..offset + 4)
            .with_context(|| format!("SIN header truncated at {offset}"))?
            .try_into()
            .expect("4-byte slice"),
    ))
}

fn be_u64(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(
        data.get(offset..offset + 8)
            .with_context(|| format!("SIN header truncated at {offset}"))?
            .try_into()
            .expect("8-byte slice"),
    ))
}

/// Extract the image carried by a Sony `.sin` file into `output`.
///
/// # Errors
///
/// Returns an error when the magic or version is unsupported, a block header
/// is malformed, or the compressed data cannot be decoded.
pub fn extract_sin(source: &Path, output: &Path) -> Result<()> {
    let data = fs::read(source).with_context(|| format!("Failed to read {}", source.display()))?;
    if data.len() < 4 || data[0] != 3 || &data[1..4] != b"SIN" {
        bail!("unsupported SIN version or magic");
    }
    let header_len = be_u32(&data, 4)? as usize;
    let hash_len = be_u32(&data, 0x14)? as usize;
    let expected = SIN_HEADER_BASE
        .checked_add(hash_len)
        .and_then(|v| v.checked_add(RSA_SIGNATURE))
        .context("SIN header length overflow")?;
    if header_len != expected {
        bail!("invalid SIN header length {header_len}, expected {expected}");
    }
    let data_header = header_len;
    if data.get(data_header..data_header + 8) != Some(b"MMCF\x00\x00\x00\x00".as_slice())
        && data.get(data_header..data_header + 4) != Some(b"MMCF".as_slice())
    {
        bail!("invalid SIN data header magic");
    }
    if data.get(data_header + 8..data_header + 12) != Some(b"GPTP".as_slice()) {
        bail!("invalid SIN GPTP magic");
    }

    let mut block_at = data_header + 0x20;
    let mut image = Vec::<u8>::new();
    while let Some(magic) = data.get(block_at..block_at + 4) {
        let block_len = match magic {
            b"ADDR" => ADDR_HEADER,
            b"LZ4A" => LZ4A_HEADER,
            _ => break,
        };
        let header = data
            .get(block_at..block_at + block_len)
            .with_context(|| format!("SIN block header at {block_at:#x} is truncated"))?;
        let declared = be_u32(header, 4)? as usize;
        if declared != block_len {
            bail!("unexpected SIN block header length {declared}, expected {block_len}");
        }
        let start = be_u64(header, 8)? as usize;
        let (source_len, dest, dest_length) = if magic == b"ADDR" {
            let len = be_u64(header, 16)? as usize;
            (len, be_u64(header, 24)? as usize, len)
        } else {
            (
                be_u64(header, 16)? as usize,
                be_u64(header, 32)? as usize,
                be_u64(header, 40)? as usize,
            )
        };
        let source_end = start
            .checked_add(source_len)
            .context("SIN block offset overflow")?;
        let source_data = data
            .get(start..source_end)
            .with_context(|| format!("SIN block data {start}..{source_end} exceeds file"))?;

        let body = if magic == b"ADDR" {
            source_data.to_vec()
        } else {
            lz4_flex::block::decompress(source_data, dest_length)
                .context("failed to decompress SIN LZ4A block")?
        };
        let end = dest
            .checked_add(body.len())
            .context("SIN block destination overflow")?;
        if image.len() < end {
            image.resize(end, 0xff);
        }
        image[dest..end].copy_from_slice(&body);
        info!(kind = ?String::from_utf8_lossy(magic), dest, size = body.len(), "sin.block.extracted");
        block_at += block_len;
    }

    if image.is_empty() {
        bail!("SIN file contains no supported blocks");
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    fs::write(output, &image).with_context(|| format!("Failed to write {}", output.display()))?;
    Ok(())
}
