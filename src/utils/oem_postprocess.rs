//! Post-processing for OEM image naming and signed-image headers.
//!
//! These transforms mirror the filename-cleanup branches of DumprX's
//! `dumper.sh`. They are deliberately separate from the format parsers: they
//! operate on already-extracted bytes and names.

use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tracing::info;

use crate::utils::partitions::get_partition_names_with_ab;

/// `dd bs=8192 skip=64` used by DumprX for SSSS-signed images.
const SSSS_SKIP: usize = 64 * 8192;
/// `dd bs=0x4040 skip=1` used for BFBF and unknown signed-image headers.
const GENERIC_HEADER_SKIP: usize = 0x4040;

/// Return the image body of an OEM signed image.
///
/// SSSS images store a little-endian 32-bit body length at bytes 60..64,
/// split into two 16-bit halves. Everything else uses the fixed `0x4040`
/// skip. The returned slice borrows `data`; no copy is made.
///
/// # Errors
///
/// Returns an error when `data` is too short to contain the declared header
/// or when the declared body would run past the end of the input.
pub fn strip_signed_image_header(data: &[u8]) -> Result<&[u8]> {
    if data.len() < 64 {
        bail!("signed image is shorter than its 64-byte header");
    }

    if data[..4] == *b"SSSS" {
        let low = u16::from_le_bytes(
            data[60..62]
                .try_into()
                .context("SSSS low offset half missing")?,
        );
        let high = u16::from_le_bytes(
            data[62..64]
                .try_into()
                .context("SSSS high offset half missing")?,
        );
        let len = u32::from(low) | (u32::from(high) << 16);
        let end = SSSS_SKIP
            .checked_add(len as usize)
            .context("SSSS body length overflow")?;
        let body = data
            .get(SSSS_SKIP..end)
            .with_context(|| format!("SSSS body {SSSS_SKIP}..{end} exceeds image length"))?;
        return Ok(body);
    }

    let body = data
        .get(GENERIC_HEADER_SKIP..)
        .with_context(|| format!("image shorter than {GENERIC_HEADER_SKIP:#x} header"))?;
    Ok(body)
}

/// Rename OEM partition variants into their canonical `.img` names.
///
/// `.bin` and `-p` files are only renamed when their stem is a known
/// partition, so unrelated binaries in the same directory are left alone.
///
/// # Errors
///
/// Returns an error when the directory cannot be read or a rename fails.
pub fn rename_oem_images(dir: &Path) -> Result<()> {
    let partitions: HashSet<String> = get_partition_names_with_ab().into_iter().collect();
    let entries = fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("Failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        let renamed = if let Some(stem) = name.strip_suffix("_image.emmc.img") {
            format!("{stem}.img")
        } else if let Some(stem) = name.strip_suffix("_new.img") {
            format!("{stem}.img")
        } else if let Some(stem) = name.strip_suffix(".img.ext4") {
            format!("{stem}.img")
        } else if let Some(stem) = name.strip_suffix("-sign.img") {
            format!("{stem}.img")
        } else if let Some(stem) = name.strip_suffix("-p") {
            if !partitions.contains(stem) {
                continue;
            }
            format!("{stem}.img")
        } else if let Some(stem) = name.strip_suffix(".bin") {
            if !partitions.contains(stem) {
                continue;
            }
            format!("{stem}.img")
        } else {
            continue;
        };

        let dest = dir.join(&renamed);
        if dest == path || dest.exists() {
            continue;
        }
        fs::rename(&path, &dest).with_context(|| {
            format!("Failed to rename {} to {}", path.display(), dest.display())
        })?;
        info!(from = name, to = %renamed, "oem_image.renamed");
    }

    Ok(())
}
