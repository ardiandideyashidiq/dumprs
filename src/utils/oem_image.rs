//! Pure helpers for OEM image post-processing decisions.

use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// Find the byte offset of an EXT4 superblock magic (`53 EF`) relative to its
/// expected position at 1080, as `dumper.sh` does for MOTO/ASUS images.
pub fn ext4_header_offset(image: &[u8]) -> usize {
    let magic: String = image
        .iter()
        .take(12)
        .copied()
        .filter(|&byte| byte != 0)
        .map(char::from)
        .collect();
    let is_moto = magic.contains("MOTO");
    let is_asus = magic.contains("ASUS");
    if !is_moto && !is_asus {
        return 0;
    }
    let Some(position) = image.windows(2).position(|window| window == [0x53, 0xef]) else {
        return 0;
    };
    let Some(offset) = position.checked_sub(1080) else {
        return 0;
    };
    if is_moto && offset == 128_055 {
        131_072
    } else {
        offset
    }
}

/// Return the image body after stripping `offset` header bytes.
pub fn strip_header(image: &[u8], offset: usize) -> &[u8] {
    image.get(offset..).unwrap_or_default()
}

/// Remove an OPlus 8-digit NV ID from a `.new.dat`-style file name.
pub fn strip_oplus_nv_id(name: &str) -> String {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 3 {
        return name.to_string();
    }
    let is_word = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    };
    for index in 1..parts.len() - 1 {
        let segment = parts[index];
        if segment.len() == 8
            && segment.bytes().all(|byte| byte.is_ascii_digit())
            && is_word(parts[index - 1])
            && is_word(parts[index + 1])
        {
            let mut result = parts[..index].join(".");
            result.push('.');
            result.push_str(&parts[index + 1..].join("."));
            return result;
        }
    }
    name.to_string()
}

/// Rename OPlus NV-ID-style files in a directory to their canonical names.
///
/// # Errors
///
/// Returns an error when a rename fails.
pub fn normalize_oplus_dat_names(dir: &Path) -> Result<()> {
    let entries = fs::read_dir(dir).with_context(|| format!("Failed to read {}", dir.display()))?;
    for entry in entries.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let normalized = strip_oplus_nv_id(name);
        if normalized == name {
            continue;
        }
        let target = dir.join(normalized);
        if target.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to remove duplicate {}", path.display()))?;
            continue;
        }
        fs::rename(&path, &target).with_context(|| {
            format!(
                "Failed to rename {} to {}",
                path.display(),
                target.display()
            )
        })?;
    }
    Ok(())
}

/// Concatenate `partition.new.dat.{0..999}` into `partition.new.dat`.
///
/// Returns `true` when chunks were consumed.
///
/// # Errors
///
/// Returns an error when a chunk cannot be read or the output cannot be written.
pub fn consolidate_dat_chunks(dir: &Path, partition: &str) -> Result<bool> {
    let first = dir.join(format!("{partition}.new.dat.1"));
    if !first.is_file() {
        return Ok(false);
    }
    let output = dir.join(format!("{partition}.new.dat"));
    let mut target = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&output)
        .with_context(|| format!("Failed to create {}", output.display()))?;
    let mut buf = vec![0u8; 256 * 1024];
    for index in 0..=999 {
        let chunk = dir.join(format!("{partition}.new.dat.{index}"));
        if !chunk.is_file() {
            continue;
        }
        let mut input =
            File::open(&chunk).with_context(|| format!("Failed to open {}", chunk.display()))?;
        loop {
            let read = input.read(&mut buf).context("reading sdat chunk")?;
            if read == 0 {
                break;
            }
            target
                .write_all(&buf[..read])
                .context("writing sdat chunk")?;
        }
        fs::remove_file(&chunk).with_context(|| format!("Failed to remove {}", chunk.display()))?;
    }
    Ok(true)
}

/// Whether a partition image should be fed to a filesystem extractor.
pub fn should_extract_filesystem(partition: &str) -> bool {
    !partition.eq_ignore_ascii_case("modem")
}
