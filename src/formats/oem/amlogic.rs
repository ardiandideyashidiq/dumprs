//! Extractor for Amlogic upgrade packages (`aml_upgrade_package.img`).
//!
//! Layout from `aml-upgrade-package-extract.c`: a 0x40-byte header whose byte
//! at 0x18 is the record count, followed by 0x240-byte records at 0x40 +
//! n*0x240. Each record carries a data offset and size at +0x10/+0x18, an
//! extension at +0x20 and a name at +0x120.

use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;
use tracing::info;

const HEADER_SIZE: usize = 0x40;
const RECORD_SIZE: usize = 0x240;
const COUNT_OFFSET: usize = 0x18;

fn c_string(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|&b| b == 0)
        .map_or(bytes, |end| &bytes[..end])
}

/// Extract every record of an Amlogic upgrade package into `output_dir`.
///
/// # Errors
///
/// Returns an error when the package is truncated, a record declares a data
/// range outside the file, or an output image cannot be written.
pub fn extract_amlogic(source: &Path, output_dir: &Path) -> Result<()> {
    let data = fs::read(source).with_context(|| format!("Failed to read {}", source.display()))?;
    let count = *data
        .get(COUNT_OFFSET)
        .context("AML header is missing its record count")?;
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    for record in 0..count as usize {
        let base = HEADER_SIZE
            .checked_add(record * RECORD_SIZE)
            .context("AML record offset overflow")?;
        let record_bytes = data
            .get(base..base + RECORD_SIZE)
            .with_context(|| format!("AML record {record} is truncated"))?;

        let offset = u32::from_le_bytes(
            record_bytes[0x10..0x14]
                .try_into()
                .context("AML data offset missing")?,
        ) as usize;
        let size = u32::from_le_bytes(
            record_bytes[0x18..0x1c]
                .try_into()
                .context("AML data size missing")?,
        ) as usize;
        let ext = c_string(&record_bytes[0x20..0x60]);
        let name = c_string(&record_bytes[0x120..0x160]);
        if name.is_empty() {
            bail!("AML record {record} has an empty name");
        }
        let name = String::from_utf8_lossy(name).replace(['/', '\\'], "_");

        let body = data.get(offset..offset + size).with_context(|| {
            format!(
                "AML record {record} data {offset}..{} exceeds file",
                offset + size
            )
        })?;

        let filename = if ext == b"PARTITION" {
            format!("{name}.img")
        } else if let Some(stem) = name.strip_suffix("_aml_dtb") {
            format!("{stem}.img")
        } else if let Some(stem) = name.strip_suffix("_a") {
            format!("{stem}.img")
        } else {
            let ext = String::from_utf8_lossy(ext).replace(['/', '\\'], "_");
            format!("{name}.{ext}")
        };

        let out_path = output_dir.join(filename);
        fs::write(&out_path, body)
            .with_context(|| format!("Failed to write {}", out_path.display()))?;
        info!(name = %name, size, "aml.record.extracted");
    }

    Ok(())
}
