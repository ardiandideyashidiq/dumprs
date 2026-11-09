use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use tracing::info;

pub fn unpack_sevenzip(filename: &Path, work_dir: &Path) -> Result<()> {
    info!(
        "Extracting 7z archive {} to {}",
        filename.display(),
        work_dir.display()
    );
    fs::create_dir_all(work_dir)
        .with_context(|| format!("Failed to create output directory {}", work_dir.display()))?;

    sevenz_rust2::decompress_file(filename, work_dir)
        .map_err(|e| anyhow::anyhow!("7z extraction failed for {}: {:?}", filename.display(), e))?;

    Ok(())
}
