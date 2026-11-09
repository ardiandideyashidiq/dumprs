use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use tracing::info;

pub fn unpack_sevenzip(filename: &Path, work_dir: &Path) -> Result<()> {
    info!(
        archive = %filename.display(),
        dest = %work_dir.display(),
        "sevenzip.extract.start"
    );
    fs::create_dir_all(work_dir)
        .with_context(|| format!("Failed to create output directory {}", work_dir.display()))?;

    sevenz_rust2::decompress_file(filename, work_dir)
        .map_err(|e| anyhow::anyhow!("7z extraction failed for {}: {:?}", filename.display(), e))?;

    info!(archive = %filename.display(), "sevenzip.extract.done");
    Ok(())
}
