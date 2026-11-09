use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::formats::sparse::unsparse_chunks;
use crate::utils::partitions::get_partition_names_with_alias;

pub fn prepare_sparsed_images(files_path: &Path) -> Result<()> {
    let entries = match fs::read_dir(files_path) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let mut chunks_by_partition: HashMap<String, Vec<(u64, PathBuf)>> = HashMap::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if let Some((part, rest)) = name.split_once(".img_sparsechunk.")
            && let Ok(num) = rest.parse::<u64>()
        {
            chunks_by_partition
                .entry(part.to_string())
                .or_default()
                .push((num, entry.path()));
        }
    }

    if chunks_by_partition.is_empty() {
        return Ok(());
    }

    let partitions: Vec<String> = get_partition_names_with_alias()
        .into_iter()
        .filter(|p| chunks_by_partition.contains_key(p))
        .collect();

    partitions.into_par_iter().try_for_each(|partition| -> Result<()> {
        let output_image = files_path.join(format!("{}.img", partition));
        if output_image.is_file() {
            return Ok(());
        }

        if let Some(mut sparsechunk_files) = chunks_by_partition.get(&partition).cloned() {
            sparsechunk_files.sort_by_key(|(k, _)| *k);
            let chunk_paths: Vec<_> = sparsechunk_files.into_iter().map(|(_, p)| p).collect();

            info!("Preparing sparsechunk images for {}", partition);
            info!(
                "Converting {} to {}",
                chunk_paths[0].display(),
                output_image.display()
            );

            unsparse_chunks(&chunk_paths, &output_image)?;
        }
        Ok(())
    })?;

    Ok(())
}
