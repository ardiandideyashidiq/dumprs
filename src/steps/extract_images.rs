use anyhow::Result;
use indicatif::HumanBytes;
use rayon::prelude::*;
use std::fs;
use std::path::Path;
use tracing::{error, info};

use crate::formats::bootimg::extract_bootimg;
use crate::formats::fs_extract::extract_filesystem;
use crate::utils::files::hardlink_or_copy;
use crate::utils::partitions::{get_partition_names, get_partition_type, PartitionType};
pub fn extract_images(
    raw_images_path: &Path,
    output_path: &Path,
    filter_partitions: &[String],
    resume: bool,
) -> Result<()> {
    let partitions: Vec<_> = get_partition_names()
        .into_iter()
        .filter(|&partition| {
            if filter_partitions.is_empty() {
                true
            } else {
                filter_partitions.iter().any(|f| f == partition)
            }
        })
        .filter_map(|partition| {
            let image_path = raw_images_path.join(format!("{}.img", partition));
            if image_path.exists() {
                get_partition_type(partition).map(|t| (partition, t, image_path))
            } else {
                None
            }
        })
        .collect();

    info!("Extracting {} partitions in parallel...", partitions.len());
    partitions
        .par_iter()
        .for_each(|&(partition, partition_type, ref image_path)| {
            let partition_out = output_path.join(partition);
            let file_size = fs::metadata(image_path).map(|m| m.len()).unwrap_or(0);

            // Resume check: if partition folder already exists and has files, skip
            if resume
                && partition_out.is_dir()
                && fs::read_dir(&partition_out).map(|mut d| d.next().is_some()).unwrap_or(false)
            {
                info!(
                    "[RESUME] Partition '{}' already extracted in {}, skipping",
                    partition,
                    partition_out.display()
                );
                return;
            }

            info!(
                "Extracting partition '{}' ({})",
                partition,
                HumanBytes(file_size)
            );

            match partition_type {
                PartitionType::Bootimage => {
                    if let Err(e) = extract_bootimg(image_path, &partition_out) {
                        error!("Failed to extract {}: {}", image_path.display(), e);
                    }
                    let copy_dest = output_path.join(format!("{}.img", partition));
                    let _ = hardlink_or_copy(image_path, &copy_dest);
                }
                PartitionType::Filesystem => {
                    if let Err(e) = extract_filesystem(image_path, &partition_out) {
                        error!("Error extracting filesystem {}: {}", image_path.display(), e);
                    }
                }
                PartitionType::Raw => {
                    let copy_dest = output_path.join(format!("{}.img", partition));
                    let _ = hardlink_or_copy(image_path, &copy_dest);
                }
                PartitionType::Logical => {
                    // Logical super.img is already handled in step 2
                }
            }
        });

    info!("Partition extraction complete ({} partitions processed)", partitions.len());
    Ok(())
}
