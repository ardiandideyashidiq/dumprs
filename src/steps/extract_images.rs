use anyhow::Result;
use indicatif::HumanBytes;
use rayon::prelude::*;
use std::fs;
use std::path::Path;
use tracing::{error, info};

use crate::formats::bootimg::extract_bootimg;
use crate::formats::fs_extract::extract_filesystem;
use crate::utils::files::{hardlink_or_copy, logical_image_size, was_early_extracted};
use crate::utils::partitions::{get_partition_names, get_partition_type, PartitionType};

pub fn extract_images(
    raw_images_path: &Path,
    output_path: &Path,
    filter_partitions: &[String],
    resume: bool,
) -> Result<()> {
    extract_images_with_cleanup(raw_images_path, output_path, filter_partitions, resume, false)
}

pub fn extract_images_with_cleanup(
    raw_images_path: &Path,
    output_path: &Path,
    filter_partitions: &[String],
    resume: bool,
    cleanup_raw: bool,
) -> Result<()> {
    let mut partitions: Vec<_> = get_partition_names()
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
            let file_size = logical_image_size(&image_path)?;
            get_partition_type(partition).map(|t| (partition, t, image_path, file_size))
        })
        .collect();

    partitions.sort_unstable_by(|a, b| b.3.cmp(&a.3));

    info!(count = partitions.len(), "partitions.extract.start");
    partitions
        .par_iter()
        .with_max_len(1)
        .for_each(|(partition, partition_type, image_path, file_size)| {
            let partition = *partition;
            let partition_type = *partition_type;
            let file_size = *file_size;
            let partition_out = output_path.join(partition);
            if was_early_extracted(&partition_out) {
                if cleanup_raw {
                    let _ = fs::remove_file(image_path);
                }
                return;
            }
            if resume
                && partition_out.is_dir()
                && fs::read_dir(&partition_out)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false)
            {
                info!(
                    partition,
                    dir = %partition_out.display(),
                    "partition.extract.resumed"
                );
                return;
            }

            info!(
                partition,
                size = %HumanBytes(file_size),
                "partition.extract.begin"
            );
            match partition_type {
                PartitionType::Bootimage => {
                    if let Err(e) = extract_bootimg(image_path, &partition_out) {
                        error!(partition, image = %image_path.display(), error = ?e, "partition.bootimg.failed");
                    }
                    let copy_dest = output_path.join(format!("{}.img", partition));
                    let _ = hardlink_or_copy(image_path, &copy_dest);
                    if cleanup_raw {
                        let _ = fs::remove_file(image_path);
                    }
                }
                PartitionType::Filesystem => {
                    match extract_filesystem(image_path, &partition_out) {
                        Ok(()) => {
                            if cleanup_raw {
                                let _ = fs::remove_file(image_path);
                            }
                        }
                        Err(e) => {
                            let is_empty = fs::read_dir(&partition_out)
                                .map(|mut d| d.next().is_none())
                                .unwrap_or(true);
                            if is_empty {
                                let _ = fs::remove_dir(&partition_out);
                                let copy_dest = output_path.join(format!("{}.img", partition));
                                if hardlink_or_copy(image_path, &copy_dest).is_ok() {
                                    info!(partition, "partition.filesystem.fallback_raw");
                                    if cleanup_raw {
                                        let _ = fs::remove_file(image_path);
                                    }
                                    return;
                                }
                            }
                            error!(partition, image = %image_path.display(), error = ?e, "partition.filesystem.failed");
                        }
                    }
                }
                PartitionType::Raw => {
                    let copy_dest = output_path.join(format!("{}.img", partition));
                    let _ = hardlink_or_copy(image_path, &copy_dest);
                    if cleanup_raw {
                        let _ = fs::remove_file(image_path);
                    }
                }
                PartitionType::Logical => {}
            }
        });

    info!(count = partitions.len(), "partitions.extract.done");
    Ok(())
}
