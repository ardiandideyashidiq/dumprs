use anyhow::Result;
use indicatif::HumanBytes;
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{error, info};

use crate::formats::boot_artifacts::generate as generate_boot_artifacts;
use crate::formats::bootimg::extract_bootimg;
use crate::formats::fs_extract::extract_filesystem;
use crate::utils::files::{hardlink_or_copy, logical_image_size, was_early_extracted};
use crate::utils::firmware::{
    HeaderKind, ScatterInfo, is_excluded_partition_name, is_scatter_filename,
    matches_partition_filter, sniff_file_header_kind,
};
use crate::utils::fs_metadata::{
    Config as FsMetadataConfig, FsMetadataOptions, generate_file_contexts, generate_fs_config,
};
use crate::utils::partitions::{PartitionType, get_partition_names, get_partition_type};

pub fn extract_images(
    raw_images_path: &Path,
    output_path: &Path,
    filter_partitions: &[String],
    resume: bool,
) -> Result<()> {
    extract_images_with_cleanup(
        raw_images_path,
        output_path,
        filter_partitions,
        resume,
        false,
        None,
        true,
    )
}

pub fn extract_images_with_cleanup(
    raw_images_path: &Path,
    output_path: &Path,
    filter_partitions: &[String],
    resume: bool,
    cleanup_raw: bool,
    fs_metadata: Option<&FsMetadataOptions>,
    boot_artifacts: bool,
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

    partitions.sort_unstable_by_key(|a| std::cmp::Reverse(a.3));

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
                    if boot_artifacts
                        && let Err(e) = generate_boot_artifacts(image_path, &partition_out, partition)
                    {
                        error!(partition, image = %image_path.display(), error = ?e, "partition.boot_artifacts.failed");
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

    // `dtbo` is a raw partition in dumprs, so it does not go through the
    // boot-image branch above. Generate its DTB/DTS artifacts from the copy.
    if boot_artifacts {
        let dtbo_image = output_path.join("dtbo.img");
        if dtbo_image.is_file() {
            let dtbo_dir = output_path.join("dtbo");
            if let Err(e) = generate_boot_artifacts(&dtbo_image, &dtbo_dir, "dtbo") {
                error!(partition = "dtbo", error = ?e, "partition.boot_artifacts.failed");
            }
        }
    }

    if let Some(options) = fs_metadata {
        let names: Vec<&str> = partitions
            .iter()
            .map(|(partition, ..)| *partition)
            .collect();
        emit_fs_metadata(output_path, &names, options)?;
    }

    extract_extra_firmware_and_scatter(
        raw_images_path,
        output_path,
        filter_partitions,
        resume,
        cleanup_raw,
    )?;
    info!(count = partitions.len(), "partitions.extract.done");
    Ok(())
}

/// Write `fs_config` and `file_contexts` sidecars for extracted partitions.
fn emit_fs_metadata(
    output_path: &Path,
    partitions: &[&str],
    options: &FsMetadataOptions,
) -> Result<()> {
    let config_root = options
        .config_root
        .clone()
        .unwrap_or_else(|| output_path.join("config"));

    for partition in partitions {
        let partition_dir = output_path.join(partition);
        if !partition_dir.is_dir() {
            continue;
        }
        let partition_config = config_root.join(partition);
        fs::create_dir_all(&partition_config)?;

        let fs_config = build_metadata_config(
            &partition_dir,
            partition_config.join(format!("{partition}_fs_config")),
            options,
        )?;
        let fs_report = generate_fs_config(&fs_config)?;

        let contexts = build_metadata_config(
            &partition_dir,
            partition_config.join(format!("{partition}_file_contexts")),
            options,
        )?;
        let context_report = generate_file_contexts(&contexts)?;

        info!(
            partition,
            fs_config_missing = fs_report.missing,
            file_contexts_missing = context_report.missing,
            "partition.fs_metadata"
        );
    }
    Ok(())
}

fn build_metadata_config(
    partition_dir: &Path,
    output: std::path::PathBuf,
    options: &FsMetadataOptions,
) -> Result<FsMetadataConfig> {
    let mut builder = FsMetadataConfig::builder(partition_dir, output)
        .fstype(options.fstype)
        .mode(options.mode)
        .dry_run(options.dry_run);
    if let Some(context) = &options.vendor_bin_context {
        builder = builder.vendor_bin_context(context);
    }
    if let Some(context) = &options.system_bin_context {
        builder = builder.system_bin_context(context);
    }
    builder.build()
}

enum ExtraItemKind {
    Scatter,
    Image(HeaderKind),
}

fn extract_extra_firmware_and_scatter(
    raw_images_path: &Path,
    output_path: &Path,
    filter_partitions: &[String],
    resume: bool,
    cleanup_raw: bool,
) -> Result<()> {
    let scatter = ScatterInfo::from_dir(raw_images_path);
    let entries = match fs::read_dir(raw_images_path) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let mut items: Vec<(String, PathBuf, u64, ExtraItemKind)> = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if fname.starts_with('.') || fname.starts_with("super") {
            continue;
        }
        if is_scatter_filename(fname) {
            if filter_partitions.is_empty()
                || filter_partitions
                    .iter()
                    .any(|f| f.eq_ignore_ascii_case("scatter") || f.eq_ignore_ascii_case(fname))
            {
                let sz = logical_image_size(&path).unwrap_or(0);
                items.push((fname.to_string(), path, sz, ExtraItemKind::Scatter));
            }
            continue;
        }

        let stem = fname.split('.').next().unwrap_or(fname);
        if fname.ends_with(".img") && get_partition_type(stem).is_some() {
            continue;
        }
        if is_excluded_partition_name(stem) {
            continue;
        }
        if scatter.is_superseded_variant(fname) {
            continue;
        }
        if !matches_partition_filter(filter_partitions, fname, &scatter) {
            continue;
        }

        let Some(file_size) = logical_image_size(&path) else {
            continue;
        };
        if file_size == 0 {
            continue;
        }
        let kind = sniff_file_header_kind(&path).unwrap_or(HeaderKind::Unknown);
        if kind == HeaderKind::NonPartition {
            continue;
        }
        let lower = fname.to_ascii_lowercase();
        if kind == HeaderKind::Unknown
            && !scatter.references_file(fname)
            && !lower.ends_with(".img")
            && !lower.ends_with(".bin")
            && !lower.ends_with(".mbn")
            && !lower.ends_with(".elf")
        {
            continue;
        }
        items.push((
            fname.to_string(),
            path,
            file_size,
            ExtraItemKind::Image(kind),
        ));
    }

    if items.is_empty() {
        return Ok(());
    }

    items.sort_unstable_by_key(|a| std::cmp::Reverse(a.2));
    info!(count = items.len(), "firmware.extract.start");

    items
        .into_par_iter()
        .with_max_len(1)
        .for_each(|(fname, image_path, file_size, item_kind)| {
            let copy_dest = output_path.join(&fname);
            match item_kind {
                ExtraItemKind::Scatter => {
                    if !(resume && copy_dest.is_file()) {
                        if let Err(e) = hardlink_or_copy(&image_path, &copy_dest) {
                            error!(file = %fname, error = ?e, "scatter.copy.failed");
                        } else {
                            info!(file = %fname, size = %HumanBytes(file_size), "scatter.extract.done");
                        }
                    }
                    if cleanup_raw {
                        let _ = fs::remove_file(&image_path);
                    }
                }
                ExtraItemKind::Image(kind) => {
                    let stem = fname.split('.').next().unwrap_or(&fname);
                    match kind {
                        HeaderKind::BootImage => {
                            let part_out = output_path.join(stem);
                            if !(resume && part_out.is_dir())
                                && let Err(e) = extract_bootimg(&image_path, &part_out)
                            {
                                error!(partition = stem, image = %image_path.display(), error = ?e, "firmware.bootimg.failed");
                            }
                            if !(resume && copy_dest.is_file())
                                && let Err(e) = hardlink_or_copy(&image_path, &copy_dest)
                            {
                                error!(file = %fname, error = ?e, "firmware.copy.failed");
                            }
                        }
                        HeaderKind::Filesystem => {
                            let part_out = output_path.join(stem);
                            if !(resume && part_out.is_dir())
                                && let Err(e) = extract_filesystem(&image_path, &part_out) {
                                    let is_empty = fs::read_dir(&part_out)
                                        .map(|mut d| d.next().is_none())
                                        .unwrap_or(true);
                                    if is_empty {
                                        let _ = fs::remove_dir(&part_out);
                                        if let Err(copy_err) = hardlink_or_copy(&image_path, &copy_dest) {
                                            error!(file = %fname, error = ?copy_err, "firmware.filesystem_fallback.failed");
                                        } else {
                                            info!(file = %fname, "firmware.filesystem.fallback_raw");
                                        }
                                    } else {
                                        error!(partition = stem, error = ?e, "firmware.filesystem.failed");
                                    }
                                }
                        }
                        HeaderKind::FirmwareRaw
                        | HeaderKind::Sparse
                        | HeaderKind::Unknown
                        | HeaderKind::NonPartition => {
                            if !(resume && copy_dest.is_file()) {
                                if let Err(e) = hardlink_or_copy(&image_path, &copy_dest) {
                                    error!(file = %fname, error = ?e, "firmware.copy.failed");
                                } else {
                                    info!(file = %fname, size = %HumanBytes(file_size), "firmware.extract.done");
                                }
                            }
                        }
                    }
                    if cleanup_raw {
                        let _ = fs::remove_file(&image_path);
                    }
                }
            }
        });

    info!("firmware.extract.done");
    Ok(())
}
