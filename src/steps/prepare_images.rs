use anyhow::Result;
use indicatif::HumanBytes;
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use tracing::{debug, info, warn};

use crate::formats::sparse::unsparse_file;
use crate::steps::oem::prepare_oem_containers;
use crate::utils::files::{get_recursive_files_list, move_or_copy};
use crate::utils::firmware::{
    HeaderKind, ScatterInfo, is_candidate_firmware_path, is_excluded_partition_name,
    is_scatter_filename, sniff_file_header_kind, strip_slot_suffix,
};
use crate::utils::multipartitions::get_multipartition_rules;
use crate::utils::oem_image::{ext4_header_offset, normalize_oplus_dat_names, strip_header};
use crate::utils::partitions::{correct_ab_filenames, fix_aliases, get_partition_names_with_ab};
use crate::utils::raw_image::get_raw_image;
use crate::utils::sparsed_images::prepare_sparsed_images;

pub fn prepare_raw_images(files_path: &Path, raw_images_path: &Path) -> Result<()> {
    get_partition_names_with_ab()
        .into_par_iter()
        .filter(|p| p != "super" && p != "super_a" && p != "super_b")
        .for_each(|partition_name| {
            let partition_output = raw_images_path.join(format!("{}.img", partition_name));
            let _ = get_raw_image(&partition_name, files_path, &partition_output);
        });
    Ok(())
}

pub fn prepare_images(extracted_archive_path: &Path, raw_images_path: &Path) -> Result<()> {
    // Normalize OPlus NV-ID file names once, before the parallel raw-image pass.
    normalize_oplus_dat_names(extracted_archive_path)?;
    // Check for sparsed images
    prepare_sparsed_images(extracted_archive_path)?;

    // OEM containers must be split before the generic firmware/raw-image
    // passes, which would otherwise treat them as ordinary files.
    prepare_oem_containers(extracted_archive_path, raw_images_path)?;

    // Decompress super.img.lz4 / super.new.dat.br in-place concurrently with partition raw images
    let (_, raw_res) = rayon::join(
        || {
            ["super", "super_a", "super_b"]
                .par_iter()
                .for_each(|super_name| {
                    let super_out = extracted_archive_path.join(format!("{}.img", super_name));
                    if !super_out.is_file() {
                        let _ = get_raw_image(super_name, extracted_archive_path, &super_out);
                    }
                });
        },
        || prepare_raw_images(extracted_archive_path, raw_images_path),
    );
    raw_res?;
    // Check for multipartitions
    let files_list = get_recursive_files_list(extracted_archive_path, true);
    let rules = get_multipartition_rules();

    let mut had_multipartition = false;
    for rule in &rules {
        let matches: Vec<_> = files_list
            .iter()
            .filter(|f| (rule.matches)(&f.to_string_lossy()))
            .collect();

        if matches.is_empty() {
            debug!(pattern = rule.name, "multipartition.pattern.absent");
            continue;
        }

        for file in matches {
            let multipart_image = extracted_archive_path.join(file);
            info!(image = %multipart_image.display(), rule = rule.name, "multipartition.extract");
            (rule.handler)(&multipart_image, raw_images_path)?;
            had_multipartition = true;
        }
    }

    // Only re-scan extracted_archive_path if a multipartition ran
    if had_multipartition {
        prepare_raw_images(extracted_archive_path, raw_images_path)?;
    }
    // Fix slotted filenames if needed
    correct_ab_filenames(raw_images_path)?;

    // Fix aliases
    fix_aliases(raw_images_path)?;

    prepare_firmware_and_scatter(extracted_archive_path, raw_images_path)?;

    Ok(())
}

fn prepare_firmware_and_scatter(
    extracted_archive_path: &Path,
    raw_images_path: &Path,
) -> Result<()> {
    let scatter = ScatterInfo::from_dir(extracted_archive_path);
    let entries = match fs::read_dir(extracted_archive_path) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let mut candidates = Vec::new();
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_scatter_filename(fname) {
            let dst = raw_images_path.join(fname);
            if !dst.exists() {
                move_or_copy(&path, &dst)?;
                info!(file = fname, "scatter.prepared");
            }
            continue;
        }
        if fname.starts_with('.') || fname.starts_with("super") {
            continue;
        }
        let stem = fname.split('.').next().unwrap_or(fname);
        if is_excluded_partition_name(stem) {
            continue;
        }
        if scatter.is_superseded_variant(fname) {
            debug!(file = fname, "firmware.superseded_by_scatter");
            continue;
        }
        if scatter.references_file(fname) || is_candidate_firmware_path(Path::new(fname)) {
            let fname_owned = fname.to_string();
            candidates.push((path, fname_owned));
        }
    }

    candidates
        .into_par_iter()
        .try_for_each(|(path, fname)| -> Result<()> {
            let (src_path, target_name) = if let Some(stripped) = fname.strip_suffix(".lz4") {
                let decomp_path = extracted_archive_path.join(stripped);
                if !decomp_path.exists() {
                    let lz4_size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    info!(file = %fname, size = %HumanBytes(lz4_size), "firmware.lz4.decompress");
                    let input = File::open(&path)?;
                    let mut decoder = lz4_flex::frame::FrameDecoder::new(BufReader::with_capacity(
                        256 * 1024,
                        input,
                    ));
                    let out_file = File::create(&decomp_path)?;
                    let mut writer = BufWriter::with_capacity(1024 * 1024, out_file);
                    let mut buf = vec![0u8; 256 * 1024];
                    loop {
                        let n = decoder.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        writer.write_all(&buf[..n])?;
                    }
                    writer.flush()?;
                    let _ = fs::remove_file(&path);
                }
                (decomp_path, stripped.to_string())
            } else {
                (path, fname.clone())
            };

            let stem = target_name.split('.').next().unwrap_or(&target_name);
            let unslotted_stem = strip_slot_suffix(stem);
            let dst = raw_images_path.join(&target_name);
            let dst_img = raw_images_path.join(format!("{}.img", unslotted_stem));
            if dst.exists() || dst_img.exists() {
                return Ok(());
            }

            if crate::utils::partitions::EXT4_PARTITIONS.contains(&unslotted_stem) {
                match fs::read(&src_path) {
                    Ok(image_bytes) => {
                        let offset = ext4_header_offset(&image_bytes);
                        if offset > 0 {
                            fs::write(&src_path, strip_header(&image_bytes, offset))?;
                            info!(file = %target_name, offset, "partition.ext4_header_stripped");
                        }
                    }
                    Err(error) => warn!(file = %target_name, error = %error, "partition.ext4_header_read_failed"),
                }
            }

            let kind = sniff_file_header_kind(&src_path)?;
            match kind {
                HeaderKind::NonPartition => {
                    debug!(file = %target_name, "firmware.ignored_non_partition");
                }
                HeaderKind::Sparse => {
                    if let Ok(true) = unsparse_file(&src_path, &dst) {
                        let _ = fs::remove_file(&src_path);
                        info!(file = %target_name, kind = "sparse", "firmware.prepared");
                    }
                }
                HeaderKind::BootImage | HeaderKind::Filesystem | HeaderKind::FirmwareRaw => {
                    move_or_copy(&src_path, &dst)?;
                    info!(file = %target_name, ?kind, "firmware.prepared");
                }
                HeaderKind::Unknown => {
                    if scatter.references_file(&target_name) {
                        move_or_copy(&src_path, &dst)?;
                        info!(file = %target_name, kind = "scatter_ref", "firmware.prepared");
                    } else {
                        debug!(file = %target_name, "firmware.ignored_unknown");
                    }
                }
            }
            Ok(())
        })?;

    Ok(())
}
