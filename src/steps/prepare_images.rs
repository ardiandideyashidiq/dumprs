use anyhow::Result;
use rayon::prelude::*;
use std::path::Path;
use tracing::{debug, info};

use crate::utils::files::get_recursive_files_list;
use crate::utils::multipartitions::get_multipartition_rules;
use crate::utils::partitions::{
    correct_ab_filenames, fix_aliases, get_partition_names_with_ab,
};
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
    // Check for sparsed images
    prepare_sparsed_images(extracted_archive_path)?;

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

    Ok(())
}
