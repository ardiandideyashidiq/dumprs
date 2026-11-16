use anyhow::{bail, Context, Result};
use indicatif::{HumanBytes, HumanDuration};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::info;
use walkdir::WalkDir;

use crate::steps::extract_archive::extract_archive;
use crate::steps::extract_images::extract_images_with_cleanup;
use crate::steps::prepare_images::prepare_images;
use crate::utils::device_info::DeviceInfo;
use crate::utils::files::{
    clear_in_memory_images, rmtree_recursive, set_allow_early_extract, sort_files,
};
use crate::utils::partitions::get_partition_names;

#[derive(Debug, Clone, Default)]
pub struct DumpOptions {
    pub debug: bool,
    pub skip_extract: bool,
    pub skip_prepare: bool,
    pub resume: bool,
    pub partitions: Vec<String>,
}

pub fn dumprs(file: &Path, output_path: &Path, options: &DumpOptions) -> Result<PathBuf> {
    let start_time = Instant::now();
    let extracted_archive_path = output_path.join("temp_extracted_archive");
    let raw_images_path = output_path.join("temp_raw_images");

    fs::create_dir_all(output_path)
        .with_context(|| format!("Failed to create output dir {}", output_path.display()))?;
    fs::create_dir_all(&extracted_archive_path)?;
    fs::create_dir_all(&raw_images_path)?;

    let has_extracted_files = fs::read_dir(&extracted_archive_path)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    let should_skip_extract = options.skip_extract || (options.resume && has_extracted_files);

    let has_raw_files = fs::read_dir(&raw_images_path)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    let should_skip_prepare = options.skip_prepare || (options.resume && has_raw_files);

    if !should_skip_extract
        && !should_skip_prepare
        && !options.resume
        && options.partitions.is_empty()
        && let Ok(entries) = fs::read_dir(output_path)
    {
        let stale_dir = raw_images_path.join(".stale");
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            if name != "temp_extracted_archive" && name != "temp_raw_images" {
                let _ = fs::create_dir_all(&stale_dir);
                let _ = fs::rename(entry.path(), stale_dir.join(&name));
            }
        }
    }

    set_allow_early_extract(options.partitions.is_empty() && !options.skip_prepare);
    let run_res = (|| -> Result<()> {
        if should_skip_extract {
            info!(
                step = 1,
                dir = %extracted_archive_path.display(),
                "step.extract_archive.skipped"
            );
        } else {
            let step_start = Instant::now();
            info!(step = 1, archive = %file.display(), "step.extract_archive.start");
            extract_archive(file, &extracted_archive_path, false)?;
            info!(
                step = 1,
                duration = %HumanDuration(step_start.elapsed()),
                "step.extract_archive.done"
            );
        }

        if should_skip_prepare {
            info!(
                step = 2,
                dir = %raw_images_path.display(),
                "step.prepare_images.skipped"
            );
        } else {
            let step_start = Instant::now();
            info!(step = 2, "step.prepare_images.start");
            prepare_images(&extracted_archive_path, &raw_images_path)?;
            info!(
                step = 2,
                duration = %HumanDuration(step_start.elapsed()),
                "step.prepare_images.done"
            );
        }

        let cleanup_temp = !options.debug && !options.resume;
        let step_start = Instant::now();
        info!(step = 3, "step.extract_partitions.start");
        extract_images_with_cleanup(
            &raw_images_path,
            output_path,
            &options.partitions,
            options.resume,
            cleanup_temp,
        )?;
        info!(
            step = 3,
            duration = %HumanDuration(step_start.elapsed()),
            "step.extract_partitions.done"
        );
        if cleanup_temp {
            clear_in_memory_images();
        }
        if options.partitions.is_empty() || options.partitions.iter().any(|p| p == "system") {
            let system_dir = output_path.join("system");
            if !system_dir.exists() {
                bail!("System folder doesn't exist in {}", output_path.display());
            }
            let mut entries = fs::read_dir(&system_dir)
                .with_context(|| format!("Failed to read {}", system_dir.display()))?;
            if entries.next().is_none() {
                bail!("System folder is empty in {}", system_dir.display());
            }
        }

        info!(step = 4, "step.finalize.start");
        Ok(())
    })();

    // Propagate failure BEFORE cleanup: on error, NEVER delete temporary files so user can resume with -r
    run_res?;
    if !options.debug && !options.resume {
        clear_in_memory_images();
    }

    let finalize_start = Instant::now();
    let cleanup_temp = !options.debug && !options.resume;

    // Generate device info and README.md
    let device_info = DeviceInfo::from_dump_dir(output_path);
    let readme_content = device_info.generate_readme();
    if let Err(e) = fs::write(output_path.join("README.md"), &readme_content) {
        tracing::warn!("Failed to write README.md: {e}");
    }

    let mut files_list = Vec::new();
    let mut total_bytes = 0u64;
    let mut root_files = 0usize;
    let mut root_bytes = 0u64;
    let mut part_stats: HashMap<String, (usize, u64)> = HashMap::new();
    rayon::join(
        || {
            if cleanup_temp {
                rayon::join(
                    || {
                        if extracted_archive_path.exists() {
                            let _ = rmtree_recursive(&extracted_archive_path);
                        }
                    },
                    || {
                        if raw_images_path.exists() {
                            let _ = rmtree_recursive(&raw_images_path);
                        }
                    },
                );
            }
        },
        || {
            let walker = WalkDir::new(output_path).into_iter().filter_entry(|e| {
                if e.depth() == 1 && e.file_type().is_dir() {
                    let name = e.file_name();
                    name != "temp_extracted_archive" && name != "temp_raw_images"
                } else {
                    true
                }
            });

            for entry in walker.filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    if let Ok(rel) = path.strip_prefix(output_path) {
                        if rel == Path::new("all_files.txt") {
                            continue;
                        }
                        let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                        total_bytes += len;
                        let mut comps = rel.components();
                        match (comps.next(), comps.next()) {
                            (Some(std::path::Component::Normal(top)), Some(_)) => {
                                if let Some(top_str) = top.to_str() {
                                    if let Some(stat) = part_stats.get_mut(top_str) {
                                        stat.0 += 1;
                                        stat.1 += len;
                                    } else {
                                        part_stats.insert(top_str.to_string(), (1, len));
                                    }
                                }
                            }
                            (Some(std::path::Component::Normal(_)), None) => {
                                root_files += 1;
                                root_bytes += len;
                            }
                            _ => {}
                        }
                        files_list.push(rel.to_path_buf());
                    }
                }
            }

            sort_files(&mut files_list);
        },
    );
    let mut content = String::with_capacity(files_list.len() * 40);
    for f in &files_list {
        content.push_str(&f.to_string_lossy());
        content.push('\n');
    }
    fs::write(output_path.join("all_files.txt"), content)?;
    info!(
        step = 4,
        duration = %HumanDuration(finalize_start.elapsed()),
        "step.finalize.done"
    );

    device_info.render_terminal();

    log_summary(
        output_path,
        start_time.elapsed(),
        files_list.len(),
        total_bytes,
        root_files,
        root_bytes,
        &part_stats,
    );
    Ok(output_path.to_path_buf())
}

fn log_summary(
    output_path: &Path,
    duration: std::time::Duration,
    total_files: usize,
    total_bytes: u64,
    root_files: usize,
    root_bytes: u64,
    part_stats: &HashMap<String, (usize, u64)>,
) {
    for partition in get_partition_names() {
        if let Some(&(count, dir_bytes)) = part_stats.get(partition) {
            info!(
                partition,
                size = %HumanBytes(dir_bytes),
                files = count,
                "partition.summary"
            );
        } else {
            let part_img = output_path.join(format!("{}.img", partition));
            if let Ok(meta) = fs::metadata(&part_img)
                && meta.is_file()
            {
                info!(
                    partition,
                    size = %HumanBytes(meta.len()),
                    kind = "raw_image",
                    "partition.summary"
                );
            }
        }
    }
    if root_files > 0 {
        info!(
            files = root_files,
            size = %HumanBytes(root_bytes),
            "firmware.summary"
        );
    }

    info!(
        duration = %HumanDuration(duration),
        files = total_files,
        size = %HumanBytes(total_bytes),
        output = %output_path.display(),
        "dump.complete"
    );
}
