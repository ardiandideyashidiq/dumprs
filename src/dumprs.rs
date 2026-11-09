use anyhow::{bail, Context, Result};
use indicatif::{HumanBytes, HumanDuration};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::info;
use walkdir::WalkDir;

use crate::steps::extract_archive::extract_archive;
use crate::steps::extract_images::extract_images;
use crate::steps::prepare_images::prepare_images;
use crate::utils::files::{rmtree_recursive, sort_files};
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

    let run_res = (|| -> Result<()> {
        if should_skip_extract {
            info!(
                "[RESUME] Found extracted files in {}, skipping Step 1 archive extraction",
                extracted_archive_path.display()
            );
        } else {
            info!("Step 1 - Extracting archive");
            extract_archive(file, &extracted_archive_path, false)?;
        }

        if should_skip_prepare {
            info!(
                "[RESUME] Found raw partition images in {}, skipping Step 2 image preparation",
                raw_images_path.display()
            );
        } else {
            info!("Step 2 - Preparing partition images");
            prepare_images(&extracted_archive_path, &raw_images_path)?;
        }

        info!("Step 3 - Extracting partitions");
        extract_images(&raw_images_path, output_path, &options.partitions, options.resume)?;

        // Make sure system folder exists and it's not empty (unless user filtered partitions)
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

        info!("Step 4 - Finalizing");
        Ok(())
    })();

    // Propagate failure BEFORE cleanup: on error, NEVER delete temporary files so user can resume with -r
    run_res?;

    // Only clean up temporary directories on SUCCESS, and only if neither debug nor resume is enabled
    if !options.debug && !options.resume {
        if extracted_archive_path.exists() {
            let _ = rmtree_recursive(&extracted_archive_path);
        }
        if raw_images_path.exists() {
            let _ = rmtree_recursive(&raw_images_path);
        }
    }

    // Single-pass walk to collect files for all_files.txt and summary statistics
    let mut files_list = Vec::new();
    let mut total_bytes = 0u64;
    let mut part_stats: HashMap<String, (usize, u64)> = HashMap::new();

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
                if let Some(std::path::Component::Normal(top)) = rel.components().next()
                    && rel.components().count() > 1
                    && let Some(top_str) = top.to_str()
                {
                    let stat = part_stats.entry(top_str.to_string()).or_insert((0, 0));
                    stat.0 += 1;
                    stat.1 += len;
                }
                files_list.push(rel.to_path_buf());
            }
        }
    }

    sort_files(&mut files_list);

    info!("Creating all_files.txt");
    let mut content = String::with_capacity(files_list.len() * 40);
    for f in &files_list {
        content.push_str(&f.to_string_lossy());
        content.push('\n');
    }
    fs::write(output_path.join("all_files.txt"), content)?;

    // Display summary statistics
    print_summary(output_path, start_time.elapsed(), files_list.len(), total_bytes, &part_stats);

    Ok(output_path.to_path_buf())
}

fn print_summary(
    output_path: &Path,
    duration: std::time::Duration,
    total_files: usize,
    total_bytes: u64,
    part_stats: &HashMap<String, (usize, u64)>,
) {
    println!("\n{}", "=".repeat(70));
    println!("{:^70}", "Dumprs Extraction Summary");
    println!("{}", "=".repeat(70));
    println!("  Duration:           {}", HumanDuration(duration));
    println!("  Total Files:        {}", total_files);
    println!("  Total Extracted:    {}", HumanBytes(total_bytes));
    println!("  Output Directory:   {}", output_path.display());
    println!("{}", "-".repeat(70));
    println!("  Partition Breakdown:");

    for partition in get_partition_names() {
        if let Some(&(count, dir_bytes)) = part_stats.get(partition) {
            println!(
                "    - {:<16} {} ({} files)",
                partition,
                HumanBytes(dir_bytes),
                count
            );
        } else {
            let part_img = output_path.join(format!("{}.img", partition));
            if let Ok(meta) = fs::metadata(&part_img) && meta.is_file() {
                println!("    - {:<16} {} (raw image)", partition, HumanBytes(meta.len()));
            }
        }
    }

    println!("{}", "-".repeat(70));
    println!("  Manifest:           all_files.txt generated ({} entries)", total_files);
    println!("{}\n", "=".repeat(70));
}
