//! `fs_config` generation, adapted from Danda420's GPL-3.0-only `gen_fs-config`.

use crate::utils::fs_metadata::reader::read_existing_keys;
use crate::utils::fs_metadata::types::{
    Config, GenerationReport, has_component_with_child, is_vendor_like,
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use tracing::info;
use walkdir::WalkDir;

/// Generate the missing `fs_config` lines for an extracted partition.
///
/// Existing entries are preserved verbatim; only absent paths are appended.
/// With `dry_run` enabled, nothing is written but the report is still exact.
///
/// # Errors
///
/// Returns an error if the partition name cannot be determined, the existing
/// sidecar cannot be read, or the output cannot be opened or written.
pub fn generate_fs_config(config: &Config) -> Result<GenerationReport> {
    let partition = config.partition_name()?;
    let existing = read_existing_keys(&config.output)?;

    let entries = collect_entries(config)?;
    let outcomes: Vec<(bool, Option<String>)> = entries
        .par_iter()
        .map(|(relative, is_file)| build_entry(relative, *is_file, &partition, &existing))
        .collect::<Result<Vec<_>>>()?;

    let missing = outcomes.iter().filter(|(needed, _)| *needed).count();
    let lines: Vec<String> = outcomes.into_iter().filter_map(|(_, line)| line).collect();

    if !config.dry_run && !lines.is_empty() {
        write_lines(&config.output, &lines)?;
    }

    let report = GenerationReport {
        missing,
        generated: if config.dry_run { 0 } else { lines.len() },
        skipped: entries.len() - missing,
    };
    info!(
        partition = %partition,
        missing = report.missing,
        generated = report.generated,
        skipped = report.skipped,
        dry_run = config.dry_run,
        "fs_config.generate"
    );
    Ok(report)
}

/// Collect relative paths with their file/directory classification.
fn collect_entries(config: &Config) -> Result<Vec<(String, bool)>> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(&config.extracted_dir)
        .min_depth(1)
        .into_iter()
        .filter_map(Result::ok)
    {
        let relative = entry.path().strip_prefix(&config.extracted_dir)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let relative_key = relative.to_string_lossy().replace('\\', "/");
        if config.mode == crate::utils::fs_metadata::types::GenerationMode::BinOnly
            && !has_component_with_child(relative, "bin")
        {
            continue;
        }
        entries.push((relative_key, entry.path().is_file()));
    }
    entries.shrink_to_fit();
    Ok(entries)
}

/// Decide the permissions line for one path, if it is missing.
fn build_entry(
    relative: &str,
    is_file: bool,
    partition: &str,
    existing: &std::collections::HashSet<String>,
) -> Result<(bool, Option<String>)> {
    let key = format!("{partition}/{relative}");
    if existing.contains(&key) {
        return Ok((false, None));
    }

    let path = Path::new(relative);
    let permissions = if is_file {
        if has_component_with_child(path, "bin") {
            "0 2000 0755"
        } else {
            "0 0 0644"
        }
    } else if is_vendor_like(partition) {
        "0 2000 0755"
    } else {
        "0 0 0755"
    };

    Ok((true, Some(format!("{key} {permissions}"))))
}

/// Append generated lines in a deterministic order.
fn write_lines(path: &Path, lines: &[String]) -> Result<()> {
    let file: File = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let mut writer = BufWriter::new(file);
    for line in lines {
        writeln!(writer, "{line}")
            .with_context(|| format!("failed to write {}", path.display()))?;
    }
    writer
        .flush()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(prefix: &str) -> std::path::PathBuf {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("dumprs-{prefix}-{}-{id}", std::process::id()))
    }

    fn tree() -> (std::path::PathBuf, std::path::PathBuf) {
        let root = temp_dir("fs-config");
        let partition = root.join("system");
        fs::create_dir_all(partition.join("bin")).unwrap();
        fs::create_dir_all(partition.join("etc")).unwrap();
        fs::write(partition.join("bin/tool"), b"x").unwrap();
        fs::write(partition.join("etc/config.xml"), b"x").unwrap();
        let output = root.join("fs_config");
        (root, output)
    }

    #[test]
    fn generates_permission_rules() {
        let (root, output) = tree();
        let config = Config::builder(root.join("system"), &output)
            .build()
            .unwrap();
        let report = generate_fs_config(&config).unwrap();
        assert_eq!(report.missing, 4);
        let content = fs::read_to_string(&output).unwrap();
        assert!(content.contains("system/bin/tool 0 2000 0755"));
        assert!(content.contains("system/etc/config.xml 0 0 0644"));
        assert!(content.contains("system/etc 0 0 0755"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn is_idempotent() {
        let (root, output) = tree();
        let config = Config::builder(root.join("system"), &output)
            .build()
            .unwrap();
        generate_fs_config(&config).unwrap();
        let second = generate_fs_config(&config).unwrap();
        assert_eq!(second.missing, 0);
        assert_eq!(second.generated, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vendor_directories_use_shell_group() {
        let root = temp_dir("fs-config-vendor");
        let vendor = root.join("vendor");
        fs::create_dir_all(vendor.join("lib")).unwrap();
        let output = root.join("fs_config");
        let config = Config::builder(&vendor, &output).build().unwrap();
        generate_fs_config(&config).unwrap();
        let content = fs::read_to_string(output).unwrap();
        assert!(content.contains("vendor/lib 0 2000 0755"));
        fs::remove_dir_all(root).unwrap();
    }
}
