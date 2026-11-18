//! `file_contexts` generation, adapted from Danda420's GPL-3.0-only
//! `gen_file-context`.

use crate::utils::fs_metadata::escape::escape_regex;
use crate::utils::fs_metadata::reader::read_existing_keys;
use crate::utils::fs_metadata::types::{
    Config, FilesystemType, GenerationMode, GenerationReport, has_component,
    has_component_with_child, has_components_with_child, is_vendor_like,
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use tracing::info;
use walkdir::WalkDir;

const HAL_EXEC: &str = "u:object_r:hal_allocator_default_exec:s0";
const SYSTEM_FILE: &str = "u:object_r:system_file:s0";
const VENDOR_FILE: &str = "u:object_r:vendor_file:s0";
const SYSTEM_LIB_FILE: &str = "u:object_r:system_lib_file:s0";
const VENDOR_CONFIGS: &str = "u:object_r:vendor_configs_file:s0";
const VENDOR_FIRMWARE: &str = "u:object_r:vendor_firmware_file:s0";
const VENDOR_APP: &str = "u:object_r:vendor_app_file:s0";
const VENDOR_FRAMEWORK: &str = "u:object_r:vendor_framework_file:s0";
const VENDOR_OVERLAY: &str = "u:object_r:vendor_overlay_file:s0";

/// Generate the missing `file_contexts` lines for an extracted partition.
///
/// Existing entries are preserved verbatim; only absent paths are appended.
/// Directory rules follow the target filesystem's conventions: ext4 emits both
/// a plain path and a `path(/.*)?` regex, while erofs/f2fs emit only the plain
/// path.
///
/// # Errors
///
/// Returns an error if the partition name cannot be determined, the existing
/// sidecar cannot be read, or the output cannot be opened or written.
pub fn generate_file_contexts(config: &Config) -> Result<GenerationReport> {
    let partition = config.partition_name()?;
    let existing = read_existing_keys(&config.output)?;
    let entries = collect_entries(config)?;

    let outcomes: Vec<(bool, Vec<String>)> = entries
        .par_iter()
        .map(|(relative, is_file)| build_entries(relative, *is_file, &partition, config, &existing))
        .collect::<Result<Vec<_>>>()?;

    let missing = outcomes.iter().filter(|(needed, _)| *needed).count();
    let lines: Vec<String> = outcomes.into_iter().flat_map(|(_, lines)| lines).collect();

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
        "file_contexts.generate"
    );
    Ok(report)
}

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
        if config.mode == GenerationMode::BinOnly && !has_component_with_child(relative, "bin") {
            continue;
        }
        entries.push((relative_key, entry.path().is_file()));
    }
    entries.shrink_to_fit();
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn build_entries(
    relative: &str,
    is_file: bool,
    partition: &str,
    config: &Config,
    existing: &HashSet<String>,
) -> Result<(bool, Vec<String>)> {
    let escaped = escape_regex(relative);
    let plain_key = format!("/{partition}/{escaped}");
    let folder_key = format!("/{partition}/{escaped}{}", config.fstype.folder_pattern());
    if existing.contains(&plain_key) || existing.contains(&folder_key) {
        return Ok((false, Vec::new()));
    }

    let path = Path::new(relative);
    let vendor = is_vendor_like(partition);
    let context: Cow<'_, str> = if is_file {
        file_context(path, vendor, config)
    } else {
        Cow::Borrowed(dir_context(path, vendor))
    };

    let mut lines = Vec::with_capacity(2);
    if is_file {
        lines.push(format!("{plain_key} {context}"));
    } else if config.fstype == FilesystemType::Ext4 {
        lines.push(format!("{plain_key} {context}"));
        lines.push(format!("{folder_key} {context}"));
    } else {
        lines.push(format!("/{partition}/{escaped} {context}"));
    }
    Ok((true, lines))
}

fn file_context(path: &Path, vendor: bool, config: &Config) -> Cow<'static, str> {
    if has_components_with_child(path, "bin", "hw") {
        return Cow::Borrowed(HAL_EXEC);
    }
    if has_component_with_child(path, "bin") {
        let context = if vendor {
            &config.vendor_bin_context
        } else {
            &config.system_bin_context
        };
        return Cow::Owned(context.to_string());
    }
    if !vendor && (has_component(path, "lib") || has_component(path, "lib64")) {
        return Cow::Borrowed(SYSTEM_LIB_FILE);
    }
    if vendor {
        return Cow::Borrowed(vendor_file_context(path, true));
    }
    Cow::Borrowed(SYSTEM_FILE)
}

fn dir_context(path: &Path, vendor: bool) -> &'static str {
    if vendor {
        vendor_file_context(path, false)
    } else {
        SYSTEM_FILE
    }
}

/// Vendor-specific mapping. `require_child` distinguishes the upstream file
/// rules (`/etc/`) from directory rules (`/etc`).
fn vendor_file_context(path: &Path, require_child: bool) -> &'static str {
    let has = |component: &str| {
        if require_child {
            has_component_with_child(path, component)
        } else {
            has_component(path, component)
        }
    };
    if has("etc") {
        VENDOR_CONFIGS
    } else if has("firmware") {
        VENDOR_FIRMWARE
    } else if has("app") || has("priv-app") {
        VENDOR_APP
    } else if has("framework") {
        VENDOR_FRAMEWORK
    } else if has("overlay") {
        VENDOR_OVERLAY
    } else {
        VENDOR_FILE
    }
}

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

    fn tree(partition: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = temp_dir(&format!("contexts-{partition}"));
        let dir = root.join(partition);
        for sub in ["bin/hw", "bin", "lib64", "etc", "framework", "app"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        fs::write(dir.join("bin/tool"), b"x").unwrap();
        fs::write(dir.join("bin/hw/hal-service"), b"x").unwrap();
        fs::write(dir.join("lib64/libx.so"), b"x").unwrap();
        fs::write(dir.join("etc/config.xml"), b"x").unwrap();
        fs::write(dir.join("app/App.apk"), b"x").unwrap();
        fs::write(dir.join("framework/fw.jar"), b"x").unwrap();
        let output = root.join("file_contexts");
        (root, output)
    }

    #[test]
    fn system_rules_match_upstream() {
        let (root, output) = tree("system");
        let config = Config::builder(root.join("system"), &output)
            .build()
            .unwrap();
        generate_file_contexts(&config).unwrap();
        let content = fs::read_to_string(output).unwrap();
        assert!(content.contains("system/bin/tool u:object_r:system_file:s0"));
        assert!(
            content.contains("system/bin/hw/hal-service u:object_r:hal_allocator_default_exec:s0")
        );
        assert!(content.contains(r"system/lib64/libx\.so u:object_r:system_lib_file:s0"));
        assert!(content.contains("/system/etc(/.*)? u:object_r:system_file:s0"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vendor_rules_match_upstream() {
        let (root, output) = tree("vendor");
        let config = Config::builder(root.join("vendor"), &output)
            .build()
            .unwrap();
        generate_file_contexts(&config).unwrap();
        let content = fs::read_to_string(output).unwrap();
        assert!(content.contains("vendor/bin/tool u:object_r:vendor_qti_init_shell_exec:s0"));
        assert!(content.contains(r"vendor/etc/config\.xml u:object_r:vendor_configs_file:s0"));
        assert!(content.contains(r"vendor/app/App\.apk u:object_r:vendor_app_file:s0"));
        assert!(content.contains(r"vendor/framework/fw\.jar u:object_r:vendor_framework_file:s0"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn erofs_does_not_emit_directory_regex() {
        let (root, output) = tree("system");
        let config = Config::builder(root.join("system"), &output)
            .fstype(FilesystemType::Erofs)
            .build()
            .unwrap();
        generate_file_contexts(&config).unwrap();
        let content = fs::read_to_string(output).unwrap();
        assert!(!content.contains("(/.*)?"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preserves_existing_entries() {
        let (root, output) = tree("system");
        fs::write(&output, "/system/bin/tool u:object_r:custom_exec:s0\n").unwrap();
        let config = Config::builder(root.join("system"), &output)
            .build()
            .unwrap();
        generate_file_contexts(&config).unwrap();
        let content = fs::read_to_string(output).unwrap();
        assert!(
            content
                .lines()
                .any(|l| l == "/system/bin/tool u:object_r:custom_exec:s0")
        );
        assert!(!content.contains("system/bin/tool u:object_r:system_file:s0"));
        fs::remove_dir_all(root).unwrap();
    }
}
