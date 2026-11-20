//! Pure helpers for dump-level metadata and auxiliary files.
//!
//! These mirror the filename/string decisions in DumprX's `dumper.sh` so they
//! can be tested without running the shell pipeline or `uvx`.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::utils::files::sort_files;

/// Write the dump's `all_files.txt` from a file list.
///
/// The list is sorted in place and the manifest excludes itself.
///
/// # Errors
///
/// Returns an error when the output file cannot be written.
pub fn write_all_files_list(output: &Path, files: &mut [PathBuf]) -> Result<()> {
    sort_files(files);
    let mut content = String::with_capacity(files.len() * 40);
    for file in files.iter() {
        content.push_str(&file.to_string_lossy());
        content.push('\n');
    }
    fs::write(output.join("all_files.txt"), content).context("writing all_files.txt")?;
    Ok(())
}

/// GNU `strings`-like extraction: printable ASCII runs of at least 4 bytes.
fn printable_strings(data: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut run = Vec::new();
    for &byte in data {
        if (0x20..=0x7e).contains(&byte) {
            run.push(byte);
        } else {
            if run.len() >= 4 {
                result.push(String::from_utf8_lossy(&run).into_owned());
            }
            run.clear();
        }
    }
    if run.len() >= 4 {
        result.push(String::from_utf8_lossy(&run).into_owned());
    }
    result
}

/// Derive the sorted, unique `require version-*` lines for `board-info.txt`.
///
/// Inputs are the raw bytes of `modem`, `tz*` and `vendor/build.prop`.
pub fn board_info_lines(modem: &[u8], tz: &[u8], vendor_props: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    for text in printable_strings(modem) {
        if let Some(rest) = text.split("QC_IMAGE_VERSION_STRING=MPSS.").nth(1) {
            let value: String = rest.chars().skip(3).collect();
            lines.push(format!("require version-baseband={value}"));
        }
    }
    for text in printable_strings(tz) {
        if let Some(rest) = text.split("QC_IMAGE_VERSION_STRING").nth(1) {
            lines.push(format!(
                "require version-trustzone={}",
                rest.trim_start_matches('=')
            ));
        }
    }
    for text in printable_strings(vendor_props) {
        if let Some(rest) = text.split("ro.vendor.build.date.utc").nth(1) {
            lines.push(format!(
                "require version-vendor={}",
                rest.trim_start_matches('=')
            ));
        }
    }
    lines.sort();
    lines.dedup();
    lines
}

/// Write `board-info.txt` at the dump root.
///
/// # Errors
///
/// Returns an error when the file cannot be written.
pub fn write_board_info(output: &Path, lines: &[String]) -> Result<()> {
    let mut content = String::new();
    for line in lines {
        content.push_str(line);
        content.push('\n');
    }
    fs::write(output.join("board-info.txt"), content).context("writing board-info.txt")?;
    Ok(())
}

/// Canonical destination for an auxiliary file that DumprX keeps.
///
/// Returns `None` for files that may be discarded.
pub fn auxiliary_target(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    if name.ends_with("android_scatter.txt") || name.ends_with("android_scatter.xml") {
        return Some(path.file_name()?.to_str()?.to_string());
    }
    if name == "da_br.bin" {
        return Some("download_agent/DA_BR.bin".to_string());
    }
    if name.ends_with("release_note.txt") {
        return Some(path.file_name()?.to_str()?.to_string());
    }
    if path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|part| part.eq_ignore_ascii_case("euclid"))
    }) {
        return Some(path.to_string_lossy().into_owned());
    }
    None
}

/// Generate `board-info.txt` from the dumped modem, trustzone and vendor props.
///
/// Missing inputs are treated as empty; a failure to write is reported.
///
/// # Errors
///
/// Returns an error when the output cannot be written.
pub fn generate_board_info(dump_dir: &Path) -> Result<()> {
    let mut modem = Vec::new();
    let mut tz = Vec::new();
    if let Ok(entries) = fs::read_dir(dump_dir) {
        for entry in entries.filter_map(|entry| entry.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            if lower == "modem.img" {
                modem.extend_from_slice(&fs::read(&path).unwrap_or_default());
            } else if lower.starts_with("tz") && lower.ends_with(".img") {
                tz.extend_from_slice(&fs::read(&path).unwrap_or_default());
            }
        }
    }
    let vendor = dump_dir.join("vendor/build.prop");
    let vendor_props = fs::read(&vendor).unwrap_or_default();
    let lines = board_info_lines(&modem, &tz, &vendor_props);
    write_board_info(dump_dir, &lines)
}

/// Copy OEM auxiliary files from the extracted archive into their canonical
/// locations at the dump root.
///
/// # Errors
///
/// Returns an error when a file cannot be copied.
pub fn preserve_auxiliary_files(extracted: &Path, output: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(extracted)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
    {
        let path = entry.path();
        let relative = match path.strip_prefix(extracted) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        let Some(target) = auxiliary_target(relative) else {
            continue;
        };
        let destination = output.join(&target);
        if destination.exists() {
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        fs::copy(path, &destination).with_context(|| {
            format!(
                "Failed to copy {} to {}",
                path.display(),
                destination.display()
            )
        })?;
        info!(file = %relative.display(), target = %target, "auxiliary.preserved");
    }
    Ok(())
}

/// Which boot image DumprX feeds to `twrpdtgen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwrpSource {
    Recovery,
    VendorBoot,
}

impl TwrpSource {
    /// File name passed to the generator.
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Recovery => "recovery.img",
            Self::VendorBoot => "vendor_boot.img",
        }
    }
}

/// Select the primary TWRP source image.
pub fn twrp_source_image(
    is_ab: bool,
    has_recovery: bool,
    has_vendor_boot: bool,
) -> Option<TwrpSource> {
    if !is_ab {
        return has_recovery.then_some(TwrpSource::Recovery);
    }
    if has_recovery {
        Some(TwrpSource::Recovery)
    } else if has_vendor_boot {
        Some(TwrpSource::VendorBoot)
    } else {
        None
    }
}

/// Generate a TWRP tree, falling back to `vendor_boot.img` on primary failure.
///
/// `generate` receives the image file name; no network or external process is
/// performed here, so the decision is fully testable.
pub fn generate_twrp_tree(
    source: Option<TwrpSource>,
    has_vendor_boot: bool,
    generate: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let Some(primary) = source else {
        return Ok(());
    };
    match generate(primary.file_name()) {
        Ok(()) => Ok(()),
        Err(error) if has_vendor_boot && primary != TwrpSource::VendorBoot => {
            info!(error = %error, "twrp.primary_failed_trying_vendor_boot");
            generate(TwrpSource::VendorBoot.file_name())
        }
        Err(error) => Err(error),
    }
}

/// Return `2..=17` for `super_2.img` through `super_17.img`.
pub fn super_chunk_index(name: &str) -> Option<u8> {
    let stem = name.strip_prefix("super_")?.strip_suffix(".img")?;
    let index = stem.parse::<u8>().ok()?;
    (2..=17).contains(&index).then_some(index)
}

/// Identify a partition name from an already-extracted `super_N.img` chunk.
pub fn identify_super_chunk(dir: &Path) -> Result<String> {
    let has_android_modules = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_dir())
        .any(|entry| {
            let text = entry.path().to_string_lossy().replace('\\', "/");
            text.contains("/lib/modules/") && text.to_ascii_lowercase().contains("android")
        });
    if has_android_modules {
        return Ok("system_dlkm".to_string());
    }

    let top_level: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("Failed to read {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .collect();
    if top_level.len() == 1 && top_level[0].file_name() == "build.prop" {
        return Ok("tr_manifest".to_string());
    }

    for candidate in ["build.prop", "etc/build.prop", "system/build.prop"] {
        let path = dir.join(candidate);
        if !path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        if let Some(start) = text.find("ro.product.") {
            let value: String = text[start + "ro.product.".len()..]
                .chars()
                .take_while(|&c| c != '.' && c != '\n' && c != '\r')
                .collect();
            if !value.is_empty() {
                return Ok(value);
            }
        }
    }
    Ok("unknown".to_string())
}
