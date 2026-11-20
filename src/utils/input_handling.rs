//! DumprX-style input classification, staging and recursive input planning.

use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const ARCHIVE_EXTENSIONS: &[&str] = &["tar", "zip", "rar", "7z"];
const COMPATIBILITY_ZIP: &str = "compatibility.zip";

const FIRMWARE_MARKERS: &[&str] = &[
    "system.ext4.tar",
    "system.new.dat",
    "system_new.img",
    "system.img",
    "system-sign.img",
    "system.bin",
    "payload.bin",
    "rawprogram",
    "system.sin",
    "system-p",
    "super",
    "update.app",
];

/// What the user supplied as input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputKind {
    Missing,
    SingleFile(PathBuf),
    /// A folder with exactly one archive: DumprX re-invokes on that archive.
    Archive(PathBuf),
    MultipleArchives(Vec<PathBuf>),
    /// A folder of loose firmware files to stage into the work directory.
    FirmwareDirectory(PathBuf),
    Unsupported(PathBuf),
}

/// A stage in the recursive input plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputStage {
    Archive,
    NestedTarMd5,
    DecryptOzip,
    DecryptOfp,
    DecryptOps,
    DecryptRuu,
    ExtractSin,
}

fn is_archive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == COMPATIBILITY_ZIP {
        return false;
    }
    lower
        .rsplit_once('.')
        .is_some_and(|(_, extension)| ARCHIVE_EXTENSIONS.contains(&extension))
}

fn is_firmware_marker(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    FIRMWARE_MARKERS.iter().any(|marker| lower.contains(marker))
        || (lower.starts_with("system_") && lower.ends_with(".sin"))
        || lower.ends_with(".pac")
        || lower.ends_with(".nb0")
}

/// Classify an input path the way DumprX does.
pub fn classify_input(path: &Path) -> InputKind {
    if !path.exists() {
        return InputKind::Missing;
    }
    if path.is_file() {
        return InputKind::SingleFile(path.to_path_buf());
    }
    if !path.is_dir() {
        return InputKind::Unsupported(path.to_path_buf());
    }

    let mut archives: Vec<PathBuf> = Vec::new();
    let mut has_firmware = false;
    let Ok(entries) = fs::read_dir(path) else {
        return InputKind::Unsupported(path.to_path_buf());
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let entry_path = entry.path();
        if !entry_path.is_file() {
            continue;
        }
        let name = entry_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if is_archive(&name) {
            archives.push(entry_path);
        }
        if is_firmware_marker(&name) {
            has_firmware = true;
        }
    }
    archives.sort();
    match archives.len() {
        1 => InputKind::Archive(archives.remove(0)),
        count if count > 1 => InputKind::MultipleArchives(archives),
        _ if has_firmware => InputKind::FirmwareDirectory(path.to_path_buf()),
        _ => InputKind::Unsupported(path.to_path_buf()),
    }
}

/// Reject inputs that DumprX would refuse.
///
/// # Errors
///
/// Returns an error naming the reason the input cannot be processed.
pub fn validate_input(kind: &InputKind) -> Result<()> {
    match kind {
        InputKind::Missing => bail!("input path does not exist"),
        InputKind::MultipleArchives(paths) => bail!(
            "{} archives found in input folder; use a direct archive path instead",
            paths.len()
        ),
        InputKind::Unsupported(path) => bail!(
            "input folder {} contains neither a supported archive nor recognizable firmware files",
            path.display()
        ),
        _ => Ok(()),
    }
}

/// Copy top-level input entries into the work directory, skipping
/// `compatibility.zip`.
///
/// # Errors
///
/// Returns an error when an entry cannot be copied.
pub fn stage_input_files(source: &Path, work: &Path) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(work).with_context(|| format!("Failed to create {}", work.display()))?;
    let mut staged = Vec::new();
    for entry in WalkDir::new(source)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if entry.depth() == 0 {
            continue;
        }
        let relative = match entry.path().strip_prefix(source) {
            Ok(relative) => relative,
            Err(_) => continue,
        };
        if relative == Path::new(COMPATIBILITY_ZIP) {
            continue;
        }
        let destination = work.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&destination)
                .with_context(|| format!("Failed to create {}", destination.display()))?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        fs::copy(entry.path(), &destination).with_context(|| {
            format!(
                "Failed to copy {} to {}",
                entry.path().display(),
                destination.display()
            )
        })?;
        staged.push(relative.to_path_buf());
    }
    Ok(staged)
}

/// Build the recursive processing chain for a classified input.
pub fn plan_input_chain(kind: &InputKind) -> Vec<InputStage> {
    let InputKind::SingleFile(path) = kind else {
        return if matches!(kind, InputKind::Archive(_)) {
            vec![InputStage::Archive]
        } else {
            Vec::new()
        };
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if name.ends_with(".ozip") {
        vec![InputStage::DecryptOzip, InputStage::Archive]
    } else if name.ends_with(".ofp") {
        vec![InputStage::DecryptOfp]
    } else if name.ends_with(".ops") {
        vec![InputStage::DecryptOps, InputStage::Archive]
    } else if name.starts_with("ruu_") && name.ends_with(".exe") {
        vec![InputStage::DecryptRuu, InputStage::Archive]
    } else if name.ends_with(".sin") {
        vec![InputStage::ExtractSin]
    } else if name.ends_with(".tar.md5") {
        vec![InputStage::Archive, InputStage::NestedTarMd5]
    } else if is_archive(&name) {
        vec![InputStage::Archive]
    } else {
        Vec::new()
    }
}
