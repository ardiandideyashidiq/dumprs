//! Pipeline step that dispatches detected OEM containers to their parsers.

use anyhow::Result;
use std::fs;
use std::path::Path;
use tracing::{debug, info};

use crate::formats::oem::qfil::{extract_qfil, list_targets};
use crate::formats::oem::update_app::extract_update_app;
use crate::utils::firmware::{FirmwareKind, detect_firmware_kind};

/// Detect and extract OEM containers left in the extracted archive directory.
///
/// Extracted images are written straight into `raw_images` and the consumed
/// container is removed so later passes do not mistake it for a partition.
///
/// # Errors
///
/// Returns an error when a detected container cannot be parsed.
pub fn prepare_oem_containers(extracted: &Path, raw_images: &Path) -> Result<()> {
    let entries = match fs::read_dir(extracted) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let kind = detect_firmware_kind(&[], name, &[] as &[String]);
        if kind == FirmwareKind::HuaweiUpdateApp {
            info!(file = name, "oem.container.detected");
            extract_update_app(&path, raw_images)?;
            let _ = fs::remove_file(&path);
        } else if kind == FirmwareKind::Qfil {
            info!(file = name, "oem.container.detected");
            for target in list_targets(&path)? {
                extract_qfil(&path, &target, raw_images)?;
            }
        } else {
            debug!(file = name, ?kind, "oem.container.skipped");
        }
    }

    Ok(())
}
