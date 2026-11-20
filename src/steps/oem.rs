//! Pipeline step that dispatches detected OEM containers to their parsers.

use anyhow::Result;
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::formats::oem::amlogic::extract_amlogic;
use crate::formats::oem::nb0::extract_nb0;
use crate::formats::oem::ofp_mtk::extract_ofp_mtk;
use crate::formats::oem::ofp_qc::extract_ofp_qc;
use crate::formats::oem::ops::extract_ops;
use crate::formats::oem::pac::extract_pac;
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
        } else if kind == FirmwareKind::Amlogic {
            info!(file = name, "oem.container.detected");
            extract_amlogic(&path, raw_images)?;
            let _ = fs::remove_file(&path);
        } else if kind == FirmwareKind::Ofp {
            // DumprX attempts the Qualcomm variant first, then falls back to
            // the MediaTek one. Report the QC failure instead of hiding it.
            if let Err(error) = extract_ofp_qc(&path, raw_images) {
                warn!(file = name, error = %error, "ofp.qualcomm.failed_trying_mtk");
                extract_ofp_mtk(&path, raw_images)?;
                info!(file = name, variant = "mtk", "oem.container.detected");
            } else {
                info!(file = name, variant = "qc", "oem.container.detected");
            }
            let _ = fs::remove_file(&path);
        } else if kind == FirmwareKind::Ruu {
            warn!(
                file = name,
                "ruu.executable.unsupported: extract the encrypted rom.zip first"
            );
        } else if kind == FirmwareKind::Ops {
            info!(file = name, "oem.container.detected");
            extract_ops(&path, raw_images)?;
            let _ = fs::remove_file(&path);
        } else if kind == FirmwareKind::Pac {
            info!(file = name, "oem.container.detected");
            extract_pac(&path, raw_images)?;
            let _ = fs::remove_file(&path);
        } else if kind == FirmwareKind::Nb0 {
            info!(file = name, "oem.container.detected");
            extract_nb0(&path, raw_images)?;
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
