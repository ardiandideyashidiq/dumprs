use anyhow::Result;

use std::fs;
use std::path::Path;


use crate::formats::liblp::lpunpack;
use crate::formats::payload::extract_android_ota_payload;
pub fn extract_payload(image: &Path, output_dir: &Path) -> Result<()> {
    extract_android_ota_payload(image, output_dir)?;
    let _ = fs::remove_file(image);
    Ok(())
}

pub fn extract_super(image: &Path, output_dir: &Path) -> Result<()> {
    let backing_path = output_dir.join(".super_backing.img");
    let target = if fs::rename(image, &backing_path).is_ok() {
        backing_path.as_path()
    } else {
        image
    };
    lpunpack(target, output_dir)?;
    if target == image {
        let _ = fs::remove_file(image);
    }
    Ok(())
}

pub struct MultipartitionRule {
    pub name: &'static str,
    pub matches: fn(&str) -> bool,
    pub handler: fn(&Path, &Path) -> Result<()>,
}

pub fn get_multipartition_rules() -> Vec<MultipartitionRule> {
    vec![
        MultipartitionRule {
            name: "payload.bin",
            matches: |name| name == "payload.bin",
            handler: extract_payload,
        },
        MultipartitionRule {
            name: "super*.img",
            matches: |name| {
                name.starts_with("super") && name.ends_with(".img") && !name.contains("_empty")
            },
            handler: extract_super,
        },
    ]
}
