use anyhow::Result;

use std::fs;
use std::path::Path;


use crate::formats::liblp::lpunpack;
use crate::formats::payload::extract_android_ota_payload;
use crate::formats::sparse::unsparse_file;
pub fn extract_payload(image: &Path, output_dir: &Path) -> Result<()> {
    extract_android_ota_payload(image, output_dir)
}

pub fn extract_super(image: &Path, output_dir: &Path) -> Result<()> {
    let unsparsed_super = output_dir.join("super.unsparsed.img");

    match unsparse_file(image, &unsparsed_super) {
        Ok(true) if unsparsed_super.is_file() => {
            let _ = fs::remove_file(image);
            let res = lpunpack(&unsparsed_super, output_dir);
            let _ = fs::remove_file(&unsparsed_super);
            res?;
            return Ok(());
        }
        _ => {
            if unsparsed_super.is_file() {
                let _ = fs::remove_file(&unsparsed_super);
            }
        }
    }

    lpunpack(image, output_dir)?;
    let _ = fs::remove_file(image);

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
