use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionType {
    Filesystem,
    Bootimage,
    Raw,
    Logical,
}

pub const PARTITIONS: &[(&str, PartitionType)] = &[
    // Bootloader/raw images
    // AOSP
    ("boot", PartitionType::Bootimage),
    ("boot-debug", PartitionType::Bootimage),
    ("dtbo", PartitionType::Raw),
    ("dtb", PartitionType::Raw),
    ("vbmeta", PartitionType::Raw),
    ("init_boot", PartitionType::Bootimage),
    ("recovery", PartitionType::Bootimage),
    ("vendor_boot", PartitionType::Bootimage),
    ("vendor_boot-debug", PartitionType::Bootimage),
    ("vendor_kernel_boot", PartitionType::Bootimage),
    // SoC vendor/OEM/ODM
    ("exaid", PartitionType::Bootimage),
    ("rescue", PartitionType::Bootimage),
    ("tz", PartitionType::Raw),
    ("odmko", PartitionType::Raw),
    ("version", PartitionType::Raw),
    ("nt_log", PartitionType::Raw),
    ("socko", PartitionType::Raw),
    // Logical partitions
    ("super", PartitionType::Logical),
    // Partitions with a standard filesystem
    // AOSP
    ("odm", PartitionType::Filesystem),
    ("odm_dlkm", PartitionType::Filesystem),
    ("oem", PartitionType::Filesystem),
    ("product", PartitionType::Filesystem),
    ("system", PartitionType::Filesystem),
    ("system_dlkm", PartitionType::Filesystem),
    ("system_ext", PartitionType::Filesystem),
    ("system_other", PartitionType::Filesystem),
    ("vendor", PartitionType::Filesystem),
    ("vendor_dlkm", PartitionType::Filesystem),
    // SoC vendor/OEM/ODM
    ("cust", PartitionType::Filesystem),
    ("factory", PartitionType::Filesystem),
    ("hw_product", PartitionType::Filesystem),
    ("india", PartitionType::Filesystem),
    ("mi_ext", PartitionType::Filesystem),
    ("modem", PartitionType::Filesystem),
    ("my_bigball", PartitionType::Filesystem),
    ("my_carrier", PartitionType::Filesystem),
    ("my_company", PartitionType::Filesystem),
    ("my_country", PartitionType::Filesystem),
    ("my_custom", PartitionType::Filesystem),
    ("my_engineering", PartitionType::Filesystem),
    ("my_heytap", PartitionType::Filesystem),
    ("my_manifest", PartitionType::Filesystem),
    ("my_odm", PartitionType::Filesystem),
    ("my_operator", PartitionType::Filesystem),
    ("my_preload", PartitionType::Filesystem),
    ("my_product", PartitionType::Filesystem),
    ("my_region", PartitionType::Filesystem),
    ("my_stock", PartitionType::Filesystem),
    ("my_version", PartitionType::Filesystem),
    ("odm_ext", PartitionType::Filesystem),
    ("oppo_product", PartitionType::Filesystem),
    ("opproduct", PartitionType::Filesystem),
    ("preas", PartitionType::Filesystem),
    ("preavs", PartitionType::Filesystem),
    ("preload", PartitionType::Filesystem),
    ("preload_common", PartitionType::Filesystem),
    ("product_h", PartitionType::Filesystem),
    ("reserve", PartitionType::Filesystem),
    ("special_preload", PartitionType::Filesystem),
    ("systemex", PartitionType::Filesystem),
    ("xrom", PartitionType::Filesystem),
    // Transsion tr_* family
    ("tr_product", PartitionType::Filesystem),
    ("tr_region", PartitionType::Filesystem),
    ("tr_carrier", PartitionType::Filesystem),
    ("tr_mi", PartitionType::Filesystem),
    ("tr_preload", PartitionType::Filesystem),
    ("tr_company", PartitionType::Filesystem),
    ("tr_system", PartitionType::Filesystem),
    ("tr_overlayfs", PartitionType::Filesystem),
    ("tr_theme", PartitionType::Filesystem),
    ("tr_manifest", PartitionType::Filesystem),
    ("tr_misc", PartitionType::Filesystem),
];

/// Partitions that may carry a MOTO/ASUS EXT4 header in OEM images.
pub const EXT4_PARTITIONS: &[&str] = &[
    "system",
    "vendor",
    "cust",
    "odm",
    "oem",
    "factory",
    "product",
    "xrom",
    "systemex",
    "oppo_product",
    "preload_common",
    "hw_product",
    "product_h",
    "preas",
    "preavs",
];

pub const ALTERNATIVE_PARTITION_NAMES: &[(&str, &str)] = &[
    ("boot-verified", "boot"),
    ("dtbo-verified", "dtbo"),
    ("recovery-verified", "recovery"),
    ("vbmeta-verified", "vbmeta"),
    ("NON-HLOS", "modem"),
];

/// File-name mappings from DumprX's `OTHERPARTITIONS`.
pub const OTHER_PARTITION_FILES: &[(&str, &str)] = &[
    ("tz.mbn", "tz"),
    ("tz.img", "tz"),
    ("modem.img", "modem"),
    ("NON-HLOS", "modem"),
    ("boot-verified.img", "boot"),
    ("recovery-verified.img", "recovery"),
    ("dtbo-verified.img", "dtbo"),
    ("vbmeta-verified.img", "vbmeta"),
];

pub fn get_partition_name(partition_name: &str) -> &str {
    for (alt, generic) in ALTERNATIVE_PARTITION_NAMES {
        if *alt == partition_name {
            return generic;
        }
    }
    partition_name
}

/// Resolve a firmware file name to its canonical partition name.
pub fn canonicalize_other_partition(file_name: &str) -> &str {
    for (alias, generic) in OTHER_PARTITION_FILES {
        if *alias == file_name {
            return generic;
        }
    }
    let stem = file_name
        .strip_suffix(".img")
        .or_else(|| file_name.strip_suffix(".mbn"))
        .unwrap_or(file_name);
    get_partition_name(stem)
}

pub fn get_partition_type(partition_name: &str) -> Option<PartitionType> {
    for (name, ptype) in PARTITIONS {
        if *name == partition_name {
            return Some(*ptype);
        }
    }
    None
}

pub fn get_partition_names() -> Vec<&'static str> {
    PARTITIONS.iter().map(|(name, _)| *name).collect()
}

pub fn get_partition_names_with_alias() -> Vec<String> {
    let mut names: Vec<String> = get_partition_names()
        .into_iter()
        .map(String::from)
        .collect();
    for (alt, _) in ALTERNATIVE_PARTITION_NAMES {
        names.push((*alt).to_string());
    }
    names
}

pub fn get_partition_names_with_ab() -> Vec<String> {
    let mut partitions = Vec::new();
    for partition in get_partition_names_with_alias() {
        partitions.push(partition.clone());
        partitions.push(format!("{}_a", partition));
        partitions.push(format!("{}_b", partition));
    }
    partitions
}

pub fn fix_aliases(images_path: &Path) -> Result<()> {
    for &(alt_name, name) in ALTERNATIVE_PARTITION_NAMES {
        let alt_path = images_path.join(format!("{}.img", alt_name));
        let partition_path = images_path.join(format!("{}.img", name));

        if !alt_path.exists() {
            continue;
        }

        if partition_path.exists() {
            info!(
                alias = alt_name,
                canonical = name,
                "partition.alias.ignored"
            );
            let _ = fs::remove_file(&alt_path);
            continue;
        }

        info!(
            alias = alt_name,
            canonical = name,
            "partition.alias.renamed"
        );
        fs::rename(&alt_path, &partition_path).with_context(|| {
            format!(
                "Failed to rename alias {} to {}",
                alt_path.display(),
                partition_path.display()
            )
        })?;
    }
    for &(source, canonical) in OTHER_PARTITION_FILES {
        let source_path = images_path.join(source);
        let target_path = images_path.join(format!("{canonical}.img"));
        if !source_path.is_file() || source_path == target_path {
            continue;
        }
        if target_path.exists() {
            let _ = fs::remove_file(&source_path);
            continue;
        }
        fs::rename(&source_path, &target_path).with_context(|| {
            format!(
                "Failed to rename {} to {}",
                source_path.display(),
                target_path.display()
            )
        })?;
    }
    Ok(())
}

fn split_stem_and_suffixes(filename: &str) -> (String, String) {
    if let Some(idx) = filename.find('.') {
        (filename[..idx].to_string(), filename[idx..].to_string())
    } else {
        (filename.to_string(), String::new())
    }
}

pub fn correct_ab_filenames(images_path: &Path) -> Result<()> {
    let partitions = get_partition_names_with_alias();
    let entries = match fs::read_dir(images_path) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let mut moved_files: HashMap<String, ()> = HashMap::new();

    for entry in entries.filter_map(|e| e.ok()) {
        let file_path = entry.path();
        if !file_path.is_file() {
            continue;
        }

        let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        let (file_stem, suffixes) = split_stem_and_suffixes(file_name);

        if !file_stem.ends_with("_a") && !file_stem.ends_with("_b") {
            continue;
        }

        let unslotted = &file_stem[..file_stem.len() - 2];
        if !partitions.iter().any(|p| p == unslotted) {
            continue;
        }

        let non_ab_path = images_path.join(format!("{}{}", unslotted, suffixes));
        let a_path = images_path.join(format!("{}_a{}", unslotted, suffixes));
        let b_path = images_path.join(format!("{}_b{}", unslotted, suffixes));

        if non_ab_path.is_file() {
            let _ = fs::remove_file(&file_path);
            continue;
        }

        if moved_files.contains_key(unslotted) {
            let _ = fs::remove_file(&file_path);
            continue;
        }

        if a_path.is_file() {
            info!(from = %a_path.display(), to = %non_ab_path.display(), "partition.slot.normalized");
            fs::rename(&a_path, &non_ab_path).with_context(|| {
                format!(
                    "Failed to rename {} to {}",
                    a_path.display(),
                    non_ab_path.display()
                )
            })?;
            moved_files.insert(unslotted.to_string(), ());
            if b_path.is_file() {
                let _ = fs::remove_file(&b_path);
            }
        } else if b_path.is_file() {
            info!(from = %b_path.display(), to = %non_ab_path.display(), "partition.slot.normalized");
            fs::rename(&b_path, &non_ab_path).with_context(|| {
                format!(
                    "Failed to rename {} to {}",
                    b_path.display(),
                    non_ab_path.display()
                )
            })?;
            moved_files.insert(unslotted.to_string(), ());
        }
    }

    Ok(())
}
