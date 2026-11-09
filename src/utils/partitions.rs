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
    ("init_boot", PartitionType::Bootimage),
    ("recovery", PartitionType::Bootimage),
    ("vendor_boot", PartitionType::Bootimage),
    ("vendor_boot-debug", PartitionType::Bootimage),
    ("vendor_kernel_boot", PartitionType::Bootimage),
    // SoC vendor/OEM/ODM
    ("exaid", PartitionType::Bootimage),
    ("rescue", PartitionType::Bootimage),
    ("tz", PartitionType::Raw),
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
];

pub const ALTERNATIVE_PARTITION_NAMES: &[(&str, &str)] = &[
    ("boot-verified", "boot"),
    ("dtbo-verified", "dtbo"),
    ("NON-HLOS", "modem"),
];

pub fn get_partition_name(partition_name: &str) -> &str {
    for (alt, generic) in ALTERNATIVE_PARTITION_NAMES {
        if *alt == partition_name {
            return generic;
        }
    }
    partition_name
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
    let mut names: Vec<String> = get_partition_names().into_iter().map(String::from).collect();
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
            info!(alias = alt_name, canonical = name, "partition.alias.ignored");
            let _ = fs::remove_file(&alt_path);
            continue;
        }

        info!(alias = alt_name, canonical = name, "partition.alias.renamed");
        fs::rename(&alt_path, &partition_path)
            .with_context(|| format!("Failed to rename alias {} to {}", alt_path.display(), partition_path.display()))?;
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
            fs::rename(&a_path, &non_ab_path)
                .with_context(|| format!("Failed to rename {} to {}", a_path.display(), non_ab_path.display()))?;
            moved_files.insert(unslotted.to_string(), ());
            if b_path.is_file() {
                let _ = fs::remove_file(&b_path);
            }
        } else if b_path.is_file() {
            info!(from = %b_path.display(), to = %non_ab_path.display(), "partition.slot.normalized");
            fs::rename(&b_path, &non_ab_path)
                .with_context(|| format!("Failed to rename {} to {}", b_path.display(), non_ab_path.display()))?;
            moved_files.insert(unslotted.to_string(), ());
        }
    }

    Ok(())
}
