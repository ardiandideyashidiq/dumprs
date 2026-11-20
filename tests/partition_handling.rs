//! Unit tests for DumprX partition coverage and OEM image post-processing.

#[path = "common/temp_dir.rs"]
mod temp_dir;

use dumprs::formats::fs_extract::{FS_BACKEND_ORDER, FsBackend};
use dumprs::utils::oem_image::{
    consolidate_dat_chunks, ext4_header_offset, should_extract_filesystem, strip_header,
    strip_oplus_nv_id,
};
use dumprs::utils::partitions::{
    PartitionType, canonicalize_other_partition, fix_aliases, get_partition_type,
};
use std::fs;

#[test]
fn partition_catalog_contains_dumprx_only_names() {
    let cases: &[(&str, PartitionType)] = &[
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
        ("dtb", PartitionType::Raw),
        ("vbmeta", PartitionType::Raw),
        ("hw_product", PartitionType::Filesystem),
        ("odmko", PartitionType::Raw),
        ("version", PartitionType::Raw),
        ("nt_log", PartitionType::Raw),
        ("socko", PartitionType::Raw),
    ];
    for (name, expected) in cases {
        assert_eq!(get_partition_type(name), Some(*expected), "case: {name}");
    }
}

#[test]
fn ext4_partition_list_matches_dumprx() {
    let expected: &[&str] = &[
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
    assert_eq!(dumprs::utils::partitions::EXT4_PARTITIONS, expected);
    assert!(!dumprs::utils::partitions::EXT4_PARTITIONS.contains(&"modem"));
}

#[test]
fn otherpartition_aliases_match_dumprx() {
    let cases: &[(&str, &str)] = &[
        ("tz.mbn", "tz"),
        ("tz.img", "tz"),
        ("modem.img", "modem"),
        ("NON-HLOS", "modem"),
        ("boot-verified.img", "boot"),
        ("recovery-verified.img", "recovery"),
        ("dtbo-verified.img", "dtbo"),
        ("vbmeta-verified.img", "vbmeta"),
        ("system.img", "system"),
    ];
    for (file, expected) in cases {
        assert_eq!(
            canonicalize_other_partition(file),
            *expected,
            "case: {file}"
        );
    }
}

#[test]
fn fix_aliases_renames_new_mappings() {
    let root = temp_dir::temp_dir();
    for name in [
        "boot-verified.img",
        "dtbo-verified.img",
        "recovery-verified.img",
        "vbmeta-verified.img",
        "tz.mbn",
    ] {
        fs::write(root.join(name), name).expect("alias written");
    }
    fs::write(root.join("boot.img"), "canonical").expect("canonical written");

    fix_aliases(&root).expect("aliases fixed");

    for canonical in ["boot", "dtbo", "recovery", "vbmeta", "tz"] {
        assert!(
            root.join(format!("{canonical}.img")).is_file(),
            "missing canonical {canonical}.img"
        );
    }
    assert_eq!(
        fs::read_to_string(root.join("boot.img")).expect("boot"),
        "canonical"
    );
    assert!(!root.join("boot-verified.img").exists());
    assert!(!root.join("tz.mbn").exists());
}

fn image_with_superblock(magic: &[u8], extra_offset: usize) -> Vec<u8> {
    let mut image = vec![0u8; 1080 + extra_offset + 2];
    image[..magic.len()].copy_from_slice(magic);
    image[1080 + extra_offset..1080 + extra_offset + 2].copy_from_slice(&[0x53, 0xef]);
    image
}

#[test]
fn ext4_header_offset_detection() {
    let cases: Vec<(Vec<u8>, usize, usize)> = vec![
        (image_with_superblock(b"ASUS", 4096), 4096, 4096),
        (image_with_superblock(b"MOTO", 128_055), 131_072, 131_072),
        (image_with_superblock(b"\0MOTO", 128_055), 131_072, 131_072),
        (image_with_superblock(b"OTHER", 4096), 0, 0),
    ];
    for (index, (mut image, expected_offset, expected_body)) in cases.into_iter().enumerate() {
        image.resize(image.len().max(expected_body + 2), 0);
        let offset = ext4_header_offset(&image);
        assert_eq!(offset, expected_offset, "case {index}: offset");
        assert_eq!(
            strip_header(&image, offset).len(),
            image.len() - expected_body,
            "case {index}: body"
        );
    }
}

#[test]
fn oplus_nv_id_filename_normalization() {
    let cases: &[(&str, &str)] = &[
        ("my_bigball.00011011.new.dat.br", "my_bigball.new.dat.br"),
        ("my_bigball.00011011.patch.dat", "my_bigball.patch.dat"),
        ("system.00011011.transfer.list", "system.transfer.list"),
        ("system.new.dat", "system.new.dat"),
        ("system.123.new.dat", "system.123.new.dat"),
    ];
    for (input, expected) in cases {
        assert_eq!(strip_oplus_nv_id(input), *expected, "case: {input}");
    }
}

#[test]
fn oplus_dat_names_are_normalized_on_disk() {
    let root = temp_dir::temp_dir();
    fs::write(root.join("my_bigball.00011011.new.dat.br"), b"a").expect("file written");
    fs::write(root.join("system.new.dat"), b"b").expect("normal file written");

    dumprs::utils::oem_image::normalize_oplus_dat_names(&root).expect("names normalized");

    assert_eq!(
        fs::read(root.join("my_bigball.new.dat.br")).expect("renamed"),
        b"a"
    );
    assert!(!root.join("my_bigball.00011011.new.dat.br").exists());
    assert_eq!(
        fs::read(root.join("system.new.dat")).expect("unchanged"),
        b"b"
    );
}

#[test]
fn dat_chunks_are_concatenated_in_numeric_order() {
    let root = temp_dir::temp_dir();
    fs::write(root.join("system.new.dat.0"), b"zero").expect("chunk 0 written");
    fs::write(root.join("system.new.dat.1"), b"one").expect("chunk 1 written");
    fs::write(root.join("system.new.dat.2"), b"two").expect("chunk 2 written");

    assert!(consolidate_dat_chunks(&root, "system").expect("chunks consolidated"));
    assert_eq!(
        fs::read(root.join("system.new.dat")).expect("merged dat"),
        b"zeroonetwo"
    );
    assert!(!root.join("system.new.dat.1").exists());
    assert!(!root.join("system.new.dat.2").exists());
    assert!(!consolidate_dat_chunks(&root, "system").expect("no chunks left"));
}

#[test]
fn fs_backend_order_is_deterministic() {
    assert_eq!(
        FS_BACKEND_ORDER,
        &[
            FsBackend::Erofs,
            FsBackend::Ext4,
            FsBackend::Squashfs,
            FsBackend::Mtk,
            FsBackend::SevenZInProcess,
            FsBackend::SevenZCli,
        ]
    );
}

#[test]
fn modem_image_is_kept_raw() {
    let cases: &[(&str, bool)] = &[
        ("modem", false),
        ("MODEM", false),
        ("system", true),
        ("vendor", true),
    ];
    for (partition, expected) in cases {
        assert_eq!(
            should_extract_filesystem(partition),
            *expected,
            "case: {partition}"
        );
    }
}

/// Differential check against dumper.sh's EXT4 offset shell pipeline.
#[test]
#[ignore = "requires the DumprX dumper.sh ext4 offset shell commands"]
fn ext4_offset_matches_dumperx_shell() {
    let root = temp_dir::temp_dir();
    let image_path = root.join("vendor.img");
    let image = image_with_superblock(b"MOTO", 128_055);
    fs::write(&image_path, &image).expect("image written");

    let script = r#"
img="$1"
MAGIC=$(head -c12 "$img" | tr -d '\0')
offset=$(LANG=C grep -aob $'\x53\xef' "$img" | head -1 | gawk '{print $1 - 1080}')
if [[ "$MAGIC" == *"MOTO"* ]]; then
  [[ "$offset" == 128055 ]] && offset=131072
elif [[ "$MAGIC" == *"ASUS"* ]]; then
  :
else
  offset=0
fi
printf '%s' "$offset"
"#;
    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg("bash")
        .arg(&image_path)
        .output()
        .expect("shell invoked");
    assert!(output.status.success(), "shell failed");
    let expected: usize = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("shell offset parsed");
    assert_eq!(ext4_header_offset(&image), expected);
}

/// Differential check against dumper.sh's Perl rename expression.
#[test]
#[ignore = "requires Perl and dumper.sh's rename expression"]
fn nv_id_rename_matches_dumperx_perl() {
    let root = temp_dir::temp_dir();
    let name = "my_bigball.00011011.new.dat.br";
    let path = root.join(name);
    fs::write(&path, b"x").expect("file written");

    // The local `rename` is the util-linux variant, not DumprX's Perl
    // `rename`; apply the identical substitution expression with Perl and
    // compare the resulting name directly.
    let output = std::process::Command::new("perl")
        .arg("-e")
        .arg(r"$f=shift; $f =~ s/(\w+)\.(\d+)\.(\w+)/$1.$3/; print $f")
        .arg(name)
        .output()
        .expect("perl invoked");
    assert!(output.status.success(), "perl failed");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        strip_oplus_nv_id(name)
    );
    assert!(
        path.is_file(),
        "original file must remain untouched in this check"
    );
}
