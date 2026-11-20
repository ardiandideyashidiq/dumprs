//! Unit tests for dump-level metadata decisions mirrored from DumprX.

#[path = "common/temp_dir.rs"]
mod temp_dir;

use dumprs::utils::dump_metadata::{
    TwrpSource, auxiliary_target, board_info_lines, generate_twrp_tree, identify_super_chunk,
    super_chunk_index, twrp_source_image, write_all_files_list, write_board_info,
};
use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn all_files_manifest_is_sorted_and_contains_itself() {
    let root = temp_dir::temp_dir();
    let mut files = vec![
        PathBuf::from("vendor/build.prop"),
        PathBuf::from("all_files.txt"),
        PathBuf::from("system/build.prop"),
    ];
    write_all_files_list(&root, &mut files).expect("manifest written");

    let content = fs::read_to_string(root.join("all_files.txt")).expect("manifest readable");
    assert_eq!(
        content, "all_files.txt\nsystem/build.prop\nvendor/build.prop\n",
        "manifest must be sorted and contain its own name as a line"
    );
    assert_eq!(files[0], PathBuf::from("all_files.txt"));
}

#[test]
fn board_info_lines_are_sorted_unique_and_prefixed() {
    let cases: Vec<(&str, &str, &str, &[&str])> = vec![
        (
            "QC_IMAGE_VERSION_STRING=MPSS.ABCDEF1234",
            "QC_IMAGE_VERSION_STRING=TZ.XYZ",
            "ro.vendor.build.date.utc=1234567890",
            &[
                "require version-baseband=DEF1234",
                "require version-trustzone=TZ.XYZ",
                "require version-vendor=1234567890",
            ],
        ),
        ("unrelated text", "unrelated", "unrelated", &[]),
        (
            "QC_IMAGE_VERSION_STRING=MPSS.ABCDEF1234",
            "QC_IMAGE_VERSION_STRING=TZ.XYZ",
            "unrelated",
            &[
                "require version-baseband=DEF1234",
                "require version-trustzone=TZ.XYZ",
            ],
        ),
    ];
    for (index, (modem, tz, vendor, expected)) in cases.iter().enumerate() {
        let lines = board_info_lines(modem.as_bytes(), tz.as_bytes(), vendor.as_bytes());
        let expected: Vec<String> = expected.iter().map(|line| (*line).to_string()).collect();
        assert_eq!(lines, expected, "case {index}: modem={modem:?}");
    }
}

#[test]
fn board_info_deduplicates_lines() {
    let modem = b"QC_IMAGE_VERSION_STRING=MPSS.ABCDEF1234\0QC_IMAGE_VERSION_STRING=MPSS.ABCDEF1234";
    let lines = board_info_lines(modem, b"", b"");
    assert_eq!(lines, vec!["require version-baseband=DEF1234"]);
}

#[test]
fn board_info_file_is_written_at_dump_root() {
    let root = temp_dir::temp_dir();
    let lines = vec![
        "require version-baseband=DEF1234".to_string(),
        "require version-trustzone=TZ.XYZ".to_string(),
    ];
    write_board_info(&root, &lines).expect("board-info written");
    assert_eq!(
        fs::read_to_string(root.join("board-info.txt")).expect("file readable"),
        "require version-baseband=DEF1234\nrequire version-trustzone=TZ.XYZ\n"
    );
}

#[test]
fn auxiliary_files_are_preserved_in_canonical_locations() {
    let cases: Vec<(&str, Option<&str>)> = vec![
        ("MTK_Android_scatter.txt", Some("MTK_Android_scatter.txt")),
        ("Android_scatter.xml", Some("Android_scatter.xml")),
        ("DA_BR.bin", Some("download_agent/DA_BR.bin")),
        ("da_br.BIN", Some("download_agent/DA_BR.bin")),
        ("vendor_Release_Note.txt", Some("vendor_Release_Note.txt")),
        (
            "vendor/euclid/product/etc/build.prop",
            Some("vendor/euclid/product/etc/build.prop"),
        ),
        ("system.img", None),
        ("preloader.bin", None),
    ];
    for (input, expected) in cases {
        let actual = auxiliary_target(Path::new(input)).map(|path| path.to_string());
        assert_eq!(actual.as_deref(), expected, "case: {input}");
    }
}

#[test]
fn generate_board_info_reads_dump_files() {
    let root = temp_dir::temp_dir();
    fs::create_dir_all(root.join("vendor")).expect("vendor dir created");
    fs::write(
        root.join("modem.img"),
        b"\0QC_IMAGE_VERSION_STRING=MPSS.ABCDEF1234\0",
    )
    .expect("modem written");
    fs::write(root.join("tz_a.img"), b"\0QC_IMAGE_VERSION_STRING=TZ.XYZ\0").expect("tz written");
    fs::write(
        root.join("vendor/build.prop"),
        b"\0ro.vendor.build.date.utc=1234567890\0",
    )
    .expect("prop written");

    dumprs::utils::dump_metadata::generate_board_info(&root).expect("board-info generated");

    let content = fs::read_to_string(root.join("board-info.txt")).expect("file readable");
    assert_eq!(
        content.lines().collect::<Vec<_>>(),
        vec![
            "require version-baseband=DEF1234",
            "require version-trustzone=TZ.XYZ",
            "require version-vendor=1234567890",
        ]
    );
}

#[test]
fn auxiliary_files_are_copied_to_canonical_locations() {
    let root = temp_dir::temp_dir();
    let extracted = root.join("extracted");
    let output = root.join("out");
    fs::create_dir_all(extracted.join("sub")).expect("dir created");
    fs::create_dir_all(&output).expect("dir created");
    fs::write(extracted.join("MTK_Android_scatter.txt"), "scatter").expect("scatter written");
    fs::write(extracted.join("sub/DA_BR.bin"), "da").expect("da written");
    fs::write(extracted.join("Release_Note.txt"), "note").expect("note written");
    fs::write(extracted.join("system.img"), "image").expect("image written");

    dumprs::utils::dump_metadata::preserve_auxiliary_files(&extracted, &output)
        .expect("auxiliary files preserved");

    assert_eq!(
        fs::read_to_string(output.join("MTK_Android_scatter.txt")).expect("scatter"),
        "scatter"
    );
    assert_eq!(
        fs::read_to_string(output.join("download_agent/DA_BR.bin")).expect("da"),
        "da"
    );
    assert_eq!(
        fs::read_to_string(output.join("Release_Note.txt")).expect("note"),
        "note"
    );
    assert!(!output.join("system.img").exists());
}

#[test]
fn twrp_source_image_selection() {
    let cases = [
        (true, true, true, Some(TwrpSource::Recovery)),
        (true, false, true, Some(TwrpSource::VendorBoot)),
        (true, false, false, None),
        (false, true, false, Some(TwrpSource::Recovery)),
        (false, false, true, None),
    ];
    for (is_ab, has_recovery, has_vendor_boot, expected) in cases {
        assert_eq!(
            twrp_source_image(is_ab, has_recovery, has_vendor_boot),
            expected,
            "case: ab={is_ab} recovery={has_recovery} vendor_boot={has_vendor_boot}"
        );
    }
}

#[test]
fn twrp_generator_falls_back_to_vendor_boot() {
    let calls = RefCell::new(Vec::new());
    let mut generator = |image: &str| -> anyhow::Result<()> {
        calls.borrow_mut().push(image.to_string());
        if image == "recovery.img" {
            Err(anyhow::anyhow!("generator failed"))
        } else {
            Ok(())
        }
    };
    generate_twrp_tree(Some(TwrpSource::Recovery), true, &mut generator)
        .expect("fallback succeeded");
    assert_eq!(
        calls.borrow().as_slice(),
        ["recovery.img", "vendor_boot.img"]
    );
}

#[test]
fn twrp_generator_without_fallback_propagates_error() {
    let mut generator =
        |_image: &str| -> anyhow::Result<()> { Err(anyhow::anyhow!("generator failed")) };
    let result = generate_twrp_tree(Some(TwrpSource::Recovery), false, &mut generator);
    assert!(result.is_err());
}

#[test]
fn super_chunk_index_range() {
    let cases = [
        ("super_2.img", Some(2)),
        ("super_17.img", Some(17)),
        ("super_1.img", None),
        ("super_18.img", None),
        ("super.img", None),
        ("system.img", None),
    ];
    for (name, expected) in cases {
        assert_eq!(super_chunk_index(name), expected, "case: {name}");
    }
}

fn write_chunk(root: &Path, files: &[(&str, &str)]) {
    for (path, content) in files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("dir created");
        }
        fs::write(full, content).expect("file written");
    }
}

#[test]
fn super_chunk_identification() {
    let cases: Vec<(&[(&str, &str)], &str)> = vec![
        (
            &[("lib/modules/5.10/android/kernel.ko", "x")],
            "system_dlkm",
        ),
        (
            &[("build.prop", "ro.product.tr_manifest=1\n")],
            "tr_manifest",
        ),
        (
            &[
                ("build.prop", "brand=generic\nro.product.product=vendor_x\n"),
                ("misc.txt", "x"),
            ],
            "product=vendor_x",
        ),
        (
            &[
                ("system/build.prop", "ro.product.system=system_x\n"),
                ("root.txt", "x"),
            ],
            "system=system_x",
        ),
        (&[("something.txt", "hello")], "unknown"),
    ];
    for (index, (files, expected)) in cases.iter().enumerate() {
        let root = temp_dir::temp_dir();
        write_chunk(&root, files);
        assert_eq!(
            identify_super_chunk(&root).expect("identified"),
            *expected,
            "case {index}"
        );
    }
}

#[test]
fn super_chunk_duplicate_names_are_disambiguated_by_caller() {
    // The identifier itself is pure; duplicate suffixing is a separate
    // pipeline decision. This test pins that it does not mutate names.
    let root = temp_dir::temp_dir();
    write_chunk(
        &root,
        &[
            ("build.prop", "ro.product.product=vendor_x\n"),
            ("root.txt", "x"),
        ],
    );
    assert_eq!(
        identify_super_chunk(&root).expect("identified"),
        "product=vendor_x"
    );
}

/// Characterization: dumprs writes boot artifacts inside the partition
/// directory, whereas DumprX uses separate `bootimg/`, `bootdts/`,
/// `vendor_bootimg/`, `vendor_bootRE/`, `dtbo/`, `dtbodts/` directories.
#[test]
fn boot_artifacts_are_written_inside_partition_dir() {
    let root = temp_dir::temp_dir();
    let image = root.join("boot.img");
    let mut data = vec![0u8; 256];
    data[..4].copy_from_slice(b"AVB0");
    fs::write(&image, data).expect("image written");
    let out = root.join("boot");

    dumprs::formats::boot_artifacts::generate(&image, &out, "boot").expect("artifacts generated");

    assert!(
        out.join("avb.txt").is_file(),
        "artifact must be in partition dir"
    );
    assert!(
        !root.join("avb.txt").exists(),
        "artifact must not leak to dump root"
    );
}

/// Differential check against DumprX's board-info.txt shell pipeline.
#[test]
#[ignore = "requires the DumprX dumper.sh string pipeline"]
fn board_info_matches_dumperx_shell_pipeline() {
    let root = temp_dir::temp_dir();
    let modem = root.join("modem.img");
    let tz = root.join("tz.img");
    let vendor = root.join("vendor");
    fs::create_dir_all(&vendor).expect("vendor dir created");
    fs::write(&modem, b"\0QC_IMAGE_VERSION_STRING=MPSS.ABCDEF1234\0").expect("modem written");
    fs::write(&tz, b"\0QC_IMAGE_VERSION_STRING=TZ.XYZ\0").expect("tz written");
    fs::write(
        vendor.join("build.prop"),
        b"\0ro.vendor.build.date.utc=1234567890\0",
    )
    .expect("prop written");

    let expected: Vec<String> = board_info_lines(
        &fs::read(&modem).expect("modem readable"),
        &fs::read(&tz).expect("tz readable"),
        &fs::read(vendor.join("build.prop")).expect("prop readable"),
    );

    let script = r#"
set -e
strings "$1" | grep "QC_IMAGE_VERSION_STRING=MPSS." | sed "s|QC_IMAGE_VERSION_STRING=MPSS.||g" | cut -c 4- | sed "s|^|require version-baseband=|" > "$4"
strings "$2" | grep "QC_IMAGE_VERSION_STRING" | sed "s|QC_IMAGE_VERSION_STRING|require version-trustzone|g" >> "$4"
strings "$3" | grep "ro.vendor.build.date.utc" | sed "s|ro.vendor.build.date.utc|require version-vendor|g" >> "$4"
sort -u < "$4" > "$5"
"#;
    let shell_out = root.join("shell.txt");
    let status = std::process::Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg("bash")
        .arg(&modem)
        .arg(&tz)
        .arg(vendor.join("build.prop"))
        .arg(root.join("raw.txt"))
        .arg(&shell_out)
        .output()
        .expect("shell pipeline invoked");
    assert!(status.status.success(), "shell pipeline failed");
    let actual: Vec<String> = fs::read_to_string(&shell_out)
        .expect("shell output readable")
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(actual, expected);
}
