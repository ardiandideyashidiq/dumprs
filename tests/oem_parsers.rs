//! Golden tests for the pure-Rust OEM container parsers.
//!
//! Every fixture is assembled by hand from the on-disk format, never by
//! calling the parser under test. See AGENTS.md for the `#[path]` helper rule.

#[path = "common/temp_dir.rs"]
mod temp_dir;

use dumprs::formats::oem::amlogic::extract_amlogic;
use dumprs::formats::oem::nb0::extract_nb0;
use dumprs::formats::oem::pac::extract_pac;
use dumprs::formats::oem::qfil::extract_qfil;
use dumprs::formats::oem::update_app::extract_update_app;
use dumprs::steps::oem::prepare_oem_containers;
use std::fs;
use std::path::Path;

/// One `UPDATE.APP` entry. Layout is taken from DumprX's `splituapp.py`:
/// magic, header size, 16 skipped bytes, file size, 32 skipped bytes, 16-byte
/// name, 22 skipped bytes, CRC bytes, then the image payload.
fn app_entry(name: &str, data: &[u8]) -> Vec<u8> {
    const HEADER_SIZE: u32 = 98 + 4;
    let mut entry = Vec::new();
    entry.extend_from_slice(&[0x55, 0xAA, 0x5A, 0xA5]);
    entry.extend_from_slice(&HEADER_SIZE.to_le_bytes());
    entry.extend_from_slice(&[0u8; 16]);
    entry.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    entry.extend_from_slice(&[0u8; 32]);
    let mut filename = [0u8; 16];
    filename[..name.len()].copy_from_slice(name.as_bytes());
    entry.extend_from_slice(&filename);
    entry.extend_from_slice(&[0u8; 22]);
    entry.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    entry.extend_from_slice(data);
    while entry.len() % 4 != 0 {
        entry.push(0);
    }
    entry
}

fn app_data(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i % 251) as u8))
        .collect()
}

/// Regression: UPDATE.APP entries must be split into one `.img` per header,
/// with the payload starting at `header_size` (not at a guessed offset).
#[test]
fn extracts_huawei_update_app_entries() {
    let root = temp_dir::temp_dir();
    let app_path = root.join("UPDATE.APP");
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");

    let system = app_data(1, 8192);
    let boot = app_data(2, 4096);
    let mut app = app_entry("system", &system);
    app.extend_from_slice(&app_entry("boot", &boot));
    fs::write(&app_path, app).expect("UPDATE.APP written");

    extract_update_app(&app_path, &out).expect("UPDATE.APP extracted");

    assert_eq!(
        fs::read(out.join("system.img")).expect("system.img"),
        system
    );
    assert_eq!(fs::read(out.join("boot.img")).expect("boot.img"), boot);
}

/// Regression: a malformed header must be reported instead of silently
/// producing a truncated image or panicking on a slice.
#[test]
fn rejects_truncated_update_app_header() {
    let root = temp_dir::temp_dir();
    let app_path = root.join("UPDATE.APP");
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");
    fs::write(&app_path, [0x55, 0xAA, 0x5A, 0xA5, 8, 0, 0, 0]).expect("fixture written");

    assert!(
        extract_update_app(&app_path, &out).is_err(),
        "a header shorter than 98 bytes must be rejected"
    );
}

/// Regression: entry names containing non-printable bytes must still yield a
/// usable filename, matching `splituapp.py`'s printable-character filter.
#[test]
fn sanitizes_update_app_entry_names() {
    let root = temp_dir::temp_dir();
    let app_path = root.join("UPDATE.APP");
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");

    let mut entry = app_entry("vendor", &app_data(3, 1024));
    // Put a non-printable byte in the padding after the 6-byte name; it must
    // be dropped rather than becoming part of the output filename.
    entry[60 + 6] = 0xFF;
    fs::write(&app_path, entry).expect("fixture written");

    extract_update_app(&app_path, &out).expect("UPDATE.APP extracted");

    assert!(
        Path::new(&out).join("vendor.img").is_file(),
        "non-printable bytes must be dropped from the name"
    );
}

/// Regression: the pipeline must route a detected OEM container to its
/// handler instead of leaving it for the generic raw-image pass.
#[test]
fn prepare_oem_containers_extracts_update_app() {
    let root = temp_dir::temp_dir();
    let extracted = root.join("extracted");
    let raw = root.join("raw");
    fs::create_dir_all(&extracted).expect("extracted dir created");
    fs::create_dir_all(&raw).expect("raw dir created");

    let system = app_data(4, 2048);
    fs::write(extracted.join("UPDATE.APP"), app_entry("system", &system))
        .expect("UPDATE.APP written");

    prepare_oem_containers(&extracted, &raw).expect("OEM containers prepared");

    assert_eq!(
        fs::read(raw.join("system.img")).expect("system.img"),
        system
    );
}

/// Regression: a QFIL rawprogram set found in the extracted archive must be
/// assembled for every partition it describes, not just one.
#[test]
fn prepare_oem_containers_assembles_qfil_partitions() {
    let root = temp_dir::temp_dir();
    let extracted = root.join("extracted");
    let raw = root.join("raw");
    fs::create_dir_all(&extracted).expect("extracted dir created");
    fs::create_dir_all(&raw).expect("raw dir created");

    fs::write(extracted.join("a_sparse.img"), vec![b'A'; 4096]).expect("system chunk written");
    fs::write(extracted.join("c_sparse.img"), vec![b'C'; 4096]).expect("vendor chunk written");
    let xml = r#"<?xml version="1.0"?>
<data>
 <program SECTOR_SIZE_IN_BYTES="512" file_sector_offset="0" filename="a_sparse.img"
          label="system" num_partition_sectors="8" physical_partition_number="0"
          sparse="true" start_sector="0"/>
 <program SECTOR_SIZE_IN_BYTES="512" file_sector_offset="0" filename="c_sparse.img"
          label="vendor" num_partition_sectors="8" physical_partition_number="0"
          sparse="true" start_sector="0"/>
</data>
"#;
    fs::write(extracted.join("rawprogram_unsparse0.xml"), xml).expect("xml written");

    prepare_oem_containers(&extracted, &raw).expect("QFIL assembled");

    assert_eq!(
        fs::read(raw.join("system.img")).expect("system.img"),
        vec![b'A'; 4096]
    );
    assert_eq!(
        fs::read(raw.join("vendor.img")).expect("vendor.img"),
        vec![b'C'; 4096]
    );
}

fn aml_record(offset: u64, size: u64, ext: &str, name: &str) -> Vec<u8> {
    let mut record = vec![0u8; 0x240];
    record[0x10..0x14].copy_from_slice(&(offset as u32).to_le_bytes());
    record[0x18..0x1c].copy_from_slice(&(size as u32).to_le_bytes());
    record[0x20..0x20 + ext.len()].copy_from_slice(ext.as_bytes());
    record[0x120..0x120 + name.len()].copy_from_slice(name.as_bytes());
    record
}

fn aml_image(header_records: &[u8], data: &[(u64, u8, usize)]) -> Vec<u8> {
    let mut image = vec![0u8; 0x40];
    image[0x18] = u8::try_from(header_records.len() / 0x240).unwrap();
    image.extend_from_slice(header_records);
    for &(offset, byte, len) in data {
        let end = (offset as usize).max(image.len()) + len;
        image.resize(end, 0);
        image[offset as usize..end].fill(byte);
    }
    image
}

/// Regression: AML records live at 0x40 + n*0x240, with name/extension at
/// +0x120/+0x20 and a little-endian data offset/size at +0x10/+0x18.
#[test]
fn extracts_amlogic_upgrade_package() {
    let root = temp_dir::temp_dir();
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");
    let records = [
        aml_record(0x1000, 4096, "img", "system"),
        aml_record(0x2000, 4096, "img", "boot"),
    ]
    .concat();
    let image = aml_image(&records, &[(0x1000, b'A', 4096), (0x2000, b'B', 4096)]);
    let path = root.join("aml_upgrade_package.img");
    fs::write(&path, image).expect("AML image written");

    extract_amlogic(&path, &out).expect("AML extracted");

    assert_eq!(
        fs::read(out.join("system.img")).expect("system"),
        vec![b'A'; 4096]
    );
    assert_eq!(
        fs::read(out.join("boot.img")).expect("boot"),
        vec![b'B'; 4096]
    );
}

/// Regression: DumprX renames AML `.PARTITION`/`_aml_dtb`/`_a` outputs into
/// canonical partition names; the Rust port must do the same.
#[test]
fn normalizes_amlogic_output_names() {
    let root = temp_dir::temp_dir();
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");
    let records = [
        aml_record(0x1000, 512, "PARTITION", "vendor"),
        aml_record(0x2000, 512, "img", "dtb_aml_dtb"),
        aml_record(0x3000, 512, "img", "recovery_a"),
    ]
    .concat();
    let image = aml_image(
        &records,
        &[
            (0x1000, b'V', 512),
            (0x2000, b'D', 512),
            (0x3000, b'R', 512),
        ],
    );
    let path = root.join("aml_upgrade_package.img");
    fs::write(&path, image).expect("AML image written");

    extract_amlogic(&path, &out).expect("AML extracted");

    assert!(out.join("vendor.img").is_file());
    assert!(out.join("dtb.img").is_file());
    assert!(out.join("recovery.img").is_file());
}

/// Regression: a standalone AML upgrade image must be routed to the AML
/// parser rather than the generic raw-image pass.
#[test]
fn prepare_oem_containers_extracts_amlogic() {
    let root = temp_dir::temp_dir();
    let extracted = root.join("extracted");
    let raw = root.join("raw");
    fs::create_dir_all(&extracted).expect("extracted dir created");
    fs::create_dir_all(&raw).expect("raw dir created");

    let records = aml_record(0x1000, 512, "img", "boot");
    fs::write(
        extracted.join("aml_upgrade_package.img"),
        aml_image(&records, &[(0x1000, b'B', 512)]),
    )
    .expect("AML image written");

    prepare_oem_containers(&extracted, &raw).expect("AML extracted");

    assert_eq!(
        fs::read(raw.join("boot.img")).expect("boot.img"),
        vec![b'B'; 512]
    );
}

fn nb0_header(offset: u32, size: u32, name: &str) -> Vec<u8> {
    let mut header = vec![0u8; 64];
    header[..4].copy_from_slice(&offset.to_le_bytes());
    header[4..8].copy_from_slice(&size.to_le_bytes());
    header[16..16 + name.len()].copy_from_slice(name.as_bytes());
    header
}

/// Regression: `.nb0` files store a count, 64-byte headers (offset, size,
/// name at +16), then the payloads back-to-back after 4 + 64*count.
#[test]
fn extracts_nb0_images() {
    let root = temp_dir::temp_dir();
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");
    let mut image = 2u32.to_le_bytes().to_vec();
    image.extend(nb0_header(0x1000, 4096, "system"));
    image.extend(nb0_header(0x2000, 2048, "boot"));
    image.extend(vec![b'A'; 4096]);
    image.extend(vec![b'B'; 2048]);
    let path = root.join("firmware.nb0");
    fs::write(&path, image).expect("nb0 written");

    extract_nb0(&path, &out).expect("nb0 extracted");

    assert_eq!(
        fs::read(out.join("system")).expect("system"),
        vec![b'A'; 4096]
    );
    assert_eq!(fs::read(out.join("boot")).expect("boot"), vec![b'B'; 2048]);
}

/// Regression: a payload shorter than the declared size must be reported
/// instead of silently producing a truncated partition.
#[test]
fn rejects_truncated_nb0_payload() {
    let root = temp_dir::temp_dir();
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");
    let mut image = 1u32.to_le_bytes().to_vec();
    image.extend(nb0_header(0, 4096, "system"));
    image.extend(vec![b'A'; 16]);
    let path = root.join("firmware.nb0");
    fs::write(&path, image).expect("nb0 written");

    assert!(extract_nb0(&path, &out).is_err());
}

/// Regression: a standalone `.nb0` must be routed to its parser before the
/// generic firmware pass sees it as an unknown image.
#[test]
fn prepare_oem_containers_extracts_nb0() {
    let root = temp_dir::temp_dir();
    let extracted = root.join("extracted");
    let raw = root.join("raw");
    fs::create_dir_all(&extracted).expect("extracted dir created");
    fs::create_dir_all(&raw).expect("raw dir created");

    let mut image = 1u32.to_le_bytes().to_vec();
    image.extend(nb0_header(0, 512, "system"));
    image.extend(vec![b'S'; 512]);
    fs::write(extracted.join("firmware.nb0"), image).expect("nb0 written");

    prepare_oem_containers(&extracted, &raw).expect("nb0 extracted");

    assert_eq!(
        fs::read(raw.join("system")).expect("system"),
        vec![b'S'; 512]
    );
}

fn utf16_field(target: &mut [u8], value: &str) {
    for (i, unit) in value.encode_utf16().enumerate() {
        target[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
}

fn pac_file(entries: &[(&str, u64)], payloads: &[&[u8]]) -> Vec<u8> {
    const PAC_HEADER_SIZE: usize = 2124;
    const FILE_HEADER_SIZE: usize = 2580;
    let data_start = PAC_HEADER_SIZE + entries.len() * FILE_HEADER_SIZE;

    let mut image = vec![0u8; data_start];
    utf16_field(&mut image[0..44], "BP_R1.0.0");
    let mut cursor = data_start;
    for &(_, size) in entries {
        cursor += size as usize;
    }
    image[44..48].copy_from_slice(&0u32.to_le_bytes());
    image[48..52].copy_from_slice(&(cursor as u32).to_le_bytes());
    image[1076..1080].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    image[1080..1084].copy_from_slice(&(PAC_HEADER_SIZE as u32).to_le_bytes());
    image[2116..2120].copy_from_slice(&0xfffafffau32.to_le_bytes());

    for (index, &(name, size)) in entries.iter().enumerate() {
        let base = PAC_HEADER_SIZE + index * FILE_HEADER_SIZE;
        image[base..base + 4].copy_from_slice(&(FILE_HEADER_SIZE as u32).to_le_bytes());
        utf16_field(&mut image[base + 516..base + 1028], name);
        image[base + 1540..base + 1544].copy_from_slice(&(size as u32).to_le_bytes());
        let offset = entries[..index]
            .iter()
            .fold(data_start, |acc, &(_, previous)| acc + previous as usize);
        image[base + 1552..base + 1556].copy_from_slice(&(offset as u32).to_le_bytes());
    }
    for payload in payloads {
        image.extend_from_slice(payload);
    }
    image
}

/// Regression: PAC entries are located via `partitionsListStart` and each
/// payload via its own data offset; the size must come from `loPartitionSize`.
#[test]
fn extracts_pac_partitions() {
    let root = temp_dir::temp_dir();
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");
    let system = vec![b'A'; 4096];
    let boot = vec![b'B'; 2048];
    let image = pac_file(
        &[("system.img", 4096), ("boot.img", 2048)],
        &[&system, &boot],
    );
    let path = root.join("firmware.pac");
    fs::write(&path, image).expect("pac written");

    extract_pac(&path, &out).expect("pac extracted");

    assert_eq!(fs::read(out.join("system.img")).expect("system"), system);
    assert_eq!(fs::read(out.join("boot.img")).expect("boot"), boot);
}

/// Regression: an unsupported PAC version must be rejected rather than
/// interpreting its headers with the wrong layout.
#[test]
fn rejects_unknown_pac_version() {
    let root = temp_dir::temp_dir();
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");
    let mut image = pac_file(&[("system.img", 16)], &[&[b'A'; 16]]);
    image[0..18].fill(0);
    utf16_field(&mut image[0..44], "BP_R9.9.9");
    let path = root.join("firmware.pac");
    fs::write(&path, image).expect("pac written");

    assert!(extract_pac(&path, &out).is_err());
}

/// Regression: a standalone `.pac` must be routed to the PAC parser instead
/// of being left as an unrecognized firmware file.
#[test]
fn prepare_oem_containers_extracts_pac() {
    let root = temp_dir::temp_dir();
    let extracted = root.join("extracted");
    let raw = root.join("raw");
    fs::create_dir_all(&extracted).expect("extracted dir created");
    fs::create_dir_all(&raw).expect("raw dir created");
    let image = pac_file(&[("system.img", 512)], &[&[b'P'; 512]]);
    fs::write(extracted.join("firmware.pac"), image).expect("pac written");

    prepare_oem_containers(&extracted, &raw).expect("pac extracted");

    assert_eq!(
        fs::read(raw.join("system.img")).expect("system.img"),
        vec![b'P'; 512]
    );
}

/// Side-by-side differential check against the tool this port replaces.
///
/// Ignored by default because it needs `python3` and the DumprX checkout.
/// Run with `cargo test --test oem_parsers -- --ignored --nocapture`.
#[test]
#[ignore = "requires python3 and the DumprX splituapp.py reference tool"]
fn matches_splituapp_python_oracle() {
    let reference = Path::new("/home/rd/Projects/android/dumpyara/DumprX/utils/splituapp.py");
    if !reference.is_file()
        || std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_err()
    {
        println!("check did not run: splituapp.py or python3 is missing");
        return;
    }

    let root = temp_dir::temp_dir();
    // Normalization, with reason: the checked-in reference mixes tabs and
    // spaces and raises TabError on modern Python. Replacing tabs with spaces
    // changes indentation width only, never the parsing logic being compared.
    let script = root.join("splituapp_fixed.py");
    let source = fs::read_to_string(reference).expect("reference script readable");
    fs::write(&script, source.replace('\t', "    ")).expect("normalized script written");
    let app_path = root.join("UPDATE.APP");
    let rust_out = root.join("rust");
    let python_root = root.join("python");
    fs::create_dir_all(&rust_out).expect("rust output dir created");
    fs::create_dir_all(&python_root).expect("python work dir created");

    let system = app_data(7, 8192);
    let boot = app_data(8, 4096);
    let mut app = app_entry("system", &system);
    app.extend_from_slice(&app_entry("boot", &boot));
    fs::write(&app_path, app).expect("fixture written");

    extract_update_app(&app_path, &rust_out).expect("rust extraction succeeded");

    let status = std::process::Command::new("python3")
        .arg(script)
        .arg("-f")
        .arg(&app_path)
        .current_dir(&python_root)
        .output()
        .expect("reference tool invoked");
    assert!(status.status.success(), "splituapp.py failed");

    for name in ["system", "boot"] {
        let python_img = python_root.join("output").join(format!("{name}.img"));
        assert_eq!(
            fs::read(rust_out.join(format!("{name}.img"))).expect("rust image readable"),
            fs::read(&python_img).expect("python oracle image readable"),
            "port differs from splituapp.py on {name}"
        );
    }
}

const QFIL_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<data>
  <program SECTOR_SIZE_IN_BYTES="512" file_sector_offset="0" filename="a_sparse.img"
           label="system" num_partition_sectors="16" physical_partition_number="0"
           size_in_KB="8.0" sparse="true" start_sector="0"/>
  <program SECTOR_SIZE_IN_BYTES="512" file_sector_offset="0" filename="b_sparse.img"
           label="system" num_partition_sectors="16" physical_partition_number="0"
           size_in_KB="8.0" sparse="true" start_sector="16"/>
  <program SECTOR_SIZE_IN_BYTES="512" file_sector_offset="0" filename="other_sparse.img"
           label="vendor" num_partition_sectors="16" physical_partition_number="0"
           size_in_KB="8.0" sparse="true" start_sector="0"/>
</data>
"#;

/// Regression: QFIL entries must be assembled at `start_sector *
/// SECTOR_SIZE_IN_BYTES`, and entries for other partitions must be ignored.
#[test]
fn extracts_qfil_rawprogram_entries() {
    let root = temp_dir::temp_dir();
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");
    fs::write(root.join("a_sparse.img"), vec![b'A'; 8192]).expect("first chunk written");
    fs::write(root.join("b_sparse.img"), vec![b'B'; 8192]).expect("second chunk written");
    let xml = root.join("rawprogram_unsparse0.xml");
    fs::write(&xml, QFIL_XML).expect("xml written");

    extract_qfil(&xml, "system", &out).expect("QFIL assembled");

    let image = fs::read(out.join("system.img")).expect("system.img written");
    let mut expected = vec![b'A'; 8192];
    expected.extend(vec![b'B'; 8192]);
    assert_eq!(image, expected);
    assert!(!out.join("vendor.img").exists(), "other partitions ignored");
}

/// Regression: a missing source chunk must fail loudly instead of leaving
/// zero-filled holes in the assembled image.
#[test]
fn rejects_missing_qfil_source_chunk() {
    let root = temp_dir::temp_dir();
    let out = root.join("out");
    fs::create_dir_all(&out).expect("output dir created");
    let xml = root.join("rawprogram_unsparse0.xml");
    fs::write(&xml, QFIL_XML).expect("xml written");

    assert!(
        extract_qfil(&xml, "system", &out).is_err(),
        "missing chunk files must be reported"
    );
}
