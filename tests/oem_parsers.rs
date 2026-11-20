//! Golden tests for the pure-Rust OEM container parsers.
//!
//! Every fixture is assembled by hand from the on-disk format, never by
//! calling the parser under test. See AGENTS.md for the `#[path]` helper rule.

#[path = "common/temp_dir.rs"]
mod temp_dir;

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
