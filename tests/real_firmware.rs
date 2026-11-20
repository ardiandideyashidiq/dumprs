#[path = "common/temp_dir.rs"]
mod temp_dir;

// Validation against the real firmware corpus and the DumprX tool that this
// code replaces. These tests are `#[ignore]`d because the corpus and the
// source tool are not part of the repository.

use dumprs::formats::boot_artifacts::avb::render_avb_info;
use dumprs::formats::boot_artifacts::dtb::{dtb_to_dts, split_dtb};
use dumprs::formats::boot_artifacts::generate;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CORPUS: &str = "/home/rd/Projects/android/dumpyara/test";
const AVBTOOL: &str = "/home/rd/Projects/android/dumpyara/DumprX/utils/avbtool.py";

fn corpus() -> &'static Path {
    Path::new(CORPUS)
}

fn normalize(text: &str) -> String {
    // The contract is the text, not the platform that rendered it.
    text.replace("\r\n", "\n")
}

fn avbtool_output(image: &Path) -> Option<String> {
    if !Path::new(AVBTOOL).is_file() {
        return None;
    }
    let output = Command::new("python3")
        .arg(AVBTOOL)
        .arg("info_image")
        .arg("--image")
        .arg(image)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[test]
#[ignore = "requires the firmware corpus in /home/rd/Projects/android/dumpyara/test"]
fn phase_one_artifacts_from_real_firmware() {
    let work = temp_dir::temp_dir();
    let dump = corpus().join("Infinix-Note-12-X670-13-11");

    for name in ["boot.img", "vendor_boot.img", "dtbo.img", "vbmeta.img"] {
        let direct = corpus().join(name);
        let image = if direct.is_file() {
            direct
        } else {
            dump.join(name)
        };
        if !image.is_file() {
            println!("{name}: not present, skipped");
            continue;
        }
        let local_image = work.join(name);
        fs::copy(&image, &local_image).expect("copy image");
        let out = work.join(format!("{name}.out"));
        fs::create_dir_all(&out).expect("output dir");

        // The real dumprs pipeline extracts these before calling generate.
        if name == "boot.img" && dump.join("boot/kernel").is_file() {
            fs::copy(dump.join("boot/kernel"), out.join("kernel")).expect("copy kernel");
        }

        if name == "dtbo.img" {
            let data = fs::read(&local_image).expect("read dtbo");
            for (index, blob) in split_dtb(&data).expect("split dtbo").iter().enumerate() {
                match dtb_to_dts(blob) {
                    Ok(_) => println!("dtbo[{index}]: DTS ok"),
                    Err(error) => println!("dtbo[{index}]: DTS failed: {error:?}"),
                }
            }
        }

        generate(&local_image, &out, name.trim_end_matches(".img"))
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));

        let size = |name: &str| fs::metadata(out.join(name)).map(|m| m.len()).unwrap_or(0);
        let kallsyms = size("kernel_kallsyms.txt").max(size("boot_kallsyms.txt"));
        println!(
            "{name}: avb={} bytes, ikconfig={} bytes, kallsyms={} bytes, elf={} bytes, dtb={} files, dts={} files",
            size("avb.txt"),
            size("ikconfig"),
            kallsyms,
            size("boot.elf"),
            fs::read_dir(out.join("dtb"))
                .map(|d| d.count())
                .unwrap_or(0),
            fs::read_dir(out.join("dts"))
                .map(|d| d.count())
                .unwrap_or(0),
        );
    }
}

#[test]
#[ignore = "requires the firmware corpus and DumprX avbtool.py"]
fn avb_output_matches_dumprx_oracle() {
    let mut not_run: Vec<String> = Vec::new();
    let mut images: Vec<PathBuf> = Vec::new();
    for name in [
        "boot.img",
        "vbmeta.img",
        "vbmeta_system.img",
        "vbmeta_vendor.img",
    ] {
        let path = corpus().join(name);
        if path.is_file() {
            images.push(path);
        }
    }
    let dump = corpus().join("Infinix-Note-12-X670-13-11");
    for name in ["vbmeta.img", "vbmeta_system.img", "vbmeta_vendor.img"] {
        let path = dump.join(name);
        if path.is_file() {
            images.push(path);
        }
    }

    for image in images {
        let name = image.file_name().unwrap().to_string_lossy().into_owned();
        let data = fs::read(&image).expect("read image");
        let rust = render_avb_info(&data, data.len() as u64)
            .unwrap_or_else(|error| panic!("{name}: rust parser failed: {error:?}"));
        match avbtool_output(&image) {
            Some(source) => {
                assert_eq!(
                    normalize(&rust),
                    normalize(&source),
                    "AVB info differs for {name}"
                );
            }
            None => not_run.push(format!("{name}: avbtool.py unavailable or failed")),
        }
    }
    for message in not_run {
        println!("check did not run: {message}");
    }
}

#[test]
#[ignore = "requires the firmware corpus and vmlinux-to-elf kallsyms-finder"]
fn kallsyms_matches_dumprx_oracle() {
    use dumprs::formats::boot_artifacts::kallsyms::{
        decompress_kernel, find_kallsyms, render_kallsyms,
    };

    let kernel_path = corpus()
        .join("Infinix-Note-12-X670-13-11")
        .join("boot/kernel");
    if !kernel_path.is_file() {
        println!("check did not run: kernel fixture missing");
        return;
    }
    let kernel = fs::read(&kernel_path).expect("read kernel");
    let kernel = decompress_kernel(&kernel);
    let symbols =
        find_kallsyms(&kernel).unwrap_or_else(|error| panic!("kallsyms discovery: {error:?}"));
    let rust = render_kallsyms(&symbols);
    println!("recovered {} symbols", symbols.len());
    fs::write("/tmp/opencode/kallsyms_rust.txt", &rust).expect("write rust kallsyms");

    let oracle = Path::new("/tmp/opencode/kallsyms_oracle.txt");
    if oracle.is_file() {
        let source = fs::read_to_string(oracle).expect("read oracle");
        let mut rust_lines: Vec<&str> = rust.lines().collect();
        let mut source_lines: Vec<&str> = source.lines().collect();
        rust_lines.sort_unstable();
        source_lines.sort_unstable();
        assert_eq!(rust_lines, source_lines, "kallsyms differs from oracle");
    } else {
        println!("check did not run: oracle output missing");
    }
}

#[test]
#[ignore = "requires the extracted Scout 6.1 kernel and kallsyms-finder oracle in /tmp/opencode/scout"]
fn kallsyms_matches_scout_61_oracle() {
    use dumprs::formats::boot_artifacts::kallsyms::{
        decompress_kernel, find_kallsyms, render_kallsyms,
    };

    let kernel_path = Path::new("/tmp/opencode/scout/kernel");
    let oracle_path = Path::new("/tmp/opencode/scout/kallsyms_oracle.txt");
    if !kernel_path.is_file() || !oracle_path.is_file() {
        println!("check did not run: Scout kernel or oracle output missing");
        return;
    }
    let kernel = fs::read(kernel_path).expect("read Scout kernel");
    let kernel = decompress_kernel(&kernel);
    let symbols =
        find_kallsyms(&kernel).unwrap_or_else(|error| panic!("Scout kallsyms: {error:?}"));
    let rust = render_kallsyms(&symbols);
    println!("recovered {} Scout symbols", symbols.len());

    let source = fs::read_to_string(oracle_path).expect("read oracle");
    let mut rust_lines: Vec<&str> = rust.lines().collect();
    let mut source_lines: Vec<&str> = source.lines().collect();
    rust_lines.sort_unstable();
    source_lines.sort_unstable();
    assert_eq!(
        rust_lines, source_lines,
        "Scout 6.1 kallsyms differs from oracle"
    );
}
