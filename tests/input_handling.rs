//! Tests for DumprX-style input classification and staging.

#[path = "common/temp_dir.rs"]
mod temp_dir;

use dumprs::utils::input_handling::{
    InputKind, InputStage, classify_input, plan_input_chain, stage_input_files, validate_input,
};
use std::fs;
use std::path::{Path, PathBuf};

fn write(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent created");
    }
    fs::write(path, b"x").expect("file written");
}

#[test]
fn input_kind_classification() {
    let root = temp_dir::temp_dir();

    let single = root.join("single.zip");
    write(&single);
    assert_eq!(
        classify_input(&single),
        InputKind::SingleFile(single.clone())
    );

    let archive_dir = root.join("archive_dir");
    write(&archive_dir.join("firmware.zip"));
    write(&archive_dir.join("notes.txt"));
    assert_eq!(
        classify_input(&archive_dir),
        InputKind::Archive(archive_dir.join("firmware.zip"))
    );

    let multi = root.join("multi");
    write(&multi.join("a.zip"));
    write(&multi.join("b.7z"));
    assert_eq!(
        classify_input(&multi),
        InputKind::MultipleArchives(vec![multi.join("a.zip"), multi.join("b.7z")])
    );

    let firmware = root.join("firmware");
    write(&firmware.join("system.img"));
    assert_eq!(
        classify_input(&firmware),
        InputKind::FirmwareDirectory(firmware.clone())
    );

    let empty = root.join("empty");
    fs::create_dir_all(&empty).expect("dir created");
    assert_eq!(
        classify_input(&empty),
        InputKind::Unsupported(empty.clone())
    );

    assert_eq!(classify_input(&root.join("missing")), InputKind::Missing);
}

#[test]
fn compatibility_zip_is_ignored() {
    let root = temp_dir::temp_dir();
    write(&root.join("compatibility.zip"));
    write(&root.join("firmware.zip"));
    assert_eq!(
        classify_input(&root),
        InputKind::Archive(root.join("firmware.zip"))
    );
}

#[test]
fn archive_extension_set_matches_dumprx() {
    let root = temp_dir::temp_dir();
    for (name, expected_count) in [
        ("fw.TAR", 1),
        ("fw.ZIP", 1),
        ("fw.rar", 1),
        ("fw.7z", 1),
        ("fw.img", 0),
        ("fw.txt", 0),
        ("fw.md5", 0),
    ] {
        let dir = root.join(name);
        write(&dir.join(name));
        let count = match classify_input(&dir) {
            InputKind::Archive(_) => 1,
            _ => 0,
        };
        assert_eq!(count, expected_count, "case: {name}");
    }
}

#[test]
fn firmware_directory_is_staged() {
    let root = temp_dir::temp_dir();
    fs::create_dir_all(root.join("firmware/sub")).expect("dir created");
    fs::write(root.join("firmware/system.img"), b"system").expect("file written");
    fs::write(root.join("firmware/compatibility.zip"), b"skip").expect("file written");
    fs::write(root.join("firmware/sub/extra.img"), b"extra").expect("file written");
    let work = root.join("work");

    let copied = stage_input_files(&root.join("firmware"), &work).expect("staging succeeded");

    assert!(copied.iter().any(|path| path == Path::new("system.img")));
    assert!(copied.iter().any(|path| path == Path::new("sub/extra.img")));
    assert!(
        !copied
            .iter()
            .any(|path| path == Path::new("compatibility.zip"))
    );
    assert_eq!(
        fs::read(work.join("system.img")).expect("staged"),
        b"system"
    );
    assert_eq!(
        fs::read(work.join("sub/extra.img")).expect("staged"),
        b"extra"
    );
}

#[test]
fn multiple_archives_returns_actionable_error() {
    let root = temp_dir::temp_dir();
    write(&root.join("a.zip"));
    write(&root.join("b.zip"));
    write(&root.join("c.7z"));
    let kind = classify_input(&root);

    let error = validate_input(&kind).expect_err("multiple archives must fail");
    let message = error.to_string();
    assert!(
        message.contains("3"),
        "message must mention count: {message}"
    );
    assert!(
        message.to_ascii_lowercase().contains("direct archive path"),
        "message must suggest a direct path: {message}"
    );
}

#[test]
fn paths_with_spaces_are_handled() {
    let root = temp_dir::temp_dir();
    let dir = root.join("firmware with spaces");
    write(&dir.join("ota update.zip"));

    assert_eq!(
        classify_input(&dir),
        InputKind::Archive(dir.join("ota update.zip"))
    );
    let work = root.join("work dir");
    stage_input_files(&dir, &work).expect("staging succeeded");
    assert!(work.join("ota update.zip").is_file());
}

#[test]
fn nested_archive_chain_is_discovered() {
    let root = temp_dir::temp_dir();
    let cases: Vec<(PathBuf, Vec<InputStage>)> = vec![
        (root.join("fw.zip"), vec![InputStage::Archive]),
        (
            root.join("fw.tar.md5"),
            vec![InputStage::Archive, InputStage::NestedTarMd5],
        ),
        (
            root.join("fw.ozip"),
            vec![InputStage::DecryptOzip, InputStage::Archive],
        ),
        (root.join("fw.ofp"), vec![InputStage::DecryptOfp]),
        (
            root.join("fw.ops"),
            vec![InputStage::DecryptOps, InputStage::Archive],
        ),
        (
            root.join("ruu_2.10.exe"),
            vec![InputStage::DecryptRuu, InputStage::Archive],
        ),
        (root.join("system.sin"), vec![InputStage::ExtractSin]),
    ];
    for (path, expected) in cases {
        write(&path);
        assert_eq!(
            plan_input_chain(&InputKind::SingleFile(path.clone())),
            expected,
            "case: {}",
            path.display()
        );
    }
    assert!(plan_input_chain(&InputKind::FirmwareDirectory(root)).is_empty());
}

#[test]
fn unsupported_input_reports_every_reason() {
    let root = temp_dir::temp_dir();
    let kind = classify_input(&root);
    let message = validate_input(&kind)
        .expect_err("empty dir must fail")
        .to_string();
    assert!(message.contains("archive"), "{message}");
    assert!(message.contains("firmware"), "{message}");
}

/// Differential check against dumper.sh's archive discovery find expression.
#[test]
#[ignore = "requires the shell commands copied from DumprX dumper.sh"]
fn input_classification_matches_dumperx_find() {
    let root = temp_dir::temp_dir();
    fs::create_dir_all(root.join("dir")).expect("dir created");
    for name in ["a.zip", "b.7z", "notes.txt", "compatibility.zip"] {
        write(&root.join("dir").join(name));
    }

    let script = r#"
dir="$1"
find "$dir" -maxdepth 1 -type f \( -name "*.tar" -o -name "*.zip" -o -name "*.rar" -o -name "*.7z" \) -print | grep -v "compatibility.zip" | sort
"#;
    let output = std::process::Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg("bash")
        .arg(root.join("dir"))
        .output()
        .expect("shell invoked");
    assert!(output.status.success(), "shell failed");
    let shell_archives: Vec<PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(PathBuf::from)
        .collect();
    let expected = match classify_input(&root.join("dir")) {
        InputKind::MultipleArchives(mut paths) => {
            paths.sort();
            paths
        }
        other => panic!("expected multiple archives, got {other:?}"),
    };
    assert_eq!(shell_archives, expected);
}
