//! Tests for DumprX-compatible bloatware cleanup.

#[path = "common/temp_dir.rs"]
mod temp_dir;

use dumprs::utils::bloat_cleanup::{
    BloatKind, CleanupConfig, classify_bloat_path, cleanup_bloat, cleanup_enabled,
};
use std::fs;
use std::path::Path;

#[test]
fn cleanup_enable_resolution() {
    let cases: &[(Option<&str>, Option<&str>, bool)] = &[
        (Some("false"), None, false),
        (Some("true"), None, true),
        (Some("false"), Some("true"), false),
        (Some("true"), Some("false"), true),
        (None, Some("false"), false),
        (None, Some("true"), true),
        (None, None, true),
        (None, Some("1"), false),
        (Some("TRUE"), None, false),
    ];
    for (bloat, gapps, expected) in cases {
        assert_eq!(
            cleanup_enabled(*bloat, *gapps),
            *expected,
            "case: bloat={bloat:?} gapps={gapps:?}"
        );
    }
}

#[test]
fn bloat_path_classification() {
    let cases: &[(&str, BloatKind)] = &[
        ("tr_region/operator/foo.apk", BloatKind::Carrier),
        ("system/app/del-app-foo/x.apk", BloatKind::DelApp),
        ("system/app/del_app_foo/x.apk", BloatKind::DelApp),
        ("vendor/data-app/bar/x.apk", BloatKind::DataApp),
        ("system/priv-app/YouTube/YouTube.apk", BloatKind::Apk),
        ("system/priv-app/GmsCore/x.apex", BloatKind::Apk),
        ("system/app/heytap/store.apk", BloatKind::Apk),
        ("system/priv-app/baidu/input.apk", BloatKind::Apk),
        ("system/app/MyApplication.apk", BloatKind::None),
        ("system/framework/framework.jar", BloatKind::None),
        ("vendor/lib/libc.so", BloatKind::None),
    ];
    for (path, expected) in cases {
        assert_eq!(
            classify_bloat_path(Path::new(path)),
            *expected,
            "case: {path}"
        );
    }
}

fn seed_tree(root: &Path) {
    let files = [
        ("tr_region/operator/operator.apk", "x"),
        ("system/app/del-app-foo/del.apk", "x"),
        ("vendor/data-app/bar/bar.apk", "x"),
        ("system/priv-app/YouTube/YouTube.apk", "x"),
        ("system/priv-app/GmsCore/gms.apex", "x"),
        ("system/app/OppoStore/heytap.apk", "x"),
        ("system/app/MyApplication.apk", "keep"),
        ("system/framework/framework.jar", "keep"),
        (".git/config", "keep"),
    ];
    for (path, content) in files {
        let full = root.join(path);
        fs::create_dir_all(full.parent().expect("parent")).expect("dir created");
        fs::write(full, content).expect("file written");
    }
}

#[test]
fn cleanup_removes_only_matching_paths() {
    let root = temp_dir::temp_dir();
    seed_tree(&root);

    let report = cleanup_bloat(&root, &CleanupConfig { enabled: true }).expect("cleanup ran");

    assert!(
        report.carrier == 1 && report.del_app == 1 && report.data_app == 1,
        "{report:?}"
    );
    assert!(report.apks >= 3, "{report:?}");
    assert!(root.join("system/app/MyApplication.apk").is_file());
    assert!(root.join("system/framework/framework.jar").is_file());
    assert!(root.join(".git/config").is_file());
    assert!(!root.join("tr_region/operator").exists());
    assert!(!root.join("system/app/del-app-foo").exists());
    assert!(!root.join("vendor/data-app/bar").exists());
    assert!(!root.join("system/priv-app/YouTube/YouTube.apk").exists());
}

#[test]
fn cleanup_removes_newly_empty_directories() {
    let root = temp_dir::temp_dir();
    seed_tree(&root);

    cleanup_bloat(&root, &CleanupConfig { enabled: true }).expect("cleanup ran");

    assert!(!root.join("system/priv-app/YouTube").exists());
    assert!(!root.join("vendor/data-app/bar").exists());
    assert!(root.join("system/framework").is_dir());
    assert!(root.is_dir());
}

#[test]
fn cleanup_respects_disable_switch() {
    let root = temp_dir::temp_dir();
    seed_tree(&root);
    let before: Vec<_> = walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().to_path_buf())
        .collect();

    cleanup_bloat(&root, &CleanupConfig { enabled: false }).expect("cleanup skipped");

    let after: Vec<_> = walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().to_path_buf())
        .collect();
    assert_eq!(before, after);
    assert!(!root.join("all_files.txt").exists());
}

#[test]
fn all_files_is_regenerated_without_git_entries() {
    let root = temp_dir::temp_dir();
    seed_tree(&root);

    cleanup_bloat(&root, &CleanupConfig { enabled: true }).expect("cleanup ran");

    let manifest = fs::read_to_string(root.join("all_files.txt")).expect("manifest written");
    assert!(manifest.contains("system/app/MyApplication.apk"));
    assert!(manifest.contains("system/framework/framework.jar"));
    assert!(!manifest.contains("YouTube.apk"));
    assert!(!manifest.contains(".git/config"));
    let entries: Vec<_> = manifest.lines().collect();
    let mut sorted = entries.clone();
    sorted.sort();
    assert_eq!(entries, sorted, "manifest must be sorted");
}

#[test]
fn cleanup_is_idempotent() {
    let root = temp_dir::temp_dir();
    seed_tree(&root);
    cleanup_bloat(&root, &CleanupConfig { enabled: true }).expect("first cleanup");
    let first_manifest = fs::read_to_string(root.join("all_files.txt")).expect("first manifest");

    cleanup_bloat(&root, &CleanupConfig { enabled: true }).expect("second cleanup");
    let second_manifest = fs::read_to_string(root.join("all_files.txt")).expect("second manifest");

    assert_eq!(first_manifest, second_manifest);
}

#[cfg(unix)]
#[test]
fn symlinked_apk_is_not_followed() {
    use std::os::unix::fs::symlink;

    let root = temp_dir::temp_dir();
    fs::create_dir_all(root.join("system/app/RealApp")).expect("dir created");
    fs::write(root.join("system/app/RealApp/target.txt"), "keep").expect("target written");
    symlink("target.txt", root.join("system/app/RealApp/YouTube.apk")).expect("symlink created");

    cleanup_bloat(&root, &CleanupConfig { enabled: true }).expect("cleanup ran");

    assert!(root.join("system/app/RealApp/target.txt").is_file());
    assert!(root.join("system/app/RealApp/YouTube.apk").is_symlink());
}

/// Differential check against the exact find/grep commands in dumper.sh:1721-1750.
#[test]
#[ignore = "requires the shell commands copied from DumprX dumper.sh"]
fn cleanup_matches_dumperx_shell() {
    let root = temp_dir::temp_dir();
    let rust_dir = root.join("rust");
    let shell_dir = root.join("shell");
    fs::create_dir_all(&rust_dir).expect("rust dir");
    fs::create_dir_all(&shell_dir).expect("shell dir");
    seed_tree(&rust_dir);
    seed_tree(&shell_dir);

    cleanup_bloat(&rust_dir, &CleanupConfig { enabled: true }).expect("rust cleanup");

    let script = r#"
out="$1"
[ -d "$out/tr_region/operator" ] && rm -rf "$out/tr_region/operator"
find "$out" -type d \( -name "*del-app*" -o -name "*del_app*" -o -name "*data-app*" \) -print0 2>/dev/null | while IFS= read -r -d '' dir; do rm -rf "$dir"; done
find "$out" -type f \( -name "*.apk" -o -name "*.apex" \) -print0 2>/dev/null | grep -ziE "google|gms|velvet|chrome|youtube|ytmusic|gmail|maps|photos|meet|arcore|speechservices|wellbeing|talkback|setupwizard|androidauto|partnersetup|playautoinstall|privatecompute|familylink|phonesky|trichromelibrary|captiveportallogingoogle|documentsuigoogle|networkstackgoogle|heytap|keke|breeno|finshell|oppostore|gamecenter|quickgame|pictorial|instant|assistantscreen|mspservice|oplusgames|mishop|micredit|mipay|migame|mivoice|mab|analytic|vivostore|vivogame|vivopay|bbkservice|baidu|sogou|tencent|alipay|taobao|weibo|bilibili|netease|amap|autonavi|youku|iqiyi|kuaishou|linktowindows" | while IFS= read -r -d '' apk; do rm -f "$apk"; done
find "$out" -type d -empty -delete 2>/dev/null
find "$out" -type f -printf '%P\n' | sort | grep -v ".git/" > "$out"/all_files.txt
"#;
    let status = std::process::Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg("bash")
        .arg(&shell_dir)
        .output()
        .expect("shell invoked");
    assert!(
        status.status.success(),
        "shell failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    let relative_files = |dir: &Path| -> Vec<String> {
        let mut files: Vec<String> = walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| {
                entry
                    .path()
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        files.sort();
        files
    };
    assert_eq!(relative_files(&rust_dir), relative_files(&shell_dir));
}
