//! DumprX-compatible bloatware cleanup, with testable decisions.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::info;

/// When true, the filesystem extractors drop bloat files instead of writing
/// them, because the finalize cleanup would delete them anyway. The final dump
/// is identical; this only avoids decompressing and writing dead data.
static SKIP_DURING_EXTRACT: AtomicBool = AtomicBool::new(false);

pub fn set_skip_during_extract(enabled: bool) {
    SKIP_DURING_EXTRACT.store(enabled, Ordering::Relaxed);
}

#[inline]
pub fn skip_during_extract() -> bool {
    SKIP_DURING_EXTRACT.load(Ordering::Relaxed)
}

use crate::utils::dump_metadata::write_all_files_list;

/// Why a path is considered removable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BloatKind {
    Carrier,
    DelApp,
    DataApp,
    Apk,
    None,
}

/// Result counts for one cleanup run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub carrier: usize,
    pub del_app: usize,
    pub data_app: usize,
    pub apks: usize,
    pub empty_dirs: usize,
}

/// Cleanup configuration resolved from DumprX's environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupConfig {
    pub enabled: bool,
}

/// Resolve `CLEANUP_BLOAT ?? CLEANUP_GAPPS ?? true`; only the literal
/// string `"true"` enables cleanup.
pub fn cleanup_enabled(bloat: Option<&str>, gapps: Option<&str>) -> bool {
    bloat.or(gapps).unwrap_or("true") == "true"
}

/// Case-insensitive keywords from dumper.sh's APK/APEX filter.
const APK_KEYWORDS: &[&str] = &[
    "google",
    "gms",
    "velvet",
    "chrome",
    "youtube",
    "ytmusic",
    "gmail",
    "maps",
    "photos",
    "meet",
    "arcore",
    "speechservices",
    "wellbeing",
    "talkback",
    "setupwizard",
    "androidauto",
    "partnersetup",
    "playautoinstall",
    "privatecompute",
    "familylink",
    "phonesky",
    "trichromelibrary",
    "captiveportallogingoogle",
    "documentsuigoogle",
    "networkstackgoogle",
    "heytap",
    "keke",
    "breeno",
    "finshell",
    "oppostore",
    "gamecenter",
    "quickgame",
    "pictorial",
    "instant",
    "assistantscreen",
    "mspservice",
    "oplusgames",
    "mishop",
    "micredit",
    "mipay",
    "migame",
    "mivoice",
    "mab",
    "analytic",
    "vivostore",
    "vivogame",
    "vivopay",
    "bbkservice",
    "baidu",
    "sogou",
    "tencent",
    "alipay",
    "taobao",
    "weibo",
    "bilibili",
    "netease",
    "amap",
    "autonavi",
    "youku",
    "iqiyi",
    "kuaishou",
    "linktowindows",
];

/// Classify a dump-relative path.
pub fn classify_bloat_path(path: &Path) -> BloatKind {
    let components: Vec<String> = path
        .components()
        .filter_map(|component| component.as_os_str().to_str())
        .map(str::to_string)
        .collect();
    if components.len() >= 2 && components[0] == "tr_region" && components[1] == "operator" {
        return BloatKind::Carrier;
    }
    if components.iter().any(|part| {
        let lower = part.to_ascii_lowercase();
        lower.contains("del-app") || lower.contains("del_app")
    }) {
        return BloatKind::DelApp;
    }
    if components
        .iter()
        .any(|part| part.to_ascii_lowercase().contains("data-app"))
    {
        return BloatKind::DataApp;
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return BloatKind::None;
    };
    let lower = file_name.to_ascii_lowercase();
    if !(lower.ends_with(".apk") || lower.ends_with(".apex")) {
        return BloatKind::None;
    }
    let full = path.to_string_lossy().to_ascii_lowercase();
    if APK_KEYWORDS.iter().any(|keyword| full.contains(keyword)) {
        BloatKind::Apk
    } else {
        BloatKind::None
    }
}

/// Dump-relative path of a file that cleanup would delete, if any.
///
/// `relative` is relative to the partition directory, so it is prefixed with
/// the partition name to match the paths `cleanup_bloat` classifies.
pub fn bloat_extract_path(partition: &str, relative: &Path) -> Option<PathBuf> {
    let dump_relative = Path::new(partition).join(relative);
    (classify_bloat_path(&dump_relative) == BloatKind::Apk).then_some(dump_relative)
}

fn is_git_path(path: &Path) -> bool {
    path.components()
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .is_some_and(|part| part == ".git")
}

/// Run cleanup and regenerate `all_files.txt`.
///
/// # Errors
///
/// Returns an error when the dump cannot be read or a removal fails.
pub fn cleanup_bloat(dump_dir: &Path, config: &CleanupConfig) -> Result<CleanupReport> {
    let mut report = CleanupReport::default();
    if !config.enabled {
        return Ok(report);
    }

    let entries: Vec<PathBuf> = walkdir::WalkDir::new(dump_dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().to_path_buf())
        .collect();

    for path in &entries {
        let Ok(relative) = path.strip_prefix(dump_dir) else {
            continue;
        };
        if !fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
        {
            continue;
        }
        if classify_bloat_path(relative) == BloatKind::Apk {
            fs::remove_file(path)
                .with_context(|| format!("Failed to remove {}", path.display()))?;
            info!(file = %relative.display(), "bloat.apk.removed");
            report.apks += 1;
        }
    }

    let carrier = dump_dir.join("tr_region/operator");
    if carrier.is_dir() {
        fs::remove_dir_all(&carrier)
            .with_context(|| format!("Failed to remove {}", carrier.display()))?;
        report.carrier += 1;
    }

    for path in &entries {
        let Ok(relative) = path.strip_prefix(dump_dir) else {
            continue;
        };
        if !fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        let kind = classify_bloat_path(relative);
        if !matches!(kind, BloatKind::DelApp | BloatKind::DataApp) {
            continue;
        }
        if !path.exists() {
            continue;
        }
        fs::remove_dir_all(path).with_context(|| format!("Failed to remove {}", path.display()))?;
        match kind {
            BloatKind::DelApp => report.del_app += 1,
            BloatKind::DataApp => report.data_app += 1,
            _ => {}
        }
        info!(dir = %relative.display(), "bloat.directory.removed");
    }

    for entry in walkdir::WalkDir::new(dump_dir)
        .contents_first(true)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_dir())
    {
        if entry.path() == dump_dir || !entry.path().exists() {
            continue;
        }
        if fs::read_dir(entry.path())
            .map(|mut dir| dir.next().is_none())
            .unwrap_or(false)
        {
            fs::remove_dir(entry.path()).with_context(|| {
                format!("Failed to remove empty dir {}", entry.path().display())
            })?;
            report.empty_dirs += 1;
        }
    }

    let manifest_path = dump_dir.join("all_files.txt");
    if !manifest_path.exists() {
        fs::write(&manifest_path, "")
            .with_context(|| format!("Failed to create {}", manifest_path.display()))?;
    }
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(dump_dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            entry
                .path()
                .strip_prefix(dump_dir)
                .ok()
                .map(Path::to_path_buf)
        })
        .filter(|relative| !is_git_path(relative))
        .collect();
    write_all_files_list(dump_dir, &mut files)?;

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_filter_matches_cleanup_classification() {
        let cases = [
            ("product/priv-app/GmsCore/GmsCore.apk", true),
            ("system/system/apex/com.google.android.art.apex", true),
            ("product/app/YouTube/YouTube.apk", true),
            ("vendor/app/GoogleExtShared/GoogleExtShared.apk", true),
            ("product/priv-app/AiCore/AiCore.apk", false),
            ("system/framework/framework.jar", false),
        ];
        for (path, expected) in cases {
            let (partition, rest) = path.split_once('/').unwrap();
            let filtered = bloat_extract_path(partition, Path::new(rest));
            assert_eq!(filtered.is_some(), expected, "extract filter for {path}");
            if let Some(dump_relative) = filtered {
                assert_eq!(
                    classify_bloat_path(&dump_relative),
                    BloatKind::Apk,
                    "filtered path must be classified as bloat by cleanup"
                );
                assert_eq!(dump_relative, Path::new(path));
            }
        }
    }
}
