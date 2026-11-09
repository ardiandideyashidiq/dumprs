use anyhow::{Context, Result};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub fn get_recursive_files_list(dir: &Path, relative: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let walker = WalkDir::new(dir).into_iter().filter_entry(|e| {
        if e.depth() == 1 && e.file_type().is_dir() {
            let name = e.file_name();
            name != "temp_extracted_archive" && name != "temp_raw_images"
        } else {
            true
        }
    });
    for entry in walker.filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let path = entry.path();
            if relative {
                if let Ok(rel) = path.strip_prefix(dir) {
                    files.push(rel.to_path_buf());
                }
            } else {
                files.push(path.to_path_buf());
            }
        }
    }
    files
}

pub fn sort_files(files: &mut [PathBuf]) {
    files.par_sort_unstable_by(|a, b| a.as_os_str().cmp(b.as_os_str()));
}

pub fn move_or_copy(src: &Path, dst: &Path) -> Result<()> {
    if src == dst {
        return Ok(());
    }
    if fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    fs::copy(src, dst)
        .with_context(|| format!("Failed to copy {} to {}", src.display(), dst.display()))?;
    let _ = fs::remove_file(src);
    Ok(())
}

pub fn hardlink_or_copy(src: &Path, dst: &Path) -> Result<()> {
    if src == dst {
        return Ok(());
    }
    if dst.exists() {
        let _ = fs::remove_file(dst);
    }
    if fs::hard_link(src, dst).is_ok() {
        return Ok(());
    }
    fs::copy(src, dst)
        .with_context(|| format!("Failed to copy {} to {}", src.display(), dst.display()))?;
    Ok(())
}
pub fn rmtree_recursive(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    // Try normal remove_dir_all first
    if fs::remove_dir_all(dir).is_ok() {
        return Ok(());
    }

    // If permission error, make all writable first
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if let Ok(meta) = fs::metadata(p) {
            let mut perms = meta.permissions();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                perms.set_mode(0o755);
                let _ = fs::set_permissions(p, perms);
            }
            #[cfg(not(unix))]
            {
                perms.set_readonly(false);
                let _ = fs::set_permissions(p, perms);
            }
        }
    }

    fs::remove_dir_all(dir).with_context(|| format!("Failed to remove directory {}", dir.display()))
}

pub fn flatten_dir(dir: &Path) -> Result<()> {
    let all_files = get_recursive_files_list(dir, false);
    for file in all_files {
        let file_name = match file.file_name() {
            Some(name) => name,
            None => continue,
        };
        let target = dir.join(file_name);
        if file != target {
            if target.exists() {
                let _ = fs::remove_file(&target);
            }
            fs::rename(&file, &target)
                .with_context(|| format!("Failed to rename {} to {}", file.display(), target.display()))?;
        }
    }

    // Remove empty subdirectories
    let mut dirs_to_remove: Vec<PathBuf> = WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
        .map(|e| e.path().to_path_buf())
        .collect();

    // Sort descending by path length so leaf directories are removed first
    dirs_to_remove.sort_by_key(|b| std::cmp::Reverse(b.as_os_str().len()));
    for d in dirs_to_remove {
        let _ = fs::remove_dir(&d);
    }

    Ok(())
}
