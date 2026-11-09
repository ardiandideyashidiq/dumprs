use anyhow::{bail, Context, Result};
use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use walkdir::WalkDir;

use crate::formats::payload::ZIP_SLICE_MAGIC;

static BACKING_MMAPS: LazyLock<Mutex<HashMap<PathBuf, Weak<Mmap>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static IN_MEM_IMAGES: LazyLock<Mutex<HashMap<PathBuf, Arc<Mmap>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static EARLY_EXTRACTED: LazyLock<Mutex<HashSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));
static ALLOW_EARLY_EXTRACT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_allow_early_extract(allow: bool) {
    ALLOW_EARLY_EXTRACT.store(allow, std::sync::atomic::Ordering::Relaxed);
}

pub fn is_early_extract_allowed() -> bool {
    ALLOW_EARLY_EXTRACT.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn mark_early_extracted(dir: PathBuf) {
    EARLY_EXTRACTED.lock().unwrap().insert(dir);
}

pub fn was_early_extracted(dir: &Path) -> bool {
    EARLY_EXTRACTED.lock().unwrap().contains(dir)
}

pub fn available_ram_bytes() -> u64 {
    if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemAvailable:") {
                let kb_str = rest.trim().split_whitespace().next().unwrap_or("0");
                if let Ok(kb) = kb_str.parse::<u64>() {
                    return kb * 1024;
                }
            }
        }
    }
    0
}

pub fn can_use_anon_mmap(needed_bytes: u64) -> bool {
    if needed_bytes < 32 * 1024 * 1024 {
        return false;
    }
    let avail = available_ram_bytes();
    avail > needed_bytes.saturating_add(2 * 1024 * 1024 * 1024)
}

pub fn register_in_memory_image(key: PathBuf, mmap: Arc<Mmap>) {
    IN_MEM_IMAGES.lock().unwrap().insert(key, mmap);
}

pub fn clear_in_memory_images() {
    IN_MEM_IMAGES.lock().unwrap().clear();
    BACKING_MMAPS.lock().unwrap().clear();
    EARLY_EXTRACTED.lock().unwrap().clear();
}

pub fn logical_image_size(path: &Path) -> Option<u64> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let len = meta.len();
    if (32..4096).contains(&len) {
        let mut f = File::open(path).ok()?;
        let mut header = [0u8; 32];
        if f.read_exact(&mut header).is_ok() && &header[..16] == ZIP_SLICE_MAGIC {
            return Some(u64::from_le_bytes(header[24..32].try_into().unwrap()));
        }
    }
    Some(len)
}

pub fn resolve_image_mmap_with_backing(path: &Path) -> Result<(Arc<Mmap>, usize, usize, PathBuf)> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("Failed to mmap {}", path.display()))?;
    if mmap.len() >= 32 && &mmap[..16] == ZIP_SLICE_MAGIC {
        let start = u64::from_le_bytes(mmap[16..24].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(mmap[24..32].try_into().unwrap()) as usize;
        let backing_str = std::str::from_utf8(&mmap[32..])
            .context("Invalid UTF-8 in image slice reference")?;
        let backing_path = PathBuf::from(backing_str);
        if let Some(in_mem) = IN_MEM_IMAGES.lock().unwrap().get(&backing_path).cloned() {
            let end = start.saturating_add(len);
            if end > in_mem.len() {
                bail!("Slice {}..{} exceeds in-memory image size", start, end);
            }
            return Ok((in_mem, start, end, backing_path));
        }
        let backing_mmap = {
            let mut cache = BACKING_MMAPS.lock().unwrap();
            if let Some(weak) = cache.get(&backing_path)
                && let Some(existing) = weak.upgrade()
            {
                existing
            } else {
                let bf = File::open(&backing_path).with_context(|| {
                    format!("Failed to open backing image {}", backing_path.display())
                })?;
                let bm = Arc::new(unsafe { Mmap::map(&bf) }.with_context(|| {
                    format!("Failed to mmap backing image {}", backing_path.display())
                })?);
                cache.insert(backing_path.clone(), Arc::downgrade(&bm));
                bm
            }
        };
        let end = start.saturating_add(len);
        if end > backing_mmap.len() {
            bail!("Slice {}..{} exceeds backing image size", start, end);
        }
        return Ok((backing_mmap, start, end, backing_path));
    }
    let len = mmap.len();
    let abs_path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    Ok((Arc::new(mmap), 0, len, abs_path))
}

pub fn resolve_image_mmap(path: &Path) -> Result<(Arc<Mmap>, usize, usize)> {
    let (mmap, start, end, _) = resolve_image_mmap_with_backing(path)?;
    Ok((mmap, start, end))
}
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
    if let Ok(meta) = fs::metadata(src)
        && (32..4096).contains(&meta.len())
        && let Ok((mmap, start, end)) = resolve_image_mmap(src)
        && (start > 0 || end != meta.len() as usize)
    {
        fs::write(dst, &mmap[start..end])
            .with_context(|| format!("Failed to write slice to {}", dst.display()))?;
        return Ok(());
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
