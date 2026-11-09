use anyhow::{bail, Context, Result};
use erofs_rs::backend::MmapImage;
use erofs_rs::EroFS;
use ext4_view::{Ext4, Ext4Read};
use memmap2::Mmap;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

pub fn extract_filesystem(image_path: &Path, output_dir: &Path) -> Result<()> {
    let part_name = image_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("image");

    info!(
        "Extracting filesystem image {} to {}",
        image_path.display(),
        output_dir.display()
    );
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;

    // 1. Try pure-Rust EROFS
    match try_extract_erofs(image_path, output_dir, part_name) {
        Ok(()) => {
            info!("Successfully extracted {} with erofs-rs", image_path.display());
            return Ok(());
        }
        Err(e) => {
            debug!("EROFS extraction failed for {}: {:?}, trying ext4", image_path.display(), e);
        }
    }

    // 2. Try pure-Rust ext4
    match try_extract_ext4(image_path, output_dir, part_name) {
        Ok(()) => {
            info!("Successfully extracted {} with ext4-view", image_path.display());
            return Ok(());
        }
        Err(e) => {
            debug!("Ext4 extraction failed for {}: {:?}, trying 7z", image_path.display(), e);
        }
    }

    // 3. Try pure-Rust 7z decompression as final fallback
    match sevenz_rust2::decompress_file(image_path, output_dir) {
        Ok(()) => {
            info!("Successfully extracted {} with sevenz-rust2", image_path.display());
            return Ok(());
        }
        Err(e) => {
            debug!("7z extraction failed for {}: {:?}", image_path.display(), e);
        }
    }

    bail!("Failed to extract filesystem image {} (tried erofs, ext4, 7z)", image_path.display())
}

fn try_extract_erofs(image_path: &Path, output_dir: &Path, part_name: &str) -> Result<()> {
    // Open memory-mapped image
    let image = unsafe {
        MmapImage::new_from_path(image_path)
            .map_err(|e| anyhow::anyhow!("MmapImage failed: {:?}", e))?
    };
    let fs = EroFS::new(image).map_err(|e| anyhow::anyhow!("EroFS init failed: {:?}", e))?;
    let verbose = tracing::enabled!(tracing::Level::DEBUG);

    let mut created_dirs: HashSet<PathBuf> = HashSet::new();
    created_dirs.insert(output_dir.to_path_buf());
    let mut copy_buf = vec![0u8; 256 * 1024];
    let mut files_extracted = 0u64;

    for entry in fs.walk_dir("/").map_err(|e| anyhow::anyhow!("EroFS walk_dir failed: {:?}", e))? {
        let entry = entry.map_err(|e| anyhow::anyhow!("EroFS entry error: {:?}", e))?;
        let entry_path = entry.dir_entry.path();
        let path_str = entry_path.to_string_lossy();
        let rel_path = path_str.strip_prefix('/').unwrap_or(&path_str);
        if rel_path.is_empty() {
            continue;
        }

        let target = output_dir.join(rel_path);

        if entry.inode.is_dir() {
            if !created_dirs.contains(&target) {
                fs::create_dir_all(&target)?;
                created_dirs.insert(target);
            }
            debug!("[{}] create dir {}", part_name, rel_path);
        } else if entry.inode.is_file() {
            if let Some(parent) = target.parent() && !created_dirs.contains(parent) {
                fs::create_dir_all(parent)?;
                created_dirs.insert(parent.to_path_buf());
            }
            let mut file = fs
                .open(&entry_path)
                .map_err(|e| anyhow::anyhow!("Failed to open erofs file {}: {:?}", path_str, e))?;
            let mut out_file = File::create(&target)
                .with_context(|| format!("Failed to create {}", target.display()))?;
            loop {
                let n = file.read(&mut copy_buf)?;
                if n == 0 {
                    break;
                }
                out_file.write_all(&copy_buf[..n])?;
            }
            files_extracted += 1;
            if verbose {
                info!("[{}] {}", part_name, rel_path);
            }
        }
    }

    if !verbose {
        info!("[{}] Extracted {} files via EROFS", part_name, files_extracted);
    }

    Ok(())
}

struct MmapExt4Reader(Mmap);

impl Ext4Read for MmapExt4Reader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = start_byte as usize;
        let end = start.checked_add(dst.len()).ok_or("ext4 read overflow")?;
        let slice = self.0.get(start..end).ok_or("ext4 read out of bounds")?;
        dst.copy_from_slice(slice);
        Ok(())
    }
}

fn try_extract_ext4(image_path: &Path, output_dir: &Path, part_name: &str) -> Result<()> {
    let file = File::open(image_path)
        .with_context(|| format!("Failed to open ext4 image {}", image_path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("Failed to mmap ext4 image {}", image_path.display()))?;
    let fs = Ext4::load(Box::new(MmapExt4Reader(mmap)))
        .map_err(|e| anyhow::anyhow!("Ext4 load failed: {:?}", e))?;

    let verbose = tracing::enabled!(tracing::Level::DEBUG);
    let mut files_extracted = 0u64;
    extract_ext4_dir(&fs, "/", output_dir, part_name, verbose, &mut files_extracted)?;
    if !verbose {
        info!("[{}] Extracted {} files via ext4", part_name, files_extracted);
    }
    Ok(())
}

fn extract_ext4_dir(
    fs: &Ext4,
    dir_path: &str,
    current_out_dir: &Path,
    part_name: &str,
    verbose: bool,
    files_extracted: &mut u64,
) -> Result<()> {
    for entry in fs
        .read_dir(dir_path)
        .map_err(|e| anyhow::anyhow!("Ext4 read_dir failed on {}: {:?}", dir_path, e))?
    {
        let entry = entry.map_err(|e| anyhow::anyhow!("Ext4 entry error: {:?}", e))?;
        let entry_name = entry
            .file_name()
            .as_str()
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in ext4 filename: {:?}", e))?;
        if entry_name.is_empty() || entry_name == "." || entry_name == ".." {
            continue;
        }

        let entry_path = entry.path();
        let path_str = entry_path
            .to_str()
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in ext4 path: {:?}", e))?;

        let target = current_out_dir.join(entry_name);
        let file_type = entry
            .file_type()
            .map_err(|e| anyhow::anyhow!("Ext4 file_type error: {:?}", e))?;

        if file_type.is_dir() {
            fs::create_dir_all(&target)?;
            debug!("[{}] create dir {}", part_name, path_str);
            extract_ext4_dir(fs, path_str, &target, part_name, verbose, files_extracted)?;
        } else if file_type.is_regular_file() {
            let data = fs
                .read(&entry_path)
                .map_err(|e| anyhow::anyhow!("Ext4 read failed on {}: {:?}", path_str, e))?;
            fs::write(&target, data)?;
            *files_extracted += 1;
            if verbose {
                info!("[{}] {}", part_name, path_str);
            }
        } else if file_type.is_symlink() {
            if let Ok(link_target) = fs.read_link(&entry_path)
                && let Ok(link_str) = link_target.to_str()
            {
                #[cfg(unix)]
                {
                    let _ = std::os::unix::fs::symlink(link_str, &target);
                }
                #[cfg(not(unix))]
                {
                    let _ = fs::write(&target, link_str);
                }
            }
            *files_extracted += 1;
            if verbose {
                info!("[{}] {}", part_name, path_str);
            }
        }
    }

    Ok(())
}

