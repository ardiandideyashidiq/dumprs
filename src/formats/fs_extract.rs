use anyhow::{Context, Result, bail};
use backhand::{FilesystemReader, InnerNode};
use erofs_rs::EroFS;
use erofs_rs::backend::SliceImage;
use ext4_view::{Ext4, Ext4Read};
use indicatif::{HumanBytes, HumanDuration};
use memmap2::Mmap;
use rayon::prelude::*;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::{debug, info};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::utils::bloat_cleanup::{bloat_extract_path, skip_during_extract};
use crate::utils::files::resolve_image_mmap;
#[cfg(unix)]
use crate::utils::files::{create_dir_with_mode, create_file_with_mode};
use crate::utils::progress::ByteProgress;

/// Filesystem extraction backends, in the order dumprs attempts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsBackend {
    Erofs,
    Ext4,
    Squashfs,
    Mtk,
    SevenZInProcess,
    SevenZCli,
}

pub const FS_BACKEND_ORDER: &[FsBackend] = &[
    FsBackend::Erofs,
    FsBackend::Ext4,
    FsBackend::Squashfs,
    FsBackend::Mtk,
    FsBackend::SevenZInProcess,
    FsBackend::SevenZCli,
];

const MTK_MAGIC_1: u32 = 0x5888_1688;
const MTK_MAGIC_2: u32 = 0x5889_1689;
thread_local! {
    static FS_COPY_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

pub fn extract_filesystem(image_path: &Path, output_dir: &Path) -> Result<()> {
    let part_name = image_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("image");

    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;

    let (mmap, start, end) = resolve_image_mmap(image_path)?;
    let slice = &mmap[start..end];

    // 1. Try pure-Rust EROFS
    match try_extract_erofs(slice, output_dir, part_name) {
        Ok(()) => return Ok(()),
        Err(e) => {
            debug!(partition = part_name, error = ?e, "fs.erofs.probe_failed");
        }
    }

    // 2. Try pure-Rust ext4
    match try_extract_ext4(&mmap, start, end, output_dir, part_name) {
        Ok(()) => return Ok(()),
        Err(e) => {
            debug!(partition = part_name, error = ?e, "fs.ext4.probe_failed");
        }
    }

    // 3. Try pure-Rust SquashFS
    match try_extract_squashfs(slice, output_dir, part_name) {
        Ok(()) => return Ok(()),
        Err(e) => {
            debug!(partition = part_name, error = ?e, "fs.squashfs.probe_failed");
        }
    }

    // 4. Try MediaTek mkimage container (e.g. MTK modem.img / md1img)
    match try_extract_mtk(slice, output_dir, part_name) {
        Ok(()) => return Ok(()),
        Err(e) => {
            debug!(partition = part_name, error = ?e, "fs.mtk.probe_failed");
        }
    }

    // 5. Try pure-Rust 7z decompression fallback
    if start == 0 && end == mmap.len() {
        match sevenz_rust2::decompress_file(image_path, output_dir) {
            Ok(()) => {
                info!(partition = part_name, fs = "7z", "fs.extract.done");
                return Ok(());
            }
            Err(e) => {
                debug!(partition = part_name, error = ?e, "fs.7z.probe_failed");
            }
        }
    }

    // 6. Try host 7zz / 7z CLI fallback (for exotic filesystems like F2FS/CramFS)
    match try_extract_7zz_cli(image_path, output_dir, part_name) {
        Ok(()) => return Ok(()),
        Err(e) => {
            debug!(partition = part_name, error = ?e, "fs.7zz_cli.probe_failed");
        }
    }

    bail!(
        "Failed to extract filesystem image {} (tried erofs, ext4, squashfs, mtk, 7z)",
        image_path.display()
    )
}
pub fn extract_filesystem_slice(slice: &[u8], output_dir: &Path, part_name: &str) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output dir {}", output_dir.display()))?;
    if try_extract_erofs(slice, output_dir, part_name).is_ok() {
        return Ok(());
    }
    if try_extract_ext4_slice(slice, output_dir, part_name).is_ok() {
        return Ok(());
    }
    if try_extract_squashfs(slice, output_dir, part_name).is_ok() {
        return Ok(());
    }
    if try_extract_mtk(slice, output_dir, part_name).is_ok() {
        return Ok(());
    }
    bail!("Failed to extract filesystem slice for {}", part_name)
}

fn try_extract_squashfs(slice: &[u8], output_dir: &Path, part_name: &str) -> Result<()> {
    if slice.len() < 4 || &slice[0..4] != b"hsqs" {
        bail!("Not a SquashFS image");
    }
    let start_time = Instant::now();
    let img_size = slice.len() as u64;
    let cursor = Cursor::new(slice);
    let filesystem = FilesystemReader::from_reader(cursor)
        .map_err(|e| anyhow::anyhow!("SquashFS parse failed: {:?}", e))?;
    let pb = ByteProgress::new(part_name, img_size);

    let mut regular_files = Vec::new();
    let mut symlinks_extracted = 0u64;

    for node in filesystem.files() {
        let path = &node.fullpath;
        let rel_path = path.strip_prefix("/").unwrap_or(path);
        if rel_path.as_os_str().is_empty() {
            continue;
        }
        let target = output_dir.join(rel_path);

        match &node.inner {
            InnerNode::Dir(_) => {
                if fs::create_dir(&target).is_err() {
                    fs::create_dir_all(&target)?;
                }
                #[cfg(unix)]
                if node.header.permissions != 0 {
                    let _ = fs::set_permissions(
                        &target,
                        std::fs::Permissions::from_mode(node.header.permissions as u32),
                    );
                }
            }
            InnerNode::File(file) => {
                if let Some(parent) = target.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                regular_files.push((file, target, node.header.permissions));
            }
            InnerNode::Symlink(symlink) => {
                if let Some(parent) = target.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let link_target = &symlink.link;
                #[cfg(unix)]
                {
                    let _ = std::os::unix::fs::symlink(link_target, &target);
                }
                #[cfg(not(unix))]
                {
                    let _ = fs::write(&target, link_target.to_string_lossy().as_bytes());
                }
                symlinks_extracted += 1;
            }
            _ => {}
        }
    }

    let files_extracted = symlinks_extracted + regular_files.len() as u64;
    let bytes_extracted = AtomicU64::new(0);

    regular_files
        .into_par_iter()
        .with_min_len(16)
        .try_for_each(|(file, target, permissions)| -> Result<()> {
            let mut reader = filesystem.file(file).reader();
            let mut file_bytes = 0u64;
            FS_COPY_BUF.with(|cell| -> Result<()> {
                let mut copy_buf = cell.borrow_mut();
                if copy_buf.len() < 4 * 1024 * 1024 {
                    copy_buf.resize(4 * 1024 * 1024, 0);
                }
                let out_file = File::create(&target)
                    .with_context(|| format!("Failed to create {}", target.display()))?;
                let mut writer = BufWriter::with_capacity(2 * 1024 * 1024, out_file);
                loop {
                    let n = reader.read(&mut copy_buf)?;
                    if n == 0 {
                        break;
                    }
                    writer.write_all(&copy_buf[..n])?;
                    file_bytes += n as u64;
                }
                writer.flush()?;
                #[cfg(unix)]
                if permissions != 0 {
                    let _ = fs::set_permissions(
                        &target,
                        std::fs::Permissions::from_mode(permissions as u32),
                    );
                }
                Ok(())
            })?;
            bytes_extracted.fetch_add(file_bytes, Ordering::Relaxed);
            pb.inc(file_bytes);
            Ok(())
        })?;

    let bytes_extracted = bytes_extracted.load(Ordering::Relaxed);
    pb.finish();
    info!(
        partition = part_name,
        fs = "squashfs",
        files = files_extracted,
        size = %HumanBytes(bytes_extracted),
        duration = %HumanDuration(start_time.elapsed()),
        "fs.extract.done"
    );
    Ok(())
}

fn try_extract_7zz_cli(image_path: &Path, output_dir: &Path, part_name: &str) -> Result<()> {
    let sevenz_cmd = if which_exists("7zz") {
        "7zz"
    } else if which_exists("7z") {
        "7z"
    } else {
        bail!("7zz/7z not found in PATH");
    };

    let start_time = Instant::now();
    let mut cmd = std::process::Command::new(sevenz_cmd);
    cmd.arg("x")
        .arg("-y")
        .arg(format!("-o{}/", output_dir.display()))
        .arg(image_path);
    if sevenz_cmd == "7zz" {
        cmd.arg("-snld");
    }
    let output = cmd
        .output()
        .with_context(|| format!("Failed to execute {}", sevenz_cmd))?;
    if !output.status.success() {
        bail!(
            "{} failed with exit code {:?}: {}",
            sevenz_cmd,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    info!(
        partition = part_name,
        tool = sevenz_cmd,
        duration = %HumanDuration(start_time.elapsed()),
        "fs.extract.7zz_cli.done"
    );
    Ok(())
}

fn which_exists(prog: &str) -> bool {
    std::process::Command::new(prog)
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn try_extract_mtk(slice: &[u8], output_dir: &Path, part_name: &str) -> Result<()> {
    if slice.len() < 68 {
        bail!("Slice too small for MTK mkimage");
    }
    let m1 = u32::from_le_bytes(slice[0..4].try_into().unwrap());
    let m2 = u32::from_le_bytes(slice[48..52].try_into().unwrap());
    if m1 != MTK_MAGIC_1 || m2 != MTK_MAGIC_2 {
        bail!("Not an MTK mkimage header");
    }

    let start_time = Instant::now();
    let mut pos = 0usize;
    let mut sections: Vec<(PathBuf, usize, usize)> = Vec::new();
    let mut bytes_extracted = 0u64;
    let mut seen_names: HashSet<String> = HashSet::new();

    while pos + 68 <= slice.len() {
        let magic1 = u32::from_le_bytes(slice[pos..pos + 4].try_into().unwrap());
        let magic2 = u32::from_le_bytes(slice[pos + 48..pos + 52].try_into().unwrap());
        if magic1 != MTK_MAGIC_1 || magic2 != MTK_MAGIC_2 {
            break;
        }
        let dsize = u32::from_le_bytes(slice[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let name_raw = &slice[pos + 8..pos + 40];
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(32);
        let base_name = String::from_utf8_lossy(&name_raw[..name_end])
            .trim()
            .replace('/', "_");
        let hdr_sz =
            (u32::from_le_bytes(slice[pos + 52..pos + 56].try_into().unwrap()) as usize).max(68);
        let align_sz =
            (u32::from_le_bytes(slice[pos + 64..pos + 68].try_into().unwrap()) as usize).max(16);

        let data_start = pos.saturating_add(hdr_sz);
        let data_end = data_start.saturating_add(dsize);
        if data_end > slice.len() {
            break;
        }

        if !base_name.is_empty() {
            let file_name = if seen_names.insert(base_name.clone()) {
                base_name
            } else {
                format!("{}_{}", base_name, sections.len())
            };
            sections.push((output_dir.join(file_name), data_start, data_end));
            bytes_extracted += dsize as u64;
        }

        let aligned_dsize = dsize.div_ceil(align_sz) * align_sz;
        pos = data_start.saturating_add(aligned_dsize);
    }

    if sections.is_empty() {
        bail!("No valid MTK sections extracted");
    }
    let files_extracted = sections.len() as u64;
    sections
        .into_par_iter()
        .try_for_each(|(out_path, start, end)| -> Result<()> {
            fs::write(&out_path, &slice[start..end])?;
            Ok(())
        })?;

    info!(
        partition = part_name,
        fs = "mtk",
        files = files_extracted,
        size = %HumanBytes(bytes_extracted),
        duration = %HumanDuration(start_time.elapsed()),
        "fs.extract.done"
    );
    Ok(())
}

fn try_extract_erofs(slice: &[u8], output_dir: &Path, part_name: &str) -> Result<()> {
    let start_time = Instant::now();
    let img_size = slice.len() as u64;
    let fs = EroFS::new(SliceImage::new(slice))
        .map_err(|e| anyhow::anyhow!("EroFS init failed: {:?}", e))?;
    let pb = ByteProgress::new(part_name, img_size);
    let mut files_to_extract = Vec::new();
    let mut symlinks_extracted = 0u64;
    let skip_bloat = skip_during_extract();

    for entry in fs
        .walk_dir("/")
        .map_err(|e| anyhow::anyhow!("EroFS walk_dir failed: {:?}", e))?
    {
        let entry = entry.map_err(|e| anyhow::anyhow!("EroFS entry error: {:?}", e))?;
        let entry_path = entry.dir_entry.path();
        let path_str = entry_path.to_string_lossy();
        let rel_path = path_str.strip_prefix('/').unwrap_or(&path_str);
        if rel_path.is_empty() {
            continue;
        }
        if skip_bloat && let Some(dump_rel) = bloat_extract_path(part_name, Path::new(rel_path)) {
            info!(file = %dump_rel.display(), "bloat.apk.removed");
            continue;
        }

        let target = output_dir.join(rel_path);

        if entry.inode.is_dir() {
            #[cfg(unix)]
            create_dir_with_mode(&target, entry.inode.permissions().mode())?;
            #[cfg(not(unix))]
            {
                if fs::create_dir(&target).is_err() {
                    fs::create_dir_all(&target)?;
                }
            }
            debug!(partition = part_name, dir = rel_path, "erofs.mkdir");
        } else if entry.inode.is_file() {
            files_to_extract.push((entry.inode, target));
        } else if entry.inode.is_symlink()
            && let Ok(link_target) = fs.read_link_inode(entry.inode)
        {
            let link_str = link_target.to_string_lossy();
            #[cfg(unix)]
            {
                let _ = std::os::unix::fs::symlink(&*link_str, &target);
            }
            #[cfg(not(unix))]
            {
                let _ = fs::write(&target, link_str.as_bytes());
            }
            symlinks_extracted += 1;
            debug!(partition = part_name, symlink = %target.display(), "erofs.extract_symlink");
        }
    }
    // Longest-processing-time-first: the biggest files would otherwise straggle
    // at the end of the walk and leave most workers idle while one writes them.
    files_to_extract.sort_unstable_by_key(|(inode, _)| std::cmp::Reverse(inode.data_size()));

    let files_extracted = symlinks_extracted + files_to_extract.len() as u64;
    let bytes_extracted = AtomicU64::new(0);

    files_to_extract
        .into_par_iter()
        .with_min_len(8)
        .try_for_each(|(inode, target)| -> Result<()> {
            let expected_size = inode.data_size() as usize;
            #[cfg(unix)]
            let mode = inode.permissions().mode();
            if expected_size == 0 {
                #[cfg(unix)]
                create_file_with_mode(&target, mode)
                    .with_context(|| format!("Failed to create {}", target.display()))?;
                #[cfg(not(unix))]
                File::create(&target)
                    .with_context(|| format!("Failed to create {}", target.display()))?;
                return Ok(());
            }

            let mut file = fs.open_inode_file(inode).map_err(|e| {
                anyhow::anyhow!("Failed to open erofs file {}: {:?}", target.display(), e)
            })?;

            FS_COPY_BUF.with(|cell| -> Result<()> {
                let mut copy_buf = cell.borrow_mut();
                if copy_buf.len() < 4 * 1024 * 1024 {
                    copy_buf.resize(4 * 1024 * 1024, 0);
                }
                if expected_size <= copy_buf.len() {
                    let mut filled = 0usize;
                    while filled < expected_size {
                        let n = file.read(&mut copy_buf[filled..expected_size])?;
                        if n == 0 {
                            break;
                        }
                        filled += n;
                    }
                    #[cfg(unix)]
                    {
                        let mut out = create_file_with_mode(&target, mode)
                            .with_context(|| format!("Failed to create {}", target.display()))?;
                        out.write_all(&copy_buf[..filled])
                            .with_context(|| format!("Failed to write {}", target.display()))?;
                    }
                    #[cfg(not(unix))]
                    fs::write(&target, &copy_buf[..filled])
                        .with_context(|| format!("Failed to write {}", target.display()))?;
                    let file_bytes = filled as u64;
                    bytes_extracted.fetch_add(file_bytes, Ordering::Relaxed);
                    pb.inc(file_bytes);
                } else {
                    #[cfg(unix)]
                    let out_file = create_file_with_mode(&target, mode)
                        .with_context(|| format!("Failed to create {}", target.display()))?;
                    #[cfg(not(unix))]
                    let out_file = File::create(&target)
                        .with_context(|| format!("Failed to create {}", target.display()))?;
                    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, out_file);
                    let mut file_bytes = 0u64;
                    loop {
                        let n = file.read(&mut copy_buf)?;
                        if n == 0 {
                            break;
                        }
                        writer.write_all(&copy_buf[..n])?;
                        file_bytes += n as u64;
                    }
                    writer.flush()?;
                    bytes_extracted.fetch_add(file_bytes, Ordering::Relaxed);
                    pb.inc(file_bytes);
                }
                Ok(())
            })?;
            debug!(partition = part_name, file = %target.display(), "erofs.extract_file");
            Ok(())
        })?;
    let bytes_extracted = bytes_extracted.load(Ordering::Relaxed);
    pb.finish();
    info!(
        partition = part_name,
        fs = "erofs",
        files = files_extracted,
        size = %HumanBytes(bytes_extracted),
        duration = %HumanDuration(start_time.elapsed()),
        "fs.extract.done"
    );
    Ok(())
}

#[derive(Clone)]
struct MmapExt4Reader {
    mmap: Arc<Mmap>,
    base: usize,
    end: usize,
}

impl Ext4Read for MmapExt4Reader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = self
            .base
            .checked_add(start_byte as usize)
            .ok_or("ext4 read overflow")?;
        let end = start.checked_add(dst.len()).ok_or("ext4 read overflow")?;
        if end > self.end {
            return Err("ext4 read out of bounds".into());
        }
        let slice = self.mmap.get(start..end).ok_or("ext4 read out of bounds")?;
        dst.copy_from_slice(slice);
        Ok(())
    }
}
#[derive(Clone, Copy)]
struct RawSliceExt4Reader {
    ptr: *const u8,
    len: usize,
}

// SAFETY: RawSliceExt4Reader points to an immutable slice valid for the duration of
// `try_extract_ext4_slice`, whose Rayon tasks join before `try_extract_ext4_slice` returns.
unsafe impl Send for RawSliceExt4Reader {}
unsafe impl Sync for RawSliceExt4Reader {}

impl Ext4Read for RawSliceExt4Reader {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = start_byte as usize;
        let end = start.checked_add(dst.len()).ok_or("ext4 read overflow")?;
        if end > self.len {
            return Err("ext4 read out of bounds".into());
        }
        let src = unsafe { std::slice::from_raw_parts(self.ptr.add(start), dst.len()) };
        dst.copy_from_slice(src);
        Ok(())
    }
}

fn try_extract_ext4_slice(slice: &[u8], output_dir: &Path, part_name: &str) -> Result<()> {
    let start_time = Instant::now();
    let img_size = slice.len() as u64;
    let reader = RawSliceExt4Reader {
        ptr: slice.as_ptr(),
        len: slice.len(),
    };
    let fs =
        Ext4::load(Box::new(reader)).map_err(|e| anyhow::anyhow!("Ext4 load failed: {:?}", e))?;
    let pb = ByteProgress::new(part_name, img_size);
    let mut symlinks_extracted = 0u64;
    let mut regular_files: Vec<(ext4_view::PathBuf, PathBuf)> = Vec::new();
    collect_ext4_entries(
        &fs,
        "/",
        output_dir,
        part_name,
        &mut symlinks_extracted,
        &mut regular_files,
    )?;

    let files_extracted = symlinks_extracted + regular_files.len() as u64;
    let bytes_extracted = AtomicU64::new(0);

    regular_files
        .into_par_iter()
        .with_min_len(64)
        .try_for_each_init(
            || Ext4::load(Box::new(reader)),
            |local_fs, (entry_path, target)| -> Result<()> {
                let fs_ref = local_fs
                    .as_ref()
                    .map_err(|e| anyhow::anyhow!("Ext4 thread init failed: {:?}", e))?;
                let len = extract_ext4_file_buffered(fs_ref, &entry_path, &target)?;
                bytes_extracted.fetch_add(len, Ordering::Relaxed);
                pb.inc(len);
                Ok(())
            },
        )?;

    let bytes_extracted = bytes_extracted.load(Ordering::Relaxed);
    pb.finish();
    info!(
        partition = part_name,
        fs = "ext4",
        files = files_extracted,
        size = %HumanBytes(bytes_extracted),
        duration = %HumanDuration(start_time.elapsed()),
        "fs.extract.done"
    );
    Ok(())
}

fn try_extract_ext4(
    mmap: &Arc<Mmap>,
    base: usize,
    end: usize,
    output_dir: &Path,
    part_name: &str,
) -> Result<()> {
    let start_time = Instant::now();
    let img_size = (end - base) as u64;
    let reader = MmapExt4Reader {
        mmap: Arc::clone(mmap),
        base,
        end,
    };
    let fs = Ext4::load(Box::new(reader.clone()))
        .map_err(|e| anyhow::anyhow!("Ext4 load failed: {:?}", e))?;
    let pb = ByteProgress::new(part_name, img_size);
    let mut symlinks_extracted = 0u64;
    let mut regular_files: Vec<(ext4_view::PathBuf, PathBuf)> = Vec::new();
    collect_ext4_entries(
        &fs,
        "/",
        output_dir,
        part_name,
        &mut symlinks_extracted,
        &mut regular_files,
    )?;

    let files_extracted = symlinks_extracted + regular_files.len() as u64;
    let bytes_extracted = AtomicU64::new(0);

    regular_files
        .into_par_iter()
        .with_min_len(64)
        .try_for_each_init(
            || Ext4::load(Box::new(reader.clone())),
            |local_fs, (entry_path, target)| -> Result<()> {
                let fs_ref = local_fs
                    .as_ref()
                    .map_err(|e| anyhow::anyhow!("Ext4 thread init failed: {:?}", e))?;
                let len = extract_ext4_file_buffered(fs_ref, &entry_path, &target)?;
                bytes_extracted.fetch_add(len, Ordering::Relaxed);
                pb.inc(len);
                debug!(partition = part_name, file = %entry_path.display(), "ext4.extract_file");
                Ok(())
            },
        )?;

    let bytes_extracted = bytes_extracted.load(Ordering::Relaxed);
    pb.finish();
    info!(
        partition = part_name,
        fs = "ext4",
        files = files_extracted,
        size = %HumanBytes(bytes_extracted),
        duration = %HumanDuration(start_time.elapsed()),
        "fs.extract.done"
    );
    Ok(())
}
fn extract_ext4_file_buffered(
    fs_ref: &Ext4,
    entry_path: &ext4_view::PathBuf,
    target: &Path,
) -> Result<u64> {
    let mut file = fs_ref
        .open(entry_path)
        .map_err(|e| anyhow::anyhow!("Ext4 open failed on {}: {:?}", entry_path.display(), e))?;
    let mode = file.metadata().mode() as u32;
    let expected_size = file.metadata().len() as usize;
    if expected_size == 0 {
        File::create(target).with_context(|| format!("Failed to create {}", target.display()))?;
        #[cfg(unix)]
        if mode != 0 {
            let _ = fs::set_permissions(target, std::fs::Permissions::from_mode(mode));
        }
        return Ok(0);
    }
    FS_COPY_BUF.with(|cell| -> Result<u64> {
        let mut copy_buf = cell.borrow_mut();
        let buf_target = expected_size.clamp(4 * 1024 * 1024, 32 * 1024 * 1024);
        if copy_buf.len() < buf_target {
            copy_buf.resize(buf_target, 0);
        }
        if expected_size <= copy_buf.len() {
            let mut filled = 0usize;
            while filled < expected_size {
                let n = file.read(&mut copy_buf[filled..expected_size])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            fs::write(target, &copy_buf[..filled])
                .with_context(|| format!("Failed to write {}", target.display()))?;
            #[cfg(unix)]
            if mode != 0 {
                let _ = fs::set_permissions(target, std::fs::Permissions::from_mode(mode));
            }
            Ok(filled as u64)
        } else {
            let out_file = File::create(target)
                .with_context(|| format!("Failed to create {}", target.display()))?;
            let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, out_file);
            let mut file_bytes = 0u64;
            let mut filled = 0usize;
            loop {
                let n = file.read(&mut copy_buf[filled..])?;
                if n == 0 {
                    if filled > 0 {
                        writer.write_all(&copy_buf[..filled])?;
                        file_bytes += filled as u64;
                    }
                    break;
                }
                filled += n;
                if filled == copy_buf.len() {
                    writer.write_all(&copy_buf)?;
                    file_bytes += filled as u64;
                    filled = 0;
                }
            }
            writer.flush()?;
            #[cfg(unix)]
            if mode != 0 {
                let _ = fs::set_permissions(target, std::fs::Permissions::from_mode(mode));
            }
            Ok(file_bytes)
        }
    })
}

fn collect_ext4_entries(
    fs: &Ext4,
    dir_path: &str,
    current_out_dir: &Path,
    part_name: &str,
    symlinks_extracted: &mut u64,
    regular_files: &mut Vec<(ext4_view::PathBuf, PathBuf)>,
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
            debug!(partition = part_name, dir = path_str, "ext4.mkdir");
            collect_ext4_entries(
                fs,
                path_str,
                &target,
                part_name,
                symlinks_extracted,
                regular_files,
            )?;
        } else if file_type.is_regular_file() {
            regular_files.push((entry_path, target));
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
            *symlinks_extracted += 1;
            debug!(
                partition = part_name,
                symlink = path_str,
                "ext4.extract_symlink"
            );
        }
    }

    Ok(())
}
