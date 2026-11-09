use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info};
use crate::formats::kdz::{unpack_dz, unpack_kdz};
use crate::formats::sevenzip::unpack_sevenzip;
use crate::utils::files::{flatten_dir, get_recursive_files_list};

fn create_progress_bar(total: u64, msg: &'static str) -> ProgressBar {
    let pb = crate::utils::progress::get_multi_progress().add(ProgressBar::new(total));
    if let Ok(style) = ProgressStyle::with_template(
        "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}",
    ) {
        pb.set_style(style.progress_chars("=>-"));
    }
    pb.set_message(msg);
    pb
}

pub fn unpack_archive(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let filename = archive_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    fs::create_dir_all(dest_dir)?;

    if filename.ends_with(".zip") {
        info!("Unpacking ZIP archive: {}", archive_path.display());
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to mmap {}", archive_path.display()))?;
        let zip = zip::ZipArchive::new(Cursor::new(&mmap[..]))
            .with_context(|| format!("Failed to parse zip {}", archive_path.display()))?;

        let total_entries = zip.len();
        let pb = create_progress_bar(total_entries as u64, "Extracting zip entries");
        let verbose = tracing::enabled!(tracing::Level::DEBUG);

        // Pre-create all parent directories once to avoid redundant stat/mkdir syscalls across threads
        let mut dirs = HashSet::new();
        for name in zip.file_names() {
            let sanitized: PathBuf = Path::new(name)
                .components()
                .filter(|c| matches!(c, std::path::Component::Normal(_)))
                .collect();
            let out_path = dest_dir.join(&sanitized);
            if name.ends_with('/') || name.ends_with('\\') {
                dirs.insert(out_path);
            } else if let Some(parent) = out_path.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }
        for dir in &dirs {
            fs::create_dir_all(dir)?;
        }

        (0..total_entries).into_par_iter().try_for_each_init(
            || (zip.clone(), vec![0u8; 1024 * 1024]),
            |(local_zip, buf), i| -> Result<()> {
                let mut zip_file = local_zip.by_index(i)?;
                if zip_file.is_dir() {
                    pb.inc(1);
                    return Ok(());
                }

                let name = zip_file.mangled_name();
                let size = zip_file.size();
                if verbose {
                    let name_str = name.to_string_lossy();
                    info!(
                        "Extracting [{}/{}] {} ({})",
                        i + 1,
                        total_entries,
                        name_str,
                        HumanBytes(size)
                    );
                }

                let out_path = dest_dir.join(&name);
                if let Some(parent) = out_path.parent() && !dirs.contains(parent) {
                    fs::create_dir_all(parent)?;
                }

                let mut out_file = File::create(&out_path)?;
                if zip_file.compression() == zip::CompressionMethod::Stored {
                    let start = zip_file.data_start() as usize;
                    let end = start.saturating_add(size as usize);
                    if end <= mmap.len() {
                        out_file.write_all(&mmap[start..end])?;
                    } else {
                        loop {
                            let n = zip_file.read(buf)?;
                            if n == 0 {
                                break;
                            }
                            out_file.write_all(&buf[..n])?;
                        }
                    }
                } else {
                    loop {
                        let n = zip_file.read(buf)?;
                        if n == 0 {
                            break;
                        }
                        out_file.write_all(&buf[..n])?;
                    }
                }

                pb.inc(1);
                Ok(())
            },
        )?;

        pb.finish_and_clear();
        info!("ZIP extraction finished ({} entries extracted)", total_entries);
        return Ok(());
    }

    if filename.ends_with(".tar.md5") || filename.ends_with(".tar") {
        info!("Unpacking TAR archive: {}", archive_path.display());
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let mut tar = tar::Archive::new(BufReader::with_capacity(1024 * 1024, file));
        for entry in tar.entries()? {
            let mut entry = entry?;
            debug!("Extracting {} ({})", entry.path()?.display(), HumanBytes(entry.size()));
            entry.unpack_in(dest_dir)?;
        }
        return Ok(());
    }

    if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        info!("Unpacking TAR.GZ archive: {}", archive_path.display());
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let gz = GzDecoder::new(BufReader::with_capacity(1024 * 1024, file));
        let mut tar = tar::Archive::new(gz);
        for entry in tar.entries()? {
            let mut entry = entry?;
            debug!("Extracting {} ({})", entry.path()?.display(), HumanBytes(entry.size()));
            entry.unpack_in(dest_dir)?;
        }
        return Ok(());
    }

    if filename.ends_with(".tar.bz2") || filename.ends_with(".tbz2") {
        info!("Unpacking TAR.BZ2 archive: {}", archive_path.display());
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let bz = bzip2::read::BzDecoder::new(BufReader::with_capacity(1024 * 1024, file));
        let mut tar = tar::Archive::new(bz);
        for entry in tar.entries()? {
            let mut entry = entry?;
            debug!("Extracting {} ({})", entry.path()?.display(), HumanBytes(entry.size()));
            entry.unpack_in(dest_dir)?;
        }
        return Ok(());
    }

    if filename.ends_with(".tar.xz") || filename.ends_with(".txz") {
        info!("Unpacking TAR.XZ archive: {}", archive_path.display());
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let xz = xz2::read::XzDecoder::new(BufReader::with_capacity(1024 * 1024, file));
        let mut tar = tar::Archive::new(xz);
        for entry in tar.entries()? {
            let mut entry = entry?;
            debug!("Extracting {} ({})", entry.path()?.display(), HumanBytes(entry.size()));
            entry.unpack_in(dest_dir)?;
        }
        return Ok(());
    }

    if filename.ends_with(".kdz") {
        return unpack_kdz(archive_path, dest_dir);
    }

    if filename.ends_with(".dz") {
        return unpack_dz(archive_path, dest_dir);
    }

    // Default: try 7-Zip (handles .7z, .bin, and any other archive formats)
    if let Err(e) = unpack_sevenzip(archive_path, dest_dir) {
        bail!("Failed to extract archive {}: {}", archive_path.display(), e);
    }

    Ok(())
}

pub fn extract_archive(
    archive_path: &Path,
    extracted_archive_path: &Path,
    is_nested: bool,
) -> Result<()> {
    debug!("Extracting archive: {}", archive_path.display());

    unpack_archive(archive_path, extracted_archive_path)?;

    if is_nested {
        debug!("Archive is nested, unlinking {}", archive_path.display());
        let _ = fs::remove_file(archive_path);
    }

    // Flatten the directory so all files are at the root
    flatten_dir(extracted_archive_path)?;

    // Check for nested archives matching *.tar.md5
    let extracted_files = get_recursive_files_list(extracted_archive_path, true);

    let matches: Vec<_> = extracted_files
        .into_iter()
        .filter(|f| f.to_string_lossy().ends_with(".tar.md5"))
        .collect();
    for file in matches {
        let nested_archive = extracted_archive_path.join(&file);
        info!("Found nested archive: {}", nested_archive.display());

        if !nested_archive.is_file() {
            debug!("Nested archive {} already handled, skipping", nested_archive.display());
            continue;
        }

        extract_archive(&nested_archive, extracted_archive_path, true)?;
    }

    debug!("Extracted archive: {}", archive_path.display());
    Ok(())
}
