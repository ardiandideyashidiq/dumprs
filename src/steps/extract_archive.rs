use anyhow::{bail, Context, Result};
use flate2::bufread::DeflateDecoder;
use flate2::read::GzDecoder;
use indicatif::{HumanBytes, HumanDuration};
use memmap2::{Mmap, MmapMut, MmapOptions};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

use crate::formats::kdz::{unpack_dz, unpack_kdz};
use crate::formats::fs_extract::extract_filesystem_slice;
use crate::formats::liblp::parse_lp_single_extents;
use crate::formats::payload::ZIP_SLICE_MAGIC;
use crate::formats::sevenzip::unpack_sevenzip;
use crate::formats::sparse::{
    extract_stream_or_sparse, extract_stream_or_sparse_pipelined, extract_stream_to_anon,
    extract_stream_to_anon_pipelined, peek_sparse_virtual_size, SharedAnonSlice,
};
use crate::utils::files::{
    can_use_anon_mmap, flatten_dir, get_recursive_files_list, is_early_extract_allowed,
    mark_early_extracted, register_in_memory_image,
};
use crate::utils::partitions::{
    get_partition_names_with_alias, get_partition_type, PartitionType,
};
use crate::utils::progress::ByteProgress;

fn unpack_tar_stream<R: Read>(reader: R, dest_dir: &Path, label: &'static str, total_hint: u64) -> Result<()> {
    let start_time = Instant::now();
    let pb = ByteProgress::new(label, total_hint);
    let mut tar = tar::Archive::new(reader);
    let mut entries_count = 0usize;
    let mut total_bytes = 0u64;
    for entry in tar.entries()? {
        let mut entry = entry?;
        let size = entry.size();
        debug!(entry = %entry.path()?.display(), size = %HumanBytes(size), "tar.entry.extract");
        entry.unpack_in(dest_dir)?;
        pb.inc(size);
        total_bytes += size;
        entries_count += 1;
    }
    pb.finish();
    info!(
        kind = label,
        entries = entries_count,
        size = %HumanBytes(total_bytes),
        duration = %HumanDuration(start_time.elapsed()),
        "archive.unpacked"
    );
    Ok(())
}

fn parse_sparsechunk_target(name: &Path, known_parts: &HashSet<String>) -> Option<String> {
    let file_name = name.file_name()?.to_str()?;
    let (part, rest) = file_name.split_once(".img_sparsechunk.")?;
    let _ = rest.parse::<u64>().ok()?;
    if known_parts.contains(part) {
        Some(part.to_string())
    } else {
        None
    }
}
enum SparseChunkTarget {
    Anon {
        mmap: MmapMut,
        slice: SharedAnonSlice,
        max_len: AtomicU64,
    },
    Disk {
        file: Arc<File>,
        max_len: AtomicU64,
    },
}

fn write_slice_marker(out_path: &Path, start: u64, len: u64, key: &Path) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_path)
        .with_context(|| format!("Failed to create slice marker {}", out_path.display()))?;
    let key_str = key.to_string_lossy();
    f.write_all(ZIP_SLICE_MAGIC)?;
    f.write_all(&start.to_le_bytes())?;
    f.write_all(&len.to_le_bytes())?;
    f.write_all(key_str.as_bytes())?;
    Ok(())
}

pub fn unpack_archive(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let filename = archive_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    fs::create_dir_all(dest_dir)?;

    if filename.ends_with(".zip") {
        let start_time = Instant::now();
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to mmap {}", archive_path.display()))?;
        let mut zip = zip::ZipArchive::new(Cursor::new(&mmap[..]))
            .with_context(|| format!("Failed to parse zip {}", archive_path.display()))?;

        let abs_archive = fs::canonicalize(archive_path)
            .unwrap_or_else(|_| archive_path.to_path_buf());
        let known_parts: HashSet<String> = get_partition_names_with_alias().into_iter().collect();
        let total_entries = zip.len();
        let mut total_bytes = 0u64;
        let mut dirs = HashSet::new();
        let mut file_indices = Vec::with_capacity(total_entries);
        let mut sparsechunk_targets: HashMap<PathBuf, SparseChunkTarget> = HashMap::new();
        let mut sparsechunk_totals: HashMap<PathBuf, (usize, u64)> = HashMap::new();

        for i in 0..total_entries {
            let entry = zip.by_index_raw(i)?;
            let size = entry.size();
            total_bytes += size;
            let mangled = entry.mangled_name();
            let out_path = dest_dir.join(&mangled);
            if entry.is_dir() {
                dirs.insert(out_path);
            } else {
                if let Some(parent) = out_path.parent() {
                    dirs.insert(parent.to_path_buf());
                }
                file_indices.push((i, size));
            }
        }
        for dir in &dirs {
            fs::create_dir_all(dir)?;
        }

        for &(i, sz) in &file_indices {
            let entry = zip.by_index_raw(i)?;
            let mangled = entry.mangled_name();
            if let Some(part) = parse_sparsechunk_target(&mangled, &known_parts) {
                let parent = dest_dir
                    .join(&mangled)
                    .parent()
                    .unwrap_or(dest_dir)
                    .to_path_buf();
                let target_img = parent.join(format!("{}.img", part));
                let stat = sparsechunk_totals.entry(target_img).or_insert((i, 0));
                stat.1 += sz;
            }
        }

        for (target_img, (sample_idx, group_bytes)) in sparsechunk_totals {
            let mut virtual_size = None;
            if can_use_anon_mmap(group_bytes) {
                let entry = zip.by_index_raw(sample_idx)?;
                let start = entry.data_start() as usize;
                let comp_end = start.saturating_add(entry.compressed_size() as usize);
                let compression = entry.compression();
                drop(entry);
                let mut hdr_buf = [0u8; 64];
                let mut got = 0usize;
                if compression == zip::CompressionMethod::Deflated && comp_end <= mmap.len() {
                    let mut dec = DeflateDecoder::new(&mmap[start..comp_end]);
                    while got < 28 {
                        let n = dec.read(&mut hdr_buf[got..])?;
                        if n == 0 {
                            break;
                        }
                        got += n;
                    }
                } else if compression == zip::CompressionMethod::Stored && comp_end <= mmap.len() {
                    got = 28.min(comp_end - start);
                    hdr_buf[..got].copy_from_slice(&mmap[start..start + got]);
                }
                if got >= 28 {
                    virtual_size = peek_sparse_virtual_size(&hdr_buf[..got])?;
                }
            }

            if let Some(vsize) = virtual_size
                && let Ok(mut anon) = MmapOptions::new().len(vsize as usize).map_anon()
            {
                let slice = SharedAnonSlice::from_mmap_mut(&mut anon);
                sparsechunk_targets.insert(
                    target_img,
                    SparseChunkTarget::Anon {
                        mmap: anon,
                        slice,
                        max_len: AtomicU64::new(vsize),
                    },
                );
            } else {
                let f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&target_img)
                    .with_context(|| format!("Failed to create {}", target_img.display()))?;
                sparsechunk_targets.insert(
                    target_img,
                    SparseChunkTarget::Disk {
                        file: Arc::new(f),
                        max_len: AtomicU64::new(0),
                    },
                );
            }
        }

        file_indices.sort_unstable_by(|a, b| b.1.cmp(&a.1));

        info!(
            archive = %archive_path.display(),
            entries = total_entries,
            size = %HumanBytes(total_bytes),
            "zip.extract.start"
        );
        let pb = ByteProgress::new("zip", total_bytes);

        file_indices
            .into_par_iter()
            .with_max_len(1)
            .try_for_each_init(
                || (zip.clone(), vec![0u8; 1024 * 1024]),
                |(local_zip, buf), (i, _)| -> Result<()> {
                    let raw_entry = local_zip.by_index_raw(i)?;
                    if raw_entry.is_dir() {
                        return Ok(());
                    }

                    let name = raw_entry.mangled_name();
                    let size = raw_entry.size();
                    let comp_size = raw_entry.compressed_size() as usize;
                    let start = raw_entry.data_start() as usize;
                    let comp_end = start.saturating_add(comp_size);
                    let compression = raw_entry.compression();
                    drop(raw_entry);

                    debug!(
                        index = i + 1,
                        total = total_entries,
                        entry = %name.display(),
                        size = %HumanBytes(size),
                        "zip.entry.extract"
                    );

                    let out_path = dest_dir.join(&name);
                    if let Some(parent) = out_path.parent()
                        && !dirs.contains(parent)
                    {
                        fs::create_dir_all(parent)?;
                    }

                    if let Some(part) = parse_sparsechunk_target(&name, &known_parts) {
                        let parent = out_path.parent().unwrap_or(dest_dir);
                        let target_img = parent.join(format!("{}.img", part));
                        if let Some(target) = sparsechunk_targets.get(&target_img) {
                            match target {
                                SparseChunkTarget::Anon { slice, max_len, .. } => {
                                    let end_off =
                                        if compression == zip::CompressionMethod::Deflated
                                            && comp_end <= mmap.len()
                                        {
                                            let mut dec = DeflateDecoder::new(&mmap[start..comp_end]);
                                            extract_stream_to_anon(
                                                &mut dec, &[], *slice, true, buf, &pb,
                                            )?
                                        } else if compression == zip::CompressionMethod::Stored
                                            && comp_end <= mmap.len()
                                        {
                                            let mut s = &mmap[start..comp_end];
                                            extract_stream_to_anon(
                                                &mut s, &[], *slice, true, buf, &pb,
                                            )?
                                        } else {
                                            let mut zf = local_zip.by_index(i)?;
                                            extract_stream_to_anon(
                                                &mut zf, &[], *slice, true, buf, &pb,
                                            )?
                                        };
                                    max_len.fetch_max(end_off, Ordering::Relaxed);
                                }
                                SparseChunkTarget::Disk { file, max_len } => {
                                    let (_, end_off) =
                                        if compression == zip::CompressionMethod::Deflated
                                            && comp_end <= mmap.len()
                                        {
                                            let mut dec = DeflateDecoder::new(&mmap[start..comp_end]);
                                            extract_stream_or_sparse(&mut dec, file, true, buf, &pb)?
                                        } else if compression == zip::CompressionMethod::Stored
                                            && comp_end <= mmap.len()
                                        {
                                            let mut s = &mmap[start..comp_end];
                                            extract_stream_or_sparse(&mut s, file, true, buf, &pb)?
                                        } else {
                                            let mut zf = local_zip.by_index(i)?;
                                            extract_stream_or_sparse(&mut zf, file, true, buf, &pb)?
                                        };
                                    max_len.fetch_max(end_off, Ordering::Relaxed);
                                }
                            }
                            return Ok(());
                        }
                    }

                    let is_img = name
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("img"));

                    if is_img
                        && size >= 128 * 1024 * 1024
                        && compression == zip::CompressionMethod::Deflated
                        && comp_end <= mmap.len()
                        && can_use_anon_mmap(size)
                    {
                        let mut dec = DeflateDecoder::new(&mmap[start..comp_end]);
                        let mut head = [0u8; 64];
                        let mut got = 0usize;
                        while got < 64 {
                            let n = dec.read(&mut head[got..])?;
                            if n == 0 {
                                break;
                            }
                            got += n;
                        }
                        let alloc_len = if got >= 28
                            && let Some(vsize) = peek_sparse_virtual_size(&head[..got])?
                        {
                            vsize as usize
                        } else {
                            size as usize
                        };
                        if let Ok(mut anon) = MmapOptions::new().len(alloc_len).map_anon() {
                            let slice = SharedAnonSlice::from_mmap_mut(&mut anon);
                            let is_super = name
                                .file_name()
                                .and_then(|n| n.to_str())
                                .is_some_and(|n| n.starts_with("super"));
                            let out_root = dest_dir.parent().map(|p| p.to_path_buf());
                            let early_ok = is_super && is_early_extract_allowed() && out_root.is_some();

                            let final_len = rayon::scope(|scope| -> Result<u64> {
                                let mut parsed_lp = false;
                                let mut pending_parts: Vec<(String, usize, usize)> = Vec::new();
                                let mut next_idx = 0usize;
                                extract_stream_to_anon_pipelined(
                                    dec,
                                    &head[..got],
                                    slice,
                                    true,
                                    &pb,
                                    |cur_off| {
                                        if !early_ok {
                                            return;
                                        }
                                        if !parsed_lp && cur_off >= 2 * 1024 * 1024 {
                                            parsed_lp = true;
                                            let meta = unsafe {
                                                slice.subslice(0, (2 * 1024 * 1024).min(alloc_len))
                                            };
                                            if let Ok(parts) = parse_lp_single_extents(meta) {
                                                pending_parts = parts;
                                            }
                                        }
                                        while next_idx < pending_parts.len() {
                                            let (ref pname, pstart, pend) = pending_parts[next_idx];
                                            if (cur_off as usize) < pend || pend > alloc_len {
                                                break;
                                            }
                                            next_idx += 1;
                                            if get_partition_type(pname)
                                                == Some(PartitionType::Filesystem)
                                                && let Some(ref root) = out_root
                                            {
                                                let part_name = pname.clone();
                                                let part_out = root.join(&part_name);
                                                let part_bytes = pend - pstart;
                                                scope.spawn(move |_| {
                                                    info!(
                                                        partition = %part_name,
                                                        size = %HumanBytes(part_bytes as u64),
                                                        mode = "streaming",
                                                        "partition.extract.begin"
                                                    );
                                                    let pslice =
                                                        unsafe { slice.subslice(pstart, pend) };
                                                    if extract_filesystem_slice(
                                                        pslice, &part_out, &part_name,
                                                    )
                                                    .is_ok()
                                                    {
                                                        mark_early_extracted(part_out);
                                                    }
                                                });
                                            }
                                        }
                                    },
                                )
                            })?;
                            let ro_mmap = Arc::new(anon.make_read_only()?);
                            let mem_key = PathBuf::from(format!("mem://{}", out_path.display()));
                            register_in_memory_image(mem_key.clone(), ro_mmap);
                            write_slice_marker(&out_path, 0, final_len, &mem_key)?;
                            return Ok(());
                        }
                    }

                    let mut out_file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&out_path)?;

                    if compression == zip::CompressionMethod::Stored && comp_end <= mmap.len() {
                        let is_payload = name.file_name().and_then(|n| n.to_str())
                            == Some("payload.bin")
                            && size >= 4
                            && &mmap[start..start + 4] == b"CrAU";
                        if is_payload && let Some(abs_str) = abs_archive.to_str() {
                            out_file.write_all(ZIP_SLICE_MAGIC)?;
                            out_file.write_all(&(start as u64).to_le_bytes())?;
                            out_file.write_all(&size.to_le_bytes())?;
                            out_file.write_all(abs_str.as_bytes())?;
                            pb.inc(size);
                        } else {
                            let mut slice = &mmap[start..comp_end];
                            let (was_sparse, end_off) = extract_stream_or_sparse(
                                &mut slice, &out_file, is_img, buf, &pb,
                            )?;
                            if was_sparse {
                                out_file.set_len(end_off)?;
                            }
                        }
                    } else if compression == zip::CompressionMethod::Deflated
                        && comp_end <= mmap.len()
                    {
                        let mut dec = DeflateDecoder::new(&mmap[start..comp_end]);
                        let (was_sparse, end_off) = if size >= 128 * 1024 * 1024 {
                            extract_stream_or_sparse_pipelined(dec, &out_file, is_img, &pb)?
                        } else {
                            extract_stream_or_sparse(&mut dec, &out_file, is_img, buf, &pb)?
                        };
                        if was_sparse {
                            out_file.set_len(end_off)?;
                        }
                    } else {
                        let mut zip_file = local_zip.by_index(i)?;
                        let (was_sparse, end_off) = extract_stream_or_sparse(
                            &mut zip_file,
                            &out_file,
                            is_img,
                            buf,
                            &pb,
                        )?;
                        if was_sparse {
                            out_file.set_len(end_off)?;
                        }
                    }

                    Ok(())
                },
            )?;

        for (target_img, target) in sparsechunk_targets {
            match target {
                SparseChunkTarget::Anon { mmap, max_len, .. } => {
                    let final_len = max_len.load(Ordering::Relaxed);
                    let ro_mmap = Arc::new(mmap.make_read_only()?);
                    let mem_key = PathBuf::from(format!("mem://{}", target_img.display()));
                    register_in_memory_image(mem_key.clone(), ro_mmap);
                    write_slice_marker(&target_img, 0, final_len, &mem_key)?;
                    info!(
                        target = %target_img.file_name().unwrap_or_default().to_string_lossy(),
                        size = %HumanBytes(final_len),
                        mode = "in_memory",
                        "zip.sparsechunks.merged"
                    );
                }
                SparseChunkTarget::Disk { file, max_len } => {
                    let final_len = max_len.load(Ordering::Relaxed);
                    file.set_len(final_len)?;
                    info!(
                        target = %target_img.file_name().unwrap_or_default().to_string_lossy(),
                        size = %HumanBytes(final_len),
                        "zip.sparsechunks.merged"
                    );
                }
            }
        }

        pb.finish();
        info!(
            entries = total_entries,
            size = %HumanBytes(total_bytes),
            duration = %HumanDuration(start_time.elapsed()),
            "zip.extract.done"
        );
        return Ok(());
    }

    if filename.ends_with(".tar.md5") || filename.ends_with(".tar") {
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        info!(archive = %archive_path.display(), size = %HumanBytes(len), "tar.extract.start");
        return unpack_tar_stream(BufReader::with_capacity(1024 * 1024, file), dest_dir, "tar", len);
    }

    if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        info!(archive = %archive_path.display(), size = %HumanBytes(len), "targz.extract.start");
        let gz = GzDecoder::new(BufReader::with_capacity(1024 * 1024, file));
        return unpack_tar_stream(gz, dest_dir, "tar.gz", len.saturating_mul(2));
    }

    if filename.ends_with(".tar.bz2") || filename.ends_with(".tbz2") {
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        info!(archive = %archive_path.display(), size = %HumanBytes(len), "tarbz2.extract.start");
        let bz = bzip2::read::BzDecoder::new(BufReader::with_capacity(1024 * 1024, file));
        return unpack_tar_stream(bz, dest_dir, "tar.bz2", len.saturating_mul(2));
    }

    if filename.ends_with(".tar.xz") || filename.ends_with(".txz") {
        let file = File::open(archive_path)
            .with_context(|| format!("Failed to open {}", archive_path.display()))?;
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        info!(archive = %archive_path.display(), size = %HumanBytes(len), "tarxz.extract.start");
        let xz = xz2::read::XzDecoder::new(BufReader::with_capacity(1024 * 1024, file));
        return unpack_tar_stream(xz, dest_dir, "tar.xz", len.saturating_mul(2));
    }

    if filename.ends_with(".kdz") {
        return unpack_kdz(archive_path, dest_dir);
    }

    if filename.ends_with(".dz") {
        return unpack_dz(archive_path, dest_dir);
    }

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
    debug!(archive = %archive_path.display(), is_nested, "archive.extract.enter");

    unpack_archive(archive_path, extracted_archive_path)?;

    if is_nested {
        debug!(archive = %archive_path.display(), "archive.nested.unlink");
        let _ = fs::remove_file(archive_path);
    }

    flatten_dir(extracted_archive_path)?;

    let extracted_files = get_recursive_files_list(extracted_archive_path, true);
    let matches: Vec<_> = extracted_files
        .into_iter()
        .filter(|f| f.to_string_lossy().ends_with(".tar.md5"))
        .collect();

    for file in matches {
        let nested_archive = extracted_archive_path.join(&file);
        if !nested_archive.is_file() {
            continue;
        }
        info!(nested = %nested_archive.display(), "archive.nested.found");
        extract_archive(&nested_archive, extracted_archive_path, true)?;
    }

    Ok(())
}
