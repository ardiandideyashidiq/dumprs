use anyhow::{Context, Result, bail};
use byteorder::{LittleEndian, ReadBytesExt};
use indicatif::{HumanBytes, HumanDuration};
use memmap2::Mmap;
use rayon::prelude::*;
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info};

use crate::formats::payload::ZIP_SLICE_MAGIC;
use crate::formats::sparse::{index_sparse_mmap, read_sparse_range, write_sparse_range};
use crate::utils::files::resolve_image_mmap_with_backing;
use crate::utils::progress::ByteProgress;
thread_local! {
    static LP_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

pub const LP_METADATA_GEOMETRY_MAGIC: u32 = 0x616c_4467;
pub const LP_METADATA_HEADER_MAGIC: u32 = 0x414c_5030;
pub const LP_SECTOR_SIZE: u64 = 512;
pub const LP_TARGET_TYPE_LINEAR: u32 = 0;

#[derive(Debug, Clone, Copy)]
pub struct TableDescriptor {
    pub offset: u32,
    pub num_entries: u32,
    pub entry_size: u32,
}

impl TableDescriptor {
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let offset = reader.read_u32::<LittleEndian>()?;
        let num_entries = reader.read_u32::<LittleEndian>()?;
        let entry_size = reader.read_u32::<LittleEndian>()?;
        Ok(Self {
            offset,
            num_entries,
            entry_size,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PartitionEntry {
    pub name: String,
    pub attributes: u32,
    pub first_extent_index: u32,
    pub num_extents: u32,
    pub group_index: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct ExtentEntry {
    pub num_sectors: u64,
    pub target_type: u32,
    pub target_data: u64,
    pub target_source: u32,
}
pub fn parse_lp_single_extents(meta_slice: &[u8]) -> Result<Vec<(String, usize, usize)>> {
    if meta_slice.len() < 12288 + 128 {
        bail!("LP slice too small");
    }
    let mut geom_cursor = &meta_slice[4096..];
    if geom_cursor.read_u32::<LittleEndian>()? != LP_METADATA_GEOMETRY_MAGIC {
        bail!("Invalid LP geometry magic");
    }
    let _struct_size = geom_cursor.read_u32::<LittleEndian>()?;
    geom_cursor = &geom_cursor[32..];
    let metadata_max_size = geom_cursor.read_u32::<LittleEndian>()?;
    let metadata_slot_count = geom_cursor.read_u32::<LittleEndian>()?;

    let mut header_offset = 12288usize;
    let mut hdr_cursor = &meta_slice[header_offset..];
    if hdr_cursor.read_u32::<LittleEndian>()? != LP_METADATA_HEADER_MAGIC {
        let backup_offset =
            12288usize + (metadata_max_size as usize) * (metadata_slot_count as usize);
        if backup_offset + 128 > meta_slice.len() {
            bail!("Invalid LP backup offset");
        }
        hdr_cursor = &meta_slice[backup_offset..];
        if hdr_cursor.read_u32::<LittleEndian>()? != LP_METADATA_HEADER_MAGIC {
            bail!("Invalid LP header magic");
        }
        header_offset = backup_offset;
    }
    let _major = hdr_cursor.read_u16::<LittleEndian>()?;
    let _minor = hdr_cursor.read_u16::<LittleEndian>()?;
    let header_size = hdr_cursor.read_u32::<LittleEndian>()?;
    hdr_cursor = &hdr_cursor[32..];
    let tables_size = hdr_cursor.read_u32::<LittleEndian>()?;
    hdr_cursor = &hdr_cursor[32..];
    let partitions_desc = TableDescriptor::read_from(&mut hdr_cursor)?;
    let extents_desc = TableDescriptor::read_from(&mut hdr_cursor)?;

    let tables_offset = header_offset + header_size as usize;
    let tables_end = tables_offset
        .saturating_add(tables_size as usize)
        .min(meta_slice.len());
    let tables_data = &meta_slice[tables_offset..tables_end];

    let mut partitions = Vec::new();
    let part_base = partitions_desc.offset as usize;
    let part_entry_sz = partitions_desc.entry_size as usize;
    for i in 0..partitions_desc.num_entries as usize {
        let entry_start = part_base + i * part_entry_sz;
        if entry_start + part_entry_sz > tables_data.len() {
            break;
        }
        let entry_bytes = &tables_data[entry_start..entry_start + part_entry_sz];
        let name_bytes = &entry_bytes[0..36];
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(36);
        let name = String::from_utf8_lossy(&name_bytes[..name_len])
            .trim()
            .to_string();
        let mut cursor = &entry_bytes[36..];
        let attributes = cursor.read_u32::<LittleEndian>()?;
        let first_extent_index = cursor.read_u32::<LittleEndian>()?;
        let num_extents = cursor.read_u32::<LittleEndian>()?;
        let group_index = cursor.read_u32::<LittleEndian>()?;
        if !name.is_empty() {
            partitions.push(PartitionEntry {
                name,
                attributes,
                first_extent_index,
                num_extents,
                group_index,
            });
        }
    }

    let mut extents = Vec::new();
    let ext_base = extents_desc.offset as usize;
    let ext_entry_sz = extents_desc.entry_size as usize;
    for i in 0..extents_desc.num_entries as usize {
        let entry_start = ext_base + i * ext_entry_sz;
        if entry_start + ext_entry_sz > tables_data.len() {
            break;
        }
        let mut cursor = &tables_data[entry_start..entry_start + ext_entry_sz];
        extents.push(ExtentEntry {
            num_sectors: cursor.read_u64::<LittleEndian>()?,
            target_type: cursor.read_u32::<LittleEndian>()?,
            target_data: cursor.read_u64::<LittleEndian>()?,
            target_source: cursor.read_u32::<LittleEndian>()?,
        });
    }

    let non_empty_a: HashSet<String> = partitions
        .iter()
        .filter(|p| p.num_extents > 0 && p.name.ends_with("_a"))
        .map(|p| p.name[..p.name.len() - 2].to_string())
        .collect();

    let mut out = Vec::new();
    for p in partitions {
        if p.num_extents != 1 {
            continue;
        }
        if let Some(stem) = p.name.strip_suffix("_b")
            && non_empty_a.contains(stem)
        {
            continue;
        }
        let Some(ext) = extents.get(p.first_extent_index as usize) else {
            continue;
        };
        if ext.target_type != LP_TARGET_TYPE_LINEAR {
            continue;
        }
        let canonical = p
            .name
            .strip_suffix("_a")
            .or_else(|| p.name.strip_suffix("_b"))
            .unwrap_or(&p.name)
            .to_string();
        let start = (ext.target_data * LP_SECTOR_SIZE) as usize;
        let len = (ext.num_sectors * LP_SECTOR_SIZE) as usize;
        if len > 0 {
            out.push((canonical, start, start + len));
        }
    }
    out.sort_unstable_by_key(|&(_, _, end)| end);
    Ok(out)
}

pub fn lpunpack(super_image_path: &Path, output_dir: &Path) -> Result<()> {
    let start_time = Instant::now();
    if !output_dir.exists() {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("Failed to create output directory {}", output_dir.display())
        })?;
    }
    let raw_meta_len = fs::metadata(super_image_path).map(|m| m.len()).unwrap_or(0) as usize;
    let resolved: Option<(Arc<Mmap>, usize, usize, std::path::PathBuf)> =
        if (32..4096).contains(&raw_meta_len) || raw_meta_len > 8 * 1024 * 1024 {
            Some(resolve_image_mmap_with_backing(super_image_path)?)
        } else {
            None
        };

    let mut small_buf = Vec::new();
    let (mmap, base_start, backing_key): (&[u8], usize, std::path::PathBuf) =
        if let Some((ref arc_m, start, end, ref key)) = resolved {
            (&arc_m[start..end], start, key.clone())
        } else {
            if raw_meta_len < 12288 + 128 {
                bail!(
                    "Super image {} is too small ({} bytes)",
                    super_image_path.display(),
                    raw_meta_len
                );
            }
            let mut file = File::open(super_image_path).with_context(|| {
                format!("Failed to open super image {}", super_image_path.display())
            })?;
            LP_BUF.with(|cell| -> Result<()> {
                let mut b = cell.borrow_mut();
                b.resize(raw_meta_len, 0);
                file.read_exact(&mut b)?;
                small_buf = std::mem::take(&mut *b);
                Ok(())
            })?;
            let abs_super = fs::canonicalize(super_image_path)
                .unwrap_or_else(|_| super_image_path.to_path_buf());
            (&small_buf, 0, abs_super)
        };

    let file_len = mmap.len();
    if file_len < 12288 + 128 {
        bail!(
            "Super image {} is too small ({} bytes)",
            super_image_path.display(),
            file_len
        );
    }
    let sparse_index = index_sparse_mmap(mmap)?;
    let mut header_window = Vec::new();
    let meta_slice: &[u8] = if let Some((virtual_size, ref spans)) = sparse_index {
        let window_len = (virtual_size as usize).min(2 * 1024 * 1024);
        header_window.resize(window_len, 0);
        read_sparse_range(mmap, spans, 0, &mut header_window)?;
        &header_window
    } else {
        mmap
    };

    let mut geom_cursor = &meta_slice[4096..];
    let geom_magic = geom_cursor.read_u32::<LittleEndian>()?;
    if geom_magic != LP_METADATA_GEOMETRY_MAGIC {
        bail!(
            "Invalid LP geometry magic: 0x{:08x} (expected 0x{:08x})",
            geom_magic,
            LP_METADATA_GEOMETRY_MAGIC
        );
    }

    let _struct_size = geom_cursor.read_u32::<LittleEndian>()?;
    geom_cursor = &geom_cursor[32..];
    let metadata_max_size = geom_cursor.read_u32::<LittleEndian>()?;
    let metadata_slot_count = geom_cursor.read_u32::<LittleEndian>()?;
    let _logical_block_size = geom_cursor.read_u32::<LittleEndian>()?;

    let mut header_offset = 12288usize;
    let mut hdr_cursor = &meta_slice[header_offset..];
    let mut header_magic = hdr_cursor.read_u32::<LittleEndian>()?;
    if header_magic != LP_METADATA_HEADER_MAGIC {
        let backup_offset =
            12288usize + (metadata_max_size as usize) * (metadata_slot_count as usize);
        if backup_offset + 128 > meta_slice.len() {
            bail!("Invalid LP backup metadata offset {}", backup_offset);
        }
        hdr_cursor = &meta_slice[backup_offset..];
        header_magic = hdr_cursor.read_u32::<LittleEndian>()?;
        if header_magic != LP_METADATA_HEADER_MAGIC {
            bail!(
                "Invalid LP header magic: 0x{:08x} (expected 0x{:08x})",
                header_magic,
                LP_METADATA_HEADER_MAGIC
            );
        }
        header_offset = backup_offset;
    }

    let _major_version = hdr_cursor.read_u16::<LittleEndian>()?;
    let _minor_version = hdr_cursor.read_u16::<LittleEndian>()?;
    let header_size = hdr_cursor.read_u32::<LittleEndian>()?;
    hdr_cursor = &hdr_cursor[32..];
    let tables_size = hdr_cursor.read_u32::<LittleEndian>()?;
    hdr_cursor = &hdr_cursor[32..];

    let partitions_desc = TableDescriptor::read_from(&mut hdr_cursor)?;
    let extents_desc = TableDescriptor::read_from(&mut hdr_cursor)?;
    let _groups_desc = TableDescriptor::read_from(&mut hdr_cursor)?;
    let _block_devices_desc = TableDescriptor::read_from(&mut hdr_cursor)?;

    debug!(
        partitions = partitions_desc.num_entries,
        extents = extents_desc.num_entries,
        tables_size,
        "lpunpack.metadata"
    );

    let tables_offset = header_offset + header_size as usize;
    let tables_end = tables_offset
        .saturating_add(tables_size as usize)
        .min(meta_slice.len());
    let tables_data = &meta_slice[tables_offset..tables_end];
    let mut partitions = Vec::new();
    let part_base = partitions_desc.offset as usize;
    let part_entry_sz = partitions_desc.entry_size as usize;
    for i in 0..partitions_desc.num_entries as usize {
        let entry_start = part_base + i * part_entry_sz;
        if entry_start + part_entry_sz > tables_data.len() {
            break;
        }
        let entry_bytes = &tables_data[entry_start..entry_start + part_entry_sz];
        let name_bytes = &entry_bytes[0..36];
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(36);
        let name = String::from_utf8_lossy(&name_bytes[..name_len])
            .trim()
            .to_string();

        let mut cursor = &entry_bytes[36..];
        let attributes = cursor.read_u32::<LittleEndian>()?;
        let first_extent_index = cursor.read_u32::<LittleEndian>()?;
        let num_extents = cursor.read_u32::<LittleEndian>()?;
        let group_index = cursor.read_u32::<LittleEndian>()?;

        if !name.is_empty() {
            partitions.push(PartitionEntry {
                name,
                attributes,
                first_extent_index,
                num_extents,
                group_index,
            });
        }
    }

    let mut extents = Vec::new();
    let ext_base = extents_desc.offset as usize;
    let ext_entry_sz = extents_desc.entry_size as usize;
    for i in 0..extents_desc.num_entries as usize {
        let entry_start = ext_base + i * ext_entry_sz;
        if entry_start + ext_entry_sz > tables_data.len() {
            break;
        }
        let entry_bytes = &tables_data[entry_start..entry_start + ext_entry_sz];
        let mut cursor = entry_bytes;
        let num_sectors = cursor.read_u64::<LittleEndian>()?;
        let target_type = cursor.read_u32::<LittleEndian>()?;
        let target_data = cursor.read_u64::<LittleEndian>()?;
        let target_source = cursor.read_u32::<LittleEndian>()?;

        extents.push(ExtentEntry {
            num_sectors,
            target_type,
            target_data,
            target_source,
        });
    }
    if file_len > 8 * 1024 * 1024 {
        let non_empty_a: HashSet<String> = partitions
            .iter()
            .filter(|p| p.num_extents > 0 && p.name.ends_with("_a"))
            .map(|p| p.name[..p.name.len() - 2].to_string())
            .collect();
        partitions.retain(|p| {
            if p.num_extents == 0 {
                return false;
            }
            if let Some(stem) = p.name.strip_suffix("_b")
                && non_empty_a.contains(stem)
            {
                return false;
            }
            true
        });
    }

    let total_super_bytes: u64 = partitions
        .iter()
        .flat_map(|p| p.first_extent_index..p.first_extent_index + p.num_extents)
        .filter_map(|e_idx| extents.get(e_idx as usize))
        .filter(|e| e.target_type == LP_TARGET_TYPE_LINEAR)
        .map(|e| e.num_sectors * LP_SECTOR_SIZE)
        .sum();

    if file_len > 8 * 1024 * 1024 {
        info!(
            partitions = partitions.len(),
            size = %HumanBytes(total_super_bytes),
            "lpunpack.start"
        );
    }
    let pb = ByteProgress::new("super.img", total_super_bytes);

    let extract_one = |part: &PartitionEntry| -> Result<()> {
        let out_img_path = output_dir.join(format!("{}.img", part.name));
        let total_size: u64 = (0..part.num_extents)
            .filter_map(|e_idx| {
                let idx = (part.first_extent_index + e_idx) as usize;
                extents.get(idx).map(|e| e.num_sectors * LP_SECTOR_SIZE)
            })
            .sum();

        debug!(
            partition = %part.name,
            size = %HumanBytes(total_size),
            extents = part.num_extents,
            "lpunpack.partition"
        );

        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&out_img_path)
            .with_context(|| {
                format!(
                    "Failed to create partition image {}",
                    out_img_path.display()
                )
            })?;

        if let Some((_, ref spans)) = sparse_index {
            out_file.set_len(0)?;
            let mut writer = BufWriter::with_capacity(1024 * 1024, out_file);
            for e_idx in 0..part.num_extents {
                let extent_idx = (part.first_extent_index + e_idx) as usize;
                if extent_idx >= extents.len() {
                    bail!(
                        "Extent index {} out of bounds ({})",
                        extent_idx,
                        extents.len()
                    );
                }
                let extent = extents[extent_idx];
                if extent.target_type != LP_TARGET_TYPE_LINEAR {
                    debug!(partition = %part.name, "lpunpack.extent.non_linear");
                    continue;
                }
                let source_offset = extent.target_data * LP_SECTOR_SIZE;
                let byte_len = extent.num_sectors * LP_SECTOR_SIZE;
                write_sparse_range(mmap, spans, source_offset, byte_len, &mut writer)?;
                pb.inc(byte_len);
            }
            writer.flush()?;
        } else if part.num_extents <= 1 {
            if part.num_extents == 1 {
                let extent_idx = part.first_extent_index as usize;
                if extent_idx >= extents.len() {
                    bail!(
                        "Extent index {} out of bounds ({})",
                        extent_idx,
                        extents.len()
                    );
                }
                let extent = extents[extent_idx];
                if extent.target_type == LP_TARGET_TYPE_LINEAR {
                    let source_offset = (extent.target_data * LP_SECTOR_SIZE) as usize;
                    let byte_len = (extent.num_sectors * LP_SECTOR_SIZE) as usize;
                    if source_offset + byte_len > mmap.len() {
                        bail!("Extent out of bounds in super image for {}", part.name);
                    }
                    if file_len > 8 * 1024 * 1024
                        && let Some(abs_str) = backing_key.to_str()
                    {
                        out_file.set_len(0)?;
                        out_file.write_all(ZIP_SLICE_MAGIC)?;
                        out_file.write_all(&((base_start + source_offset) as u64).to_le_bytes())?;
                        out_file.write_all(&(byte_len as u64).to_le_bytes())?;
                        out_file.write_all(abs_str.as_bytes())?;
                    } else {
                        out_file.write_all(&mmap[source_offset..source_offset + byte_len])?;
                        if out_file.metadata().map(|m| m.len()).unwrap_or(0) != total_size {
                            out_file.set_len(total_size)?;
                        }
                    }
                    pb.inc(byte_len as u64);
                }
            } else {
                out_file.set_len(0)?;
            }
        } else {
            out_file.set_len(0)?;
            let mut writer = BufWriter::with_capacity(1024 * 1024, out_file);
            for e_idx in 0..part.num_extents {
                let extent_idx = (part.first_extent_index + e_idx) as usize;
                if extent_idx >= extents.len() {
                    bail!(
                        "Extent index {} out of bounds ({})",
                        extent_idx,
                        extents.len()
                    );
                }
                let extent = extents[extent_idx];
                if extent.target_type != LP_TARGET_TYPE_LINEAR {
                    debug!(partition = %part.name, "lpunpack.extent.non_linear");
                    continue;
                }
                let source_offset = (extent.target_data * LP_SECTOR_SIZE) as usize;
                let byte_len = (extent.num_sectors * LP_SECTOR_SIZE) as usize;
                if source_offset + byte_len > mmap.len() {
                    bail!("Extent out of bounds in super image for {}", part.name);
                }
                writer.write_all(&mmap[source_offset..source_offset + byte_len])?;
                pb.inc(byte_len as u64);
            }
            writer.flush()?;
        }

        Ok(())
    };

    if partitions.len() <= 1 {
        for part in &partitions {
            extract_one(part)?;
        }
    } else {
        partitions.par_iter().try_for_each(extract_one)?;
    }

    if !small_buf.is_empty() {
        LP_BUF.with(|cell| {
            *cell.borrow_mut() = small_buf;
        });
    }

    pb.finish();
    if file_len > 8 * 1024 * 1024 {
        info!(
            partitions = partitions.len(),
            size = %HumanBytes(total_super_bytes),
            duration = %HumanDuration(start_time.elapsed()),
            "lpunpack.done"
        );
    }
    Ok(())
}
