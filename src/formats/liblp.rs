use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use memmap2::Mmap;
use rayon::prelude::*;
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use tracing::{debug, info};

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

pub fn lpunpack(super_image_path: &Path, output_dir: &Path) -> Result<()> {
    info!(
        "Unpacking super image {} to {}",
        super_image_path.display(),
        output_dir.display()
    );
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory {}", output_dir.display()))?;
    }

    let mut file = File::open(super_image_path)
        .with_context(|| format!("Failed to open super image {}", super_image_path.display()))?;
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0) as usize;
    if file_len < 12288 + 128 {
        bail!("Super image {} is too small ({} bytes)", super_image_path.display(), file_len);
    }

    let owned_mmap: Option<Mmap> = if file_len > 8 * 1024 * 1024 {
        Some(
            unsafe { Mmap::map(&file) }
                .with_context(|| format!("Failed to mmap super image {}", super_image_path.display()))?,
        )
    } else {
        None
    };

    let mut small_buf = Vec::new();
    let mmap: &[u8] = if let Some(m) = &owned_mmap {
        m
    } else {
        LP_BUF.with(|cell| -> Result<()> {
            let mut b = cell.borrow_mut();
            b.resize(file_len, 0);
            file.read_exact(&mut b)?;
            small_buf = std::mem::take(&mut *b);
            Ok(())
        })?;
        &small_buf
    };
    let mut geom_cursor = &mmap[4096..];
    let geom_magic = geom_cursor.read_u32::<LittleEndian>()?;
    if geom_magic != LP_METADATA_GEOMETRY_MAGIC {
        bail!(
            "Invalid LP geometry magic: 0x{:08x} (expected 0x{:08x})",
            geom_magic,
            LP_METADATA_GEOMETRY_MAGIC
        );
    }

    let _struct_size = geom_cursor.read_u32::<LittleEndian>()?;
    geom_cursor = &geom_cursor[32..]; // skip 32-byte checksum
    let metadata_max_size = geom_cursor.read_u32::<LittleEndian>()?;
    let metadata_slot_count = geom_cursor.read_u32::<LittleEndian>()?;
    let _logical_block_size = geom_cursor.read_u32::<LittleEndian>()?;

    // Primary metadata offset: LP_PARTITION_RESERVED_BYTES (4096) + LP_METADATA_GEOMETRY_SIZE * 2 (8192) = 12288
    let mut header_offset = 12288usize;
    let mut hdr_cursor = &mmap[header_offset..];
    let mut header_magic = hdr_cursor.read_u32::<LittleEndian>()?;
    if header_magic != LP_METADATA_HEADER_MAGIC {
        // Try backup metadata offset
        let backup_offset = 12288usize + (metadata_max_size as usize) * (metadata_slot_count as usize);
        if backup_offset + 128 > mmap.len() {
            bail!("Invalid LP backup metadata offset {}", backup_offset);
        }
        hdr_cursor = &mmap[backup_offset..];
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
    hdr_cursor = &hdr_cursor[32..]; // skip header_checksum
    let tables_size = hdr_cursor.read_u32::<LittleEndian>()?;
    hdr_cursor = &hdr_cursor[32..]; // skip tables_checksum

    let partitions_desc = TableDescriptor::read_from(&mut hdr_cursor)?;
    let extents_desc = TableDescriptor::read_from(&mut hdr_cursor)?;
    let _groups_desc = TableDescriptor::read_from(&mut hdr_cursor)?;
    let _block_devices_desc = TableDescriptor::read_from(&mut hdr_cursor)?;

    debug!(
        "LP metadata: {} partitions, {} extents, tables_size {}",
        partitions_desc.num_entries, extents_desc.num_entries, tables_size
    );

    let tables_offset = header_offset + header_size as usize;
    let tables_end = tables_offset.saturating_add(tables_size as usize).min(mmap.len());
    let tables_data = &mmap[tables_offset..tables_end];
    // Parse partitions
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
        let name = String::from_utf8_lossy(&name_bytes[..name_len]).trim().to_string();

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

    // Parse extents
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

    let pb = if mmap.len() >= 16 * 1024 * 1024 {
        let p = crate::utils::progress::get_multi_progress().add(ProgressBar::new(partitions.len() as u64));
        if let Ok(style) = ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:30.cyan/blue}] {pos}/{len} partitions: {msg}",
        ) {
            p.set_style(style.progress_chars("=>-"));
        }
        Some(p)
    } else {
        None
    };

    let extract_one = |part: &PartitionEntry| -> Result<()> {
        let out_img_path = output_dir.join(format!("{}.img", part.name));
        let total_size: u64 = (0..part.num_extents)
            .filter_map(|e_idx| {
                let idx = (part.first_extent_index + e_idx) as usize;
                extents.get(idx).map(|e| e.num_sectors * LP_SECTOR_SIZE)
            })
            .sum();

        if let Some(p) = &pb {
            p.set_message(format!("{} ({})", part.name, HumanBytes(total_size)));
        }
        info!(
            "Extracting logical partition '{}' ({} in {} extents)",
            part.name,
            HumanBytes(total_size),
            part.num_extents
        );

        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&out_img_path)
            .with_context(|| format!("Failed to create partition image {}", out_img_path.display()))?;

        if part.num_extents <= 1 {
            if part.num_extents == 1 {
                let extent_idx = part.first_extent_index as usize;
                if extent_idx >= extents.len() {
                    bail!("Extent index {} out of bounds ({})", extent_idx, extents.len());
                }
                let extent = extents[extent_idx];
                if extent.target_type == LP_TARGET_TYPE_LINEAR {
                    let source_offset = (extent.target_data * LP_SECTOR_SIZE) as usize;
                    let byte_len = (extent.num_sectors * LP_SECTOR_SIZE) as usize;
                    if source_offset + byte_len > mmap.len() {
                        bail!("Extent out of bounds in super image for {}", part.name);
                    }
                    out_file.write_all(&mmap[source_offset..source_offset + byte_len])?;
                    if out_file.metadata().map(|m| m.len()).unwrap_or(0) != total_size {
                        out_file.set_len(total_size)?;
                    }
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
                    bail!("Extent index {} out of bounds ({})", extent_idx, extents.len());
                }
                let extent = extents[extent_idx];
                if extent.target_type != LP_TARGET_TYPE_LINEAR {
                    debug!("Skipping non-linear extent in partition {}", part.name);
                    continue;
                }
                let source_offset = (extent.target_data * LP_SECTOR_SIZE) as usize;
                let byte_len = (extent.num_sectors * LP_SECTOR_SIZE) as usize;
                if source_offset + byte_len > mmap.len() {
                    bail!("Extent out of bounds in super image for {}", part.name);
                }
                writer.write_all(&mmap[source_offset..source_offset + byte_len])?;
            }
            writer.flush()?;
        }

        if let Some(p) = &pb {
            p.inc(1);
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

    if let Some(p) = pb {
        p.finish_and_clear();
    }
    info!("Super partitions unpacked ({} partitions extracted)", partitions.len());
    Ok(())
}
