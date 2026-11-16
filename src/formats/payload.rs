use anyhow::{Context, Result, bail};
use byteorder::{BigEndian, ReadBytesExt};
use indicatif::HumanBytes;
use memmap2::Mmap;
use prost::Message;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::utils::progress::ByteProgress;

pub mod update_engine {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}

use update_engine::DeltaArchiveManifest;
use update_engine::install_operation::Type as OpType;

const BRILLO_MAGIC: &[u8; 4] = b"CrAU";
const BLOCK_SIZE: u64 = 4096;
pub const ZIP_SLICE_MAGIC: &[u8; 16] = b"DUMPRS_ZIP_SLICE";

pub struct PayloadHeader {
    pub version: u64,
    pub manifest_len: u64,
    pub metadata_signature_len: u32,
    pub header_size: u64,
}

impl PayloadHeader {
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != BRILLO_MAGIC {
            bail!("Invalid payload magic: {:?}", magic);
        }

        let version = reader.read_u64::<BigEndian>()?;
        let manifest_len = reader.read_u64::<BigEndian>()?;
        let (metadata_signature_len, header_size) = if version >= 2 {
            let sig_len = reader.read_u32::<BigEndian>()?;
            (sig_len, 24)
        } else {
            (0, 20)
        };

        Ok(Self {
            version,
            manifest_len,
            metadata_signature_len,
            header_size,
        })
    }
}

#[cfg(unix)]
fn write_at(file: &File, mut buf: &[u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !buf.is_empty() {
        let n = file.write_at(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write whole buffer",
            ));
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn write_at(file: &File, mut buf: &[u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_write(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write whole buffer",
            ));
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

fn compute_partition_size(partition: &update_engine::PartitionUpdate) -> u64 {
    let max_extent_end = partition
        .operations
        .iter()
        .flat_map(|op| op.dst_extents.iter())
        .map(|ext| (ext.start_block.unwrap_or(0) + ext.num_blocks.unwrap_or(0)) * BLOCK_SIZE)
        .max()
        .unwrap_or(0);
    partition
        .new_partition_info
        .as_ref()
        .and_then(|info| info.size)
        .unwrap_or(max_extent_end)
        .max(max_extent_end)
}

pub fn extract_android_ota_payload(payload_path: &Path, output_dir: &Path) -> Result<()> {
    let payload_file = File::open(payload_path)
        .with_context(|| format!("Failed to open payload {}", payload_path.display()))?;
    let mmap = unsafe { Mmap::map(&payload_file) }
        .with_context(|| format!("Failed to mmap payload {}", payload_path.display()))?;

    if mmap.len() >= 32 && &mmap[..16] == ZIP_SLICE_MAGIC {
        let start = u64::from_le_bytes(mmap[16..24].try_into().unwrap()) as usize;
        let len = u64::from_le_bytes(mmap[24..32].try_into().unwrap()) as usize;
        let archive_path_str = std::str::from_utf8(&mmap[32..])
            .context("Invalid UTF-8 in payload zip slice reference")?;
        let archive_file = File::open(archive_path_str)
            .with_context(|| format!("Failed to open source archive {}", archive_path_str))?;
        let archive_mmap = unsafe { Mmap::map(&archive_file) }
            .with_context(|| format!("Failed to mmap source archive {}", archive_path_str))?;
        let end = start.saturating_add(len);
        if end > archive_mmap.len() {
            bail!("Zip slice {}..{} exceeds archive size", start, end);
        }
        return extract_android_ota_payload_bytes(&archive_mmap[start..end], output_dir);
    }

    extract_android_ota_payload_bytes(&mmap, output_dir)
}

pub fn extract_android_ota_payload_bytes(mmap: &[u8], output_dir: &Path) -> Result<()> {
    let mut cursor = mmap;
    let header = PayloadHeader::read_from(&mut cursor)?;
    debug!(
        version = header.version,
        manifest_len = header.manifest_len,
        sig_len = header.metadata_signature_len,
        "payload.header"
    );

    let manifest_start = header.header_size as usize;
    let manifest_end = manifest_start + header.manifest_len as usize;
    if manifest_end > mmap.len() {
        bail!("Payload manifest exceeds file size");
    }

    let manifest = DeltaArchiveManifest::decode(&mmap[manifest_start..manifest_end])
        .context("Failed to parse DeltaArchiveManifest protobuf")?;

    let data_offset =
        header.header_size + header.manifest_len + header.metadata_signature_len as u64;
    let check_hashes = tracing::enabled!(tracing::Level::DEBUG);

    let total_output_bytes: u64 = manifest.partitions.iter().map(compute_partition_size).sum();

    info!(
        partitions = manifest.partitions.len(),
        size = %HumanBytes(total_output_bytes),
        "payload.extract.start"
    );
    let pb = ByteProgress::new("payload.bin", total_output_bytes);

    manifest.partitions.par_iter().for_each(|partition| {
        let name = format!("{}.img", partition.partition_name);
        let part_size = compute_partition_size(partition);
        debug!(partition = %partition.partition_name, size = %HumanBytes(part_size), "payload.partition.start");
        let out_path = output_dir.join(&name);

        let out_file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&out_path)
        {
            Ok(f) => f,
            Err(e) => {
                warn!(path = %out_path.display(), error = %e, "payload.partition.open_failed");
                return;
            }
        };

        if let Err(e) = parse_partition_operations(
            &mmap,
            data_offset,
            partition,
            part_size,
            &out_file,
            check_hashes,
            &pb,
        ) {
            warn!(partition = %name, error = %e, "payload.partition.extract_failed");
            drop(out_file);
            let _ = std::fs::remove_file(&out_path);
        }
    });

    pb.finish();
    info!(
        partitions = manifest.partitions.len(),
        size = %HumanBytes(total_output_bytes),
        "payload.extract.done"
    );

    Ok(())
}

fn write_extents(out_file: &File, extents: &[update_engine::Extent], data: &[u8]) -> Result<u64> {
    let mut data_offset = 0usize;
    for ext in extents {
        let start_block = ext.start_block.unwrap_or(0);
        let num_blocks = ext.num_blocks.unwrap_or(0);
        let ext_bytes = (num_blocks * BLOCK_SIZE) as usize;
        if data_offset + ext_bytes > data.len() {
            let remaining = data.len().saturating_sub(data_offset);
            if remaining > 0 {
                write_at(
                    out_file,
                    &data[data_offset..data_offset + remaining],
                    start_block * BLOCK_SIZE,
                )?;
                data_offset += remaining;
            }
            break;
        }
        write_at(
            out_file,
            &data[data_offset..data_offset + ext_bytes],
            start_block * BLOCK_SIZE,
        )?;
        data_offset += ext_bytes;
    }
    Ok(data_offset as u64)
}

fn parse_partition_operations(
    mmap: &[u8],
    data_offset: u64,
    partition: &update_engine::PartitionUpdate,
    partition_size: u64,
    out_file: &File,
    check_hashes: bool,
    pb: &ByteProgress,
) -> Result<()> {
    if partition_size > 0 {
        out_file.set_len(partition_size)?;
    }

    partition.operations.par_iter().try_for_each_init(
        || Vec::with_capacity(2 * 1024 * 1024),
        |decompressed, operation| -> Result<()> {
            let op_type = OpType::try_from(operation.r#type)
                .map_err(|_| anyhow::anyhow!("Unknown operation type: {}", operation.r#type))?;

            let extents = &operation.dst_extents;
            if extents.is_empty() {
                return Ok(());
            }

            if op_type == OpType::Zero {
                let zero_bytes: u64 = extents
                    .iter()
                    .map(|e| e.num_blocks.unwrap_or(0) * BLOCK_SIZE)
                    .sum();
                pb.inc(zero_bytes);
                return Ok(());
            }

            let op_offset = operation.data_offset.unwrap_or(0);
            let op_length = operation.data_length.unwrap_or(0);
            let start = (data_offset + op_offset) as usize;
            let end = start + (op_length as usize);
            if end > mmap.len() {
                bail!(
                    "Operation data range {}..{} exceeds payload size",
                    start,
                    end
                );
            }
            let blob = &mmap[start..end];

            if check_hashes
                && !blob.is_empty()
                && let Some(expected_hash) = &operation.data_sha256_hash
            {
                let actual_hash = Sha256::digest(blob);
                if actual_hash.as_slice() != expected_hash.as_slice() {
                    debug!(offset = op_offset, "payload.operation.hash_mismatch");
                }
            }

            let written = match op_type {
                OpType::Replace => write_extents(out_file, extents, blob)?,
                OpType::ReplaceXz => {
                    decompressed.clear();
                    let mut decoder = xz2::read::XzDecoder::new(blob);
                    decoder.read_to_end(decompressed)?;
                    write_extents(out_file, extents, decompressed)?
                }
                OpType::ReplaceBz => {
                    decompressed.clear();
                    let mut decoder = bzip2::read::BzDecoder::new(blob);
                    decoder.read_to_end(decompressed)?;
                    write_extents(out_file, extents, decompressed)?
                }
                _ => {
                    bail!("Unhandled operation type: {:?}", op_type);
                }
            };
            pb.inc(written);
            Ok(())
        },
    )?;

    Ok(())
}
