use anyhow::{Context, Result, bail};
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::ZlibDecoder;
use indicatif::HumanBytes;
use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::{debug, info};

use crate::utils::progress::ByteProgress;

const KDZ_V0: &[u8; 8] = b"\x28\x05\x00\x00\x34\x31\x25\x80";
const KDZ_V1: &[u8; 8] = b"\x18\x05\x00\x00\x32\x79\x44\x50";
const KDZ_V2: &[u8; 8] = b"\x28\x05\x00\x00\x24\x38\x22\x25";

const DZ_FILE_HEADER: &[u8; 4] = b"\x32\x96\x18\x74";
const DZ_CHUNK_HEADER: &[u8; 4] = b"\x30\x12\x95\x78";

struct KdzEntry {
    name: String,
    length: u64,
    offset: u64,
}

pub fn unpack_kdz(filename: &Path, work_dir: &Path) -> Result<()> {
    let file = File::open(filename)
        .with_context(|| format!("Failed to open KDZ file {}", filename.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("Failed to mmap KDZ file {}", filename.display()))?;

    if mmap.len() < 8 {
        bail!("KDZ file too small: {}", filename.display());
    }
    let magic = &mmap[0..8];
    if magic != KDZ_V0 && magic != KDZ_V1 && magic != KDZ_V2 {
        bail!("Invalid KDZ magic: {:?}", magic);
    }

    let mut entries = Vec::new();
    let mut pos = 8usize;
    while pos + 272 <= mmap.len() {
        let header_buf = &mmap[pos..pos + 272];
        pos += 272;

        let name_bytes = &header_buf[0..256];
        let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(256);
        let name = String::from_utf8_lossy(&name_bytes[..name_len])
            .trim()
            .to_string();

        let mut cursor = &header_buf[256..272];
        let length = cursor.read_u64::<LittleEndian>()?;
        let offset = cursor.read_u64::<LittleEndian>()?;

        if !name.is_empty() && length > 0 {
            entries.push(KdzEntry {
                name,
                length,
                offset,
            });
        }

        if pos >= mmap.len() || mmap[pos] == 0x03 || mmap[pos] == 0x00 {
            break;
        }
    }

    let total_bytes: u64 = entries.iter().map(|e| e.length).sum();
    info!(
        entries = entries.len(),
        size = %HumanBytes(total_bytes),
        "kdz.extract.start"
    );
    let pb = ByteProgress::new("kdz", total_bytes);
    let mut dz_files = Vec::new();

    for entry in entries {
        let out_file_path = work_dir.join(&entry.name);
        debug!(entry = %entry.name, size = %HumanBytes(entry.length), "kdz.entry.extract");

        let start = entry.offset as usize;
        let end = start.saturating_add(entry.length as usize);
        if end > mmap.len() {
            bail!("KDZ entry {} exceeds file bounds", entry.name);
        }
        let mut out_file = File::create(&out_file_path)
            .with_context(|| format!("Failed to create {}", out_file_path.display()))?;
        out_file.write_all(&mmap[start..end])?;
        pb.inc(entry.length);

        if entry.name.ends_with(".dz") {
            dz_files.push(out_file_path);
        }
    }
    pb.finish();

    if let Some(dz_path) = dz_files.first() {
        unpack_dz(dz_path, work_dir)?;
    }

    Ok(())
}

struct DzChunk {
    slice_name: String,
    data_size: u32,
    target_addr: u32,
}

#[derive(Debug, Clone)]
pub struct GptPartition {
    pub name: String,
    pub start_lba: u64,
    pub end_lba: u64,
}

pub fn parse_gpt_entries(data: &[u8]) -> Vec<GptPartition> {
    let mut partitions = Vec::new();
    let gpt_offsets = [512usize, 4096usize];
    let mut header_offset = None;
    for &off in &gpt_offsets {
        if off + 92 <= data.len() && &data[off..off + 8] == b"EFI PART" {
            header_offset = Some(off);
            break;
        }
    }

    let Some(off) = header_offset else {
        return partitions;
    };

    let block_shift = if off == 4096 { 12 } else { 9 };
    let block_size = 1usize << block_shift;

    let mut cursor = &data[off + 72..off + 92];
    let entry_lba = match cursor.read_u64::<LittleEndian>() {
        Ok(v) => v,
        Err(_) => return partitions,
    };
    let num_entries = match cursor.read_u32::<LittleEndian>() {
        Ok(v) => v as usize,
        Err(_) => return partitions,
    };
    let entry_size = match cursor.read_u32::<LittleEndian>() {
        Ok(v) => v as usize,
        Err(_) => return partitions,
    };

    let entries_offset = (entry_lba as usize) * block_size;
    if entries_offset >= data.len() || entry_size < 128 {
        return partitions;
    }

    let mut cur_pos = entries_offset;
    for _ in 0..num_entries.min(256) {
        if cur_pos + entry_size > data.len() {
            break;
        }
        let entry_buf = &data[cur_pos..cur_pos + entry_size];
        cur_pos += entry_size;

        let type_guid = &entry_buf[0..16];
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }

        let mut entry_cursor = &entry_buf[32..56];
        let start_lba = match entry_cursor.read_u64::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let end_lba = match entry_cursor.read_u64::<LittleEndian>() {
            Ok(v) => v,
            Err(_) => continue,
        };

        let name_bytes = &entry_buf[56..128];
        let name_u16: Vec<u16> = name_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();

        let name = String::from_utf16_lossy(&name_u16).trim().to_string();
        if !name.is_empty() {
            partitions.push(GptPartition {
                name,
                start_lba,
                end_lba,
            });
        }
    }

    partitions
}

pub fn unpack_dz(filename: &Path, work_dir: &Path) -> Result<()> {
    let file = File::open(filename)
        .with_context(|| format!("Failed to open DZ file {}", filename.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("Failed to mmap DZ file {}", filename.display()))?;

    if mmap.len() < 512 {
        bail!("DZ file too small: {}", filename.display());
    }
    let header_buf = &mmap[0..512];

    if &header_buf[0..4] != DZ_FILE_HEADER {
        bail!("Invalid DZ header magic: {:?}", &header_buf[0..4]);
    }

    let chunk_count = (&header_buf[192..196]).read_u32::<LittleEndian>()?;
    debug!(chunks = chunk_count, "dz.header");

    let mut chunks = Vec::with_capacity(chunk_count as usize);
    let mut pos = 512usize;
    let mut total_input_bytes = 0u64;
    for _ in 0..chunk_count {
        if pos + 512 > mmap.len() {
            bail!("Unexpected EOF reading DZ chunk headers");
        }
        let chunk_buf = &mmap[pos..pos + 512];
        pos += 512;
        if &chunk_buf[0..4] != DZ_CHUNK_HEADER {
            bail!("Invalid DZ chunk header: {:?}", &chunk_buf[0..4]);
        }

        let slice_name_raw = &chunk_buf[4..36];
        let name_len = slice_name_raw.iter().position(|&b| b == 0).unwrap_or(32);
        let slice_name = String::from_utf8_lossy(&slice_name_raw[..name_len])
            .trim()
            .to_string();

        let mut cursor = &chunk_buf[100..128];
        let _target_size = cursor.read_u32::<LittleEndian>()?;
        let data_size = cursor.read_u32::<LittleEndian>()?;
        let mut _md5 = [0u8; 16];
        cursor.read_exact(&mut _md5)?;
        let target_addr = cursor.read_u32::<LittleEndian>()?;

        total_input_bytes += data_size as u64;
        chunks.push(DzChunk {
            slice_name,
            data_size,
            target_addr,
        });
    }

    info!(
        chunks = chunk_count,
        input_size = %HumanBytes(total_input_bytes),
        "dz.extract.start"
    );
    let pb = ByteProgress::new("dz", total_input_bytes);
    let mut open_files: HashMap<String, File> = HashMap::new();
    let mut slice_extents: HashMap<String, (u64, u64)> = HashMap::new();
    let mut decompressed = Vec::with_capacity(256 * 1024);
    let mut gpt_partitions: Vec<GptPartition> = Vec::new();

    for chunk in chunks {
        let data_len = chunk.data_size as usize;
        if pos + data_len > mmap.len() {
            bail!("Unexpected EOF reading DZ chunk payload");
        }
        let compressed_data = &mmap[pos..pos + data_len];
        pos += data_len;

        let payload: &[u8] = if compressed_data.starts_with(&[0x78]) {
            decompressed.clear();
            let mut decoder = ZlibDecoder::new(compressed_data);
            decoder.read_to_end(&mut decompressed)?;
            &decompressed
        } else if compressed_data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            decompressed.clear();
            zstd::stream::copy_decode(compressed_data, &mut decompressed)?;
            &decompressed
        } else {
            compressed_data
        };

        if gpt_partitions.is_empty() && (payload.len() >= 1024) {
            let found = parse_gpt_entries(payload);
            if !found.is_empty() {
                info!(count = found.len(), "dz.gpt.parsed");
                gpt_partitions = found;
            }
        }

        let chunk_start_lba = chunk.target_addr as u64;
        let chunk_blocks = (payload.len() as u64).div_ceil(512);
        let chunk_end_lba = chunk_start_lba.saturating_add(chunk_blocks);
        slice_extents
            .entry(chunk.slice_name.clone())
            .and_modify(|(min_lba, max_lba)| {
                *min_lba = (*min_lba).min(chunk_start_lba);
                *max_lba = (*max_lba).max(chunk_end_lba);
            })
            .or_insert((chunk_start_lba, chunk_end_lba));

        let out_file = if let Some(f) = open_files.get_mut(&chunk.slice_name) {
            f
        } else {
            let file_name = format!("{}.img", chunk.slice_name);
            let out_file_path = work_dir.join(&file_name);
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&out_file_path)?;
            open_files.entry(chunk.slice_name).or_insert(f)
        };

        let offset = (chunk.target_addr as u64) * 512;
        out_file.seek(SeekFrom::Start(offset))?;
        out_file.write_all(payload)?;
        pb.inc(data_len as u64);
    }

    pb.finish();
    for (_, mut f) in open_files {
        let _ = f.flush();
    }

    // Write .params metadata files for each slice
    for (slice_name, (start_lba, end_lba)) in slice_extents {
        let params_path = work_dir.join(format!("{}.params", slice_name));
        let params_content = format!(
            "# saved parameters for the file \"{}\"\nstartLBA={}\nstartAddr={}\nendLBA={}\nendAddr={}\ndev=0\nblockSize=512\nblockShift=9\n",
            slice_name,
            start_lba,
            start_lba * 512,
            end_lba,
            end_lba * 512
        );
        let _ = fs::write(params_path, params_content);
    }

    // Write .params for any additional GPT-declared partitions
    for part in gpt_partitions {
        let params_path = work_dir.join(format!("{}.params", part.name));
        if !params_path.exists() {
            let params_content = format!(
                "# saved parameters for the file \"{}\"\nstartLBA={}\nstartAddr={}\nendLBA={}\nendAddr={}\ndev=0\nblockSize=512\nblockShift=9\n",
                part.name,
                part.start_lba,
                part.start_lba * 512,
                part.end_lba,
                (part.end_lba + 1) * 512
            );
            let _ = fs::write(params_path, params_content);
        }
    }

    Ok(())
}
