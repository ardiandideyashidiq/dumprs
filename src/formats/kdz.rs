use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::ZlibDecoder;
use indicatif::HumanBytes;
use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
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
        let name = String::from_utf8_lossy(&name_bytes[..name_len]).trim().to_string();

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
        let slice_name = String::from_utf8_lossy(&slice_name_raw[..name_len]).trim().to_string();

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
    let mut decompressed = Vec::with_capacity(256 * 1024);

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

    Ok(())
}
