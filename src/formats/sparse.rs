use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use indicatif::{HumanBytes, ProgressBar, ProgressStyle};
use memmap2::Mmap;
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

pub const SPARSE_MAGIC: u32 = 0xed26_ff3a;
const CHUNK_TYPE_RAW: u16 = 0xcac1;
const CHUNK_TYPE_FILL: u16 = 0xcac2;
const CHUNK_TYPE_DONT_CARE: u16 = 0xcac3;
const CHUNK_TYPE_CRC32: u16 = 0xcac4;

const PROGRESS_THRESHOLD: u64 = 16 * 1024 * 1024;
const HOLE_SEEK_THRESHOLD: u64 = 64 * 1024;
const FAST_MEM_LIMIT: u64 = 8 * 1024 * 1024;
const ZERO_BUF: [u8; 64 * 1024] = [0u8; 64 * 1024];

thread_local! {
    static SPARSE_IN_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static SPARSE_OUT_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}
pub fn is_sparse_file(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let magic = match file.read_u32::<LittleEndian>() {
        Ok(m) => m,
        Err(_) => return false,
    };
    magic == SPARSE_MAGIC
}

#[derive(Clone, Copy)]
struct SparseHeader {
    file_hdr_sz: usize,
    chunk_hdr_sz: usize,
    blk_sz: u64,
    total_blks: u64,
    total_chunks: u32,
}

fn parse_sparse_header(data: &[u8]) -> Result<Option<SparseHeader>> {
    if data.len() < 28 {
        return Ok(None);
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != SPARSE_MAGIC {
        return Ok(None);
    }
    let major = u16::from_le_bytes(data[4..6].try_into().unwrap());
    if major != 1 {
        bail!("Unsupported sparse major version: {}", major);
    }
    let file_hdr_sz = u16::from_le_bytes(data[8..10].try_into().unwrap()) as usize;
    let chunk_hdr_sz = u16::from_le_bytes(data[10..12].try_into().unwrap()) as usize;
    if file_hdr_sz < 28 || chunk_hdr_sz < 12 || data.len() < file_hdr_sz {
        bail!("Invalid sparse header sizes: file_hdr_sz={}, chunk_hdr_sz={}", file_hdr_sz, chunk_hdr_sz);
    }
    let blk_sz = u32::from_le_bytes(data[12..16].try_into().unwrap()) as u64;
    let total_blks = u32::from_le_bytes(data[16..20].try_into().unwrap()) as u64;
    let total_chunks = u32::from_le_bytes(data[20..24].try_into().unwrap());
    Ok(Some(SparseHeader {
        file_hdr_sz,
        chunk_hdr_sz,
        blk_sz,
        total_blks,
        total_chunks,
    }))
}

fn decode_sparse_mmap(
    mmap: &[u8],
    hdr: SparseHeader,
    writer: &mut BufWriter<File>,
    fill_buf: &mut Vec<u8>,
    mut pb: Option<&mut ProgressBar>,
    file_name: &str,
) -> Result<u64> {
    let mut in_offset = hdr.file_hdr_sz;
    let mut out_offset = 0u64;
    let mut last_pb_update = 0u64;
    let mut last_milestone = 0u64;
    let total_size = hdr.total_blks * hdr.blk_sz;

    for _ in 0..hdr.total_chunks {
        if in_offset + hdr.chunk_hdr_sz > mmap.len() {
            bail!("Unexpected EOF reading sparse chunk header in {}", file_name);
        }
        let ch = &mmap[in_offset..in_offset + hdr.chunk_hdr_sz];
        let chunk_type = u16::from_le_bytes(ch[0..2].try_into().unwrap());
        let chunk_sz = u32::from_le_bytes(ch[4..8].try_into().unwrap()) as u64;
        let total_sz = u32::from_le_bytes(ch[8..12].try_into().unwrap()) as usize;
        if total_sz < hdr.chunk_hdr_sz || in_offset + total_sz > mmap.len() {
            bail!("Invalid sparse chunk total_sz {} in {}", total_sz, file_name);
        }

        let payload_start = in_offset + hdr.chunk_hdr_sz;
        let payload_len = total_sz - hdr.chunk_hdr_sz;
        let out_bytes = chunk_sz * hdr.blk_sz;

        match chunk_type {
            CHUNK_TYPE_RAW => {
                if payload_len as u64 != out_bytes {
                    bail!("RAW chunk size mismatch in {}", file_name);
                }
                writer.write_all(&mmap[payload_start..payload_start + payload_len])?;
                out_offset += out_bytes;
            }
            CHUNK_TYPE_FILL => {
                if payload_len < 4 {
                    bail!("FILL chunk payload too small in {}", file_name);
                }
                let fill_bytes: [u8; 4] = mmap[payload_start..payload_start + 4].try_into().unwrap();
                let fill_val = u32::from_le_bytes(fill_bytes);
                if fill_val == 0 {
                    if out_bytes >= HOLE_SEEK_THRESHOLD {
                        writer.flush()?;
                        writer.get_mut().seek(SeekFrom::Start(out_offset + out_bytes))?;
                    } else {
                        let mut rem = out_bytes as usize;
                        while rem > 0 {
                            let n = rem.min(ZERO_BUF.len());
                            writer.write_all(&ZERO_BUF[..n])?;
                            rem -= n;
                        }
                    }
                } else {
                    if fill_buf.is_empty() {
                        fill_buf.resize(256 * 1024, 0);
                    }
                    for chunk in fill_buf.chunks_exact_mut(4) {
                        chunk.copy_from_slice(&fill_bytes);
                    }
                    let mut rem = out_bytes as usize;
                    while rem > 0 {
                        let n = rem.min(fill_buf.len());
                        writer.write_all(&fill_buf[..n])?;
                        rem -= n;
                    }
                }
                out_offset += out_bytes;
            }
            CHUNK_TYPE_DONT_CARE => {
                if out_bytes > 0 {
                    writer.flush()?;
                    writer.get_mut().seek(SeekFrom::Start(out_offset + out_bytes))?;
                    out_offset += out_bytes;
                }
            }
            CHUNK_TYPE_CRC32 => {}
            other => bail!("Unknown sparse chunk type 0x{:04x} in {}", other, file_name),
        }

        in_offset += total_sz;

        if let Some(pb_ref) = pb.as_deref_mut() && out_offset - last_pb_update >= PROGRESS_THRESHOLD {
            last_pb_update = out_offset;
            pb_ref.set_position(out_offset);
        }
        if out_offset >= last_milestone + 500 * 1024 * 1024 {
            last_milestone = out_offset;
            info!(
                "Unsparsing {}: {} / {} decoded",
                file_name,
                HumanBytes(out_offset),
                HumanBytes(total_size)
            );
        }
    }

    Ok(out_offset)
}

pub fn unsparse_file(src_path: &Path, dst_path: &Path) -> Result<bool> {
    let mut src_file = match File::open(src_path) {
        Ok(f) => f,
        Err(_) => return Ok(false),
    };
    let file_len = src_file.metadata().map(|m| m.len()).unwrap_or(0);
    if file_len < 28 {
        return Ok(false);
    }

    if file_len <= FAST_MEM_LIMIT {
        let mut hdr_bytes = [0u8; 28];
        src_file.read_exact(&mut hdr_bytes)?;
        let Some(hdr) = parse_sparse_header(&hdr_bytes)? else {
            return Ok(false);
        };
        let total_size = hdr.total_blks * hdr.blk_sz;
        if total_size <= FAST_MEM_LIMIT {
            return SPARSE_IN_BUF.with(|in_cell| {
                SPARSE_OUT_BUF.with(|out_cell| {
                    let mut in_buf = in_cell.borrow_mut();
                    in_buf.resize(file_len as usize, 0);
                    in_buf[..28].copy_from_slice(&hdr_bytes);
                    src_file.read_exact(&mut in_buf[28..])?;

                    let mut out_buf = out_cell.borrow_mut();
                    out_buf.resize(total_size as usize, 0);

                    let mut in_offset = hdr.file_hdr_sz;
                    let mut out_offset = 0usize;
                    for _ in 0..hdr.total_chunks {
                        if in_offset + hdr.chunk_hdr_sz > in_buf.len() {
                            bail!("Unexpected EOF reading sparse chunk header");
                        }
                        let ch = &in_buf[in_offset..in_offset + hdr.chunk_hdr_sz];
                        let chunk_type = u16::from_le_bytes(ch[0..2].try_into().unwrap());
                        let chunk_sz = u32::from_le_bytes(ch[4..8].try_into().unwrap()) as usize;
                        let total_sz = u32::from_le_bytes(ch[8..12].try_into().unwrap()) as usize;
                        let payload_start = in_offset + hdr.chunk_hdr_sz;
                        let payload_len = total_sz - hdr.chunk_hdr_sz;
                        let out_bytes = chunk_sz * (hdr.blk_sz as usize);

                        match chunk_type {
                            CHUNK_TYPE_RAW => {
                                out_buf[out_offset..out_offset + out_bytes].copy_from_slice(
                                    &in_buf[payload_start..payload_start + payload_len],
                                );
                                out_offset += out_bytes;
                            }
                            CHUNK_TYPE_FILL => {
                                let fill_bytes: [u8; 4] =
                                    in_buf[payload_start..payload_start + 4].try_into().unwrap();
                                if u32::from_le_bytes(fill_bytes) == 0 {
                                    out_buf[out_offset..out_offset + out_bytes].fill(0);
                                } else {
                                    for chunk in out_buf[out_offset..out_offset + out_bytes]
                                        .chunks_exact_mut(4)
                                    {
                                        chunk.copy_from_slice(&fill_bytes);
                                    }
                                }
                                out_offset += out_bytes;
                            }
                            CHUNK_TYPE_DONT_CARE => {
                                out_buf[out_offset..out_offset + out_bytes].fill(0);
                                out_offset += out_bytes;
                            }
                            CHUNK_TYPE_CRC32 => {}
                            other => bail!("Unknown sparse chunk type 0x{:04x}", other),
                        }
                        in_offset += total_sz;
                    }

                    let mut dst_file = OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(dst_path)
                        .with_context(|| {
                            format!("Failed to create destination {}", dst_path.display())
                        })?;
                    dst_file.write_all(&out_buf[..out_offset])?;
                    if dst_file.metadata().map(|m| m.len()).unwrap_or(0) != out_offset as u64 {
                        dst_file.set_len(out_offset as u64)?;
                    }
                    Ok(true)
                })
            });
        }
    }

    let mmap = unsafe { Mmap::map(&src_file) }
        .with_context(|| format!("Failed to mmap sparse image {}", src_path.display()))?;
    let hdr = match parse_sparse_header(&mmap)? {
        Some(h) => h,
        None => return Ok(false),
    };

    let file_name = src_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    info!("Unsparsing {} -> {}", src_path.display(), dst_path.display());

    let total_size = hdr.total_blks * hdr.blk_sz;
    let dst_file = File::create(dst_path)
        .with_context(|| format!("Failed to create destination {}", dst_path.display()))?;
    let mut writer = BufWriter::with_capacity(64 * 1024, dst_file);

    let mut pb = if total_size >= PROGRESS_THRESHOLD {
        let p = crate::utils::progress::get_multi_progress().add(ProgressBar::new(total_size));
        if let Ok(style) = ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:30.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta}) {msg}",
        ) {
            p.set_style(style.progress_chars("=>-"));
        }
        p.set_message(format!("Unsparsing {}", file_name));
        Some(p)
    } else {
        None
    };

    let mut fill_buf = Vec::new();
    let out_offset = decode_sparse_mmap(&mmap, hdr, &mut writer, &mut fill_buf, pb.as_mut(), file_name)?;

    writer.flush()?;
    let inner = writer.get_mut();
    if inner.stream_position()? < out_offset {
        inner.set_len(out_offset)?;
    }

    if let Some(p) = pb {
        p.finish_and_clear();
    }
    info!("Unsparsed {} ({} total)", file_name, HumanBytes(out_offset));

    Ok(true)
}

pub fn unsparse_chunks(chunk_paths: &[PathBuf], dst_path: &Path) -> Result<()> {
    if chunk_paths.is_empty() {
        return Ok(());
    }

    info!(
        "Unsparsing {} chunks into {}",
        chunk_paths.len(),
        dst_path.display()
    );

    let dst_file = File::create(dst_path)
        .with_context(|| format!("Failed to create output {}", dst_path.display()))?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, dst_file);

    let pb = crate::utils::progress::get_multi_progress().add(ProgressBar::new(chunk_paths.len() as u64));
    if let Ok(style) = ProgressStyle::with_template(
        "[{elapsed_precise}] [{bar:30.cyan/blue}] {pos}/{len} chunks ({eta}) {msg}",
    ) {
        pb.set_style(style.progress_chars("=>-"));
    }

    let mut fill_buf = Vec::new();
    let mut max_written = 0u64;

    for (idx, chunk) in chunk_paths.iter().enumerate() {
        let chunk_name = chunk
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        pb.set_message(chunk_name.to_string());
        debug!("Processing sparse chunk {}", chunk.display());

        let file = File::open(chunk)
            .with_context(|| format!("Failed to open chunk {}", chunk.display()))?;
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to mmap chunk {}", chunk.display()))?;

        if let Some(hdr) = parse_sparse_header(&mmap)? {
            // Each sparsechunk starts from logical offset 0 and uses DONT_CARE to skip prior chunks
            writer.flush()?;
            writer.get_mut().seek(SeekFrom::Start(0))?;
            let end_offset = decode_sparse_mmap(&mmap, hdr, &mut writer, &mut fill_buf, None, chunk_name)?;
            max_written = max_written.max(end_offset);
        } else {
            writer.write_all(&mmap)?;
            let rem = mmap.len() % 4096;
            if rem != 0 {
                let pad = 4096 - rem;
                writer.write_all(&ZERO_BUF[..pad])?;
            }
            writer.flush()?;
            max_written = max_written.max(writer.get_mut().stream_position()?);
        }
        pb.set_position((idx + 1) as u64);
    }

    writer.flush()?;
    let inner = writer.get_mut();
    if inner.metadata()?.len() < max_written {
        inner.set_len(max_written)?;
    }

    pb.finish_and_clear();
    info!("All chunks unsparsed ({} chunks processed)", chunk_paths.len());

    for chunk in chunk_paths {
        let _ = fs::remove_file(chunk);
    }

    Ok(())
}
