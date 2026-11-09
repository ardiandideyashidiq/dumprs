use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use indicatif::{HumanBytes, HumanDuration};
use memmap2::Mmap;
use rayon::prelude::*;
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Instant;
use tracing::{debug, info};
use crate::utils::progress::ByteProgress;

pub const SPARSE_MAGIC: u32 = 0xed26_ff3a;
const CHUNK_TYPE_RAW: u16 = 0xcac1;
const CHUNK_TYPE_FILL: u16 = 0xcac2;
const CHUNK_TYPE_DONT_CARE: u16 = 0xcac3;
const CHUNK_TYPE_CRC32: u16 = 0xcac4;

const HOLE_SEEK_THRESHOLD: u64 = 64 * 1024;
const FAST_MEM_LIMIT: u64 = 8 * 1024 * 1024;
const ZERO_BUF: [u8; 64 * 1024] = [0u8; 64 * 1024];

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
#[derive(Clone, Copy)]
pub struct SharedAnonSlice {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: SharedAnonSlice points to a live MmapMut of length `len` that outlives all
// worker tasks; callers write to disjoint block ranges and bounds-check every access.
unsafe impl Send for SharedAnonSlice {}
unsafe impl Sync for SharedAnonSlice {}

impl SharedAnonSlice {
    pub fn from_mmap_mut(mmap: &mut memmap2::MmapMut) -> Self {
        let ptr = mmap.as_mut_ptr();
        let len = mmap.len();
        #[cfg(target_os = "linux")]
        {
            unsafe extern "C" {
                fn madvise(addr: *mut core::ffi::c_void, len: usize, advice: i32) -> i32;
            }
            const MADV_HUGEPAGE: i32 = 14;
            unsafe {
                let _ = madvise(ptr.cast(), len, MADV_HUGEPAGE);
            }
        }
        Self { ptr, len }
    }

    /// # Safety
    /// Caller must ensure `start..end` has already been completely written and is no longer mutated.
    #[inline]
    pub unsafe fn subslice(&self, start: usize, end: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.add(start), end - start) }
    }

    #[inline]
    pub fn write_at(&self, buf: &[u8], offset: u64) -> std::io::Result<()> {
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "anon slice overflow")
        })?;
        if end > self.len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "anon slice out of bounds",
            ));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), self.ptr.add(start), buf.len());
        }
        Ok(())
    }

    #[inline]
    pub fn read_exact_at<R: Read>(
        &self,
        reader: &mut R,
        offset: u64,
        len: usize,
        pb: &ByteProgress,
    ) -> Result<()> {
        let start = offset as usize;
        let end = start
            .checked_add(len)
            .context("anon slice read_exact_at overflow")?;
        if end > self.len {
            bail!("anon slice read_exact_at out of bounds ({} > {})", end, self.len);
        }
        // SAFETY: `start..end` is within `0..self.len` and exclusively owned by this chunk.
        let dst = unsafe { std::slice::from_raw_parts_mut(self.ptr.add(start), len) };
        let mut filled = 0usize;
        while filled < len {
            let step = (len - filled).min(4 * 1024 * 1024);
            let n = reader.read(&mut dst[filled..filled + step])?;
            if n == 0 {
                bail!("Unexpected EOF reading directly into anon mmap");
            }
            filled += n;
            pb.inc(n as u64);
        }
        Ok(())
    }
}

pub fn peek_sparse_virtual_size(data: &[u8]) -> Result<Option<u64>> {
    Ok(parse_sparse_header(data)?.map(|hdr| hdr.total_blks * hdr.blk_sz))
}

pub fn peek_sparse_first_offset(data: &[u8]) -> Result<Option<(u64, u64)>> {
    let Some(hdr) = parse_sparse_header(data)? else {
        return Ok(None);
    };
    let vsize = hdr.total_blks * hdr.blk_sz;
    if data.len() < hdr.file_hdr_sz + hdr.chunk_hdr_sz {
        return Ok(Some((vsize, 0)));
    }
    let ch0 = &data[hdr.file_hdr_sz..hdr.file_hdr_sz + hdr.chunk_hdr_sz];
    let chunk_type = u16::from_le_bytes(ch0[0..2].try_into().unwrap());
    let chunk_sz = u32::from_le_bytes(ch0[4..8].try_into().unwrap()) as u64;
    let first_off = if chunk_type == CHUNK_TYPE_DONT_CARE {
        chunk_sz * hdr.blk_sz
    } else {
        0
    };
    Ok(Some((vsize, first_off)))
}

pub fn peek_sparse_prefix<R: Read>(mut reader: R, want_bytes: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut filled = 0usize;
    while filled < 64 {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    let Some(hdr) = parse_sparse_header(&buf[..filled])? else {
        return Ok(Vec::new());
    };
    let mut pos = 0usize;
    let ensure = |pos: &mut usize,
                  filled: &mut usize,
                  buf: &mut [u8],
                  reader: &mut R,
                  need: usize|
     -> Result<()> {
        if *filled - *pos >= need {
            return Ok(());
        }
        let rem = *filled - *pos;
        if *pos > 0 && rem > 0 {
            buf.copy_within(*pos..*filled, 0);
        }
        *pos = 0;
        *filled = rem;
        while *filled < need {
            let n = reader.read(&mut buf[*filled..])?;
            if n == 0 {
                bail!("Unexpected EOF in peek_sparse_prefix");
            }
            *filled += n;
        }
        Ok(())
    };
    ensure(&mut pos, &mut filled, &mut buf, &mut reader, hdr.file_hdr_sz)?;
    pos += hdr.file_hdr_sz;

    let mut out = Vec::with_capacity(want_bytes);
    for _ in 0..hdr.total_chunks {
        if out.len() >= want_bytes {
            break;
        }
        ensure(&mut pos, &mut filled, &mut buf, &mut reader, hdr.chunk_hdr_sz)?;
        let ch = &buf[pos..pos + hdr.chunk_hdr_sz];
        let chunk_type = u16::from_le_bytes(ch[0..2].try_into().unwrap());
        let chunk_sz = u32::from_le_bytes(ch[4..8].try_into().unwrap()) as usize;
        let total_sz = u32::from_le_bytes(ch[8..12].try_into().unwrap()) as usize;
        pos += hdr.chunk_hdr_sz;
        let payload_len = total_sz.saturating_sub(hdr.chunk_hdr_sz);
        let out_bytes = chunk_sz * (hdr.blk_sz as usize);
        let need_out = (want_bytes - out.len()).min(out_bytes);

        match chunk_type {
            CHUNK_TYPE_RAW => {
                let mut rem_copy = need_out;
                let avail = (filled - pos).min(rem_copy);
                out.extend_from_slice(&buf[pos..pos + avail]);
                pos += avail;
                rem_copy -= avail;
                while rem_copy > 0 {
                    let step = rem_copy.min(buf.len());
                    let n = reader.read(&mut buf[..step])?;
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
                    rem_copy -= n;
                }
                let mut skip = payload_len.saturating_sub(need_out);
                let avail_skip = (filled - pos).min(skip);
                pos += avail_skip;
                skip -= avail_skip;
                while skip > 0 {
                    let max_skip = skip.min(buf.len());
                    let n = reader.read(&mut buf[..max_skip])?;
                    if n == 0 {
                        break;
                    }
                    skip -= n;
                }
            }
            CHUNK_TYPE_FILL => {
                ensure(&mut pos, &mut filled, &mut buf, &mut reader, payload_len)?;
                let pat: [u8; 4] = buf[pos..pos + 4].try_into().unwrap();
                pos += payload_len;
                for i in 0..need_out {
                    out.push(pat[i & 3]);
                }
            }
            CHUNK_TYPE_DONT_CARE => {
                out.resize(out.len() + need_out, 0);
            }
            _ => {}
        }
    }
    Ok(out)
}
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
pub struct SparseChunkSpan {
    pub out_start: u64,
    pub out_end: u64,
    pub payload_offset: Option<usize>,
    pub fill_pattern: [u8; 4],
}

pub fn index_sparse_mmap(mmap: &[u8]) -> Result<Option<(u64, Vec<SparseChunkSpan>)>> {
    let Some(hdr) = parse_sparse_header(mmap)? else {
        return Ok(None);
    };
    let mut spans = Vec::with_capacity(hdr.total_chunks as usize);
    let mut in_offset = hdr.file_hdr_sz;
    let mut out_offset = 0u64;

    for _ in 0..hdr.total_chunks {
        if in_offset + hdr.chunk_hdr_sz > mmap.len() {
            bail!("Unexpected EOF reading sparse chunk header");
        }
        let ch = &mmap[in_offset..in_offset + hdr.chunk_hdr_sz];
        let chunk_type = u16::from_le_bytes(ch[0..2].try_into().unwrap());
        let chunk_sz = u32::from_le_bytes(ch[4..8].try_into().unwrap()) as u64;
        let total_sz = u32::from_le_bytes(ch[8..12].try_into().unwrap()) as usize;
        if total_sz < hdr.chunk_hdr_sz || in_offset + total_sz > mmap.len() {
            bail!("Invalid sparse chunk total_sz {}", total_sz);
        }
        let payload_start = in_offset + hdr.chunk_hdr_sz;
        let payload_len = total_sz - hdr.chunk_hdr_sz;
        let out_bytes = chunk_sz * hdr.blk_sz;

        if out_bytes > 0 {
            match chunk_type {
                CHUNK_TYPE_RAW => {
                    if payload_len as u64 != out_bytes {
                        bail!("RAW chunk size mismatch");
                    }
                    spans.push(SparseChunkSpan {
                        out_start: out_offset,
                        out_end: out_offset + out_bytes,
                        payload_offset: Some(payload_start),
                        fill_pattern: [0; 4],
                    });
                }
                CHUNK_TYPE_FILL => {
                    if payload_len < 4 {
                        bail!("FILL chunk payload too small");
                    }
                    let fill_pattern: [u8; 4] =
                        mmap[payload_start..payload_start + 4].try_into().unwrap();
                    spans.push(SparseChunkSpan {
                        out_start: out_offset,
                        out_end: out_offset + out_bytes,
                        payload_offset: None,
                        fill_pattern,
                    });
                }
                CHUNK_TYPE_DONT_CARE => {
                    spans.push(SparseChunkSpan {
                        out_start: out_offset,
                        out_end: out_offset + out_bytes,
                        payload_offset: None,
                        fill_pattern: [0; 4],
                    });
                }
                CHUNK_TYPE_CRC32 => {}
                other => bail!("Unknown sparse chunk type 0x{:04x}", other),
            }
            out_offset += out_bytes;
        }
        in_offset += total_sz;
    }

    Ok(Some((out_offset, spans)))
}

pub fn read_sparse_range(
    mmap: &[u8],
    spans: &[SparseChunkSpan],
    mut offset: u64,
    mut dst: &mut [u8],
) -> Result<()> {
    let mut idx = spans.partition_point(|s| s.out_end <= offset);
    while !dst.is_empty() && idx < spans.len() {
        let span = &spans[idx];
        if offset < span.out_start {
            bail!("Sparse read gap at offset {}", offset);
        }
        let rel_off = (offset - span.out_start) as usize;
        let avail = (span.out_end - offset) as usize;
        let to_copy = dst.len().min(avail);
        let (chunk_dst, rest) = dst.split_at_mut(to_copy);

        if let Some(base) = span.payload_offset {
            chunk_dst.copy_from_slice(&mmap[base + rel_off..base + rel_off + to_copy]);
        } else if span.fill_pattern == [0, 0, 0, 0] {
            chunk_dst.fill(0);
        } else {
            for (i, b) in chunk_dst.iter_mut().enumerate() {
                *b = span.fill_pattern[(rel_off + i) & 3];
            }
        }

        offset += to_copy as u64;
        dst = rest;
        if offset >= span.out_end {
            idx += 1;
        }
    }
    if !dst.is_empty() {
        dst.fill(0);
    }
    Ok(())
}

pub fn write_sparse_range<W: Write>(
    mmap: &[u8],
    spans: &[SparseChunkSpan],
    mut offset: u64,
    mut len: u64,
    writer: &mut W,
) -> Result<()> {
    let mut idx = spans.partition_point(|s| s.out_end <= offset);
    while len > 0 && idx < spans.len() {
        let span = &spans[idx];
        if offset < span.out_start {
            bail!("Sparse write gap at offset {}", offset);
        }
        let rel_off = (offset - span.out_start) as usize;
        let avail = span.out_end - offset;
        let to_write = len.min(avail) as usize;

        if let Some(base) = span.payload_offset {
            writer.write_all(&mmap[base + rel_off..base + rel_off + to_write])?;
        } else if span.fill_pattern == [0, 0, 0, 0] {
            let mut rem = to_write;
            while rem > 0 {
                let n = rem.min(ZERO_BUF.len());
                writer.write_all(&ZERO_BUF[..n])?;
                rem -= n;
            }
        } else {
            let mut pat_buf = [0u8; 4096];
            for (i, b) in pat_buf.iter_mut().enumerate() {
                *b = span.fill_pattern[(rel_off + i) & 3];
            }
            let mut rem = to_write;
            while rem > 0 {
                let n = rem.min(pat_buf.len());
                writer.write_all(&pat_buf[..n])?;
                rem -= n;
            }
        }

        offset += to_write as u64;
        len -= to_write as u64;
        if offset >= span.out_end {
            idx += 1;
        }
    }
    Ok(())
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
        bail!(
            "Invalid sparse header sizes: file_hdr_sz={}, chunk_hdr_sz={}",
            file_hdr_sz,
            chunk_hdr_sz
        );
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
    pb: &ByteProgress,
    file_name: &str,
) -> Result<u64> {
    let mut in_offset = hdr.file_hdr_sz;
    let mut out_offset = 0u64;

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
                pb.inc(out_bytes);
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
                pb.inc(out_bytes);
            }
            CHUNK_TYPE_DONT_CARE => {
                if out_bytes > 0 {
                    writer.flush()?;
                    writer.get_mut().seek(SeekFrom::Start(out_offset + out_bytes))?;
                    out_offset += out_bytes;
                    pb.inc(out_bytes);
                }
            }
            CHUNK_TYPE_CRC32 => {}
            other => bail!("Unknown sparse chunk type 0x{:04x} in {}", other, file_name),
        }

        in_offset += total_sz;
    }

    Ok(out_offset)
}
fn decode_sparse_mmap_at(
    mmap: &[u8],
    hdr: SparseHeader,
    dst_file: &File,
    fill_buf: &mut Vec<u8>,
    pb: &ByteProgress,
    file_name: &str,
) -> Result<u64> {
    let mut in_offset = hdr.file_hdr_sz;
    let mut out_offset = 0u64;

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
                let mut rem = payload_len;
                let mut cur_in = payload_start;
                let mut cur_out = out_offset;
                while rem > 0 {
                    let step = rem.min(4 * 1024 * 1024);
                    write_at(dst_file, &mmap[cur_in..cur_in + step], cur_out)?;
                    cur_in += step;
                    cur_out += step as u64;
                    rem -= step;
                    pb.inc(step as u64);
                }
                out_offset += out_bytes;
            }
            CHUNK_TYPE_FILL => {
                if payload_len < 4 {
                    bail!("FILL chunk payload too small in {}", file_name);
                }
                let fill_bytes: [u8; 4] =
                    mmap[payload_start..payload_start + 4].try_into().unwrap();
                let fill_val = u32::from_le_bytes(fill_bytes);
                if fill_val != 0 {
                    if fill_buf.is_empty() {
                        fill_buf.resize(256 * 1024, 0);
                    }
                    for chunk in fill_buf.chunks_exact_mut(4) {
                        chunk.copy_from_slice(&fill_bytes);
                    }
                    let mut rem = out_bytes as usize;
                    let mut cur_out = out_offset;
                    while rem > 0 {
                        let n = rem.min(fill_buf.len());
                        write_at(dst_file, &fill_buf[..n], cur_out)?;
                        cur_out += n as u64;
                        rem -= n;
                    }
                }
                out_offset += out_bytes;
            }
            CHUNK_TYPE_DONT_CARE => {
                out_offset += out_bytes;
            }
            CHUNK_TYPE_CRC32 => {}
            other => bail!("Unknown sparse chunk type 0x{:04x} in {}", other, file_name),
        }

        in_offset += total_sz;
    }

    Ok((hdr.total_blks * hdr.blk_sz).max(out_offset))
}

struct ChannelReader {
    rx: mpsc::Receiver<Vec<u8>>,
    recycle_tx: mpsc::SyncSender<Vec<u8>>,
    current: Vec<u8>,
    pos: usize,
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.current.len() {
            if !self.current.is_empty() {
                let old = std::mem::take(&mut self.current);
                let _ = self.recycle_tx.try_send(old);
            }
            match self.rx.recv() {
                Ok(buf) => {
                    self.current = buf;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let avail = self.current.len() - self.pos;
        let n = out.len().min(avail);
        out[..n].copy_from_slice(&self.current[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

pub fn extract_stream_or_sparse_pipelined<R: Read + Send>(
    mut reader: R,
    out_file: &File,
    try_sparse: bool,
    pb: &ByteProgress,
) -> Result<(bool, u64)> {
    const CHUNK_CAP: usize = 2 * 1024 * 1024;
    let (data_tx, data_rx) = mpsc::sync_channel::<Vec<u8>>(6);
    let (recycle_tx, recycle_rx) = mpsc::sync_channel::<Vec<u8>>(6);

    std::thread::scope(|s| -> Result<(bool, u64)> {
        let producer = s.spawn(move || -> Result<()> {
            loop {
                let mut buf = recycle_rx
                    .try_recv()
                    .unwrap_or_else(|_| vec![0u8; CHUNK_CAP]);
                if buf.len() < CHUNK_CAP {
                    buf.resize(CHUNK_CAP, 0);
                }
                let mut filled = 0usize;
                while filled < CHUNK_CAP {
                    let n = reader.read(&mut buf[filled..])?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                if filled == 0 {
                    break;
                }
                buf.truncate(filled);
                if data_tx.send(buf).is_err() {
                    break;
                }
            }
            Ok(())
        });

        let mut chan_reader = ChannelReader {
            rx: data_rx,
            recycle_tx,
            current: Vec::new(),
            pos: 0,
        };
        let mut work_buf = vec![0u8; 1024 * 1024];
        let res = extract_stream_or_sparse(&mut chan_reader, out_file, try_sparse, &mut work_buf, pb);
        drop(chan_reader);
        producer
            .join()
            .map_err(|_| anyhow::anyhow!("Decompressor thread panicked"))??;
        res
    })
}

pub fn extract_stream_or_sparse<R: Read>(
    reader: &mut R,
    out_file: &File,
    try_sparse: bool,
    buf: &mut [u8],
    pb: &ByteProgress,
) -> Result<(bool, u64)> {
    let mut filled = 0usize;
    while filled < 64 && filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }

    let hdr_opt = if try_sparse && filled >= 28 {
        parse_sparse_header(&buf[..filled])?
    } else {
        None
    };

    let Some(hdr) = hdr_opt else {
        let mut total_written = 0u64;
        if filled > 0 {
            write_at(out_file, &buf[..filled], 0)?;
            total_written += filled as u64;
            pb.inc(filled as u64);
        }
        loop {
            let n = reader.read(buf)?;
            if n == 0 {
                break;
            }
            write_at(out_file, &buf[..n], total_written)?;
            total_written += n as u64;
            pb.inc(n as u64);
        }
        return Ok((false, total_written));
    };

    let mut pos = 0usize;
    let ensure_bytes = |pos: &mut usize,
                        filled: &mut usize,
                        buf: &mut [u8],
                        reader: &mut R,
                        need: usize|
     -> Result<()> {
        if *filled - *pos >= need {
            return Ok(());
        }
        let rem = *filled - *pos;
        if *pos > 0 && rem > 0 {
            buf.copy_within(*pos..*filled, 0);
        }
        *pos = 0;
        *filled = rem;
        while *filled < need {
            let n = reader.read(&mut buf[*filled..])?;
            if n == 0 {
                bail!("Unexpected EOF in sparse stream (needed {} bytes)", need);
            }
            *filled += n;
        }
        Ok(())
    };

    ensure_bytes(&mut pos, &mut filled, buf, reader, hdr.file_hdr_sz)?;
    pos += hdr.file_hdr_sz;
    pb.inc(hdr.file_hdr_sz as u64);

    let mut out_offset = 0u64;
    let mut fill_buf = Vec::new();

    for _ in 0..hdr.total_chunks {
        ensure_bytes(&mut pos, &mut filled, buf, reader, hdr.chunk_hdr_sz)?;
        let ch = &buf[pos..pos + hdr.chunk_hdr_sz];
        let chunk_type = u16::from_le_bytes(ch[0..2].try_into().unwrap());
        let chunk_sz = u32::from_le_bytes(ch[4..8].try_into().unwrap()) as u64;
        let total_sz = u32::from_le_bytes(ch[8..12].try_into().unwrap()) as usize;
        if total_sz < hdr.chunk_hdr_sz {
            bail!("Invalid sparse chunk total_sz {}", total_sz);
        }
        pos += hdr.chunk_hdr_sz;
        pb.inc(hdr.chunk_hdr_sz as u64);

        let payload_len = total_sz - hdr.chunk_hdr_sz;
        let out_bytes = chunk_sz * hdr.blk_sz;

        match chunk_type {
            CHUNK_TYPE_RAW => {
                if payload_len as u64 != out_bytes {
                    bail!("RAW chunk size mismatch in sparse stream");
                }
                let mut rem = payload_len;
                let avail = (filled - pos).min(rem);
                if avail > 0 {
                    write_at(out_file, &buf[pos..pos + avail], out_offset)?;
                    pos += avail;
                    out_offset += avail as u64;
                    rem -= avail;
                    pb.inc(avail as u64);
                }
                while rem > 0 {
                    let target_read = rem.min(buf.len());
                    let mut chunk_filled = 0usize;
                    while chunk_filled < target_read {
                        let n = reader.read(&mut buf[chunk_filled..target_read])?;
                        if n == 0 {
                            bail!("Unexpected EOF reading RAW sparse chunk payload");
                        }
                        chunk_filled += n;
                    }
                    write_at(out_file, &buf[..chunk_filled], out_offset)?;
                    out_offset += chunk_filled as u64;
                    rem -= chunk_filled;
                    pb.inc(chunk_filled as u64);
                }
            }
            CHUNK_TYPE_FILL => {
                if payload_len < 4 {
                    bail!("FILL chunk payload too small");
                }
                ensure_bytes(&mut pos, &mut filled, buf, reader, payload_len)?;
                let fill_bytes: [u8; 4] = buf[pos..pos + 4].try_into().unwrap();
                pos += payload_len;
                pb.inc(payload_len as u64);
                if u32::from_le_bytes(fill_bytes) != 0 {
                    if fill_buf.is_empty() {
                        fill_buf.resize(256 * 1024, 0);
                    }
                    for chunk in fill_buf.chunks_exact_mut(4) {
                        chunk.copy_from_slice(&fill_bytes);
                    }
                    let mut rem = out_bytes as usize;
                    let mut cur_out = out_offset;
                    while rem > 0 {
                        let n = rem.min(fill_buf.len());
                        write_at(out_file, &fill_buf[..n], cur_out)?;
                        cur_out += n as u64;
                        rem -= n;
                    }
                }
                out_offset += out_bytes;
            }
            CHUNK_TYPE_DONT_CARE | CHUNK_TYPE_CRC32 => {
                let mut rem = payload_len;
                let avail = (filled - pos).min(rem);
                pos += avail;
                rem -= avail;
                pb.inc(avail as u64);
                while rem > 0 {
                    let max_read = rem.min(buf.len());
                    let n = reader.read(&mut buf[..max_read])?;
                    if n == 0 {
                        bail!("Unexpected EOF skipping sparse chunk payload");
                    }
                    rem -= n;
                    pb.inc(n as u64);
                }
                if chunk_type == CHUNK_TYPE_DONT_CARE {
                    out_offset += out_bytes;
                }
            }
            other => bail!("Unknown sparse chunk type 0x{:04x}", other),
        }
    }

    Ok((true, (hdr.total_blks * hdr.blk_sz).max(out_offset)))
}
pub fn extract_stream_to_anon_pipelined<R, F>(
    mut reader: R,
    initial: &[u8],
    target: SharedAnonSlice,
    try_sparse: bool,
    pb: &ByteProgress,
    on_offset: F,
) -> Result<u64>
where
    R: Read + Send,
    F: FnMut(u64) + Send,
{
    const CHUNK_CAP: usize = 2 * 1024 * 1024;
    let (data_tx, data_rx) = mpsc::sync_channel::<Vec<u8>>(8);
    let (recycle_tx, recycle_rx) = mpsc::sync_channel::<Vec<u8>>(8);
    let initial_vec = initial.to_vec();

    std::thread::scope(|s| -> Result<u64> {
        let producer = s.spawn(move || -> Result<()> {
            loop {
                let mut buf = recycle_rx
                    .try_recv()
                    .unwrap_or_else(|_| vec![0u8; CHUNK_CAP]);
                if buf.len() < CHUNK_CAP {
                    buf.resize(CHUNK_CAP, 0);
                }
                let mut filled = 0usize;
                while filled < CHUNK_CAP {
                    let n = reader.read(&mut buf[filled..])?;
                    if n == 0 {
                        break;
                    }
                    filled += n;
                }
                if filled == 0 {
                    break;
                }
                buf.truncate(filled);
                if data_tx.send(buf).is_err() {
                    break;
                }
            }
            Ok(())
        });

        let mut chan_reader = ChannelReader {
            rx: data_rx,
            recycle_tx,
            current: Vec::new(),
            pos: 0,
        };
        let mut work_buf = vec![0u8; 1024 * 1024];
        let res = extract_stream_to_anon_with_cb(
            &mut chan_reader,
            &initial_vec,
            target,
            try_sparse,
            &mut work_buf,
            pb,
            on_offset,
        );
        drop(chan_reader);
        producer
            .join()
            .map_err(|_| anyhow::anyhow!("Decompressor thread panicked"))??;
        res
    })
}

pub fn extract_stream_to_anon<R: Read>(
    reader: &mut R,
    initial: &[u8],
    target: SharedAnonSlice,
    try_sparse: bool,
    buf: &mut [u8],
    pb: &ByteProgress,
) -> Result<u64> {
    extract_stream_to_anon_with_cb(reader, initial, target, try_sparse, buf, pb, |_| {})
}

pub fn extract_stream_to_anon_with_cb<R: Read, F: FnMut(u64)>(
    reader: &mut R,
    initial: &[u8],
    target: SharedAnonSlice,
    try_sparse: bool,
    buf: &mut [u8],
    pb: &ByteProgress,
    mut on_offset: F,
) -> Result<u64> {
    let mut filled = initial.len();
    buf[..filled].copy_from_slice(initial);
    while filled < 64 && filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }

    let hdr_opt = if try_sparse && filled >= 28 {
        parse_sparse_header(&buf[..filled])?
    } else {
        None
    };

    let Some(hdr) = hdr_opt else {
        let mut total_written = 0u64;
        if filled > 0 {
            target.write_at(&buf[..filled], 0)?;
            total_written += filled as u64;
            pb.inc(filled as u64);
        }
        loop {
            let n = reader.read(buf)?;
            if n == 0 {
                break;
            }
            target.write_at(&buf[..n], total_written)?;
            total_written += n as u64;
            pb.inc(n as u64);
        }
        return Ok(total_written);
    };

    let mut pos = 0usize;
    let ensure_bytes = |pos: &mut usize,
                        filled: &mut usize,
                        buf: &mut [u8],
                        reader: &mut R,
                        need: usize|
     -> Result<()> {
        if *filled - *pos >= need {
            return Ok(());
        }
        let rem = *filled - *pos;
        if *pos > 0 && rem > 0 {
            buf.copy_within(*pos..*filled, 0);
        }
        *pos = 0;
        *filled = rem;
        while *filled < need {
            let n = reader.read(&mut buf[*filled..])?;
            if n == 0 {
                bail!("Unexpected EOF in sparse stream (needed {} bytes)", need);
            }
            *filled += n;
        }
        Ok(())
    };

    ensure_bytes(&mut pos, &mut filled, buf, reader, hdr.file_hdr_sz)?;
    pos += hdr.file_hdr_sz;
    pb.inc(hdr.file_hdr_sz as u64);

    let mut out_offset = 0u64;
    let mut fill_buf = Vec::new();

    for _ in 0..hdr.total_chunks {
        ensure_bytes(&mut pos, &mut filled, buf, reader, hdr.chunk_hdr_sz)?;
        let ch = &buf[pos..pos + hdr.chunk_hdr_sz];
        let chunk_type = u16::from_le_bytes(ch[0..2].try_into().unwrap());
        let chunk_sz = u32::from_le_bytes(ch[4..8].try_into().unwrap()) as u64;
        let total_sz = u32::from_le_bytes(ch[8..12].try_into().unwrap()) as usize;
        if total_sz < hdr.chunk_hdr_sz {
            bail!("Invalid sparse chunk total_sz {}", total_sz);
        }
        pos += hdr.chunk_hdr_sz;
        pb.inc(hdr.chunk_hdr_sz as u64);

        let payload_len = total_sz - hdr.chunk_hdr_sz;
        let out_bytes = chunk_sz * hdr.blk_sz;

        match chunk_type {
            CHUNK_TYPE_RAW => {
                if payload_len as u64 != out_bytes {
                    bail!("RAW chunk size mismatch in sparse stream");
                }
                let mut rem = payload_len;
                let avail = (filled - pos).min(rem);
                if avail > 0 {
                    target.write_at(&buf[pos..pos + avail], out_offset)?;
                    pos += avail;
                    out_offset += avail as u64;
                    rem -= avail;
                    pb.inc(avail as u64);
                }
                if rem > 0 {
                    target.read_exact_at(reader, out_offset, rem, pb)?;
                    out_offset += rem as u64;
                }
            }
            CHUNK_TYPE_FILL => {
                if payload_len < 4 {
                    bail!("FILL chunk payload too small");
                }
                ensure_bytes(&mut pos, &mut filled, buf, reader, payload_len)?;
                let fill_bytes: [u8; 4] = buf[pos..pos + 4].try_into().unwrap();
                pos += payload_len;
                pb.inc(payload_len as u64);
                if u32::from_le_bytes(fill_bytes) != 0 {
                    if fill_buf.is_empty() {
                        fill_buf.resize(256 * 1024, 0);
                    }
                    for chunk in fill_buf.chunks_exact_mut(4) {
                        chunk.copy_from_slice(&fill_bytes);
                    }
                    let mut rem = out_bytes as usize;
                    let mut cur_out = out_offset;
                    while rem > 0 {
                        let n = rem.min(fill_buf.len());
                        target.write_at(&fill_buf[..n], cur_out)?;
                        cur_out += n as u64;
                        rem -= n;
                    }
                }
                out_offset += out_bytes;
            }
            CHUNK_TYPE_DONT_CARE | CHUNK_TYPE_CRC32 => {
                let mut rem = payload_len;
                let avail = (filled - pos).min(rem);
                pos += avail;
                rem -= avail;
                pb.inc(avail as u64);
                while rem > 0 {
                    let max_read = rem.min(buf.len());
                    let n = reader.read(&mut buf[..max_read])?;
                    if n == 0 {
                        bail!("Unexpected EOF skipping sparse chunk payload");
                    }
                    rem -= n;
                    pb.inc(n as u64);
                }
                if chunk_type == CHUNK_TYPE_DONT_CARE {
                    out_offset += out_bytes;
                }
            }
            other => bail!("Unknown sparse chunk type 0x{:04x}", other),
        }
        on_offset(out_offset);
    }

    Ok((hdr.total_blks * hdr.blk_sz).max(out_offset))
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
                    debug!(image = %src_path.display(), size = %HumanBytes(out_offset as u64), "sparse.decoded");
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
        .unwrap_or("sparse");

    let total_size = hdr.total_blks * hdr.blk_sz;
    info!(
        image = file_name,
        size = %HumanBytes(total_size),
        chunks = hdr.total_chunks,
        "sparse.decode.start"
    );

    let dst_file = File::create(dst_path)
        .with_context(|| format!("Failed to create destination {}", dst_path.display()))?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, dst_file);
    let pb = ByteProgress::new(file_name, total_size);

    let mut fill_buf = Vec::new();
    let out_offset = decode_sparse_mmap(&mmap, hdr, &mut writer, &mut fill_buf, &pb, file_name)?;

    writer.flush()?;
    let inner = writer.get_mut();
    if inner.stream_position()? < out_offset {
        inner.set_len(out_offset)?;
    }

    pb.finish();
    info!(image = file_name, size = %HumanBytes(out_offset), "sparse.decode.done");

    Ok(true)
}

pub fn unsparse_chunks(chunk_paths: &[PathBuf], dst_path: &Path) -> Result<()> {
    if chunk_paths.is_empty() {
        return Ok(());
    }
    let start_time = Instant::now();

    let total_input: u64 = chunk_paths
        .iter()
        .filter_map(|p| fs::metadata(p).ok().map(|m| m.len()))
        .sum();
    let dst_name = dst_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sparsechunks");

    info!(
        target = dst_name,
        chunks = chunk_paths.len(),
        input_size = %HumanBytes(total_input),
        "sparsechunks.decode.start"
    );

    let first_is_sparse = is_sparse_file(&chunk_paths[0]);
    let pb = ByteProgress::new(dst_name, total_input);

    if first_is_sparse {
        let dst_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dst_path)
            .with_context(|| format!("Failed to create output {}", dst_path.display()))?;
        let max_written = AtomicU64::new(0);

        chunk_paths.par_iter().try_for_each_init(
            Vec::new,
            |fill_buf, chunk| -> Result<()> {
                let chunk_name = chunk
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                debug!(chunk = %chunk.display(), "sparsechunks.chunk.process");
                let file = File::open(chunk)
                    .with_context(|| format!("Failed to open chunk {}", chunk.display()))?;
                let mmap = unsafe { Mmap::map(&file) }
                    .with_context(|| format!("Failed to mmap chunk {}", chunk.display()))?;
                let Some(hdr) = parse_sparse_header(&mmap)? else {
                    bail!("Expected sparse header in chunk {}", chunk.display());
                };
                let end_offset =
                    decode_sparse_mmap_at(&mmap, hdr, &dst_file, fill_buf, &pb, chunk_name)?;
                max_written.fetch_max(end_offset, Ordering::Relaxed);
                drop(mmap);
                drop(file);
                let _ = fs::remove_file(chunk);
                Ok(())
            },
        )?;

        let final_size = max_written.load(Ordering::Relaxed);
        dst_file.set_len(final_size)?;
        pb.finish();
        info!(
            target = dst_name,
            chunks = chunk_paths.len(),
            size = %HumanBytes(final_size),
            duration = %HumanDuration(start_time.elapsed()),
            "sparsechunks.decode.done"
        );
        return Ok(());
    }

    let dst_file = File::create(dst_path)
        .with_context(|| format!("Failed to create output {}", dst_path.display()))?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, dst_file);
    let mut max_written = 0u64;

    for chunk in chunk_paths {
        let file = File::open(chunk)
            .with_context(|| format!("Failed to open chunk {}", chunk.display()))?;
        let mmap = unsafe { Mmap::map(&file) }
            .with_context(|| format!("Failed to mmap chunk {}", chunk.display()))?;
        writer.write_all(&mmap)?;
        let rem = mmap.len() % 4096;
        if rem != 0 {
            let pad = 4096 - rem;
            writer.write_all(&ZERO_BUF[..pad])?;
        }
        writer.flush()?;
        max_written = max_written.max(writer.get_mut().stream_position()?);
        pb.inc(mmap.len() as u64);
        drop(mmap);
        drop(file);
        let _ = fs::remove_file(chunk);
    }

    writer.flush()?;
    let inner = writer.get_mut();
    if inner.metadata()?.len() < max_written {
        inner.set_len(max_written)?;
    }
    pb.finish();
    info!(
        target = dst_name,
        chunks = chunk_paths.len(),
        size = %HumanBytes(max_written),
        duration = %HumanDuration(start_time.elapsed()),
        "sparsechunks.decode.done"
    );
    Ok(())
}
