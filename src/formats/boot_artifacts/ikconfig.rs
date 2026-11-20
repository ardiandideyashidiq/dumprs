//! Extraction of the kernel `.config` embedded via `CONFIG_IKCONFIG`.

use anyhow::Result;
use std::io::Read;

const START_MAGIC: &[u8] = b"IKCFG_ST";
const END_MAGIC: &[u8] = b"IKCFG_ED";
/// An embedded `.config` is a few hundred KiB at most; cap decompression so a
/// malicious/corrupt payload cannot exhaust memory.
const MAX_CONFIG_SIZE: u64 = 8 * 1024 * 1024;

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn limited_decode<R: Read>(reader: R) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader.take(MAX_CONFIG_SIZE).read_to_end(&mut out).ok()?;
    (!out.is_empty()).then_some(out)
}

fn decode_gzip(data: &[u8]) -> Option<Vec<u8>> {
    limited_decode(flate2::bufread::MultiGzDecoder::new(data))
}

fn decode_xz(data: &[u8]) -> Option<Vec<u8>> {
    limited_decode(xz2::read::XzDecoder::new(data))
}

fn decode_bzip2(data: &[u8]) -> Option<Vec<u8>> {
    limited_decode(bzip2::read::BzDecoder::new(data))
}

fn decode_zstd(data: &[u8]) -> Option<Vec<u8>> {
    limited_decode(zstd::stream::read::Decoder::new(data).ok()?)
}

fn decode_lz4(data: &[u8]) -> Option<Vec<u8>> {
    limited_decode(lz4_flex::frame::FrameDecoder::new(data))
}

fn take<'a>(data: &'a [u8], position: &mut usize, len: usize) -> Option<&'a [u8]> {
    let slice = data.get(*position..*position + len)?;
    *position += len;
    Some(slice)
}

fn be_u32(data: &[u8], position: &mut usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        take(data, position, 4)?.try_into().ok()?,
    ))
}

/// Decode an LZOP container (magic `89 4C 5A 4F 00 0D 0A 1A 0A`) into its
/// payload. This is what `extract-ikconfig` invokes as `lzop -d`.
/// Header, per-block and final data checksums are verified; a mismatch means
/// the payload is rejected rather than silently trusted.
pub fn decode_lzop(data: &[u8]) -> Option<Vec<u8>> {
    const MAGIC: [u8; 9] = [0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a];
    const F_H_FILTER: u32 = 0x0000_0800;
    const F_H_EXTRA_FIELD: u32 = 0x0000_0040;
    const F_ADLER32_C: u32 = 0x0000_0002;
    const F_CRC32_D: u32 = 0x0000_0100;
    const F_CRC32_C: u32 = 0x0000_0200;
    const F_H_CRC32: u32 = 0x0000_1000;

    let checksum = |bytes: &[u8], crc32: bool| {
        if crc32 {
            crc32fast::hash(bytes)
        } else {
            adler2::adler32_slice(bytes)
        }
    };

    let mut position = 0usize;
    if take(data, &mut position, 9)? != MAGIC {
        return None;
    }
    let header_start = position;
    let version = u16::from_be_bytes(take(data, &mut position, 2)?.try_into().ok()?);
    let _lib_version = take(data, &mut position, 2)?;
    if version >= 0x0940 {
        let _needed = take(data, &mut position, 2)?;
    }
    let _method = take(data, &mut position, 1)?;
    let _level = take(data, &mut position, 1)?;
    let flags = be_u32(data, &mut position)?;
    if flags & F_H_FILTER != 0 {
        let _filter = take(data, &mut position, 4)?;
    }
    let _mode = take(data, &mut position, 4)?;
    let _mtime_low = take(data, &mut position, 4)?;
    if version >= 0x0940 {
        let _mtime_high = take(data, &mut position, 4)?;
    }
    let name_len = take(data, &mut position, 1)?[0] as usize;
    let _name = take(data, &mut position, name_len)?;
    let header_end = position;
    let stored_header_checksum = be_u32(data, &mut position)?;
    if stored_header_checksum != checksum(&data[header_start..header_end], flags & F_H_CRC32 != 0) {
        return None;
    }
    if flags & F_H_EXTRA_FIELD != 0 {
        let extra_len = be_u32(data, &mut position)? as usize;
        let extra_start = position;
        let _extra = take(data, &mut position, extra_len)?;
        let extra_end = position;
        let stored = be_u32(data, &mut position)?;
        if stored != checksum(&data[extra_start..extra_end], flags & F_H_CRC32 != 0) {
            return None;
        }
    }

    let data_is_crc32 = flags & F_CRC32_D != 0;
    let compressed_is_crc32 = flags & F_CRC32_C != 0;
    let mut out = Vec::new();
    loop {
        let uncompressed_size = be_u32(data, &mut position)? as usize;
        if uncompressed_size == 0 {
            let stored_final = be_u32(data, &mut position)?;
            if stored_final != checksum(&out, data_is_crc32) {
                return None;
            }
            break;
        }
        let compressed_size = be_u32(data, &mut position)? as usize;
        let stored_block = be_u32(data, &mut position)?;
        let stored_compressed = if flags & (F_ADLER32_C | F_CRC32_C) != 0 {
            Some(be_u32(data, &mut position)?)
        } else {
            None
        };
        let payload = take(data, &mut position, compressed_size)?;
        if out.len() + uncompressed_size > MAX_CONFIG_SIZE as usize {
            return None;
        }
        if let Some(stored) = stored_compressed
            && stored != checksum(payload, compressed_is_crc32)
        {
            return None;
        }
        if compressed_size == uncompressed_size {
            out.extend_from_slice(payload);
        } else {
            let start = out.len();
            out.resize(start + uncompressed_size, 0);
            lzo::decompress_into(payload, &mut out[start..]).ok()?;
        }
        if stored_block != checksum(&out[out.len() - uncompressed_size..], data_is_crc32) {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn decode_lzma(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut input = std::io::BufReader::new(data);
    lzma_rs::lzma_decompress(&mut input, &mut out).ok()?;
    (!out.is_empty() && out.len() as u64 <= MAX_CONFIG_SIZE).then_some(out)
}

/// Extract the embedded kernel `.config`.
///
/// Mirrors the codec cascade of `scripts/extract-ikconfig`: the payload after
/// `IKCFG_ST` is tried raw first, then gzip, xz, bzip2, LZMA, LZ4 and zstd.
/// `Ok(None)` means "no usable config" and is a normal outcome (many kernels
/// are built without `CONFIG_IKCONFIG`).
pub fn extract_ikconfig(data: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some(start) = find_subslice(data, START_MAGIC) else {
        return Ok(None);
    };
    let payload_start = start + START_MAGIC.len();
    let payload = match find_subslice(&data[payload_start..], END_MAGIC) {
        Some(end) => &data[payload_start..payload_start + end],
        None => &data[payload_start..],
    };
    if payload.is_empty() || payload.len() as u64 > MAX_CONFIG_SIZE {
        return Ok(None);
    }

    let looks_like_config = |bytes: &[u8]| bytes.starts_with(b"CONFIG_");

    if looks_like_config(payload) {
        return Ok(Some(payload.to_vec()));
    }
    for decode in [
        decode_gzip,
        decode_xz,
        decode_bzip2,
        decode_lzma,
        decode_lz4,
        decode_zstd,
        decode_lzop,
    ] {
        if let Some(decoded) = decode(payload)
            && looks_like_config(&decoded)
        {
            return Ok(Some(decoded));
        }
    }
    Ok(None)
}
