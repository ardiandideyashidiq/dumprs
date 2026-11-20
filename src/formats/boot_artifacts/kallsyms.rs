//! Recovery of the compressed kernel symbol table (`kallsyms`) from a raw kernel image.

use anyhow::{Result, bail};
use std::borrow::Cow;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub address: u64,
    pub kind: char,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

fn read_uint(data: &[u8], offset: usize, size: usize, endian: Endian) -> Result<u64> {
    let bytes = data
        .get(offset..offset + size)
        .ok_or_else(|| anyhow::anyhow!("truncated integer at {offset:#x}"))?;
    Ok(match (size, endian) {
        (2, Endian::Little) => u16::from_le_bytes(bytes[..2].try_into()?) as u64,
        (2, Endian::Big) => u16::from_be_bytes(bytes[..2].try_into()?) as u64,
        (4, Endian::Little) => u32::from_le_bytes(bytes[..4].try_into()?) as u64,
        (4, Endian::Big) => u32::from_be_bytes(bytes[..4].try_into()?) as u64,
        (8, Endian::Little) => u64::from_le_bytes(bytes[..8].try_into()?),
        (8, Endian::Big) => u64::from_be_bytes(bytes[..8].try_into()?),
        _ => bail!("unsupported integer size {size}"),
    })
}

fn is_symbol_type(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'-' | b'?')
}

/// Decode the length-prefixed, token-compressed `kallsyms_names` table.
/// Each entry is a length byte (two bytes when the high bit is set, for names
/// longer than 127 tokens) followed by token indices into `token_table`.
pub fn decode_names(names: &[u8], token_table: &[Vec<u8>], count: usize) -> Result<Vec<String>> {
    let mut result = Vec::with_capacity(count);
    let mut position = 0usize;
    for _ in 0..count {
        let first = *names
            .get(position)
            .ok_or_else(|| anyhow::anyhow!("truncated kallsyms name length"))?;
        position += 1;
        let len = if first & 0x80 != 0 {
            let second = *names
                .get(position)
                .ok_or_else(|| anyhow::anyhow!("truncated long kallsyms name length"))?;
            position += 1;
            ((first & 0x7f) as usize) | ((second as usize) << 7)
        } else {
            first as usize
        };
        let mut name = String::new();
        for _ in 0..len {
            let index = *names
                .get(position)
                .ok_or_else(|| anyhow::anyhow!("truncated kallsyms token"))?
                as usize;
            position += 1;
            let token = token_table
                .get(index)
                .ok_or_else(|| anyhow::anyhow!("kallsyms token index {index} out of range"))?;
            name.push_str(&String::from_utf8_lossy(token));
        }
        result.push(name);
    }
    Ok(result)
}

/// Render symbols in the `/proc/kallsyms` format used by `kallsyms-finder`.
pub fn render_kallsyms(symbols: &[Symbol]) -> String {
    let mut out = String::new();
    for symbol in symbols {
        out.push_str(&format!(
            "{:016x} {} {}\n",
            symbol.address, symbol.kind, symbol.name
        ));
    }
    out
}

/// Find every non-overlapping occurrence of `needle` in `data`.
///
/// Uses SIMD-accelerated substring search from `memchr` and yields offsets
/// lazily into the caller's vector, avoiding a second scan per match.
pub fn find_all_offsets(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > data.len() {
        return Vec::new();
    }
    memchr::memmem::find_iter(data, needle).collect()
}

/// Interpret a raw 32-bit word as a two's-complement `i32` in the given
/// byte order. Used for `kallsyms_offsets`, which are signed `.long` values.
pub fn offset_i32(raw: u32, big_endian: bool) -> i32 {
    if big_endian {
        i32::from_be_bytes(raw.to_be_bytes())
    } else {
        i32::from_le_bytes(raw.to_le_bytes())
    }
}

/// Locate `kallsyms_token_table`: 256 NUL-terminated fragments, where the
/// ASCII digits occupy their own indices contiguously.
fn find_token_table(kernel: &[u8]) -> Result<(usize, Vec<Vec<u8>>)> {
    let needle: Vec<u8> = (b'0'..=b'9').flat_map(|digit| [digit, 0]).collect();
    let mut candidates = Vec::new();
    let mut preferred = Vec::new();
    for position in find_all_offsets(kernel, &needle) {
        let after = position + needle.len();
        let tail = kernel.get(after..).unwrap_or_default();
        if [
            b":\0".as_slice(),
            b"\0\0",
            b"\x00\x01",
            b"\x00\x02",
            b"ASCII\0",
        ]
        .iter()
        .any(|bad| tail.starts_with(bad))
        {
            continue;
        }
        candidates.push(position);
        if tail.first().is_some_and(u8::is_ascii_alphanumeric) {
            preferred.push(position);
        }
    }
    let position = if candidates.len() == 1 {
        candidates[0]
    } else if preferred.len() == 1 {
        preferred[0]
    } else {
        bail!(
            "found {} candidates for kallsyms_token_table",
            candidates.len()
        );
    };

    let mut start = position;
    if start == 0 || kernel[start - 1] != 0 {
        bail!("digit sequence is not part of a kallsyms token table");
    }
    start -= 1;
    for _ in 0..(b'0' as usize) {
        let mut chars = 0usize;
        loop {
            if start == 0 {
                bail!("truncated kallsyms token table");
            }
            start -= 1;
            let byte = kernel[start];
            if byte == 0 || byte > b'z' {
                break;
            }
            chars += 1;
            if chars >= 50 {
                bail!("not a kallsyms token table");
            }
        }
    }
    start += 1;
    start = start.div_ceil(4) * 4;

    let mut tokens = Vec::with_capacity(256);
    let mut cursor = start;
    for _ in 0..256 {
        let end = kernel[cursor..]
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(|| anyhow::anyhow!("truncated kallsyms token table"))?
            + cursor;
        tokens.push(kernel[cursor..end].to_vec());
        cursor = end + 1;
    }
    Ok((start, tokens))
}

/// Locate `kallsyms_token_index` by searching for the 256 offsets computed
/// from the token table, simultaneously determining endianness.
fn find_token_index(
    kernel: &[u8],
    table_offset: usize,
    tokens: &[Vec<u8>],
) -> Result<(usize, Endian)> {
    let mut offsets = Vec::with_capacity(256);
    let mut position = table_offset;
    for token in tokens {
        offsets.push((position - table_offset) as u16);
        position += token.len() + 1;
    }
    let area_end = (position + 512 + 256).min(kernel.len());
    let area = &kernel[position..area_end];

    let mut le = Vec::with_capacity(512);
    let mut be = Vec::with_capacity(512);
    for offset in &offsets {
        le.extend_from_slice(&offset.to_le_bytes());
        be.extend_from_slice(&offset.to_be_bytes());
    }
    let le_pos = find_all_offsets(area, &le).into_iter().next_back();
    let be_pos = find_all_offsets(area, &be).into_iter().next_back();
    match (le_pos, be_pos) {
        (Some(l), Some(b)) if b > l => Ok((position + b, Endian::Big)),
        (Some(l), _) => Ok((position + l, Endian::Little)),
        (None, Some(b)) => Ok((position + b, Endian::Big)),
        (None, None) => bail!("kallsyms_token_index not found"),
    }
}

/// Locate `kallsyms_markers`: a sorted list of offsets into `kallsyms_names`.
fn find_markers(kernel: &[u8], table_offset: usize, endian: Endian) -> Result<(usize, usize)> {
    for element_size in [4usize, 8, 2] {
        let limit = table_offset.min(kernel.len());
        let floor = limit.saturating_sub(2 * 1024 * 1024);
        let mut cursor = limit;
        for _ in 0..32 {
            let mut position = cursor
                .saturating_sub(element_size)
                .saturating_sub((cursor - floor) % element_size);
            let mut found = None;
            while position >= floor && position + element_size <= kernel.len() {
                if kernel[position..position + element_size]
                    .iter()
                    .all(|&byte| byte == 0)
                {
                    found = Some(position);
                    break;
                }
                if position == 0 {
                    break;
                }
                position -= element_size;
            }
            let Some(found) = found else {
                break;
            };
            cursor = found;
            let position = found - (found % element_size);
            let entries: Result<Vec<u64>> = (0..4)
                .map(|index| {
                    read_uint(
                        kernel,
                        position + index * element_size,
                        element_size,
                        endian,
                    )
                })
                .collect();
            let Ok(entries) = entries else {
                continue;
            };
            if entries[0] != 0 {
                continue;
            }
            if (1..4).all(|index| {
                entries[index - 1] + 0x200 <= entries[index]
                    && entries[index] <= entries[index - 1] + 0x40000
            }) {
                return Ok((position, element_size));
            }
        }
    }
    bail!("Could not find kallsyms_markers")
}

fn find_names_offset(
    kernel: &[u8],
    markers_offset: usize,
    table_offset: usize,
    element_size: usize,
    endian: Endian,
) -> Result<usize> {
    let count = (table_offset - markers_offset) / element_size;
    let mut entries = Vec::new();
    for index in 0..count.min(3000) {
        let value = read_uint(
            kernel,
            markers_offset + index * element_size,
            element_size,
            endian,
        )?;
        if let Some(previous) = entries.last()
            && (*previous + 0x200 >= value || *previous + 0x40000 < value)
        {
            break;
        }
        entries.push(value);
    }
    let marker_count = entries.len();
    let last = entries
        .into_iter()
        .rev()
        .find(|value| *value != 0)
        .unwrap_or(0) as usize;
    // Markers point at every 256th name, so extrapolating the last marker to
    // the full table gives the byte length of `kallsyms_names`.
    let names_size = if marker_count > 1 {
        last * marker_count / (marker_count - 1)
    } else {
        last
    };
    let mut position = markers_offset
        .checked_sub(names_size)
        .filter(|position| *position > 0)
        .ok_or_else(|| anyhow::anyhow!("invalid kallsyms_names offset"))?;
    position -= position % element_size;
    Ok(position)
}

fn find_num_syms(
    kernel: &[u8],
    names_offset: usize,
    markers_offset: usize,
    tokens: &[Vec<u8>],
    element_size: usize,
    endian: Endian,
) -> Result<(usize, usize, usize)> {
    let base = names_offset;
    for direction in [1isize, -1isize] {
        for step in 0..8192usize {
            let Some(names_offset) = (base as isize)
                .checked_add(direction * (step as isize) * 4)
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| *value < markers_offset)
            else {
                continue;
            };
            let length = *kernel.get(names_offset).unwrap_or(&0) as usize;
            let token = kernel.get(names_offset + 1).copied().unwrap_or(0) as usize;
            if length == 0
                || tokens
                    .get(token)
                    .and_then(|entry| entry.first().copied())
                    .is_none_or(|byte| !is_symbol_type(byte))
            {
                continue;
            }
            let names = &kernel[names_offset..markers_offset];
            let mut count = 0usize;
            let mut position = 0usize;
            while position < names.len() {
                let length = names[position] as usize;
                if length == 0 {
                    break;
                }
                position += 1 + length;
                count += 1;
            }
            if count >= 256 {
                let encoded = match element_size {
                    2 => (count as u16).to_le_bytes().to_vec(),
                    4 => (count as u32).to_le_bytes().to_vec(),
                    _ => (count as u64).to_le_bytes().to_vec(),
                };
                let encoded = match endian {
                    Endian::Little => encoded,
                    Endian::Big => match element_size {
                        2 => (count as u16).to_be_bytes().to_vec(),
                        4 => (count as u32).to_be_bytes().to_vec(),
                        _ => (count as u64).to_be_bytes().to_vec(),
                    },
                };
                let start = names_offset.saturating_sub(256 + 20);
                if let Some(found) = kernel[start..names_offset]
                    .windows(encoded.len())
                    .rposition(|window| window == encoded)
                {
                    return Ok((names_offset, count, start + found));
                }
            }
        }
    }
    bail!("Could not find kallsyms_num_syms")
}

fn plausible_address(value: u64, pointer_size: usize) -> bool {
    if pointer_size == 8 {
        (0x4000_0000..0xffff_ffff_ffff_0000).contains(&value)
    } else {
        value >= 0x4000_0000
    }
}

fn find_addresses(
    kernel: &[u8],
    num_syms_offset: usize,
    count: usize,
    endian: Endian,
) -> Result<Vec<u64>> {
    for pointer_size in [8usize, 4] {
        let array_size = count
            .checked_mul(pointer_size)
            .ok_or_else(|| anyhow::anyhow!("kallsyms address array overflow"))?;
        // For kernels before 6.4 the address array sits immediately before
        // kallsyms_num_syms, separated only by zero alignment padding.
        let mut end = num_syms_offset;
        while end >= pointer_size
            && kernel[end - pointer_size..end]
                .iter()
                .all(|&byte| byte == 0)
        {
            end -= pointer_size;
        }
        let Some(start) = end
            .checked_sub(array_size)
            .filter(|start| *start + array_size <= kernel.len())
        else {
            continue;
        };
        let values: Result<Vec<u64>> = (0..count)
            .map(|index| read_uint(kernel, start + index * pointer_size, pointer_size, endian))
            .collect();
        if let Ok(values) = values
            && !values.is_empty()
            && values
                .iter()
                .all(|&value| plausible_address(value, pointer_size))
        {
            return Ok(values);
        }
    }
    bail!("Could not find kallsyms addresses")
}

/// Decompress a kernel payload in place-style (gzip/xz/zstd/lz4/bzip2/LZMA).
/// Returns the input unchanged when it is already a raw kernel image.
pub fn decompress_kernel(data: &[u8]) -> Cow<'_, [u8]> {
    fn decode<R: Read>(reader: R) -> Option<Cow<'static, [u8]>> {
        let mut out = Vec::new();
        reader.take(512 * 1024 * 1024).read_to_end(&mut out).ok()?;
        (!out.is_empty()).then_some(Cow::Owned(out))
    }

    if data.starts_with(&[0x1f, 0x8b]) {
        decode(flate2::bufread::MultiGzDecoder::new(data)).unwrap_or(Cow::Borrowed(data))
    } else if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        decode(xz2::read::XzDecoder::new(data)).unwrap_or(Cow::Borrowed(data))
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        match zstd::stream::read::Decoder::new(data) {
            Ok(decoder) => decode(decoder).unwrap_or(Cow::Borrowed(data)),
            Err(_) => Cow::Borrowed(data),
        }
    } else if data.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        decode(lz4_flex::frame::FrameDecoder::new(data)).unwrap_or(Cow::Borrowed(data))
    } else if data.starts_with(b"BZh") {
        decode(bzip2::read::BzDecoder::new(data)).unwrap_or(Cow::Borrowed(data))
    } else if data.starts_with(&[0x5d, 0x00, 0x00, 0x00]) {
        let mut out = Vec::new();
        let mut input = std::io::BufReader::new(data);
        if lzma_rs::lzma_decompress(&mut input, &mut out).is_ok() && !out.is_empty() {
            Cow::Owned(out)
        } else {
            Cow::Borrowed(data)
        }
    } else {
        Cow::Borrowed(data)
    }
}

/// Translate `kallsyms_offsets` into virtual addresses. With
/// `CONFIG_KALLSYMS_ABSOLUTE_PERCPU`, negative offsets encode absolute
/// per-CPU symbols as `base - 1 - offset` (see `kernel/kallsyms.c`).
pub fn decode_relative_addresses(base: u64, offsets: &[i32], absolute_percpu: bool) -> Vec<u64> {
    offsets
        .iter()
        .map(|&offset| {
            if absolute_percpu {
                if offset < 0 {
                    base.wrapping_sub(1).wrapping_sub(offset as u64)
                } else {
                    offset as u64
                }
            } else {
                base.wrapping_add(offset as u64)
            }
        })
        .collect()
}

/// Locate `kallsyms_offsets` + `kallsyms_relative_base` (kernels with
/// `CONFIG_KALLSYMS_BASE_RELATIVE`, default since 4.6 on most architectures).
fn find_relative_addresses(
    kernel: &[u8],
    num_syms_offset: usize,
    count: usize,
    element_size: usize,
    endian: Endian,
) -> Result<Vec<u64>> {
    let offset_size = element_size.min(4);
    for address_size in [8usize, 4] {
        let mut position = num_syms_offset;
        while position >= address_size
            && kernel[position - address_size..position]
                .iter()
                .all(|&byte| byte == 0)
        {
            position -= address_size;
        }
        let base = match read_uint(
            kernel,
            position.saturating_sub(address_size),
            address_size,
            endian,
        ) {
            Ok(value) => value,
            Err(_) => continue,
        };
        position = position.saturating_sub(address_size);
        while position >= offset_size
            && kernel[position - offset_size..position]
                .iter()
                .all(|&byte| byte == 0)
        {
            position -= offset_size;
        }
        let array_size = match count.checked_mul(offset_size) {
            Some(size) => size,
            None => continue,
        };
        let Some(start) = position.checked_sub(array_size) else {
            continue;
        };
        let offsets: Result<Vec<i32>> = (0..count)
            .map(|index| {
                let raw = read_uint(kernel, start + index * offset_size, offset_size, endian)?;
                let raw = u32::try_from(raw)
                    .map_err(|_| anyhow::anyhow!("kallsyms offset out of range"))?;
                Ok(offset_i32(raw, endian == Endian::Big))
            })
            .collect();
        let Ok(offsets) = offsets else {
            continue;
        };
        if offsets.len() >= 3 && !(offsets[0] <= offsets[1] && offsets[1] <= offsets[2]) {
            continue;
        }
        let absolute_percpu =
            offsets.iter().filter(|&&offset| offset < 0).count() * 2 >= offsets.len();
        let addresses = decode_relative_addresses(base, &offsets, absolute_percpu);
        if !addresses.is_empty()
            && addresses
                .iter()
                .all(|&value| plausible_address(value, address_size))
        {
            return Ok(addresses);
        }
    }
    bail!("Could not find kallsyms relative addresses")
}

/// Locate and decode the kallsyms table inside a raw kernel image.
pub fn find_kallsyms(kernel: &[u8]) -> Result<Vec<Symbol>> {
    let (_table_offset, tokens) = find_token_table(kernel)?;
    let (_index_offset, endian) = find_token_index(kernel, _table_offset, &tokens)?;
    let (markers_offset, element_size) = find_markers(kernel, _table_offset, endian)?;
    let names_offset =
        find_names_offset(kernel, markers_offset, _table_offset, element_size, endian)?;
    let (names_offset, count, num_syms_offset) = find_num_syms(
        kernel,
        names_offset,
        markers_offset,
        &tokens,
        element_size,
        endian,
    )?;
    let addresses = match find_addresses(kernel, num_syms_offset, count, endian) {
        Ok(addresses) => addresses,
        Err(absolute_error) => find_relative_addresses(
            kernel,
            num_syms_offset,
            count,
            element_size,
            endian,
        )
        .map_err(|relative_error| {
            anyhow::anyhow!(
                "no kallsyms address table (absolute: {absolute_error}; base-relative: {relative_error})"
            )
        })?,
    };
    let encoded_names = decode_names(&kernel[names_offset..markers_offset], &tokens, count)?;

    let mut symbols = Vec::with_capacity(count);
    for (address, encoded) in addresses.into_iter().zip(encoded_names) {
        let mut chars = encoded.chars();
        let kind = chars
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty kallsyms name"))?;
        let name = chars.as_str().to_string();
        symbols.push(Symbol {
            address,
            kind,
            name,
        });
    }
    Ok(symbols)
}
