//! Flattened Device Tree helpers: split concatenated DTB blobs and render DTS.

use anyhow::{Result, bail};
use dtoolkit::fdt::Fdt;

/// Big-endian bytes of the FDT magic `0xd00dfeed`.
const FDT_MAGIC: [u8; 4] = [0xd0, 0x0d, 0xfe, 0xed];
/// Big-endian bytes of the DTBO container magic `0xd7b7ab1e`.
const DTBO_MAGIC: [u8; 4] = [0xd7, 0xb7, 0xab, 0x1e];
const FDT_HEADER_SIZE: usize = 40;

/// Split a blob containing one or more concatenated FDT blobs into the
/// individual blobs. Zero-copy: every returned slice points into `data`.
///
/// # Errors
///
/// Returns an error when an FDT header declares an invalid or truncated
/// `totalsize`.
///
/// Junk before/between blobs is skipped in 4-byte steps (FDTs are aligned),
/// which is what `extract-dtb` effectively does when scanning an image.
pub fn split_dtb(data: &[u8]) -> Result<Vec<&[u8]>> {
    let mut blobs = Vec::new();
    let mut pos = 0usize;
    while pos + FDT_HEADER_SIZE <= data.len() {
        let magic = &data[pos..pos + 4];
        if magic == DTBO_MAGIC {
            // DTBO container header; the FDT follows it.
            pos += 4;
            continue;
        }
        if magic != FDT_MAGIC {
            pos += 4;
            continue;
        }
        let total_size = u32::from_be_bytes(data[pos + 4..pos + 8].try_into()?) as usize;
        if total_size < FDT_HEADER_SIZE {
            bail!("invalid FDT totalsize {total_size} at offset {pos}");
        }
        let end = pos
            .checked_add(total_size)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| anyhow::anyhow!("truncated FDT at offset {pos}"))?;
        blobs.push(&data[pos..end]);
        pos = end;
    }
    Ok(blobs)
}

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

fn be_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = slice(data, offset, 4, "FDT field")?;
    Ok(u32::from_be_bytes(bytes.try_into()?))
}

fn slice<'a>(data: &'a [u8], offset: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| anyhow::anyhow!("truncated FDT {what}"))?;
    Ok(&data[offset..end])
}

fn align4(value: usize) -> usize {
    value.div_ceil(4) * 4
}

/// Validate the FDT structure block ourselves. `dtoolkit`'s strict validator
/// rejects property names longer than 31 characters, which real vendor DTBs
/// (and `dtc`) accept, so we validate the structure without that restriction
/// before using its unchecked (zero-copy) view to render DTS.
fn validate_fdt(data: &[u8]) -> Result<()> {
    if data.len() < FDT_HEADER_SIZE || data[0..4] != FDT_MAGIC {
        bail!("not an FDT blob");
    }
    if be_u32(data, 4)? as usize != data.len() {
        bail!("FDT totalsize does not match the blob length");
    }
    let struct_offset = be_u32(data, 8)? as usize;
    let strings_offset = be_u32(data, 12)? as usize;
    let strings_size = be_u32(data, 32)? as usize;
    let struct_size = be_u32(data, 36)? as usize;

    let struct_end = struct_offset
        .checked_add(struct_size)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| anyhow::anyhow!("FDT structure block out of bounds"))?;
    let strings_end = strings_offset
        .checked_add(strings_size)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| anyhow::anyhow!("FDT strings block out of bounds"))?;

    let mut position = struct_offset;
    let mut depth = 0usize;
    loop {
        let tag = be_u32(data, position)?;
        position += 4;
        match tag {
            FDT_BEGIN_NODE => {
                let name = slice(
                    data,
                    position,
                    struct_end.saturating_sub(position),
                    "node name",
                )?;
                let name_end = name
                    .iter()
                    .position(|&byte| byte == 0)
                    .ok_or_else(|| anyhow::anyhow!("unterminated FDT node name"))?;
                position = align4(position + name_end + 1);
                depth += 1;
            }
            FDT_END_NODE => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("unbalanced FDT nodes"))?;
            }
            FDT_PROP => {
                let header = slice(data, position, 8, "property header")?;
                let len = u32::from_be_bytes(header[0..4].try_into()?) as usize;
                let name_offset = u32::from_be_bytes(header[4..8].try_into()?) as usize;
                position += 8;
                if name_offset >= strings_size {
                    bail!("FDT property name offset out of bounds");
                }
                let name = slice(
                    data,
                    strings_offset + name_offset,
                    strings_end - strings_offset - name_offset,
                    "property name",
                )?;
                if !name.contains(&0) {
                    bail!("unterminated FDT property name");
                }
                position = align4(
                    position
                        .checked_add(len)
                        .ok_or_else(|| anyhow::anyhow!("FDT property length overflow"))?,
                );
                if position > struct_end {
                    bail!("FDT property extends past the structure block");
                }
            }
            FDT_NOP => {}
            FDT_END => {
                if depth != 0 {
                    bail!("unbalanced FDT nodes at FDT_END");
                }
                return Ok(());
            }
            other => bail!("unknown FDT tag {other}"),
        }
    }
}

/// Render one FDT blob as DTS source text, equivalent to
/// `dtc -I dtb -O dts`.
///
/// # Errors
///
/// Returns an error when the FDT structure block is invalid.
pub fn dtb_to_dts(data: &[u8]) -> Result<String> {
    validate_fdt(data)?;
    // SAFETY by inspection: `validate_fdt` walks the whole structure block,
    // checks every property header and string offset, and requires a balanced
    // FDT_END. dtoolkit's own `new()` additionally enforces a 31-character
    // property-name limit that `dtc` and real vendor DTBs do not have.
    let fdt = Fdt::new_unchecked(data);
    Ok(format!("{fdt}"))
}
