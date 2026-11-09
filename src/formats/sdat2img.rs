use anyhow::{bail, Context, Result};
use memmap2::Mmap;
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::{debug, info};

const BLOCK_SIZE: u64 = 4096;
const SMALL_GAP_THRESHOLD: u64 = 64 * 1024;
const FAST_MEM_LIMIT: u64 = 8 * 1024 * 1024;
const ZERO_BUF: [u8; 64 * 1024] = [0u8; 64 * 1024];

thread_local! {
    static SDAT_IN_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static SDAT_OUT_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn parse_rangeset_into(
    src: &str,
    is_new: bool,
    new_ranges: &mut Vec<(u64, u64)>,
    max_block: &mut u64,
) -> Result<()> {
    let mut iter = src.trim().split(',');
    let count_str = iter.next().context("Empty rangeset")?;
    let count: usize = count_str.parse().context("Invalid rangeset count")?;
    if is_new {
        new_ranges.reserve(count / 2);
    }
    let mut parsed = 0usize;
    while let Some(begin_str) = iter.next() {
        let end_str = iter.next().context("Odd number of elements in rangeset")?;
        let begin: u64 = begin_str.parse().context("Invalid rangeset begin")?;
        let end: u64 = end_str.parse().context("Invalid rangeset end")?;
        if end > *max_block {
            *max_block = end;
        }
        if is_new {
            new_ranges.push((begin, end));
        }
        parsed += 2;
    }
    if parsed != count {
        bail!("Rangeset count mismatch: expected {}, got {}", count, parsed);
    }
    Ok(())
}

fn parse_transfer_list(path: &Path) -> Result<(u32, u64, u64, Vec<(u64, u64)>)> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let mut lines = content.lines();

    let version: u32 = lines
        .next()
        .context("Missing transfer.list version")?
        .trim()
        .parse()
        .context("Invalid transfer.list version")?;

    let new_blocks: u64 = lines
        .next()
        .context("Missing transfer.list new_blocks")?
        .trim()
        .parse()
        .context("Invalid transfer.list new_blocks")?;

    if version >= 2 {
        let _ = lines.next(); // stash entries
        let _ = lines.next(); // max stashed blocks
    }

    let mut new_ranges = Vec::with_capacity(64);
    let mut max_block = 0u64;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let Some(cmd) = parts.next() else {
            continue;
        };

        if cmd == "erase" || cmd == "new" || cmd == "zero" {
            if let Some(range_arg) = parts.next() {
                parse_rangeset_into(range_arg, cmd == "new", &mut new_ranges, &mut max_block)?;
            }
        } else if !cmd.as_bytes().first().map(|b| b.is_ascii_digit()).unwrap_or(false) {
            debug!("Unknown command in transfer.list: {}", cmd);
        }
    }

    Ok((version, new_blocks, max_block, new_ranges))
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

fn advance_output(
    output_img: &mut BufWriter<File>,
    current_pos: &mut u64,
    target_pos: u64,
) -> Result<()> {
    if target_pos == *current_pos {
        return Ok(());
    }
    if target_pos > *current_pos && target_pos - *current_pos <= SMALL_GAP_THRESHOLD {
        let mut gap = (target_pos - *current_pos) as usize;
        while gap > 0 {
            let n = gap.min(ZERO_BUF.len());
            output_img.write_all(&ZERO_BUF[..n])?;
            gap -= n;
        }
    } else {
        output_img.flush()?;
        output_img.get_mut().seek(SeekFrom::Start(target_pos))?;
    }
    *current_pos = target_pos;
    Ok(())
}

pub fn sdat2img(
    transfer_list_path: &Path,
    new_data_path: &Path,
    output_img_path: &Path,
) -> Result<()> {
    let (version, _new_blocks, max_block, new_ranges) = parse_transfer_list(transfer_list_path)?;
    info!("sdat2img: detected transfer list version {}", version);

    let max_file_size = max_block * BLOCK_SIZE;

    let mut new_data_file = File::open(new_data_path)
        .with_context(|| format!("Failed to open new data file {}", new_data_path.display()))?;
    let in_len = new_data_file.metadata().map(|m| m.len()).unwrap_or(0);

    if max_file_size <= FAST_MEM_LIMIT && in_len <= FAST_MEM_LIMIT {
        return SDAT_IN_BUF.with(|in_cell| {
            SDAT_OUT_BUF.with(|out_cell| {
                let mut in_buf = in_cell.borrow_mut();
                in_buf.resize(in_len as usize, 0);
                new_data_file.read_exact(&mut in_buf)?;

                let mut out_buf = out_cell.borrow_mut();
                let out_len = max_file_size as usize;
                out_buf.resize(out_len, 0);

                let mut src_offset = 0usize;
                let mut prev_end = 0usize;
                for &(begin, end) in &new_ranges {
                    let byte_count = ((end - begin) * BLOCK_SIZE) as usize;
                    let target_pos = (begin * BLOCK_SIZE) as usize;
                    if target_pos > prev_end {
                        out_buf[prev_end..target_pos].fill(0);
                    }
                    if src_offset + byte_count > in_buf.len() {
                        bail!(
                            "sdat2img: new.dat EOF at offset {} (needed {} bytes)",
                            src_offset,
                            byte_count
                        );
                    }
                    out_buf[target_pos..target_pos + byte_count]
                        .copy_from_slice(&in_buf[src_offset..src_offset + byte_count]);
                    src_offset += byte_count;
                    prev_end = prev_end.max(target_pos + byte_count);
                }
                if prev_end < out_len {
                    out_buf[prev_end..out_len].fill(0);
                }

                let mut output_file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(output_img_path)
                    .with_context(|| {
                        format!("Failed to open output image {}", output_img_path.display())
                    })?;
                output_file.write_all(&out_buf)?;
                if output_file.metadata().map(|m| m.len()).unwrap_or(0) != max_file_size {
                    output_file.set_len(max_file_size)?;
                }
                info!("sdat2img: output image written to {}", output_img_path.display());
                Ok(())
            })
        });
    }

    let mmap = unsafe { Mmap::map(&new_data_file) }
        .with_context(|| format!("Failed to mmap new data file {}", new_data_path.display()))?;

    let output_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_img_path)
        .with_context(|| format!("Failed to open output image {}", output_img_path.display()))?;

    let mut src_offset = 0usize;
    let mut max_written = 0u64;

    for &(begin, end) in &new_ranges {
        let byte_count = ((end - begin) * BLOCK_SIZE) as usize;
        let target_pos = begin * BLOCK_SIZE;

        if src_offset + byte_count > mmap.len() {
            bail!(
                "sdat2img: new.dat EOF at offset {} (needed {} bytes)",
                src_offset,
                byte_count
            );
        }
        write_at(&output_file, &mmap[src_offset..src_offset + byte_count], target_pos)?;
        src_offset += byte_count;
        max_written = max_written.max(target_pos + byte_count as u64);
    }

    if max_written < max_file_size {
        output_file.set_len(max_file_size)?;
    }

    info!("sdat2img: output image written to {}", output_img_path.display());
    Ok(())
}

pub fn sdat2img_from_reader<R: Read>(
    transfer_list_path: &Path,
    new_data_reader: &mut R,
    output_img_path: &Path,
) -> Result<()> {
    let (version, _new_blocks, max_block, new_ranges) = parse_transfer_list(transfer_list_path)?;
    info!("sdat2img: detected transfer list version {}", version);

    let max_file_size = max_block * BLOCK_SIZE;

    let output_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_img_path)
        .with_context(|| format!("Failed to open output image {}", output_img_path.display()))?;
    let mut output_img = BufWriter::with_capacity(1024 * 1024, output_file);

    let mut buf = vec![0u8; 1024 * 1024];
    let mut current_pos = 0u64;

    for &(begin, end) in &new_ranges {
        let mut remaining_bytes = (end - begin) * BLOCK_SIZE;
        let target_pos = begin * BLOCK_SIZE;
        advance_output(&mut output_img, &mut current_pos, target_pos)?;

        while remaining_bytes > 0 {
            let to_read = remaining_bytes.min(buf.len() as u64) as usize;
            new_data_reader.read_exact(&mut buf[..to_read])?;
            output_img.write_all(&buf[..to_read])?;
            remaining_bytes -= to_read as u64;
            current_pos += to_read as u64;
        }
    }

    output_img.flush()?;
    let inner_file = output_img.get_mut();
    if current_pos < max_file_size {
        inner_file.set_len(max_file_size)?;
    }

    info!("sdat2img: output image written to {}", output_img_path.display());
    Ok(())
}
