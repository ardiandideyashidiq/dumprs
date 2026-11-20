//! Assembler for Qualcomm QFIL `rawprogram*.xml` partition sets.
//!
//! Each `<program>` entry names a chunk file and the sector at which it
//! belongs. Entries for the requested partition are placed at
//! `start_sector * SECTOR_SIZE_IN_BYTES` in the output image; gaps stay zero.

use anyhow::{Context, Result, bail};
use roxmltree::Document;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use tracing::info;

#[cfg(unix)]
fn write_at(file: &File, mut buf: &[u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !buf.is_empty() {
        let n = file.write_at(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write whole QFIL chunk",
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
                "failed to write whole QFIL chunk",
            ));
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

/// List the distinct partition targets referenced by a rawprogram XML.
///
/// # Errors
///
/// Returns an error when the XML is malformed or an entry has neither a
/// `label` nor a `filename`.
pub fn list_targets(xml_path: &Path) -> Result<Vec<String>> {
    let xml = fs::read_to_string(xml_path)
        .with_context(|| format!("Failed to read {}", xml_path.display()))?;
    let document = Document::parse(&xml).context("Failed to parse rawprogram XML")?;
    let mut targets = Vec::new();
    for node in document.descendants().filter(|n| n.has_tag_name("program")) {
        let target = node
            .attribute("label")
            .filter(|s| !s.is_empty())
            .or_else(|| node.attribute("filename").filter(|s| !s.is_empty()))
            .context("rawprogram entry has no label or filename")?;
        if !targets.iter().any(|t: &String| t == target) {
            targets.push(target.to_string());
        }
    }
    Ok(targets)
}

/// Assemble the chunks of `target` described by a QFIL rawprogram XML.
///
/// The output is `<output_dir>/<target>.img`, matching the rename DumprX
/// performs after running `packsparseimg`.
///
/// # Errors
///
/// Returns an error when the XML is malformed, no entry matches `target`, a
/// source chunk is missing, or the output cannot be written.
pub fn extract_qfil(xml_path: &Path, target: &str, output_dir: &Path) -> Result<()> {
    let xml = fs::read_to_string(xml_path)
        .with_context(|| format!("Failed to read {}", xml_path.display()))?;
    let document = Document::parse(&xml).context("Failed to parse rawprogram XML")?;
    let base = xml_path.parent().unwrap_or_else(|| Path::new("."));

    let mut entries: Vec<(u64, PathBuf)> = Vec::new();
    for node in document.descendants().filter(|n| n.has_tag_name("program")) {
        let label = node.attribute("label").unwrap_or("");
        let filename = node.attribute("filename").unwrap_or("");
        if label != target && !filename.starts_with(target) {
            continue;
        }
        if filename.is_empty() {
            bail!("rawprogram entry for {target} has no filename");
        }
        let sector_size: u64 = node
            .attribute("SECTOR_SIZE_IN_BYTES")
            .unwrap_or("512")
            .parse()
            .context("invalid SECTOR_SIZE_IN_BYTES")?;
        let start_sector: u64 = node
            .attribute("start_sector")
            .unwrap_or("0")
            .parse()
            .context("invalid start_sector")?;
        entries.push((start_sector * sector_size, base.join(filename)));
    }
    entries.sort_by_key(|&(offset, _)| offset);
    if entries.is_empty() {
        bail!("no rawprogram entries for {target}");
    }

    let mut total = 0u64;
    for &(offset, ref path) in &entries {
        let len = fs::metadata(path)
            .with_context(|| format!("Failed to stat {}", path.display()))?
            .len();
        total = total.max(offset.saturating_add(len));
    }

    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;
    let out_path = output_dir.join(format!("{target}.img"));
    let out = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&out_path)
        .with_context(|| format!("Failed to create {}", out_path.display()))?;
    out.set_len(total)
        .context("setting assembled image length")?;

    let mut buf = vec![0u8; 256 * 1024];
    for (offset, path) in entries {
        let file =
            File::open(&path).with_context(|| format!("Failed to open {}", path.display()))?;
        let mut reader = BufReader::with_capacity(buf.len(), file);
        let mut written = 0u64;
        loop {
            let n = reader.read(&mut buf).context("reading QFIL chunk")?;
            if n == 0 {
                break;
            }
            write_at(&out, &buf[..n], offset + written).context("writing QFIL chunk")?;
            written += n as u64;
        }
        info!(partition = target, file = %path.display(), offset, written, "qfil.chunk.assembled");
    }

    Ok(())
}
