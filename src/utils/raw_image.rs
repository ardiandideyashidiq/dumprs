use anyhow::{Context, Result};
use indicatif::HumanBytes;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use tracing::{debug, info};

use crate::formats::sdat2img::{sdat2img, sdat2img_from_reader};
use crate::formats::sparse::unsparse_file;
use crate::utils::files::move_or_copy;
use crate::utils::progress::ByteProgress;

fn copy_with_progress<R: Read>(mut reader: R, out_path: &Path, label: &str, total_hint: u64) -> Result<u64> {
    let output_file = File::create(out_path)
        .with_context(|| format!("Failed to create {}", out_path.display()))?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, output_file);
    let pb = ByteProgress::new(label, total_hint);
    let mut buf = vec![0u8; 256 * 1024];
    let mut written = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        written += n as u64;
        pb.inc(n as u64);
    }
    writer.flush()?;
    pb.finish();
    Ok(written)
}

pub fn get_raw_image(partition: &str, files_path: &Path, output_image_path: &Path) -> Result<bool> {
    if output_image_path.is_file() {
        return Ok(true);
    }

    let brotli_image = files_path.join(format!("{}.new.dat.br", partition));
    let dat_image = files_path.join(format!("{}.new.dat", partition));
    let transfer_list = files_path.join(format!("{}.transfer.list", partition));
    let lz4_image = files_path.join(format!("{}.img.lz4", partition));
    let raw_image = files_path.join(format!("{}.img", partition));

    let possible_image_names = [
        partition.to_string(),
        format!("{}.bin", partition),
        format!("{}.ext4", partition),
        format!("{}.image", partition),
        format!("{}.img", partition),
        format!("{}.img.ext4", partition),
        format!("{}.mbn", partition),
        format!("{}.raw", partition),
        format!("{}.raw.img", partition),
    ];

    if brotli_image.is_file() {
        if transfer_list.is_file() && !dat_image.is_file() {
            info!(partition, "raw_image.brotli_sdat.stream");
            let input_file = File::open(&brotli_image)
                .with_context(|| format!("Failed to open {}", brotli_image.display()))?;
            let mut reader = brotli::Decompressor::new(
                BufReader::with_capacity(256 * 1024, input_file),
                256 * 1024,
            );
            sdat2img_from_reader(&transfer_list, &mut reader, output_image_path)?;
            let _ = fs::remove_file(&brotli_image);
            let _ = fs::remove_file(&transfer_list);
            return Ok(true);
        }

        let br_size = fs::metadata(&brotli_image).map(|m| m.len()).unwrap_or(0);
        info!(partition, input_size = %HumanBytes(br_size), "raw_image.brotli.decompress");
        let input_file = File::open(&brotli_image)
            .with_context(|| format!("Failed to open {}", brotli_image.display()))?;
        let reader = brotli::Decompressor::new(
            BufReader::with_capacity(256 * 1024, input_file),
            256 * 1024,
        );
        copy_with_progress(reader, &dat_image, partition, br_size.saturating_mul(2))?;
        let _ = fs::remove_file(&brotli_image);
    }

    if dat_image.is_file() && transfer_list.is_file() {
        info!(partition, "raw_image.sdat2img.convert");
        sdat2img(&transfer_list, &dat_image, output_image_path)?;
        let _ = fs::remove_file(&dat_image);
        let _ = fs::remove_file(&transfer_list);
        return Ok(true);
    }

    if lz4_image.is_file() {
        let lz4_size = fs::metadata(&lz4_image).map(|m| m.len()).unwrap_or(0);
        info!(partition, input_size = %HumanBytes(lz4_size), "raw_image.lz4.decompress");
        let input_file = File::open(&lz4_image)
            .with_context(|| format!("Failed to open {}", lz4_image.display()))?;
        let decoder =
            lz4_flex::frame::FrameDecoder::new(BufReader::with_capacity(256 * 1024, input_file));
        copy_with_progress(decoder, &raw_image, partition, lz4_size.saturating_mul(2))?;
        let _ = fs::remove_file(&lz4_image);
    }

    for image_name in &possible_image_names {
        let image_path = files_path.join(image_name);
        if !image_path.is_file() {
            continue;
        }
        if image_path == output_image_path {
            return Ok(true);
        }

        match unsparse_file(&image_path, output_image_path) {
            Ok(true) if output_image_path.is_file() => {
                let _ = fs::remove_file(&image_path);
                return Ok(true);
            }
            _ => {
                debug!(image = %image_name, "raw_image.already_raw");
                if output_image_path != image_path && output_image_path.is_file() {
                    let _ = fs::remove_file(output_image_path);
                }
            }
        }

        debug!(image = %image_name, "raw_image.move");
        move_or_copy(&image_path, output_image_path)?;
        return Ok(true);
    }
    Ok(false)
}
