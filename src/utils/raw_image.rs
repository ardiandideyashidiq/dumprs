use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use tracing::{debug, info};

use crate::formats::sdat2img::{sdat2img, sdat2img_from_reader};
use crate::formats::sparse::unsparse_file;
use crate::utils::files::move_or_copy;

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
            info!(
                "Streaming brotli + sdat2img for {} -> {}",
                brotli_image.file_name().unwrap().to_string_lossy(),
                output_image_path.file_name().unwrap().to_string_lossy()
            );
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

        info!(
            "Decompressing {} as brotli image",
            brotli_image.file_name().unwrap().to_string_lossy()
        );
        let input_file = File::open(&brotli_image)
            .with_context(|| format!("Failed to open {}", brotli_image.display()))?;
        let mut reader = brotli::Decompressor::new(
            BufReader::with_capacity(256 * 1024, input_file),
            256 * 1024,
        );
        let output_file = File::create(&dat_image)
            .with_context(|| format!("Failed to create {}", dat_image.display()))?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, output_file);
        std::io::copy(&mut reader, &mut writer)?;
        let _ = fs::remove_file(&brotli_image);
    }

    if dat_image.is_file() && transfer_list.is_file() {
        info!(
            "Converting {} to {}",
            dat_image.file_name().unwrap().to_string_lossy(),
            output_image_path.file_name().unwrap().to_string_lossy()
        );
        sdat2img(&transfer_list, &dat_image, output_image_path)?;
        let _ = fs::remove_file(&dat_image);
        let _ = fs::remove_file(&transfer_list);
        return Ok(true);
    }

    if lz4_image.is_file() {
        info!(
            "Decompressing {} as LZ4 image",
            lz4_image.file_name().unwrap().to_string_lossy()
        );
        let input_file = File::open(&lz4_image)
            .with_context(|| format!("Failed to open {}", lz4_image.display()))?;
        let mut decoder = lz4_flex::frame::FrameDecoder::new(BufReader::with_capacity(256 * 1024, input_file));
        let output_file = File::create(&raw_image)
            .with_context(|| format!("Failed to create {}", raw_image.display()))?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, output_file);
        std::io::copy(&mut decoder, &mut writer)?;
        let _ = fs::remove_file(&lz4_image);
    }

    for image_name in &possible_image_names {
        let image_path = files_path.join(image_name);
        if !image_path.is_file() {
            continue;
        }

        // Unsparse directly into output_image_path if sparse; otherwise move in O(1)
        match unsparse_file(&image_path, output_image_path) {
            Ok(true) if output_image_path.is_file() => {
                let _ = fs::remove_file(&image_path);
                return Ok(true);
            }
            _ => {
                debug!("Image {} is already a raw image", image_name);
                if output_image_path != image_path && output_image_path.is_file() {
                    let _ = fs::remove_file(output_image_path);
                }
            }
        }

        info!("Moving {}", image_name);
        move_or_copy(&image_path, output_image_path)?;
        return Ok(true);
    }
    Ok(false)
}
