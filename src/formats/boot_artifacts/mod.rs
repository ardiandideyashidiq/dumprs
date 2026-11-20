//! Generation of boot and kernel artifacts from Android boot images.
//!
//! Every artifact is written into the partition directory, never the dump root.

pub mod avb;
pub mod dtb;
pub mod ikconfig;
pub mod kallsyms;
pub mod vmlinux_elf;

use anyhow::{Context, Result};
use std::borrow::Cow;
use std::fs;
use std::path::Path;
use tracing::{error, info, warn};

/// Generate the boot/kernel artifacts for one boot-like partition.
///
/// All artifacts are written under `output_dir` (the partition directory):
/// `avb.txt`, `ikconfig`, `dtb/*.dtb` and `dts/*.dts`. A failure in one
/// generator is reported but does not discard the other artifacts.
///
/// # Errors
///
/// Returns an error only when the output directory or image cannot be
/// created/read; individual generator failures are logged instead.
pub fn generate(image: &Path, output_dir: &Path, partition: &str) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("creating boot artifact dir {}", output_dir.display()))?;
    let image_data =
        fs::read(image).with_context(|| format!("reading boot image {}", image.display()))?;

    match avb::render_avb_info(&image_data, image_data.len() as u64) {
        Ok(info_text) => {
            let path = output_dir.join("avb.txt");
            fs::write(&path, info_text).with_context(|| format!("writing {}", path.display()))?;
            info!(partition, artifact = "avb", "boot.artifact.generated");
        }
        Err(err) => {
            warn!(partition, error = %err, "boot.artifact.avb.unavailable");
        }
    }

    let kernel_path = output_dir.join("kernel");
    // Reuse the image bytes when no extracted kernel is available: reading
    // the same 64 MiB boot image twice would double peak memory here.
    let kernel_data: Cow<'_, [u8]> = if kernel_path.is_file() {
        match fs::read(&kernel_path) {
            Ok(data) => Cow::Owned(data),
            Err(err) => {
                error!(partition, error = %err, "boot.artifact.kernel.read_failed");
                Cow::Owned(Vec::new())
            }
        }
    } else {
        Cow::Borrowed(image_data.as_slice())
    };
    if !kernel_data.is_empty() {
        match ikconfig::extract_ikconfig(&kernel_data) {
            Ok(Some(config)) => {
                let path = output_dir.join("ikconfig");
                fs::write(&path, config).with_context(|| format!("writing {}", path.display()))?;
                info!(partition, artifact = "ikconfig", "boot.artifact.generated");
            }
            Ok(None) => {
                info!(partition, "boot.artifact.ikconfig.not_found");
            }
            Err(err) => {
                error!(partition, error = %err, "boot.artifact.ikconfig.failed");
            }
        }
    }

    if partition == "boot" || partition == "vendor_boot" {
        let decompressed_kernel = kallsyms::decompress_kernel(&kernel_data);
        match kallsyms::find_kallsyms(&decompressed_kernel) {
            Ok(symbols) => {
                let kallsyms_name = if partition == "boot" && kernel_path.is_file() {
                    "kernel_kallsyms.txt"
                } else if partition == "boot" {
                    "boot_kallsyms.txt"
                } else {
                    "vendor_boot_kallsyms.txt"
                };
                let path = output_dir.join(kallsyms_name);
                fs::write(&path, kallsyms::render_kallsyms(&symbols))
                    .with_context(|| format!("writing {}", path.display()))?;
                let elf_name = if partition == "boot" {
                    "boot.elf"
                } else {
                    "vendor_boot.elf"
                };
                let elf_path = output_dir.join(elf_name);
                if let Err(err) = vmlinux_elf::write_elf(&symbols, &decompressed_kernel, &elf_path)
                {
                    error!(partition, error = %err, "boot.artifact.elf.failed");
                }
                info!(
                    partition,
                    count = symbols.len(),
                    "boot.artifact.kallsyms.generated"
                );
            }
            Err(err) => {
                warn!(partition, error = %err, "boot.artifact.kallsyms.unavailable");
            }
        }
    }

    let dtb_sources: Vec<std::path::PathBuf> = if partition == "dtbo" {
        vec![image.to_path_buf()]
    } else {
        vec![output_dir.join("dtb.img"), output_dir.join("dt.img")]
    };
    let mut dtb_index = 0usize;
    for source in dtb_sources {
        if !source.is_file() {
            continue;
        }
        let data = match fs::read(&source) {
            Ok(data) => data,
            Err(err) => {
                error!(partition, image = %source.display(), error = %err, "boot.artifact.dtb.read_failed");
                continue;
            }
        };
        let blobs = match dtb::split_dtb(&data) {
            Ok(blobs) => blobs,
            Err(err) => {
                error!(partition, image = %source.display(), error = %err, "boot.artifact.dtb.failed");
                continue;
            }
        };
        for blob in blobs {
            let dtb_dir = output_dir.join("dtb");
            let dts_dir = output_dir.join("dts");
            if let Err(err) =
                fs::create_dir_all(&dtb_dir).and_then(|_| fs::create_dir_all(&dts_dir))
            {
                error!(partition, error = %err, "boot.artifact.dtb.dir_failed");
                break;
            }
            let dtb_path = dtb_dir.join(format!("{dtb_index}.dtb"));
            if let Err(err) = fs::write(&dtb_path, blob) {
                error!(partition, file = %dtb_path.display(), error = %err, "boot.artifact.dtb.write_failed");
                break;
            }
            match dtb::dtb_to_dts(blob) {
                Ok(dts) => {
                    let dts_path = dts_dir.join(format!("{dtb_index}.dts"));
                    if let Err(err) = fs::write(&dts_path, dts) {
                        error!(partition, file = %dts_path.display(), error = %err, "boot.artifact.dts.write_failed");
                    }
                }
                Err(err) => {
                    error!(partition, index = dtb_index, error = %err, "boot.artifact.dts.failed");
                }
            }
            dtb_index += 1;
        }
    }
    if dtb_index > 0 {
        info!(partition, count = dtb_index, "boot.artifact.dtb.generated");
    }
    Ok(())
}
