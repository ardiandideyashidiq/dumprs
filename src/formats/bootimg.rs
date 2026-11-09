use anyhow::{bail, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::GzDecoder;
use std::borrow::Cow;
use std::fs;
use std::io::Read;
use std::path::Path;
use tracing::info;

use crate::utils::files::resolve_image_mmap;
const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";
const VENDOR_BOOT_MAGIC: &[u8; 8] = b"VNDRBOOT";

#[derive(Debug, Default)]
pub struct BootImgInfo {
    pub magic: String,
    pub header_version: u32,
    pub page_size: u32,
    pub kernel_size: u32,
    pub ramdisk_size: u32,
    pub second_size: u32,
    pub dtb_size: u32,
    pub recovery_dtbo_size: u32,
    pub cmdline: String,
}

impl std::fmt::Display for BootImgInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "magic: {}", self.magic)?;
        writeln!(f, "header_version: {}", self.header_version)?;
        writeln!(f, "page_size: {}", self.page_size)?;
        writeln!(f, "kernel_size: {}", self.kernel_size)?;
        writeln!(f, "ramdisk_size: {}", self.ramdisk_size)?;
        writeln!(f, "second_size: {}", self.second_size)?;
        writeln!(f, "dtb_size: {}", self.dtb_size)?;
        writeln!(f, "recovery_dtbo_size: {}", self.recovery_dtbo_size)?;
        writeln!(f, "cmdline: {}", self.cmdline)?;
        Ok(())
    }
}

fn align_to(val: u64, align: u64) -> u64 {
    if align == 0 {
        val
    } else {
        ((val + align - 1) / align) * align
    }
}

pub fn extract_bootimg(image_path: &Path, output_path: &Path) -> Result<()> {
    let (full_mmap, start, end) = resolve_image_mmap(image_path)?;
    let mmap = &full_mmap[start..end];

    if mmap.len() < 8 {
        bail!("Boot image too small: {}", image_path.display());
    }
    let magic = &mmap[0..8];

    fs::create_dir_all(output_path)?;

    if magic == BOOT_MAGIC {
        extract_standard_bootimg(mmap, output_path)?;
    } else if magic == VENDOR_BOOT_MAGIC {
        extract_vendor_bootimg(mmap, output_path)?;
    } else {
        bail!("Unknown boot image magic: {:?}", magic);
    }

    Ok(())
}

fn extract_standard_bootimg(mmap: &[u8], output_path: &Path) -> Result<()> {
    let mut cursor = &mmap[8..];
    let kernel_size = cursor.read_u32::<LittleEndian>()?;
    let _kernel_addr = cursor.read_u32::<LittleEndian>()?;
    let ramdisk_size = cursor.read_u32::<LittleEndian>()?;
    let _ramdisk_addr = cursor.read_u32::<LittleEndian>()?;
    let second_size = cursor.read_u32::<LittleEndian>()?;
    let _second_addr = cursor.read_u32::<LittleEndian>()?;
    let _tags_addr = cursor.read_u32::<LittleEndian>()?;
    let page_size = cursor.read_u32::<LittleEndian>()?;
    let header_version = cursor.read_u32::<LittleEndian>()?;

    let mut info = BootImgInfo {
        magic: "ANDROID!".to_string(),
        header_version,
        page_size,
        kernel_size,
        ramdisk_size,
        second_size,
        ..Default::default()
    };

    let (kernel_offset, ramdisk_offset, second_offset, recovery_dtbo_offset, dtb_offset);

    if header_version == 3 || header_version == 4 {
        let fixed_page_size = 4096u64;
        info.page_size = 4096;
        let cmdline_buf = &cursor[..1536.min(cursor.len())];
        let end = cmdline_buf.iter().position(|&b| b == 0).unwrap_or(cmdline_buf.len());
        info.cmdline = String::from_utf8_lossy(&cmdline_buf[..end]).to_string();

        kernel_offset = fixed_page_size;
        ramdisk_offset = kernel_offset + align_to(kernel_size as u64, fixed_page_size);
        second_offset = 0;
        recovery_dtbo_offset = 0;
        dtb_offset = 0;
    } else {
        let _os_version = cursor.read_u32::<LittleEndian>()?;
        cursor = &cursor[16..]; // skip name_buf
        let cmdline_buf = &cursor[..512];
        cursor = &cursor[512..];
        let end = cmdline_buf.iter().position(|&b| b == 0).unwrap_or(512);
        info.cmdline = String::from_utf8_lossy(&cmdline_buf[..end]).to_string();

        cursor = &cursor[32 + 1024..]; // skip id (32) + extra_cmdline (1024)

        let page = page_size as u64;
        kernel_offset = page;
        ramdisk_offset = kernel_offset + align_to(kernel_size as u64, page);
        second_offset = ramdisk_offset + align_to(ramdisk_size as u64, page);

        let mut next_offset = second_offset + align_to(second_size as u64, page);

        if header_version >= 1 {
            let recovery_dtbo_size = cursor.read_u32::<LittleEndian>()?;
            let _recovery_dtbo_addr = cursor.read_u64::<LittleEndian>()?;
            let _header_size = cursor.read_u32::<LittleEndian>()?;
            info.recovery_dtbo_size = recovery_dtbo_size;

            recovery_dtbo_offset = next_offset;
            next_offset += align_to(recovery_dtbo_size as u64, page);
        } else {
            recovery_dtbo_offset = 0;
        }

        if header_version >= 2 {
            let dtb_size = cursor.read_u32::<LittleEndian>()?;
            let _dtb_addr = cursor.read_u64::<LittleEndian>()?;
            info.dtb_size = dtb_size;
            dtb_offset = next_offset;
        } else {
            dtb_offset = 0;
        }
    }

    fs::write(output_path.join("info.txt"), info.to_string())?;

    if kernel_size > 0 {
        let start = kernel_offset as usize;
        let end = start + kernel_size as usize;
        if end <= mmap.len() {
            fs::write(output_path.join("kernel"), &mmap[start..end])?;
            info!(size = kernel_size, "bootimg.kernel.extracted");
        }
    }

    if ramdisk_size > 0 {
        let start = ramdisk_offset as usize;
        let end = start + ramdisk_size as usize;
        if end <= mmap.len() {
            let buf = &mmap[start..end];
            fs::write(output_path.join("ramdisk.img"), buf)?;
            extract_ramdisk(buf, &output_path.join("ramdisk"));
            info!(size = ramdisk_size, "bootimg.ramdisk.extracted");
        }
    }

    if second_size > 0 && second_offset > 0 {
        let start = second_offset as usize;
        let end = start + second_size as usize;
        if end <= mmap.len() {
            fs::write(output_path.join("second.img"), &mmap[start..end])?;
        }
    }

    if info.recovery_dtbo_size > 0 && recovery_dtbo_offset > 0 {
        let start = recovery_dtbo_offset as usize;
        let end = start + info.recovery_dtbo_size as usize;
        if end <= mmap.len() {
            fs::write(output_path.join("dtbo.img"), &mmap[start..end])?;
        }
    }

    if info.dtb_size > 0 && dtb_offset > 0 {
        let start = dtb_offset as usize;
        let end = start + info.dtb_size as usize;
        if end <= mmap.len() {
            fs::write(output_path.join("dtb.img"), &mmap[start..end])?;
        }
    }

    Ok(())
}

fn extract_vendor_bootimg(mmap: &[u8], output_path: &Path) -> Result<()> {
    let mut cursor = &mmap[8..];
    let header_version = cursor.read_u32::<LittleEndian>()?;
    let page_size = cursor.read_u32::<LittleEndian>()?;
    let _kernel_addr = cursor.read_u32::<LittleEndian>()?;
    let _ramdisk_addr = cursor.read_u32::<LittleEndian>()?;
    let vendor_ramdisk_size = cursor.read_u32::<LittleEndian>()?;

    let cmdline_buf = &cursor[..2048];
    cursor = &cursor[2048..];
    let end = cmdline_buf.iter().position(|&b| b == 0).unwrap_or(2048);
    let cmdline = String::from_utf8_lossy(&cmdline_buf[..end]).to_string();

    let _tags_addr = cursor.read_u32::<LittleEndian>()?;
    cursor = &cursor[16..]; // skip name
    let _header_size = cursor.read_u32::<LittleEndian>()?;
    let dtb_size = cursor.read_u32::<LittleEndian>()?;
    let _dtb_addr = cursor.read_u64::<LittleEndian>()?;

    let info = BootImgInfo {
        magic: "VNDRBOOT".to_string(),
        header_version,
        page_size,
        ramdisk_size: vendor_ramdisk_size,
        dtb_size,
        cmdline,
        ..Default::default()
    };

    fs::write(output_path.join("info.txt"), info.to_string())?;

    let page = page_size as u64;
    let ramdisk_offset = page;
    let dtb_offset = ramdisk_offset + align_to(vendor_ramdisk_size as u64, page);

    if vendor_ramdisk_size > 0 {
        let start = ramdisk_offset as usize;
        let end = start + vendor_ramdisk_size as usize;
        if end <= mmap.len() {
            let buf = &mmap[start..end];
            fs::write(output_path.join("ramdisk.img"), buf)?;
            extract_ramdisk(buf, &output_path.join("ramdisk"));
        }
    }

    if dtb_size > 0 {
        let start = dtb_offset as usize;
        let end = start + dtb_size as usize;
        if end <= mmap.len() {
            fs::write(output_path.join("dtb.img"), &mmap[start..end])?;
        }
    }

    Ok(())
}

fn extract_ramdisk(data: &[u8], out_dir: &Path) {
    let decompressed: Cow<'_, [u8]> = if data.starts_with(&[0x1f, 0x8b]) {
        // Gzip
        let mut gz = GzDecoder::new(data);
        let mut out = Vec::with_capacity(data.len() * 2);
        if gz.read_to_end(&mut out).is_ok() {
            Cow::Owned(out)
        } else {
            return;
        }
    } else if data.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        // LZ4 frame
        let mut frame_decoder = lz4_flex::frame::FrameDecoder::new(data);
        let mut out = Vec::with_capacity(data.len() * 2);
        if frame_decoder.read_to_end(&mut out).is_ok() {
            Cow::Owned(out)
        } else {
            return;
        }
    } else {
        Cow::Borrowed(data)
    };

    // Try unpacking CPIO archive (magic 070701 or 070702)
    if decompressed.starts_with(b"070701") || decompressed.starts_with(b"070702") {
        let _ = unpack_cpio(&decompressed, out_dir);
    }
}

fn unpack_cpio(data: &[u8], out_dir: &Path) -> Result<()> {
    let mut pos = 0usize;

    while pos + 110 <= data.len() {
        let header = &data[pos..pos + 110];
        pos += 110;

        let magic = &header[0..6];
        if magic != b"070701" && magic != b"070702" {
            break;
        }

        let namesize = u32::from_str_radix(std::str::from_utf8(&header[94..102])?, 16)? as usize;
        let filesize = u32::from_str_radix(std::str::from_utf8(&header[54..62])?, 16)? as usize;

        if pos + namesize > data.len() {
            break;
        }
        let name_buf = &data[pos..pos + namesize];
        let name_pad = (4 - ((110 + namesize) % 4)) % 4;
        pos += namesize + name_pad;

        let name = std::str::from_utf8(name_buf)
            .unwrap_or_default()
            .trim_end_matches('\0');

        if name == "TRAILER!!!" {
            break;
        }

        if pos + filesize > data.len() {
            break;
        }
        let file_buf = &data[pos..pos + filesize];
        let file_pad = (4 - (filesize % 4)) % 4;
        pos += filesize + file_pad;

        let target_path = out_dir.join(name);
        if let Some(parent) = target_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if !name.is_empty() && filesize > 0 {
            let _ = fs::write(&target_path, file_buf);
        }
    }

    Ok(())
}
