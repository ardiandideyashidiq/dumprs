use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use crate::formats::payload::ZIP_SLICE_MAGIC;
use crate::utils::files::resolve_image_mmap;

const SPARSE_MAGIC: u32 = 0xed26_ff3a;
const DTBO_MAGIC_BE: u32 = 0xd7b7_ab1e;
const MTK_MAGIC_1: u32 = 0x5888_1688;
const MTK_MAGIC_2: u32 = 0x5889_1689;
const EROFS_MAGIC: u32 = 0xe0f5_e1e2;
const F2FS_MAGIC: u32 = 0xf2f5_2010;
const EXT4_MAGIC: u16 = 0xef53;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    BootImage,
    Filesystem,
    Sparse,
    FirmwareRaw,
    NonPartition,
    Unknown,
}

/// Kind of a firmware container or OEM encryption layer.
///
/// Detection runs before extraction so the right handler can be selected from
/// one place instead of a chain of filename checks spread across the pipeline.
/// The variant order follows the priority of DumprX's `dumper.sh` dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareKind {
    /// Oppo/Realme/OnePlus `.ozip` (`OPPOENCRYPT!` magic).
    Ozip,
    /// OnePlus/Oppo `.ops`.
    Ops,
    /// Oppo `.ofp` (Qualcomm or MediaTek).
    Ofp,
    /// HTC `ruu_*.exe`.
    Ruu,
    /// Amlogic upgrade package.
    Amlogic,
    /// Qualcomm QFIL `rawprogram*.xml` set.
    Qfil,
    /// Nokia/Sharp/Unisoc `.nb0`.
    Nb0,
    /// Sony Xperia `.sin`.
    SonySin,
    /// Spreadtrum/Unisoc `.pac`.
    Pac,
    /// Android `super.img`.
    Super,
    /// Samsung `AP_*.tar.md5`.
    TarMd5,
    /// Android OTA `payload.bin` (`CrAU` magic).
    Payload,
    /// Plain zip container.
    Zip,
    /// Plain tar container.
    Tar,
    /// Gzip-compressed tar.
    TarGz,
    /// Bzip2-compressed tar.
    TarBz2,
    /// Xz-compressed tar.
    TarXz,
    /// LG `.kdz`.
    Kdz,
    /// LG `.dz`.
    Dz,
    /// Huawei `UPDATE.APP`.
    HuaweiUpdateApp,
    /// Rockchip upgrade image.
    Rockchip,
    /// Nothing identified; fall through to the generic pipeline.
    Other,
}

fn members_match(lowered: &[String], pred: impl Fn(&str) -> bool) -> bool {
    lowered.iter().any(|m| pred(m.as_str()))
}

/// Detect the firmware kind from the first bytes of a file, its name, and the
/// member names of an already-opened archive.
///
/// `members` should contain paths as reported by the archive reader; matching
/// is case-insensitive and uses the final path component where appropriate.
pub fn detect_firmware_kind(head: &[u8], filename: &str, members: &[String]) -> FirmwareKind {
    let name = filename.to_ascii_lowercase();
    let lowered: Vec<String> = members.iter().map(|m| m.to_ascii_lowercase()).collect();
    fn base(m: &str) -> &str {
        m.rsplit('/').next().unwrap_or(m)
    }

    if head.starts_with(b"OPPOENCRYPT!") || name.ends_with(".ozip") {
        return FirmwareKind::Ozip;
    }
    if name.ends_with(".ops") || members_match(&lowered, |m| base(m).ends_with(".ops")) {
        return FirmwareKind::Ops;
    }
    if name.ends_with(".ofp") || members_match(&lowered, |m| base(m).ends_with(".ofp")) {
        return FirmwareKind::Ofp;
    }
    if name.starts_with("ruu_") && name.ends_with(".exe") {
        return FirmwareKind::Ruu;
    }
    if members_match(&lowered, |m| base(m).contains("aml")) {
        return FirmwareKind::Amlogic;
    }
    if members_match(&lowered, |m| {
        let b = base(m);
        b.starts_with("rawprogram") && b.ends_with(".xml")
    }) {
        return FirmwareKind::Qfil;
    }
    if members_match(&lowered, |m| base(m).ends_with(".nb0")) {
        return FirmwareKind::Nb0;
    }
    if members_match(&lowered, |m| base(m).ends_with(".sin")) {
        return FirmwareKind::SonySin;
    }
    if name.ends_with(".pac") || members_match(&lowered, |m| base(m).ends_with(".pac")) {
        return FirmwareKind::Pac;
    }
    if members_match(&lowered, |m| {
        base(m).starts_with("super") && base(m).ends_with(".img")
    }) {
        return FirmwareKind::Super;
    }
    if name.ends_with(".tar.md5") {
        return FirmwareKind::TarMd5;
    }
    if head.starts_with(b"CrAU") || members_match(&lowered, |m| base(m) == "payload.bin") {
        return FirmwareKind::Payload;
    }
    // Member-based OEM containers must win over the generic container
    // extension: a zip holding UPDATE.APP is a Huawei firmware, not a zip.
    if name == "update.app" || members_match(&lowered, |m| base(m) == "update.app") {
        return FirmwareKind::HuaweiUpdateApp;
    }
    if members_match(&lowered, |m| base(m) == "rockchip") {
        return FirmwareKind::Rockchip;
    }
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        return FirmwareKind::TarGz;
    }
    if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") {
        return FirmwareKind::TarBz2;
    }
    if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        return FirmwareKind::TarXz;
    }
    if name.ends_with(".tar") {
        return FirmwareKind::Tar;
    }
    if name.ends_with(".zip") {
        return FirmwareKind::Zip;
    }
    if name.ends_with(".kdz") {
        return FirmwareKind::Kdz;
    }
    if name.ends_with(".dz") {
        return FirmwareKind::Dz;
    }
    FirmwareKind::Other
}

#[derive(Debug, Default, Clone)]
pub struct ScatterInfo {
    /// Lowercased basename (e.g. `preloader_x670_h814.bin`) -> unslotted partition name (`preloader`).
    file_to_partition: HashMap<String, String>,
    /// Unslotted active partition names referenced by downloadable scatter entries.
    active_partitions: HashSet<String>,
}

impl ScatterInfo {
    pub fn is_empty(&self) -> bool {
        self.file_to_partition.is_empty()
    }

    pub fn from_dir(dir: &Path) -> Self {
        let mut info = Self::default();
        let Ok(entries) = fs::read_dir(dir) else {
            return info;
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if is_scatter_filename(fname)
                && let Ok(bytes) = fs::read(&path)
            {
                info.parse_bytes(&bytes);
            }
        }
        info
    }

    pub fn parse_bytes(&mut self, data: &[u8]) {
        let text = String::from_utf8_lossy(data);
        if text.trim_start().starts_with('<') {
            self.parse_xml(&text);
        } else {
            self.parse_txt(&text);
        }
    }

    fn record_entry(
        &mut self,
        partition_name: &str,
        file_name: &str,
        is_download: Option<bool>,
        operation_type: &str,
    ) {
        let pname = partition_name.trim();
        let fname = file_name.trim();
        if pname.is_empty() || fname.is_empty() || fname.eq_ignore_ascii_case("NONE") {
            return;
        }
        if is_download == Some(false) {
            return;
        }
        if operation_type.eq_ignore_ascii_case("INVISIBLE")
            || operation_type.eq_ignore_ascii_case("RESERVED")
        {
            return;
        }

        let base = Path::new(fname)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(fname);
        let unslotted = strip_slot_suffix(pname).to_ascii_lowercase();
        if is_excluded_partition_name(&unslotted) || unslotted == "super" {
            return;
        }

        self.active_partitions.insert(unslotted.clone());
        self.file_to_partition
            .entry(base.to_ascii_lowercase())
            .or_insert(unslotted);
    }

    fn parse_xml(&mut self, text: &str) {
        let mut rest = text;
        while let Some(start) = rest.find("<partition_index") {
            let after_start = &rest[start..];
            let Some(end) = after_start.find("</partition_index>") else {
                break;
            };
            let block = &after_start[..end];
            let pname = extract_xml_tag(block, "partition_name").unwrap_or("");
            let fname = extract_xml_tag(block, "file_name").unwrap_or("");
            let dl = extract_xml_tag(block, "is_download").and_then(parse_bool);
            let op = extract_xml_tag(block, "operation_type").unwrap_or("");
            self.record_entry(pname, fname, dl, op);
            rest = &after_start[end + "</partition_index>".len()..];
        }
    }

    fn parse_txt(&mut self, text: &str) {
        let mut in_part = false;
        let mut pname = String::new();
        let mut fname = String::new();
        let mut is_dl: Option<bool> = None;
        let mut op = String::new();

        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("- partition_index:") {
                if in_part {
                    self.record_entry(&pname, &fname, is_dl, &op);
                }
                let _ = rest;
                in_part = true;
                pname.clear();
                fname.clear();
                is_dl = None;
                op.clear();
                continue;
            }
            if line.starts_with("- ") {
                if in_part {
                    self.record_entry(&pname, &fname, is_dl, &op);
                    in_part = false;
                }
                continue;
            }
            if !in_part {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim();
                let val = v.trim();
                match key {
                    "partition_name" => pname = val.to_string(),
                    "file_name" => fname = val.to_string(),
                    "is_download" => is_dl = parse_bool(val),
                    "operation_type" => op = val.to_string(),
                    _ => {}
                }
            }
        }
        if in_part {
            self.record_entry(&pname, &fname, is_dl, &op);
        }
    }

    pub fn references_file(&self, filename: &str) -> bool {
        let base = Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(filename);
        self.file_to_partition
            .contains_key(&base.to_ascii_lowercase())
    }

    pub fn partition_for_file(&self, filename: &str) -> Option<&str> {
        let base = Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(filename);
        self.file_to_partition
            .get(&base.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Returns true if scatter explicitly selects a different file for the same bootloader/partition
    /// family (e.g. `preloader_x670_h814.bin` supersedes `preloader.img` / `preloader_emmc.img`).
    pub fn is_superseded_variant(&self, filename: &str) -> bool {
        if self.is_empty() {
            return false;
        }
        let base = Path::new(filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(filename);
        let lower = base.to_ascii_lowercase();
        if self.file_to_partition.contains_key(&lower) {
            return false;
        }
        let stem = lower.split('.').next().unwrap_or(&lower);
        let unslotted = strip_slot_suffix(stem);
        if self.active_partitions.contains(unslotted) {
            return true;
        }
        if self.active_partitions.contains("preloader") && unslotted.starts_with("preloader_") {
            return true;
        }
        false
    }
}

fn extract_xml_tag<'a>(block: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = block.find(&open)? + open.len();
    let rest = &block[start..];
    let end = rest.find(&close)?;
    Some(rest[..end].trim())
}

fn parse_bool(val: &str) -> Option<bool> {
    if val.eq_ignore_ascii_case("true") || val == "1" {
        Some(true)
    } else if val.eq_ignore_ascii_case("false") || val == "0" {
        Some(false)
    } else {
        None
    }
}

pub fn strip_slot_suffix(name: &str) -> &str {
    name.strip_suffix("_a")
        .or_else(|| name.strip_suffix("_b"))
        .or_else(|| name.strip_suffix("_A"))
        .or_else(|| name.strip_suffix("_B"))
        .unwrap_or(name)
}

pub fn is_scatter_filename(name: &str) -> bool {
    let base = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name);
    let lower = base.to_ascii_lowercase();
    lower.ends_with("_scatter.xml")
        || lower.ends_with("_scatter.txt")
        || lower == "scatter.xml"
        || lower == "scatter.txt"
}

pub fn is_excluded_partition_name(name: &str) -> bool {
    let lower = strip_slot_suffix(name).to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "userdata"
            | "tranfs"
            | "cache"
            | "metadata"
            | "frp"
            | "nvram"
            | "nvdata"
            | "nvcfg"
            | "proinfo"
            | "protect1"
            | "protect2"
            | "seccfg"
            | "persist"
            | "para"
            | "misc"
            | "boot_para"
            | "expdb"
            | "flashinfo"
            | "pgpt"
            | "sgpt"
            | "otp"
            | "super_empty"
    )
}

pub fn is_candidate_firmware_path(rel_path: &Path) -> bool {
    for comp in rel_path.parent().into_iter().flat_map(|p| p.components()) {
        if let std::path::Component::Normal(s) = comp
            && let Some(dir_name) = s.to_str()
        {
            let lower_dir = dir_name.to_ascii_lowercase();
            if matches!(
                lower_dir.as_str(),
                "download_agent" | "log" | "logs" | "apdb" | "mddb"
            ) {
                return false;
            }
        }
    }

    let Some(fname) = rel_path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = fname.to_ascii_lowercase();
    if is_scatter_filename(&lower) {
        return true;
    }

    let stem = lower.split('.').next().unwrap_or(&lower);
    if is_excluded_partition_name(stem) || stem == "super" {
        return false;
    }
    if lower.starts_with("apdb_") || lower.starts_with("mddb_") || lower.ends_with(".edb") {
        return false;
    }

    lower.ends_with(".img")
        || lower.ends_with(".bin")
        || lower.ends_with(".mbn")
        || lower.ends_with(".elf")
        || lower.ends_with(".img.lz4")
        || lower.ends_with(".bin.lz4")
        || lower.ends_with(".mbn.lz4")
        || lower.ends_with(".elf.lz4")
}

pub fn sniff_header_kind(head: &[u8]) -> HeaderKind {
    if head.starts_with(b"MTK_DOWNLOAD_AGENT")
        || head.starts_with(b"CATD")
        || head.starts_with(b"gDla")
        || head.starts_with(b"CrAU")
    {
        return HeaderKind::NonPartition;
    }
    let trimmed = head.iter().position(|&b| !b.is_ascii_whitespace());
    if let Some(idx) = trimmed
        && head[idx..].starts_with(b"<?xml")
    {
        return HeaderKind::NonPartition;
    }

    if head.len() >= 28 && u32::from_le_bytes(head[0..4].try_into().unwrap()) == SPARSE_MAGIC {
        return HeaderKind::Sparse;
    }

    if head.starts_with(b"ANDROID!") || head.starts_with(b"VNDRBOOT") {
        return HeaderKind::BootImage;
    }

    if head.len() >= 1028
        && (u32::from_le_bytes(head[1024..1028].try_into().unwrap()) == EROFS_MAGIC
            || u32::from_le_bytes(head[1024..1028].try_into().unwrap()) == F2FS_MAGIC)
    {
        return HeaderKind::Filesystem;
    }
    if head.len() >= 1082 && u16::from_le_bytes(head[1080..1082].try_into().unwrap()) == EXT4_MAGIC
    {
        return HeaderKind::Filesystem;
    }
    if head.starts_with(b"hsqs") || head.starts_with(b"sqsh") {
        return HeaderKind::Filesystem;
    }
    if head.len() >= 512
        && head[510] == 0x55
        && head[511] == 0xaa
        && (head[0] == 0xeb || head[0] == 0xe9)
        && (head[54..62].starts_with(b"FAT")
            || head[82..90].starts_with(b"FAT32")
            || head[3..11].starts_with(b"EXFAT")
            || head[3..8].starts_with(b"MSDOS"))
    {
        return HeaderKind::Filesystem;
    }

    if head.starts_with(b"AVB0")
        || (head.len() >= 4 && u32::from_be_bytes(head[0..4].try_into().unwrap()) == DTBO_MAGIC_BE)
        || (head.len() >= 8 && {
            let m = u32::from_le_bytes(head[0..4].try_into().unwrap());
            m == MTK_MAGIC_1 || m == MTK_MAGIC_2
        })
        || head.starts_with(b"EMMC_BOOT")
        || head.starts_with(b"UFS_BOOT")
        || (head.len() >= 17 && &head[0..4] == b"MMM\x01" && &head[8..17] == b"FILE_INFO")
        || head.starts_with(b"\x7fELF")
    {
        return HeaderKind::FirmwareRaw;
    }

    HeaderKind::Unknown
}

pub fn sniff_file_header_kind(path: &Path) -> Result<HeaderKind> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 2048];
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = file.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    if filled >= ZIP_SLICE_MAGIC.len() && &buf[..ZIP_SLICE_MAGIC.len()] == ZIP_SLICE_MAGIC {
        let (mmap, start, end) = resolve_image_mmap(path)?;
        let slice_end = end.min(start + 2048);
        return Ok(sniff_header_kind(&mmap[start..slice_end]));
    }
    Ok(sniff_header_kind(&buf[..filled]))
}

pub fn matches_partition_filter(
    filter_partitions: &[String],
    filename: &str,
    scatter: &ScatterInfo,
) -> bool {
    if filter_partitions.is_empty() {
        return true;
    }
    let stem = filename.split('.').next().unwrap_or(filename);
    let unslotted = strip_slot_suffix(stem);
    let scatter_part = scatter.partition_for_file(filename);
    filter_partitions.iter().any(|f| {
        f.eq_ignore_ascii_case(filename)
            || f.eq_ignore_ascii_case(stem)
            || f.eq_ignore_ascii_case(unslotted)
            || scatter_part.is_some_and(|sp| f.eq_ignore_ascii_case(sp))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xml_and_txt_scatter_and_dedups_preloader() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<root>
  <storage_type name="EMMC">
    <partition_index name="SYS0">
      <partition_name>preloader</partition_name>
      <file_name>preloader_x670_h814.bin</file_name>
      <is_download>true</is_download>
      <operation_type>BOOTLOADERS</operation_type>
    </partition_index>
    <partition_index name="SYS2">
      <partition_name>pgpt</partition_name>
      <file_name>NONE</file_name>
      <is_download>false</is_download>
      <operation_type>INVISIBLE</operation_type>
    </partition_index>
    <partition_index name="SYS10">
      <partition_name>vbmeta_a</partition_name>
      <file_name>vbmeta.img</file_name>
      <is_download>true</is_download>
      <operation_type>UPDATE</operation_type>
    </partition_index>
    <partition_index name="SYS20">
      <partition_name>userdata</partition_name>
      <file_name>userdata.img</file_name>
      <is_download>true</is_download>
      <operation_type>NEEDRESIZE</operation_type>
    </partition_index>
  </storage_type>
</root>"#;
        let mut info = ScatterInfo::default();
        info.parse_bytes(xml);
        assert!(info.references_file("preloader_x670_h814.bin"));
        assert!(info.references_file("vbmeta.img"));
        assert!(!info.references_file("userdata.img"));
        assert_eq!(info.partition_for_file("vbmeta.img"), Some("vbmeta"));
        assert!(info.is_superseded_variant("preloader.img"));
        assert!(info.is_superseded_variant("preloader_emmc.img"));
        assert!(info.is_superseded_variant("preloader_raw.img"));
        assert!(info.is_superseded_variant("preloader_ufs.img"));
        assert!(!info.is_superseded_variant("preloader_x670_h814.bin"));

        let txt = b"
- partition_index: SYS0
  partition_name: lk_a
  file_name: lk.img
  is_download: true
  operation_type: UPDATE
- partition_index: SYS1
  partition_name: tranfs
  file_name: tranfs.img
  is_download: true
  operation_type: UPDATE
";
        let mut txt_info = ScatterInfo::default();
        txt_info.parse_bytes(txt);
        assert!(txt_info.references_file("lk.img"));
        assert_eq!(txt_info.partition_for_file("lk.img"), Some("lk"));
        assert!(!txt_info.references_file("tranfs.img"));
    }

    #[test]
    fn sniffs_firmware_and_non_partition_headers() {
        assert_eq!(sniff_header_kind(b"ANDROID!rest"), HeaderKind::BootImage);
        assert_eq!(sniff_header_kind(b"VNDRBOOTrest"), HeaderKind::BootImage);
        assert_eq!(
            sniff_header_kind(b"AVB0\x00\x00\x00\x01"),
            HeaderKind::FirmwareRaw
        );
        assert_eq!(
            sniff_header_kind(&[0xd7, 0xb7, 0xab, 0x1e, 0, 0, 0, 0]),
            HeaderKind::FirmwareRaw
        );
        assert_eq!(
            sniff_header_kind(&[0x88, 0x16, 0x88, 0x58, 0, 0, 0, 0]),
            HeaderKind::FirmwareRaw
        );
        assert_eq!(
            sniff_header_kind(b"EMMC_BOOT\x00\x00\x00\x01"),
            HeaderKind::FirmwareRaw
        );
        assert_eq!(
            sniff_header_kind(b"MMM\x018\x00\x00\x00FILE_INFO\x00"),
            HeaderKind::FirmwareRaw
        );
        assert_eq!(
            sniff_header_kind(b"\x7fELF\x02\x01\x01\x00"),
            HeaderKind::FirmwareRaw
        );
        let mut sparse_hdr = [0u8; 28];
        sparse_hdr[..5].copy_from_slice(&[0x3a, 0xff, 0x26, 0xed, 1]);
        assert_eq!(sniff_header_kind(&sparse_hdr), HeaderKind::Sparse);
        assert_eq!(
            sniff_header_kind(b"MTK_DOWNLOAD_AGENT\x00"),
            HeaderKind::NonPartition
        );
        assert_eq!(
            sniff_header_kind(b"CATD\x04\x00\x00\x00"),
            HeaderKind::NonPartition
        );
        assert_eq!(
            sniff_header_kind(b"gDla4\x00\x00\x00"),
            HeaderKind::NonPartition
        );

        let mut ext4 = vec![0u8; 2048];
        ext4[1080] = 0x53;
        ext4[1081] = 0xef;
        assert_eq!(sniff_header_kind(&ext4), HeaderKind::Filesystem);

        let mut erofs = vec![0u8; 2048];
        erofs[1024..1028].copy_from_slice(&EROFS_MAGIC.to_le_bytes());
        assert_eq!(sniff_header_kind(&erofs), HeaderKind::Filesystem);
    }

    /// Regression: OEM containers must be detected before the generic archive
    /// fallback, otherwise their handlers are never invoked and the dump
    /// silently produces an empty output. The expected values are taken from
    /// the `dumper.sh` if/elif order, not from the detector itself.
    #[test]
    fn detects_firmware_kind_from_magic_filename_and_members() {
        let cases: &[(&[u8], &str, &[&str], FirmwareKind)] = &[
            (b"OPPOENCRYPT!0000", "fw.bin", &[], FirmwareKind::Ozip),
            (b"", "fw.ozip", &[], FirmwareKind::Ozip),
            (b"", "fw.zip", &["system.ops"], FirmwareKind::Ops),
            (b"", "fw.ofp", &[], FirmwareKind::Ofp),
            (b"", "ruu_2.10.651.1.exe", &[], FirmwareKind::Ruu),
            (
                b"",
                "fw.zip",
                &["UPDATE.APP"],
                FirmwareKind::HuaweiUpdateApp,
            ),
            (
                b"",
                "UPDATE.APP",
                &[] as &[&str],
                FirmwareKind::HuaweiUpdateApp,
            ),
            (
                b"",
                "fw.zip",
                &["rawprogram0.xml", "system.img"],
                FirmwareKind::Qfil,
            ),
            (b"", "fw.zip", &["system.pac"], FirmwareKind::Pac),
            (b"", "fw.zip", &["system.nb0"], FirmwareKind::Nb0),
            (b"", "fw.zip", &["system.sin"], FirmwareKind::SonySin),
            // dumper.sh checks `super.img` before the rockchip branch.
            (
                b"",
                "fw.zip",
                &["rockchip", "super.img"],
                FirmwareKind::Super,
            ),
            // dumper.sh checks `.ops` long before `UPDATE.APP`.
            (
                b"",
                "fw.zip",
                &["UPDATE.APP", "system.ops"],
                FirmwareKind::Ops,
            ),
            (b"CrAU", "fw.bin", &[], FirmwareKind::Payload),
            (b"", "fw.zip", &["super.img"], FirmwareKind::Super),
            (b"", "fw.zip", &[], FirmwareKind::Zip),
        ];
        for &(head, filename, members, expected) in cases {
            let members: Vec<String> = members.iter().map(|s| (*s).to_string()).collect();
            assert_eq!(
                detect_firmware_kind(head, filename, &members),
                expected,
                "head={head:?} filename={filename} members={members:?}"
            );
        }
    }
}
