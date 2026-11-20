//! Decryptor for Qualcomm Oppo/Realme `.ofp` firmware packages.
//!
//! Based on the MIT-licensed `ofp_qc_decrypt.py`: a page-aligned encrypted XML
//! manifest describes each image's offset and length, and image prefixes are
//! AES-CFB encrypted with a key derived from an obfuscated key table.

use aes::Aes128;
use anyhow::{Context, Result, bail};
use cfb_mode::Decryptor as CfbDecryptor;
use cfb_mode::cipher::KeyIvInit;
use md5::Md5;
use md5::digest::Digest;
use roxmltree::Document;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::info;

type Cfb = CfbDecryptor<Aes128>;
type ManifestKey = (u64, [u8; 16], [u8; 16]);

const PAGE_MARKER: u32 = 0x7cef;
const DECRYPT_SIZE: u64 = 0x4_0000;

/// (mask, encrypted key, encrypted IV) triples from `ofp_qc_decrypt.py`.
const KEY_TRIPLES: &[(&str, &str, &str)] = &[
    (
        "27827963787265EF89D126B69A495A21",
        "82C50203285A2CE7D8C3E198383CE94C",
        "422DD5399181E223813CD8ECDF2E4D72",
    ),
    (
        "E11AA7BB558A436A8375FD15DDD4651F",
        "77DDF6A0696841F6B74782C097835169",
        "A739742384A44E8BA45207AD5C3700EA",
    ),
    (
        "67657963787565E837D226B69A495D21",
        "F6C50203515A2CE7D8C3E1F938B7E94C",
        "42F2D5399137E2B2813CD8ECDF2F4D72",
    ),
    (
        "3C2D518D9BF2E4279DC758CD535147C3",
        "87C74A29709AC1BF2382276C4E8DF232",
        "598D92E967265E9BCABE2469FE4A915E",
    ),
    (
        "8FB8FB261930260BE945B841AEFA9FD4",
        "E529E82B28F5A2F8831D860AE39E425D",
        "8A09DA60ED36F125D64709973372C1CF",
    ),
    (
        "E8AE288C0192C54BF10C5707E9C4705B",
        "D64FC385DCD52A3C9B5FBA8650F92EDA",
        "79051FD8D8B6297E2E4559E997F63B7F",
    ),
];

fn hex16(value: &str) -> Result<[u8; 16]> {
    let bytes = (0..16)
        .map(|i| {
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                .with_context(|| format!("invalid OFP key {value}"))
        })
        .collect::<Result<Vec<_>>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid OFP key length"))
}

fn md5_ascii(data: [u8; 16]) -> Result<[u8; 16]> {
    let digest = Md5::digest(data);
    let mut hex = String::with_capacity(32);
    for byte in digest.iter().take(8) {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex.as_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid derived OFP key"))
}

fn derive(triple: &(&str, &str, &str)) -> Result<([u8; 16], [u8; 16])> {
    let mask = hex16(triple.0)?;
    let deobfuscate = |encoded: &str| -> Result<[u8; 16]> {
        let encrypted = hex16(encoded)?;
        let mut out = [0u8; 16];
        for (i, (&value, &mask_byte)) in encrypted.iter().zip(mask.iter()).enumerate() {
            let xored = value ^ mask_byte;
            out[i] = xored.rotate_left(4);
        }
        Ok(out)
    };
    Ok((
        md5_ascii(deobfuscate(triple.1)?)?,
        md5_ascii(deobfuscate(triple.2)?)?,
    ))
}

fn cfb_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    Cfb::new(key.into(), iv.into()).decrypt(data);
}

fn read_u32(file: &mut File) -> Result<u32> {
    let mut bytes = [0u8; 4];
    file.read_exact(&mut bytes)
        .context("truncated OFP header")?;
    Ok(u32::from_le_bytes(bytes))
}

fn locate_manifest(file: &mut File, file_len: u64) -> Result<Option<ManifestKey>> {
    let mut pagesize = 0u64;
    for candidate in [0x200u64, 0x1000] {
        if file_len < candidate + 0x14 {
            continue;
        }
        file.seek(SeekFrom::Start(file_len - candidate + 0x10))
            .context("seeking OFP page marker")?;
        if read_u32(file)? == PAGE_MARKER {
            pagesize = candidate;
            break;
        }
    }
    if pagesize == 0 {
        bail!("unknown OFP page size");
    }
    let xmloffset = file_len - pagesize;
    file.seek(SeekFrom::Start(xmloffset + 0x14))
        .context("seeking OFP manifest location")?;
    let page = u64::from(read_u32(file)?);
    let mut length = u64::from(read_u32(file)?);
    let offset = page
        .checked_mul(pagesize)
        .context("OFP manifest offset overflow")?;
    if length < 200 {
        length = xmloffset.saturating_sub(offset + 0x57);
    }
    if offset.checked_add(length).is_none_or(|end| end > file_len) {
        bail!("OFP manifest range exceeds file length");
    }

    for triple in KEY_TRIPLES {
        let (key, iv) = derive(triple)?;
        file.seek(SeekFrom::Start(offset))
            .context("seeking OFP manifest")?;
        let mut data = vec![0u8; length as usize];
        file.read_exact(&mut data).context("reading OFP manifest")?;
        cfb_decrypt(&key, &iv, &mut data);
        if data.windows(5).any(|w| w == b"<?xml") {
            return Ok(Some((pagesize, key, iv)));
        }
    }
    Ok(None)
}

fn attribute<'a>(node: roxmltree::Node<'a, 'a>, name: &str) -> Option<&'a str> {
    node.attribute(name)
}

fn sanitize(value: &str) -> String {
    value.replace(['/', '\\'], "_")
}

struct Item {
    name: String,
    start: u64,
    length: u64,
    rlength: u64,
    decryptsize: u64,
    copy: bool,
}

fn parse_item(node: roxmltree::Node, pagesize: u64, tag: &str) -> Option<Item> {
    let name = attribute(node, "Path")
        .or_else(|| attribute(node, "filename"))
        .filter(|s| !s.is_empty())?;
    let start = attribute(node, "FileOffsetInSrc")
        .or_else(|| attribute(node, "SizeInSectorInSrc"))
        .and_then(|s| s.parse::<u64>().ok())?
        .checked_mul(pagesize)?;
    let rlength = attribute(node, "SizeInByteInSrc")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let mut length = attribute(node, "SizeInSectorInSrc")
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(|s| s.checked_mul(pagesize))
        .unwrap_or(rlength);
    let mut decryptsize = DECRYPT_SIZE;
    if tag == "Sahara" {
        decryptsize = rlength;
    }
    if matches!(
        tag,
        "Config" | "Provision" | "ChainedTableOfDigests" | "DigestsToSign" | "Firmware"
    ) {
        length = rlength;
    }
    let copy = matches!(tag, "DigestsToSign" | "ChainedTableOfDigests" | "Firmware");
    Some(Item {
        name: sanitize(name),
        start,
        length,
        rlength,
        decryptsize,
        copy,
    })
}

fn extract_item(
    file: &mut File,
    item: Item,
    out_dir: &Path,
    key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<()> {
    if item.name.is_empty() || item.start == 0 {
        return Ok(());
    }
    let out_path = out_dir.join(&item.name);
    let mut out = File::create(&out_path)
        .with_context(|| format!("Failed to create {}", out_path.display()))?;
    file.seek(SeekFrom::Start(item.start))
        .context("seeking OFP image")?;

    if item.copy {
        let mut remaining = item.length;
        let mut buf = vec![0u8; 256 * 1024];
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            let n = file.read(&mut buf[..want]).context("reading OFP image")?;
            if n == 0 {
                bail!("OFP image {} ended early", item.name);
            }
            out.write_all(&buf[..n]).context("writing OFP image")?;
            remaining -= n as u64;
        }
        return Ok(());
    }

    let rlength = item.rlength;
    let size = rlength.min(item.decryptsize);
    let mut data = vec![0u8; size as usize];
    file.read_exact(&mut data)
        .context("reading encrypted OFP image")?;
    let padded = data.len().div_ceil(4) * 4;
    data.resize(padded, 0);
    cfb_decrypt(key, iv, &mut data);
    out.write_all(&data[..size as usize])
        .context("writing OFP image")?;
    if rlength > item.decryptsize {
        let mut remaining = rlength - size;
        let mut buf = vec![0u8; 256 * 1024];
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            let n = file
                .read(&mut buf[..want])
                .context("reading OFP image tail")?;
            if n == 0 {
                bail!("OFP image {} ended early", item.name);
            }
            out.write_all(&buf[..n]).context("writing OFP image tail")?;
            remaining -= n as u64;
        }
    }
    Ok(())
}

/// Extract every image of a Qualcomm `.ofp` firmware into `output_dir`.
///
/// # Errors
///
/// Returns an error when no published key decrypts the manifest, the XML is
/// invalid, or an image cannot be written.
pub fn extract_ofp_qc(source: &Path, output_dir: &Path) -> Result<()> {
    let mut file =
        File::open(source).with_context(|| format!("Failed to open {}", source.display()))?;
    let file_len = file.metadata().context("reading OFP metadata")?.len();
    let Some((pagesize, key, iv)) = locate_manifest(&mut file, file_len)? else {
        bail!("unknown OFP key: no published key decrypted the manifest");
    };
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;

    let xmloffset = file_len - pagesize;
    file.seek(SeekFrom::Start(xmloffset + 0x14))
        .context("seeking OFP manifest location")?;
    let xml_offset = u64::from(read_u32(&mut file)?) * pagesize;
    let mut xml_length = u64::from(read_u32(&mut file)?);
    if xml_length < 200 {
        xml_length = xmloffset.saturating_sub(xml_offset + 0x57);
    }
    file.seek(SeekFrom::Start(xml_offset))
        .context("seeking OFP XML")?;
    let mut xml = vec![0u8; xml_length as usize];
    file.read_exact(&mut xml).context("reading OFP XML")?;
    cfb_decrypt(&key, &iv, &mut xml);
    fs::write(output_dir.join("ProFile.xml"), &xml).context("writing ProFile.xml")?;

    let text = std::str::from_utf8(&xml).context("OFP manifest is not UTF-8")?;
    let document = Document::parse(text).context("invalid OFP manifest XML")?;
    let root = document.root_element();
    for child in root.children().filter(|n| n.is_element()) {
        let tag = child.tag_name().name();
        for node in child.children().filter(|n| n.is_element()) {
            if attribute(node, "Path").is_none() && attribute(node, "filename").is_none() {
                for sub in node.children().filter(|n| n.is_element()) {
                    if let Some(item) = parse_item(sub, pagesize, tag) {
                        extract_item(&mut file, item, output_dir, &key, &iv)?;
                    }
                }
            }
            if let Some(item) = parse_item(node, pagesize, tag) {
                extract_item(&mut file, item, output_dir, &key, &iv)?;
            }
        }
    }
    info!(pagesize, "ofp_qc.extracted");
    Ok(())
}
