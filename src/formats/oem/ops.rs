//! Decryptor for OnePlus/Oppo `.ops` firmware packages.
//!
//! Port of the MIT-licensed `opscrypto.py`: a custom key schedule driven by a
//! fixed S-box, used first to decrypt the trailing `settings.xml` and then
//! the SAHARA entries named by that manifest.

use anyhow::{Context, Result};
use roxmltree::Document;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use tracing::info;

const SECTOR: usize = 0x200;

const KEY_WORDS: [u32; 4] = [0x9e_e3_b5_d1, 0x9d_04_ea_5e, 0xab_d5_1d_67, 0xaf_cb_af_d2];

const MBOX4: [u32; 64] = [
    0xC4, 0x5D, 0x05, 0x71, 0x99, 0xDD, 0xBB, 0xEE, 0x29, 0xA1, 0x6D, 0xC7, 0xAD, 0xBF, 0xA4, 0x3F,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
];
const MBOX5: [u32; 64] = [
    0x60, 0x8A, 0x3F, 0x2D, 0x68, 0x6B, 0xD4, 0x23, 0x51, 0x0C, 0xD0, 0x95, 0xBB, 0x40, 0xE9, 0x76,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
];
const MBOX6: [u32; 64] = [
    0xAA, 0x69, 0x82, 0x9E, 0x5D, 0xDE, 0xB1, 0x3D, 0x30, 0xBB, 0x81, 0xA3, 0x46, 0x65, 0xA3, 0xE1,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
];
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

/// Build the 2048-byte S-box used by `gsbox`. Each 8-byte group is the
/// GF(2^8) word `[2s, s, s, 3s]` (where `s` is the AES S-box entry) twice.
fn build_sbox() -> Vec<u8> {
    let mut aes_sbox = [0u8; 256];
    for value in 0..=255u8 {
        let inverse = if value == 0 {
            0
        } else {
            (1u8..=255u8)
                .find(|&candidate| gf_mul(value, candidate) == 1)
                .unwrap_or(0)
        };
        aes_sbox[value as usize] = inverse
            ^ inverse.rotate_left(1)
            ^ inverse.rotate_left(2)
            ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4)
            ^ 0x63;
    }
    let mut table = Vec::with_capacity(2048);
    for &s in &aes_sbox {
        let word = [gf_mul(s, 2), s, s, gf_mul(s, 3)];
        table.extend_from_slice(&word);
        table.extend_from_slice(&word);
    }
    table
}

fn gsbox(table: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        table
            .get(offset..offset + 4)
            .expect("S-box index out of range")
            .try_into()
            .expect("4-byte slice"),
    )
}

fn key_update(iv: [u32; 4], table: &[u8], asbox: &dyn Fn(usize) -> u32) -> [u32; 4] {
    let g = |offset: usize| gsbox(table, offset);
    let (v0, v1, v2, v3) = (iv[0], iv[1], iv[2], iv[3]);

    let d = v0 ^ asbox(0);
    let a = v1 ^ asbox(1);
    let b = v2 ^ asbox(2);
    let c = v3 ^ asbox(3);
    let mut e = g(((b >> 0x10) & 0xff) as usize * 8 + 2)
        ^ g(((a >> 8) & 0xff) as usize * 8 + 3)
        ^ g((c >> 0x18) as usize * 8 + 1)
        ^ g((d & 0xff) as usize * 8)
        ^ asbox(4);
    let mut h = g(((c >> 0x10) & 0xff) as usize * 8 + 2)
        ^ g(((b >> 8) & 0xff) as usize * 8 + 3)
        ^ g((d >> 0x18) as usize * 8 + 1)
        ^ g((a & 0xff) as usize * 8)
        ^ asbox(5);
    let mut i = g(((d >> 0x10) & 0xff) as usize * 8 + 2)
        ^ g(((c >> 8) & 0xff) as usize * 8 + 3)
        ^ g((a >> 0x18) as usize * 8 + 1)
        ^ g((b & 0xff) as usize * 8)
        ^ asbox(6);
    let mut a2 = g(((d >> 8) & 0xff) as usize * 8 + 3)
        ^ g(((a >> 0x10) & 0xff) as usize * 8 + 2)
        ^ g((b >> 0x18) as usize * 8 + 1)
        ^ g((c & 0xff) as usize * 8)
        ^ asbox(7);

    let rounds = asbox(0x3c).saturating_sub(2) as usize;
    let mut index = 8usize;
    for _ in 0..rounds {
        let d = e >> 0x18;
        let m = h >> 0x10;
        let s = h >> 0x18;
        let z = e >> 0x10;
        let l = i >> 0x18;
        let t = e >> 8;
        e = g(((i >> 0x10) & 0xff) as usize * 8 + 2)
            ^ g(((h >> 8) & 0xff) as usize * 8 + 3)
            ^ g((a2 >> 0x18) as usize * 8 + 1)
            ^ g((e & 0xff) as usize * 8)
            ^ asbox(index);
        h = g(((a2 >> 0x10) & 0xff) as usize * 8 + 2)
            ^ g(((i >> 8) & 0xff) as usize * 8 + 3)
            ^ g((d & 0xff) as usize * 8 + 1)
            ^ g((h & 0xff) as usize * 8)
            ^ asbox(index + 1);
        i = g((z & 0xff) as usize * 8 + 2)
            ^ g(((a2 >> 8) & 0xff) as usize * 8 + 3)
            ^ g((s & 0xff) as usize * 8 + 1)
            ^ g((i & 0xff) as usize * 8)
            ^ asbox(index + 2);
        a2 = g((t & 0xff) as usize * 8 + 3)
            ^ g((m & 0xff) as usize * 8 + 2)
            ^ g((l & 0xff) as usize * 8 + 1)
            ^ g((a2 & 0xff) as usize * 8)
            ^ asbox(index + 3);
        index += 4;
    }

    [
        (g(((i >> 0x10) & 0xff) as usize * 8) & 0x00ff_0000)
            ^ (g(((h >> 8) & 0xff) as usize * 8 + 1) & 0x0000_ff00)
            ^ (g((a2 >> 0x18) as usize * 8 + 3) & 0xff00_0000)
            ^ (g((e & 0xff) as usize * 8 + 2) & 0xff)
            ^ asbox(index),
        (g(((a2 >> 0x10) & 0xff) as usize * 8) & 0x00ff_0000)
            ^ (g(((i >> 8) & 0xff) as usize * 8 + 1) & 0x0000_ff00)
            ^ (g((e >> 0x18) as usize * 8 + 3) & 0xff00_0000)
            ^ (g((h & 0xff) as usize * 8 + 2) & 0xff)
            ^ asbox(index + 3),
        (g(((e >> 0x10) & 0xff) as usize * 8) & 0x00ff_0000)
            ^ (g(((a2 >> 8) & 0xff) as usize * 8 + 1) & 0x0000_ff00)
            ^ (g((h >> 0x18) as usize * 8 + 3) & 0xff00_0000)
            ^ (g((i & 0xff) as usize * 8 + 2) & 0xff)
            ^ asbox(index + 2),
        (g(((h >> 0x10) & 0xff) as usize * 8) & 0x00ff_0000)
            ^ (g(((e >> 8) & 0xff) as usize * 8 + 1) & 0x0000_ff00)
            ^ (g((i >> 0x18) as usize * 8 + 3) & 0xff00_0000)
            ^ (g((a2 & 0xff) as usize * 8 + 2) & 0xff)
            ^ asbox(index + 1),
    ]
}

fn word_at(data: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    let available = data.len().saturating_sub(offset).min(4);
    bytes[..available].copy_from_slice(&data[offset..offset + available]);
    u32::from_le_bytes(bytes)
}

fn key_custom(input: &[u8], sbox: &[u8], mbox: &[u32; 64]) -> Vec<u8> {
    let mut rkey = KEY_WORDS;
    let mut out = Vec::with_capacity(input.len());
    let mut length = input.len() as i64;
    let mut ptr = 0usize;

    if length > 0x0f {
        let blocks = (length as usize).div_ceil(0x10);
        for block in 0..blocks {
            ptr = block * 0x10;
            rkey = key_update(rkey, sbox, &|i| mbox[i]);
            let slen = 4usize;
            let source = |i: usize| word_at(input, ptr + i * 4);
            let words: Vec<u32> = (0..slen).map(|i| rkey[i] ^ source(i)).collect();
            for word in &words {
                out.extend_from_slice(&word.to_le_bytes());
            }
            rkey = (0..slen)
                .map(source)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            length -= 0x10;
        }
    }
    if length > 0 {
        rkey = key_update(rkey, sbox, &|i| sbox[i] as u32);
        let mut j = ptr;
        let mut m = 0usize;
        while length > 0 {
            let word = word_at(input, j);
            let decrypted = word ^ rkey[m];
            out.extend_from_slice(&decrypted.to_le_bytes());
            rkey[m] = word;
            length -= 4;
            j += 4;
            m += 1;
        }
    }
    out
}

fn decrypted_region(source: &[u8], mbox: &[u32; 64]) -> Option<(Vec<u8>, usize, usize)> {
    if source.len() < SECTOR {
        return None;
    }
    let header = &source[source.len() - SECTOR..];
    let xml_length = u32::from_le_bytes(header[0x18..0x1c].try_into().ok()?) as usize;
    let padding = SECTOR - (xml_length % SECTOR);
    let region_len = xml_length.checked_add(padding)?;
    let start = source.len().checked_sub(SECTOR + region_len)?;
    let end = source.len() - SECTOR;
    let plain = key_custom(&source[start..end], &build_sbox(), mbox);
    if plain.windows(4).any(|w| w == b"xml ") {
        Some((plain, xml_length, start))
    } else {
        None
    }
}

fn sanitize(value: &str) -> String {
    value.replace(['/', '\\'], "_")
}

/// Extract every image described by the `.ops` manifest into `output_dir`.
///
/// # Errors
///
/// Returns an error when the file is truncated, no known MBox variant
/// decrypts the manifest, or an image cannot be written.
pub fn extract_ops(source: &Path, output_dir: &Path) -> Result<()> {
    let data = fs::read(source).with_context(|| format!("Failed to read {}", source.display()))?;
    let sbox = build_sbox();
    let mut detected = None;
    for mbox in [MBOX5, MBOX6, MBOX4] {
        if let Some(found) = decrypted_region(&data, &mbox) {
            detected = Some((mbox, found));
            break;
        }
    }
    let (mbox, (plain, _xml_length, _xml_start)) =
        detected.context("unsupported .ops key: no MBox variant decrypted settings.xml")?;

    let xml_end = plain
        .windows(7)
        .position(|w| w == b"</root>")
        .map(|at| at + 7)
        .unwrap_or(plain.len());
    let text = std::str::from_utf8(&plain[..xml_end]).context("settings.xml is not UTF-8")?;
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;
    fs::write(output_dir.join("settings.xml"), &plain[..xml_end])
        .context("writing settings.xml")?;

    let document = Document::parse(text).context("invalid settings.xml in .ops")?;
    let root = document.root_element();
    for child in root.children().filter(|n| n.is_element()) {
        let tag = child.tag_name().name();
        for item in child.children().filter(|n| n.is_element()) {
            let is_file = item.tag_name().name() == "File" || item.attribute("filename").is_some();
            if !is_file {
                continue;
            }
            let name = item
                .attribute("Path")
                .or_else(|| item.attribute("filename"))
                .filter(|s| !s.is_empty())
                .context("settings.xml entry has no file name")?;
            let start = item
                .attribute("FileOffsetInSrc")
                .and_then(|s| s.parse::<usize>().ok())
                .context("settings.xml entry has no offset")?
                * SECTOR;
            let length = item
                .attribute("SizeInByteInSrc")
                .and_then(|s| s.parse::<usize>().ok())
                .context("settings.xml entry has no size")?;
            let end = start
                .checked_add(length)
                .context("settings.xml entry offset overflow")?;
            let body = data
                .get(start..end)
                .context("settings.xml entry exceeds .ops size")?;

            let output = if tag == "SAHARA" {
                let mut padded = body.to_vec();
                if padded.len() % 4 != 0 {
                    padded.resize(padded.len().div_ceil(4) * 4, 0);
                }
                key_custom(&padded, &sbox, &mbox)
            } else {
                body.to_vec()
            };
            let out_path = output_dir.join(sanitize(name));
            let mut out = File::create(&out_path)
                .with_context(|| format!("Failed to create {}", out_path.display()))?;
            out.write_all(&output[..length])
                .context("writing .ops image")?;
            info!(file = name, size = length, "ops.image.extracted");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_custom_decrypts_reference_block() {
        let ciphertext: Vec<u8> = (0..16)
            .map(|i| {
                u8::from_str_radix(&"7454aa684ddf38d0079e3a039e108273"[i * 2..i * 2 + 2], 16)
                    .unwrap()
            })
            .collect();
        let plain = key_custom(&ciphertext, &build_sbox(), &MBOX5);
        assert_eq!(&plain[..16], b"BOOTDATA12345678");
    }

    #[test]
    fn sbox_matches_reference_head() {
        let box_bytes = build_sbox();
        assert_eq!(
            &box_bytes[..8],
            &[0xc6, 0x63, 0x63, 0xa5, 0xc6, 0x63, 0x63, 0xa5]
        );
    }
}
