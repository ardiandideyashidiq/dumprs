//! Decryptor for Oppo/Realme MediaTek `.ofp` firmware packages.
//!
//! Based on the MIT-licensed `ofp_mtk_decrypt.py`: the key is discovered by
//! brute-forcing a fixed table against the first 16 AES-CFB bytes, and the
//! file table lives in a shuffled header at the end of the image.

use aes::Aes128;
use anyhow::{Context, Result, bail};
use cfb_mode::Decryptor as CfbDecryptor;
use cfb_mode::cipher::KeyIvInit;
use md5::Md5;
use md5::digest::Digest;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::info;

const HEADER_LEN: usize = 0x6c;
const ENTRY_LEN: usize = 0x60;
const HEADER_KEY: &[u8] = b"geyixue";

type Cfb = CfbDecryptor<Aes128>;

/// (obfuscation key, encrypted key, encrypted IV) triples; the last entry
/// stores the ASCII key and IV directly.
const KEYTABLES: &[&[&str]] = &[
    &[
        "67657963787565E837D226B69A495D21",
        "F6C50203515A2CE7D8C3E1F938B7E94C",
        "42F2D5399137E2B2813CD8ECDF2F4D72",
    ],
    &[
        "9E4F32639D21357D37D226B69A495D21",
        "A3D8D358E42F5A9E931DD3917D9A3218",
        "386935399137416B67416BECF22F519A",
    ],
    &[
        "892D57E92A4D8A975E3C216B7C9DE189",
        "D26DF2D9913785B145D18C7219B89F26",
        "516989E4A1BFC78B365C6BC57D944391",
    ],
    &[
        "27827963787265EF89D126B69A495A21",
        "82C50203285A2CE7D8C3E198383CE94C",
        "422DD5399181E223813CD8ECDF2E4D72",
    ],
    &[
        "3C4A618D9BF2E4279DC758CD535147C3",
        "87B13D29709AC1BF2382276C4E8DF232",
        "59B7A8E967265E9BCABE2469FE4A915E",
    ],
    &[
        "1C3288822BF824259DC852C1733127D3",
        "E7918D22799181CF2312176C9E2DF298",
        "3247F889A7B6DECBCA3E28693E4AAAFE",
    ],
    &[
        "1E4F32239D65A57D37D2266D9A775D43",
        "A332D3C3E42F5A3E931DD991729A321D",
        "3F2A35399A373377674155ECF28FD19A",
    ],
    &[
        "122D57E92A518AFF5E3C786B7C34E189",
        "DD6DF2D9543785674522717219989FB0",
        "12698965A132C76136CC88C5DD94EE91",
    ],
    &["ab3f76d7989207f2", "2bf515b3a9737835"],
];

fn nibble_swap(byte: u8) -> u8 {
    ((byte & 0xf0) >> 4) | ((byte & 0x0f) << 4)
}

fn shuffle(key: &[u8], input: &mut [u8]) {
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = key[i % key.len()] ^ nibble_swap(*byte);
    }
}

fn shuffle2(key: &[u8], input: &mut [u8]) {
    for (i, byte) in input.iter_mut().enumerate() {
        let tmp = key[i % key.len()] ^ *byte;
        *byte = nibble_swap(tmp);
    }
}

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

fn cfb_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Cfb::new(key.into(), iv.into());
    cipher.decrypt(data);
}

fn derive_key(table: &[&str]) -> Result<([u8; 16], [u8; 16])> {
    if table.len() == 2 {
        return Ok((
            table[0].as_bytes().try_into()?,
            table[1].as_bytes().try_into()?,
        ));
    }
    let obfuscation = hex16(table[0])?;
    let to_md5 = |encoded: &str| -> Result<[u8; 16]> {
        let mut bytes = hex16(encoded)?;
        shuffle2(&obfuscation, &mut bytes);
        let digest = Md5::digest(bytes);
        let hex = format!("{:02x}", digest[0])
            + &format!("{:02x}", digest[1])
            + &format!("{:02x}", digest[2])
            + &format!("{:02x}", digest[3])
            + &format!("{:02x}", digest[4])
            + &format!("{:02x}", digest[5])
            + &format!("{:02x}", digest[6])
            + &format!("{:02x}", digest[7]);
        hex.as_bytes()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid derived OFP key"))
    };
    Ok((to_md5(table[1])?, to_md5(table[2])?))
}

fn brute_key(first_block: &[u8]) -> Result<([u8; 16], [u8; 16])> {
    for table in KEYTABLES {
        let (key, iv) = derive_key(table)?;
        let mut probe = first_block.to_vec();
        cfb_decrypt(&key, &iv, &mut probe);
        if probe.starts_with(b"MMM") {
            info!(table_index = ?KEYTABLES.iter().position(|t| *t == *table), "ofp_mtk.key_found");
            return Ok((key, iv));
        }
    }
    bail!("unknown MTK OFP AES key")
}

fn c_string(bytes: &[u8]) -> String {
    let name: Vec<u8> = bytes.iter().copied().take_while(|&b| b != 0).collect();
    String::from_utf8_lossy(&name).replace(['/', '\\'], "_")
}

fn u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .with_context(|| "truncated MTK OFP header")?
            .try_into()
            .expect("8-byte slice"),
    ))
}

/// Extract every image of a MediaTek `.ofp` firmware into `output_dir`.
///
/// # Errors
///
/// Returns an error when no key matches, the trailing headers are truncated,
/// or an image cannot be written.
pub fn extract_ofp_mtk(source: &Path, output_dir: &Path) -> Result<()> {
    let mut input =
        File::open(source).with_context(|| format!("Failed to open {}", source.display()))?;
    let len = input.metadata().context("reading OFP metadata")?.len();
    if len < HEADER_LEN as u64 + ENTRY_LEN as u64 {
        bail!("file is too small to be an MTK OFP firmware");
    }

    let mut first = [0u8; 16];
    input
        .read_exact(&mut first)
        .context("reading OFP key probe")?;
    let (key, iv) = brute_key(&first)?;

    input
        .seek(SeekFrom::End(-(HEADER_LEN as i64)))
        .context("seeking OFP header")?;
    let mut header = vec![0u8; HEADER_LEN];
    input
        .read_exact(&mut header)
        .context("reading OFP header")?;
    shuffle(HEADER_KEY, &mut header);
    let entries = u16::from_le_bytes(
        header[72..74]
            .try_into()
            .context("OFP entry count missing")?,
    ) as usize;
    let table_len = entries
        .checked_mul(ENTRY_LEN)
        .context("OFP entry count overflow")?;
    if table_len as u64 + HEADER_LEN as u64 > len {
        bail!("OFP entry table exceeds file length");
    }

    input
        .seek(SeekFrom::End(-((table_len + HEADER_LEN) as i64)))
        .context("seeking OFP entry table")?;
    let mut table = vec![0u8; table_len];
    input
        .read_exact(&mut table)
        .context("reading OFP entry table")?;
    shuffle(HEADER_KEY, &mut table);

    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create {}", output_dir.display()))?;
    for chunk in table.as_chunks::<ENTRY_LEN>().0 {
        let filename = c_string(&chunk[56..88]);
        if filename.is_empty() {
            continue;
        }
        let start = u64_le(chunk, 32)?;
        let mut length = u64_le(chunk, 40)?;
        let encrypted = u64_le(chunk, 48)?;
        input
            .seek(SeekFrom::Start(start))
            .context("seeking OFP image")?;

        let out_path = output_dir.join(filename);
        let mut out = File::create(&out_path)
            .with_context(|| format!("Failed to create {}", out_path.display()))?;
        if encrypted > 0 {
            let mut data = vec![0u8; encrypted as usize];
            input
                .read_exact(&mut data)
                .context("reading encrypted OFP data")?;
            let padded = data.len().div_ceil(16) * 16;
            data.resize(padded, 0);
            cfb_decrypt(&key, &iv, &mut data);
            out.write_all(&data[..encrypted as usize])
                .context("writing OFP image")?;
            length = length.saturating_sub(encrypted);
        }
        let mut remaining = length;
        let mut buf = vec![0u8; 256 * 1024];
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            let n = input.read(&mut buf[..want]).context("reading OFP image")?;
            if n == 0 {
                bail!("OFP image ended {remaining} bytes early");
            }
            out.write_all(&buf[..n]).context("writing OFP image")?;
            remaining -= n as u64;
        }
        info!(file = %out_path.display(), size = length + encrypted, "ofp_mtk.image.extracted");
    }

    Ok(())
}
