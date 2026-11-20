//! Decryptor for HTC encrypted RUU `rom.zip` packages.
//!
//! Port of the GPL-3.0 `ruuveal` tool: a 128-byte `Htc@egi$` header selects a
//! device key index and chunk count; AES-128-CBC is then applied to the first
//! 1 MiB of every `chunks << 20` byte region.

#[path = "ruu_devices.rs"]
mod devices;

use aes::Aes128;
use anyhow::{Context, Result, bail};
use cbc::Decryptor as CbcDecryptor;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::info;

const HEADER_SIZE: usize = 0x80;
const READ_BUFFER: usize = 0x8000;
const READ_BUFFER_ROUNDS: u32 = 0x20;
const KEY_DATA_LEN: usize = 0x60;
const HEADER_MAGIC: &[u8; 8] = b"Htc@egi$";

const KEY_DATA: &[u8] = include_bytes!("htc_keydata.bin");
const KEY_MAP: &[u8] = include_bytes!("htc_keymap.bin");

type Aes128Cbc = CbcDecryptor<Aes128>;

fn derive_keys(device: &str, keymap_index: u16) -> Result<([u8; 16], [u8; 16])> {
    let offset = devices::DEVICES
        .iter()
        .find(|(name, _)| *name == device)
        .map(|(_, offset)| *offset)
        .with_context(|| format!("unsupported HTC device {device}"))?;
    let keydata = KEY_DATA
        .get(offset * KEY_DATA_LEN..offset * KEY_DATA_LEN + KEY_DATA_LEN)
        .context("HTC key data table is truncated")?;
    let map_start = (usize::from(keymap_index) - 1) << 5;
    let keymap = KEY_MAP
        .get(map_start..map_start + 32)
        .context("HTC keymap index out of range")?;
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    for i in 0..16 {
        key[i] = keydata[usize::from(keymap[i])];
        iv[i] = keydata[usize::from(keymap[i + 16])];
    }
    Ok((key, iv))
}

fn chunk_count(size: usize, chunk_size: usize) -> usize {
    if chunk_size <= 1 || size < chunk_size {
        return 0;
    }
    if size == chunk_size {
        return 1;
    }
    let mut chunks = size / chunk_size - 1;
    if size - chunk_size * chunks != 0 {
        chunks += 1;
    }
    chunks
}

/// Try every compiled-in device key until one decrypts the ZIP magic.
///
/// # Errors
///
/// Returns an error when no device key produces a ZIP header.
pub fn detect_device(source: &Path) -> Result<&'static str> {
    let mut input =
        File::open(source).with_context(|| format!("Failed to open {}", source.display()))?;
    let mut header = [0u8; HEADER_SIZE];
    input
        .read_exact(&mut header)
        .context("reading HTC zip header")?;
    let start = if header[..8] == *HEADER_MAGIC {
        HEADER_SIZE
    } else {
        input
            .seek(SeekFrom::Start(0x100))
            .context("seeking HTC header")?;
        input
            .read_exact(&mut header)
            .context("reading HTC header")?;
        if header[..8] != *HEADER_MAGIC {
            bail!("not an encrypted HTC rom.zip");
        }
        0x100 + HEADER_SIZE
    };
    let keymap_index = u16::from_be_bytes(
        header[8..10]
            .try_into()
            .context("HTC keymap index missing")?,
    );
    input
        .seek(SeekFrom::Start(start as u64))
        .context("seeking RUU data")?;
    let mut probe = [0u8; 16];
    input
        .read_exact(&mut probe)
        .context("reading RUU probe block")?;

    for &(device, _) in devices::DEVICES {
        let (key, iv) = derive_keys(device, keymap_index)?;
        let mut candidate = probe;
        cbc_decrypt_block(&mut candidate, &key, &iv)?;
        if candidate.starts_with(b"PK") {
            return Ok(device);
        }
    }
    bail!("no HTC device key decrypted the RUU header")
}

/// Decrypt an HTC rom.zip, detecting the device key automatically.
///
/// # Errors
///
/// Returns an error when the device key cannot be determined or decryption
/// fails.
pub fn decrypt_ruu_zip_auto(source: &Path, output: &Path) -> Result<()> {
    let device = detect_device(source)?;
    decrypt_ruu_zip(source, output, device)
}

fn cbc_decrypt_block(data: &mut [u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<[u8; 16]> {
    let next_iv: [u8; 16] = data[data.len() - 16..]
        .try_into()
        .context("AES block too short")?;
    Aes128Cbc::new(key.into(), iv.into())
        .decrypt_padded::<NoPadding>(data)
        .context("AES-CBC decryption failed")?;
    Ok(next_iv)
}

/// Decrypt an HTC encrypted `rom.zip` into `output`.
///
/// # Errors
///
/// Returns an error when the HTC header is missing, the device or keymap
/// index is unsupported, or the output cannot be written.
pub fn decrypt_ruu_zip(source: &Path, output: &Path, device: &str) -> Result<()> {
    let mut input =
        File::open(source).with_context(|| format!("Failed to open {}", source.display()))?;
    let mut header = [0u8; HEADER_SIZE];
    input
        .read_exact(&mut header)
        .context("reading HTC zip header")?;
    let data_start = if header[..8] == *HEADER_MAGIC {
        HEADER_SIZE
    } else {
        input
            .seek(SeekFrom::Start(0x100))
            .context("seeking alternate HTC header")?;
        input
            .read_exact(&mut header)
            .context("reading alternate HTC header")?;
        if header[..8] != *HEADER_MAGIC {
            bail!("not an encrypted HTC rom.zip");
        }
        0x100 + HEADER_SIZE
    };

    let keymap_index = u16::from_be_bytes(
        header[8..10]
            .try_into()
            .context("HTC keymap index missing")?,
    );
    let chunks = usize::from(header[10]);
    let (key, original_iv) = derive_keys(device, keymap_index)?;
    let mut iv = original_iv;
    let chunk_size = chunks << 20;

    let total = input.metadata().context("reading RUU metadata")?.len() as usize;
    let size = total.saturating_sub(data_start);
    let chunks_total = chunk_count(size, chunk_size);

    fs::create_dir_all(
        output
            .parent()
            .context("output path has no parent directory")?,
    )
    .context("creating output directory")?;
    let mut out =
        File::create(output).with_context(|| format!("Failed to create {}", output.display()))?;

    let mut buffer = vec![0u8; READ_BUFFER];
    let mut bytesdone = 0usize;
    let mut chunksdone = 0usize;
    let mut count = READ_BUFFER_ROUNDS + 1;
    while bytesdone < size {
        let read = input.read(&mut buffer).context("reading encrypted RUU")?;
        if read == 0 {
            break;
        }
        let before = bytesdone;
        bytesdone += read;
        let bytes = if bytesdone > size {
            read - (bytesdone - size)
        } else {
            read
        };

        if chunksdone < chunks_total {
            if before.is_multiple_of(chunk_size) {
                count = 0;
                iv = original_iv;
            }
            if count < READ_BUFFER_ROUNDS {
                iv = cbc_decrypt_block(&mut buffer[..bytes], &key, &iv)?;
                count += 1;
            } else if count == READ_BUFFER_ROUNDS {
                chunksdone += 1;
                count += 1;
            }
        }
        out.write_all(&buffer[..bytes])
            .context("writing decrypted RUU")?;
    }

    info!(device, keymap_index, chunks, size, "ruu.zip.decrypted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AES-128-CBC vector produced by OpenSSL with the keys derived for
    /// device `m7_ul`, keymap 0xA4.
    #[test]
    fn cbc_matches_openssl_vector() {
        let key: [u8; 16] = [
            0xf7, 0xda, 0x06, 0x26, 0x7c, 0xbc, 0x06, 0xbe, 0xcf, 0xfb, 0x4d, 0xcb, 0x24, 0xcf,
            0x5a, 0x00,
        ];
        let iv: [u8; 16] = [
            0x7c, 0x02, 0xda, 0x72, 0x8b, 0xbe, 0x40, 0xb4, 0xaf, 0x00, 0x9b, 0x06, 0x16, 0xda,
            0xcf, 0xb7,
        ];
        let mut ciphertext: Vec<u8> = (0..16)
            .map(|i| {
                u8::from_str_radix(&"3e081b84219c99111a947ad92ec523b6"[i * 2..i * 2 + 2], 16)
                    .unwrap()
            })
            .collect();
        cbc_decrypt_block(&mut ciphertext, &key, &iv).expect("block decrypted");
        assert_eq!(ciphertext, b"PK\x03\x040123456789ab");
    }

    #[test]
    fn derives_keys_from_builtin_tables() {
        let (key, iv) = derive_keys("m7_ul", 0xa4).expect("keys derived");
        assert_eq!(
            key.as_slice(),
            &[
                0xf7, 0xda, 0x06, 0x26, 0x7c, 0xbc, 0x06, 0xbe, 0xcf, 0xfb, 0x4d, 0xcb, 0x24, 0xcf,
                0x5a, 0x00,
            ]
        );
        assert_eq!(
            iv.as_slice(),
            &[
                0x7c, 0x02, 0xda, 0x72, 0x8b, 0xbe, 0x40, 0xb4, 0xaf, 0x00, 0x9b, 0x06, 0x16, 0xda,
                0xcf, 0xb7,
            ]
        );
    }
}
