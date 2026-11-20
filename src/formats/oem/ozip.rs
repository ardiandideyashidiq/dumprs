//! Decryptor for Oppo/Realme/OnePlus `.ozip` firmware packages.
//!
//! Mode 1 layout (from the MIT-licensed `ozipdecrypt.py`): a 0x1050-byte
//! header, then repeating blocks of one 16-byte AES-128-ECB encrypted chunk
//! followed by 0x4000 plaintext bytes. The key is discovered by decrypting
//! the first 16 bytes at 0x1050 and looking for a known file magic.

use aes::Aes128;
use aes::cipher::{Block, BlockModeDecrypt, KeyInit};
use anyhow::{Context, Result, bail};
use ecb::Decryptor;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use tracing::info;

const HEADER_SIZE: usize = 0x1050;
const ENCRYPTED_CHUNK: usize = 16;
const PLAIN_CHUNK: usize = 0x4000;
const MAGIC: &[u8; 12] = b"OPPOENCRYPT!";

type Aes128Ecb = Decryptor<Aes128>;

/// Keys published by `ozipdecrypt.py`, in the same order.
const KEYS: &[&str] = &[
    "D6EECF0AE5ACD4E0E9FE522DE7CE381E",
    "D6ECCF0AE5ACD4E0E92E522DE7C1381E",
    "D6DCCF0AD5ACD4E0292E522DB7C1381E",
    "D7DCCE1AD4AFDCE2393E5161CBDC4321",
    "D7DBCE2AD4ADDCE1393E5521CBDC4321",
    "D7DBCE1AD4AFDCE1393E5121CBDC4321",
    "D4D2CD61D4AFDCE13B5E01221BD14D20",
    "261CC7131D7C1481294E532DB752381E",
    "1CA21E12271335AE33AB81B2A7B14622",
    "D4D2CE11D4AFDCE13B3E0121CBD14D20",
    "1C4C1EA3A12531AE491B21BB31613C11",
    "1C4C1EA3A12531AE4A1B21BB31C13C21",
    "1C4A11A3A12513AE441B23BB31513121",
    "1C4A11A3A12589AE441A23BB31517733",
    "1C4A11A3A22513AE541B53BB31513121",
    "2442CE821A4F352E33AE81B22BC1462E",
    "14C2CD6214CFDC2733AE81B22BC1462C",
    "1E38C1B72D522E29E0D4ACD50ACFDCD6",
    "12341EAAC4C123CE193556A1BBCC232D",
    "2143DCCB21513E39E1DCAFD41ACEDBD7",
    "2D23CCBBA1563519CE23C1C4AA1E3412",
    "172B3E14E46F3CE13E2B5121CBDC4321",
    "ACAA1E12A71431CE4A1B21BBA1C1C6A2",
    "ACAC1E13A72531AE4A1B22BB31C1CC22",
    "1C4411A3A12533AE441B21BB31613C11",
    "1C4416A8A42717AE441523B336513121",
    "55EEAA33112133AE441B23BB31513121",
    "ACAC1E13A12531AE4A1B21BB31C13C21",
    "ACAC1E13A72431AE4A1B22BBA1C1C6A2",
    "12CAC11211AAC3AEA2658690122C1E81",
    "1CA21E12271435AE331B81BBA7C14612",
    "D1DACF24351CE428A9CE32ED87323216",
    "A1CC75115CAECB890E4A563CA1AC67C8",
    "2132321EA2CA86621A11241ABA512722",
    "22A21E821743E5EE33AE81B227B1462E",
];

fn hex_key(value: &str) -> Result<[u8; 16]> {
    let bytes = (0..16)
        .map(|i| {
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                .with_context(|| format!("invalid ozip key {value}"))
        })
        .collect::<Result<Vec<_>>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ozip key length"))
}

fn decrypt_block(cipher: &mut Aes128Ecb, data: &[u8]) -> [u8; ENCRYPTED_CHUNK] {
    let mut block = Block::<Aes128Ecb>::try_from(data).expect("16-byte AES block");
    cipher.decrypt_block(&mut block);
    block.into()
}

fn find_key(first_block: &[u8]) -> Result<Aes128Ecb> {
    for hex in KEYS {
        let key = hex_key(hex)?;
        let mut cipher = Aes128Ecb::new(&key.into());
        let plain = decrypt_block(&mut cipher, first_block);
        if plain.starts_with(b"PK\x03\x04")
            || plain.starts_with(b"AVB0")
            || plain.starts_with(b"ANDR")
        {
            info!(key = %hex, "ozip.key_found");
            return Ok(cipher);
        }
    }
    bail!("unknown ozip AES key")
}

/// Decrypt a mode-1 `.ozip` into `output`.
///
/// # Errors
///
/// Returns an error when the magic is wrong, no published key matches, an
/// encrypted chunk is truncated, or the output cannot be written.
pub fn decrypt_ozip(source: &Path, output: &Path) -> Result<()> {
    let mut input =
        File::open(source).with_context(|| format!("Failed to open {}", source.display()))?;
    let mut header = [0u8; HEADER_SIZE];
    input
        .read_exact(&mut header)
        .context("ozip header is truncated")?;
    if &header[..MAGIC.len()] != MAGIC {
        bail!("ozip has unknown magic, OPPOENCRYPT! expected");
    }

    let mut first = [0u8; ENCRYPTED_CHUNK];
    input
        .read_exact(&mut first)
        .context("ozip first block is truncated")?;
    let mut cipher = find_key(&first)?;

    let mut out =
        File::create(output).with_context(|| format!("Failed to create {}", output.display()))?;
    out.write_all(&decrypt_block(&mut cipher, &first))
        .context("writing decrypted ozip block")?;

    let mut plain = vec![0u8; PLAIN_CHUNK];
    let mut encrypted = [0u8; ENCRYPTED_CHUNK];
    loop {
        let n = input
            .read(&mut plain)
            .context("reading ozip plaintext chunk")?;
        if n == 0 {
            break;
        }
        out.write_all(&plain[..n])
            .context("writing ozip plaintext chunk")?;
        let read = input
            .read(&mut encrypted)
            .context("reading ozip encrypted chunk")?;
        if read == 0 {
            break;
        }
        if read < ENCRYPTED_CHUNK {
            bail!("ozip ends with a truncated encrypted block");
        }
        out.write_all(&decrypt_block(&mut cipher, &encrypted))
            .context("writing decrypted ozip block")?;
    }

    Ok(())
}
