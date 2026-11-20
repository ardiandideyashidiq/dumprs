use anyhow::{Result, bail};
use byteorder::{BigEndian, ReadBytesExt};
use sha1::{Digest, Sha1};
use std::fmt::Write as _;
use std::io::Cursor;

const HEADER_SIZE: usize = 256;
const FOOTER_SIZE: usize = 64;
const HEADER_MAGIC: &[u8; 4] = b"AVB0";
const FOOTER_MAGIC: &[u8; 4] = b"AVBf";

struct Footer {
    version_major: u32,
    version_minor: u32,
    original_size: u64,
    vbmeta_offset: u64,
    vbmeta_size: u64,
}

struct Header {
    required_major: u32,
    required_minor: u32,
    auth_size: u64,
    aux_size: u64,
    algorithm_type: u32,
    descriptors_offset: u64,
    descriptors_size: u64,
    rollback_index: u64,
    flags: u32,
    rollback_index_location: u32,
    release_string: String,
    public_key_offset: u64,
    public_key_size: u64,
}

enum Descriptor {
    Property {
        key: String,
        value: Vec<u8>,
    },
    Hash {
        image_size: u64,
        algorithm: String,
        partition_name: String,
        salt: Vec<u8>,
        digest: Vec<u8>,
        flags: u32,
    },
    Hashtree {
        dm_verity_version: u32,
        image_size: u64,
        tree_offset: u64,
        tree_size: u64,
        data_block_size: u32,
        hash_block_size: u32,
        fec_num_roots: u32,
        fec_offset: u64,
        fec_size: u64,
        hash_algorithm: String,
        partition_name: String,
        salt: Vec<u8>,
        root_digest: Vec<u8>,
        flags: u32,
    },
    KernelCmdline {
        flags: u32,
        cmdline: String,
    },
    ChainPartition {
        rollback_index_location: u32,
        partition_name: String,
        public_key: Vec<u8>,
        flags: u32,
    },
    Unknown {
        tag: u64,
        data: Vec<u8>,
    },
}

fn be_u32(slice: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(slice.try_into()?))
}

fn be_u64(slice: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(slice.try_into()?))
}

fn slice_at<'a>(data: &'a [u8], offset: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| anyhow::anyhow!("truncated AVB {what}"))?;
    Ok(&data[offset..end])
}

fn cstring(data: &[u8]) -> String {
    let end = data
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Approximate Python's `repr(bytes)` for the printable values avbtool shows,
/// then strip the leading `b` as avbtool does for cross-version stability.
fn python_bytes_repr(bytes: &[u8]) -> String {
    let use_double = bytes.contains(&b'\'') && !bytes.contains(&b'"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for &byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            value if value == quote as u8 => {
                out.push('\\');
                out.push(quote);
            }
            0x20..=0x7e => out.push(byte as char),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out.push(quote);
    out
}

fn parse_footer(data: &[u8]) -> Option<Footer> {
    if data.len() < FOOTER_SIZE {
        return None;
    }
    let footer = &data[data.len() - FOOTER_SIZE..];
    if &footer[0..4] != FOOTER_MAGIC {
        return None;
    }
    Some(Footer {
        version_major: be_u32(&footer[4..8]).ok()?,
        version_minor: be_u32(&footer[8..12]).ok()?,
        original_size: be_u64(&footer[12..20]).ok()?,
        vbmeta_offset: be_u64(&footer[20..28]).ok()?,
        vbmeta_size: be_u64(&footer[28..36]).ok()?,
    })
}

fn parse_header(data: &[u8]) -> Result<Header> {
    let header = slice_at(data, 0, HEADER_SIZE, "header")?;
    if &header[0..4] != HEADER_MAGIC {
        bail!("image does not look like a vbmeta image");
    }
    let mut cursor = Cursor::new(header);
    cursor.set_position(4);
    let required_major = cursor.read_u32::<BigEndian>()?;
    let required_minor = cursor.read_u32::<BigEndian>()?;
    let auth_size = cursor.read_u64::<BigEndian>()?;
    let aux_size = cursor.read_u64::<BigEndian>()?;
    let algorithm_type = cursor.read_u32::<BigEndian>()?;
    let _hash_offset = cursor.read_u64::<BigEndian>()?;
    let _hash_size = cursor.read_u64::<BigEndian>()?;
    let _signature_offset = cursor.read_u64::<BigEndian>()?;
    let _signature_size = cursor.read_u64::<BigEndian>()?;
    let public_key_offset = cursor.read_u64::<BigEndian>()?;
    let public_key_size = cursor.read_u64::<BigEndian>()?;
    let _pk_metadata_offset = cursor.read_u64::<BigEndian>()?;
    let _pk_metadata_size = cursor.read_u64::<BigEndian>()?;
    let descriptors_offset = cursor.read_u64::<BigEndian>()?;
    let descriptors_size = cursor.read_u64::<BigEndian>()?;
    let rollback_index = cursor.read_u64::<BigEndian>()?;
    let flags = cursor.read_u32::<BigEndian>()?;
    let rollback_index_location = cursor.read_u32::<BigEndian>()?;
    let release_string = cstring(&header[128..175]);

    Ok(Header {
        required_major,
        required_minor,
        auth_size,
        aux_size,
        algorithm_type,
        descriptors_offset,
        descriptors_size,
        rollback_index,
        flags,
        rollback_index_location,
        release_string,
        public_key_offset,
        public_key_size,
    })
}

fn parse_descriptor(tag: u64, body: &[u8]) -> Result<Descriptor> {
    match tag {
        0 => {
            if body.len() < 16 {
                bail!("truncated property descriptor");
            }
            let key_len = be_u64(&body[0..8])? as usize;
            let value_len = be_u64(&body[8..16])? as usize;
            let key = cstring(slice_at(body, 16, key_len, "property key")?);
            let value = slice_at(body, 16 + key_len + 1, value_len, "property value")?;
            Ok(Descriptor::Property {
                key,
                value: value.to_vec(),
            })
        }
        1 => {
            if body.len() < 104 {
                bail!("truncated hashtree descriptor");
            }
            let name_len = be_u32(&body[88..92])? as usize;
            let salt_len = be_u32(&body[92..96])? as usize;
            let digest_len = be_u32(&body[96..100])? as usize;
            // The hashtree body is 164 bytes (SIZE 180 minus the 16-byte
            // descriptor header); the variable-length name follows it.
            const HASHTREE_FIXED: usize = 164;
            let name = cstring(slice_at(body, HASHTREE_FIXED, name_len, "hashtree name")?);
            let salt = slice_at(body, HASHTREE_FIXED + name_len, salt_len, "hashtree salt")?;
            let digest = slice_at(
                body,
                HASHTREE_FIXED + name_len + salt_len,
                digest_len,
                "hashtree digest",
            )?;
            Ok(Descriptor::Hashtree {
                dm_verity_version: be_u32(&body[0..4])?,
                image_size: be_u64(&body[4..12])?,
                tree_offset: be_u64(&body[12..20])?,
                tree_size: be_u64(&body[20..28])?,
                data_block_size: be_u32(&body[28..32])?,
                hash_block_size: be_u32(&body[32..36])?,
                fec_num_roots: be_u32(&body[36..40])?,
                fec_offset: be_u64(&body[40..48])?,
                fec_size: be_u64(&body[48..56])?,
                hash_algorithm: cstring(&body[56..88]),
                partition_name: name,
                salt: salt.to_vec(),
                root_digest: digest.to_vec(),
                flags: be_u32(&body[100..104])?,
            })
        }
        2 => {
            if body.len() < 56 {
                bail!("truncated hash descriptor");
            }
            let name_len = be_u32(&body[40..44])? as usize;
            let salt_len = be_u32(&body[44..48])? as usize;
            let digest_len = be_u32(&body[48..52])? as usize;
            let name = cstring(slice_at(body, 116, name_len, "hash partition name")?);
            let salt = slice_at(body, 116 + name_len, salt_len, "hash salt")?;
            let digest = slice_at(body, 116 + name_len + salt_len, digest_len, "hash digest")?;
            Ok(Descriptor::Hash {
                image_size: be_u64(&body[0..8])?,
                algorithm: cstring(&body[8..40]),
                partition_name: name,
                salt: salt.to_vec(),
                digest: digest.to_vec(),
                flags: be_u32(&body[52..56])?,
            })
        }
        3 => {
            if body.len() < 8 {
                bail!("truncated kernel cmdline descriptor");
            }
            let len = be_u32(&body[4..8])? as usize;
            let cmdline = cstring(slice_at(body, 8, len, "kernel cmdline")?);
            Ok(Descriptor::KernelCmdline {
                flags: be_u32(&body[0..4])?,
                cmdline,
            })
        }
        4 => {
            if body.len() < 76 {
                bail!("truncated chain partition descriptor");
            }
            let name_len = be_u32(&body[4..8])? as usize;
            let key_len = be_u32(&body[8..12])? as usize;
            let name = cstring(slice_at(body, 76, name_len, "chain partition name")?);
            let key = slice_at(body, 76 + name_len, key_len, "chain partition key")?;
            Ok(Descriptor::ChainPartition {
                rollback_index_location: be_u32(&body[0..4])?,
                partition_name: name,
                public_key: key.to_vec(),
                flags: be_u32(&body[12..16])?,
            })
        }
        _ => Ok(Descriptor::Unknown {
            tag,
            data: body.to_vec(),
        }),
    }
}

fn parse_descriptors(data: &[u8]) -> Result<Vec<Descriptor>> {
    let mut descriptors = Vec::new();
    let mut position = 0usize;
    while position < data.len() {
        let header = slice_at(data, position, 16, "descriptor header")?;
        let tag = be_u64(&header[0..8])?;
        let following = be_u64(&header[8..16])? as usize;
        let end = position
            .checked_add(16 + following)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| anyhow::anyhow!("truncated AVB descriptor with tag {tag}"))?;
        descriptors.push(parse_descriptor(tag, &data[position + 16..end])?);
        position = end;
    }
    Ok(descriptors)
}

fn algorithm_name(algorithm_type: u32) -> &'static str {
    match algorithm_type {
        0 => "NONE",
        1 => "SHA256_RSA2048",
        2 => "SHA256_RSA4096",
        3 => "SHA256_RSA8192",
        4 => "SHA512_RSA2048",
        5 => "SHA512_RSA4096",
        6 => "SHA512_RSA8192",
        _ => "UNKNOWN",
    }
}

fn render_descriptor(out: &mut String, descriptor: &Descriptor) {
    match descriptor {
        Descriptor::Property { key, value } => {
            let rendered = python_bytes_repr(value);
            if value.len() < 256 {
                let _ = writeln!(out, "    Prop: {key} -> {rendered}");
            } else {
                let _ = writeln!(out, "    Prop: {key} -> ({} bytes)", value.len());
            }
        }
        Descriptor::Hash {
            image_size,
            algorithm,
            partition_name,
            salt,
            digest,
            flags,
        } => {
            let _ = writeln!(out, "    Hash descriptor:");
            let _ = writeln!(out, "      Image Size:            {image_size} bytes");
            let _ = writeln!(out, "      Hash Algorithm:        {algorithm}");
            let _ = writeln!(out, "      Partition Name:        {partition_name}");
            let _ = writeln!(out, "      Salt:                  {}", hex(salt));
            let _ = writeln!(out, "      Digest:                {}", hex(digest));
            let _ = writeln!(out, "      Flags:                 {flags}");
        }
        Descriptor::Hashtree {
            dm_verity_version,
            image_size,
            tree_offset,
            tree_size,
            data_block_size,
            hash_block_size,
            fec_num_roots,
            fec_offset,
            fec_size,
            hash_algorithm,
            partition_name,
            salt,
            root_digest,
            flags,
        } => {
            let _ = writeln!(out, "    Hashtree descriptor:");
            let _ = writeln!(out, "      Version of dm-verity:  {dm_verity_version}");
            let _ = writeln!(out, "      Image Size:            {image_size} bytes");
            let _ = writeln!(out, "      Tree Offset:           {tree_offset}");
            let _ = writeln!(out, "      Tree Size:             {tree_size} bytes");
            let _ = writeln!(out, "      Data Block Size:       {data_block_size} bytes");
            let _ = writeln!(out, "      Hash Block Size:       {hash_block_size} bytes");
            let _ = writeln!(out, "      FEC num roots:         {fec_num_roots}");
            let _ = writeln!(out, "      FEC offset:            {fec_offset}");
            let _ = writeln!(out, "      FEC size:              {fec_size} bytes");
            let _ = writeln!(out, "      Hash Algorithm:        {hash_algorithm}");
            let _ = writeln!(out, "      Partition Name:        {partition_name}");
            let _ = writeln!(out, "      Salt:                  {}", hex(salt));
            let _ = writeln!(out, "      Root Digest:           {}", hex(root_digest));
            let _ = writeln!(out, "      Flags:                 {flags}");
        }
        Descriptor::KernelCmdline { flags, cmdline } => {
            let _ = writeln!(out, "    Kernel Cmdline descriptor:");
            let _ = writeln!(out, "      Flags:                 {flags}");
            let _ = writeln!(out, "      Kernel Cmdline:        '{cmdline}'");
        }
        Descriptor::ChainPartition {
            rollback_index_location,
            partition_name,
            public_key,
            flags,
        } => {
            let _ = writeln!(out, "    Chain Partition descriptor:");
            let _ = writeln!(out, "      Partition Name:          {partition_name}");
            let _ = writeln!(
                out,
                "      Rollback Index Location: {rollback_index_location}"
            );
            let mut hasher = Sha1::new();
            hasher.update(public_key);
            let _ = writeln!(
                out,
                "      Public key (sha1):       {}",
                hex(&hasher.finalize())
            );
            let _ = writeln!(out, "      Flags:                   {flags}");
        }
        Descriptor::Unknown { tag, data } => {
            let _ = writeln!(out, "    Unknown descriptor:");
            let _ = writeln!(out, "      Tag:  {tag}");
            if data.len() < 256 {
                let _ = writeln!(
                    out,
                    "      Data: {} ({} bytes)",
                    python_bytes_repr(data),
                    data.len()
                );
            } else {
                let _ = writeln!(out, "      Data: {} bytes", data.len());
            }
        }
    }
}

/// Parse a vbmeta blob (standalone `vbmeta.img` or the blob referenced by an
/// AVB footer at the end of a partition image) and render it exactly like
/// `avbtool info_image`.
pub fn render_avb_info(data: &[u8], image_size: u64) -> Result<String> {
    let footer = parse_footer(data);
    let (vbmeta_offset, vbmeta_size) = match &footer {
        Some(footer) => (footer.vbmeta_offset as usize, footer.vbmeta_size as usize),
        None => (0usize, data.len()),
    };
    let vbmeta = slice_at(data, vbmeta_offset, vbmeta_size, "vbmeta blob")?;
    let header = parse_header(vbmeta)?;

    let aux_start = HEADER_SIZE
        .checked_add(header.auth_size as usize)
        .filter(|offset| *offset <= vbmeta.len())
        .ok_or_else(|| anyhow::anyhow!("AVB authentication block out of bounds"))?;
    let descriptors_start = aux_start
        .checked_add(header.descriptors_offset as usize)
        .filter(|offset| *offset <= vbmeta.len())
        .ok_or_else(|| anyhow::anyhow!("AVB descriptors offset out of bounds"))?;
    let descriptors = slice_at(
        vbmeta,
        descriptors_start,
        header.descriptors_size as usize,
        "descriptors",
    )?;
    let descriptors = parse_descriptors(descriptors)?;

    let mut out = String::new();
    if let Some(footer) = &footer {
        let _ = writeln!(
            out,
            "Footer version:           {}.{}",
            footer.version_major, footer.version_minor
        );
        let _ = writeln!(out, "Image size:               {image_size} bytes");
        let _ = writeln!(
            out,
            "Original image size:      {} bytes",
            footer.original_size
        );
        let _ = writeln!(out, "VBMeta offset:            {}", footer.vbmeta_offset);
        let _ = writeln!(
            out,
            "VBMeta size:              {} bytes",
            footer.vbmeta_size
        );
        let _ = writeln!(out, "--");
    }
    let _ = writeln!(
        out,
        "Minimum libavb version:   {}.{}",
        header.required_major, header.required_minor
    );
    let _ = writeln!(out, "Header Block:             {HEADER_SIZE} bytes");
    let _ = writeln!(out, "Authentication Block:     {} bytes", header.auth_size);
    let _ = writeln!(out, "Auxiliary Block:          {} bytes", header.aux_size);
    if header.public_key_size > 0 {
        let key = slice_at(
            vbmeta,
            aux_start + header.public_key_offset as usize,
            header.public_key_size as usize,
            "public key",
        )?;
        let mut hasher = Sha1::new();
        hasher.update(key);
        let _ = writeln!(out, "Public key (sha1):        {}", hex(&hasher.finalize()));
    }
    let _ = writeln!(
        out,
        "Algorithm:                {}",
        algorithm_name(header.algorithm_type)
    );
    let _ = writeln!(out, "Rollback Index:           {}", header.rollback_index);
    let _ = writeln!(out, "Flags:                    {}", header.flags);
    let _ = writeln!(
        out,
        "Rollback Index Location:  {}",
        header.rollback_index_location
    );
    let _ = writeln!(out, "Release String:           '{}'", header.release_string);
    let _ = writeln!(out, "Descriptors:");
    if descriptors.is_empty() {
        let _ = writeln!(out, "    (none)");
    }
    for descriptor in &descriptors {
        render_descriptor(&mut out, descriptor);
    }
    Ok(out)
}
