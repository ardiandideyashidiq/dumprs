//! Deterministic builders for the boot-artifact tests.
//!
//! These construct the binary inputs by hand from the AVB/bootimg/DTB/kallsyms
//! specs, independently of the code under test.

pub const ORIGINAL_SIZE: u64 = 4096;
pub const RELEASE_STRING: &[u8] = b"avbtool test";
pub const PROP_KEY: &str = "com.android.build.system.os_version";
pub const PROP_VALUE: &[u8] = b"13";
pub const HASH_ALGO: &str = "sha256";
pub const HASH_PARTITION: &str = "system";
pub const HASH_IMAGE_SIZE: u64 = 1234;
pub const CMDLINE: &str = "root=/dev/dm-0";
pub const ROLLBACK_INDEX: u64 = 7;
pub const ROLLBACK_LOCATION: u32 = 3;
pub const KERNEL_CONFIG: &[u8] = b"CONFIG_TEST=y\nCONFIG_IKCONFIG=y\n";

pub const KALLSYMS_COUNT: usize = 1024;
pub const KALLSYMS_BASE: u64 = 0xffff_0000_8000_0000;

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn append_property(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    let key = key.as_bytes();
    let raw = 32 - 16 + key.len() + 1 + value.len() + 1;
    let following = align_up(raw, 8);
    push_u64(out, 0); // tag PROPERTY
    push_u64(out, following as u64);
    push_u64(out, key.len() as u64);
    push_u64(out, value.len() as u64);
    out.extend_from_slice(key);
    out.push(0);
    out.extend_from_slice(value);
    out.push(0);
    out.resize(out.len() + (following - raw), 0);
}

fn append_hash(
    out: &mut Vec<u8>,
    image_size: u64,
    algorithm: &str,
    name: &str,
    salt: &[u8],
    digest: &[u8],
) {
    let name = name.as_bytes();
    let raw = 132 - 16 + name.len() + salt.len() + digest.len();
    let following = align_up(raw, 8);
    push_u64(out, 2); // tag HASH
    push_u64(out, following as u64);
    push_u64(out, image_size);
    let mut algo = [0u8; 32];
    algo[..algorithm.len()].copy_from_slice(algorithm.as_bytes());
    out.extend_from_slice(&algo);
    push_u32(out, name.len() as u32);
    push_u32(out, salt.len() as u32);
    push_u32(out, digest.len() as u32);
    push_u32(out, 0); // flags
    out.resize(out.len() + 60, 0); // reserved
    out.extend_from_slice(name);
    out.extend_from_slice(salt);
    out.extend_from_slice(digest);
    out.resize(out.len() + (following - raw), 0);
}

fn append_kernel_cmdline(out: &mut Vec<u8>, flags: u32, cmdline: &str) {
    let raw = 24 - 16 + cmdline.len();
    let following = align_up(raw, 8);
    push_u64(out, 3); // tag KERNEL_CMD
    push_u64(out, following as u64);
    push_u32(out, flags);
    push_u32(out, cmdline.len() as u32);
    out.extend_from_slice(cmdline.as_bytes());
    out.resize(out.len() + (following - raw), 0);
}

/// A standalone vbmeta image with an AVB footer appended, mirroring the
/// layout in `DumprX/utils/avbtool.py`.
pub fn vbmeta_with_footer() -> Vec<u8> {
    let mut descriptors = Vec::new();
    append_property(&mut descriptors, PROP_KEY, PROP_VALUE);
    append_hash(
        &mut descriptors,
        HASH_IMAGE_SIZE,
        HASH_ALGO,
        HASH_PARTITION,
        &[0x00],
        &[0x11],
    );
    append_kernel_cmdline(&mut descriptors, 0, CMDLINE);

    let aux_size = align_up(descriptors.len(), 64);
    let mut header = vec![0u8; 256];
    header[0..4].copy_from_slice(b"AVB0");
    header[4..8].copy_from_slice(&1u32.to_be_bytes()); // required libavb major
    header[8..12].copy_from_slice(&0u32.to_be_bytes()); // minor
    header[12..20].copy_from_slice(&0u64.to_be_bytes()); // authentication block
    header[20..28].copy_from_slice(&(aux_size as u64).to_be_bytes());
    header[28..32].copy_from_slice(&1u32.to_be_bytes()); // SHA256_RSA2048
    header[96..104].copy_from_slice(&0u64.to_be_bytes()); // descriptor offset
    header[104..112].copy_from_slice(&(descriptors.len() as u64).to_be_bytes());
    header[112..120].copy_from_slice(&ROLLBACK_INDEX.to_be_bytes());
    header[120..124].copy_from_slice(&0u32.to_be_bytes()); // flags
    header[124..128].copy_from_slice(&ROLLBACK_LOCATION.to_be_bytes());
    header[128..128 + RELEASE_STRING.len()].copy_from_slice(RELEASE_STRING);

    let mut image = header;
    image.extend_from_slice(&descriptors);
    image.resize(image.len() + (aux_size - descriptors.len()), 0);

    let mut footer = vec![0u8; 64];
    footer[0..4].copy_from_slice(b"AVBf");
    footer[4..8].copy_from_slice(&1u32.to_be_bytes());
    footer[8..12].copy_from_slice(&1u32.to_be_bytes());
    footer[12..20].copy_from_slice(&ORIGINAL_SIZE.to_be_bytes());
    footer[20..28].copy_from_slice(&0u64.to_be_bytes()); // vbmeta offset
    footer[28..36].copy_from_slice(&(image.len() as u64).to_be_bytes());
    image.extend_from_slice(&footer);
    image
}

/// Gzip-compressed `CONFIG_TEST=y` embedded like `CONFIG_IKCONFIG`.
pub fn ikconfig_gzip() -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(KERNEL_CONFIG).expect("gzip write");
    let compressed = encoder.finish().expect("gzip finish");

    let mut data = b"IKCFG_ST".to_vec();
    data.extend_from_slice(&compressed);
    data.extend_from_slice(b"IKCFG_ED");
    data
}

/// One DTB blob built with `dtoolkit` (an independent producer).
pub fn dtb(name: &str) -> Vec<u8> {
    use dtoolkit::model::{DeviceTree, DeviceTreeNode, DeviceTreeProperty};

    let mut tree = DeviceTree::new();
    let node = DeviceTreeNode::builder(name)
        .expect("valid node name")
        .property(DeviceTreeProperty::new("compatible", b"dumprs,test\0").expect("valid property"))
        .build();
    tree.root.add_child(node);
    tree.to_dtb()
}

pub fn kallsyms_token_table() -> Vec<Vec<u8>> {
    (0..256)
        .map(|index| {
            if index == 0 {
                vec![] // the real table's first token is the empty string
            } else if index == b':' as usize {
                vec![b'x', b'x'] // avoid the ":\0" sequence the finder rejects
            } else {
                vec![index as u8]
            }
        })
        .collect()
}

/// The names encoded in `synthetic_kernel()`, in order.
pub fn kallsyms_names() -> Vec<String> {
    (0..KALLSYMS_COUNT)
        .map(|index| format!("Tsym{index:04}"))
        .collect()
}

/// A little-endian 64-bit raw kernel image with a complete, spec-shaped
/// kallsyms table. Every field is written independently of the finder.
pub fn synthetic_kernel() -> Vec<u8> {
    let tokens = kallsyms_token_table();
    let names = kallsyms_names();

    let mut kernel = vec![0u8; 0x1000];

    for address in (0..KALLSYMS_COUNT).map(|i| KALLSYMS_BASE + (i as u64) * 4) {
        kernel.extend_from_slice(&address.to_le_bytes());
    }
    kernel.extend_from_slice(&(KALLSYMS_COUNT as u32).to_le_bytes());
    while !kernel.len().is_multiple_of(4) {
        kernel.push(0);
    }

    let mut names_blob = Vec::new();
    let mut markers = Vec::new();
    for (index, name) in names.iter().enumerate() {
        if index % 256 == 0 {
            markers.push(names_blob.len() as u32);
        }
        names_blob.push(name.len() as u8);
        for byte in name.bytes() {
            names_blob.push(byte); // token index == ASCII byte in this fixture
        }
    }
    kernel.extend_from_slice(&names_blob);
    while !kernel.len().is_multiple_of(4) {
        kernel.push(0);
    }

    for marker in &markers {
        kernel.extend_from_slice(&marker.to_le_bytes());
    }
    while !kernel.len().is_multiple_of(4) {
        kernel.push(0);
    }

    let mut offsets = Vec::with_capacity(256);
    let mut table_blob = Vec::new();
    for token in &tokens {
        offsets.push(table_blob.len() as u16);
        table_blob.extend_from_slice(token);
        table_blob.push(0);
    }
    while !table_blob.len().is_multiple_of(4) {
        table_blob.push(0);
    }
    kernel.extend_from_slice(&table_blob);
    for offset in offsets {
        kernel.extend_from_slice(&offset.to_le_bytes());
    }
    kernel
}

/// A little-endian kernel using CONFIG_KALLSYMS_BASE_RELATIVE: the address
/// array is replaced by i32 offsets plus a u64 relative base.
pub fn synthetic_base_relative_kernel() -> Vec<u8> {
    let tokens = kallsyms_token_table();
    let names = kallsyms_names();

    let mut kernel = vec![0u8; 0x1000];
    for index in 0..KALLSYMS_COUNT {
        let address = KALLSYMS_BASE + (index as u64) * 4;
        kernel.extend_from_slice(&((address - KALLSYMS_BASE) as i32).to_le_bytes());
    }
    while !kernel.len().is_multiple_of(8) {
        kernel.push(0);
    }
    kernel.extend_from_slice(&KALLSYMS_BASE.to_le_bytes());
    kernel.extend_from_slice(&(KALLSYMS_COUNT as u32).to_le_bytes());
    while !kernel.len().is_multiple_of(4) {
        kernel.push(0);
    }

    let mut names_blob = Vec::new();
    let mut markers = Vec::new();
    for (index, name) in names.iter().enumerate() {
        if index % 256 == 0 {
            markers.push(names_blob.len() as u32);
        }
        names_blob.push(name.len() as u8);
        names_blob.extend_from_slice(name.as_bytes());
    }
    kernel.extend_from_slice(&names_blob);
    while !kernel.len().is_multiple_of(4) {
        kernel.push(0);
    }
    for marker in &markers {
        kernel.extend_from_slice(&marker.to_le_bytes());
    }
    while !kernel.len().is_multiple_of(4) {
        kernel.push(0);
    }

    let mut offsets = Vec::with_capacity(256);
    let mut table_blob = Vec::new();
    for token in &tokens {
        offsets.push(table_blob.len() as u16);
        table_blob.extend_from_slice(token);
        table_blob.push(0);
    }
    while !table_blob.len().is_multiple_of(4) {
        table_blob.push(0);
    }
    kernel.extend_from_slice(&table_blob);
    for offset in offsets {
        kernel.extend_from_slice(&offset.to_le_bytes());
    }
    kernel
}

/// A minimal LZOP container wrapping one raw LZO1X block that decodes to
/// "hello, lzo world!" (the vector published by the `lzo` crate).
pub fn lzop_hello() -> Vec<u8> {
    lzop_hello_with(false)
}

pub fn lzop_hello_crc32() -> Vec<u8> {
    lzop_hello_with(true)
}

fn lzop_hello_with(crc32: bool) -> Vec<u8> {
    let block: &[u8] = &[
        34, b'h', b'e', b'l', b'l', b'o', b',', b' ', b'l', b'z', b'o', b' ', b'w', b'o', b'r',
        b'l', b'd', b'!', 17, 0, 0,
    ];
    let plain = b"hello, lzo world!";
    let flags: u32 = if crc32 { 0x0000_1100 } else { 0 }; // F_H_CRC32 | F_CRC32_D
    let mut header = Vec::new();
    header.extend_from_slice(&0x1040u16.to_be_bytes());
    header.extend_from_slice(&0x1040u16.to_be_bytes());
    header.extend_from_slice(&0x0940u16.to_be_bytes());
    header.push(1); // LZO1X_1
    header.push(5);
    header.extend_from_slice(&flags.to_be_bytes());
    header.extend_from_slice(&0u32.to_be_bytes()); // mode
    header.extend_from_slice(&0u32.to_be_bytes()); // mtime low
    header.extend_from_slice(&0u32.to_be_bytes()); // mtime high
    header.push(0); // filename length

    let checksum = |data: &[u8]| {
        if crc32 {
            crc32fast::hash(data)
        } else {
            adler2::adler32_slice(data)
        }
    };

    let mut data = vec![0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a];
    data.extend_from_slice(&header);
    data.extend_from_slice(&checksum(&header).to_be_bytes());
    data.extend_from_slice(&(plain.len() as u32).to_be_bytes());
    data.extend_from_slice(&(block.len() as u32).to_be_bytes());
    data.extend_from_slice(&checksum(plain).to_be_bytes());
    data.extend_from_slice(block);
    data.extend_from_slice(&0u32.to_be_bytes()); // end marker
    data.extend_from_slice(&checksum(plain).to_be_bytes());
    data
}
