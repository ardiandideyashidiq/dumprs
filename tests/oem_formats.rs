//! Fast-path tests for the OEM/OTA format gaps.
//!
//! Fixtures are built by hand from the published formats, independently of
//! the code under test. See AGENTS.md for why `temp_dir` is included by path.

#[path = "common/temp_dir.rs"]
mod temp_dir;

use dumprs::formats::payload::{
    extract_android_ota_payload_bytes,
    update_engine::{
        DeltaArchiveManifest, Extent, InstallOperation, PartitionInfo, PartitionUpdate,
        install_operation::Type as OpType,
    },
};
use dumprs::utils::oem_postprocess::{rename_oem_images, strip_signed_image_header};
use dumprs::utils::raw_image::get_raw_image;
use std::fs;
use std::io::Write;

use prost::Message;
use std::path::Path;

const TRANSFER_LIST: &str = "2\n1\n0\n0\nnew 2,0,1\n";

/// 4 KiB of a recognizable repeating pattern: one block referenced by the
/// transfer list above.
fn payload() -> Vec<u8> {
    (0..4096).map(|i| (i % 251) as u8).collect()
}

fn xz_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(data).expect("xz input written");
    encoder.finish().expect("xz stream finished")
}

/// Regression: a `system.new.dat.xz` OTA must be decoded and converted by
/// sdat2img, instead of being ignored as an unknown image name.
#[test]
fn get_raw_image_decodes_xz_compressed_sdat() {
    let root = temp_dir::temp_dir();
    let files = root.join("files");
    fs::create_dir_all(&files).expect("files dir created");

    let raw = payload();
    fs::write(files.join("system.transfer.list"), TRANSFER_LIST).expect("transfer list written");
    fs::write(files.join("system.new.dat.xz"), xz_compress(&raw)).expect("xz dat written");

    let output = root.join("system.img");
    let found = get_raw_image("system", &files, &output).expect("get_raw_image succeeded");

    assert!(found, "xz-compressed sdat must be recognized");
    assert_eq!(
        fs::read(&output).expect("output image readable"),
        raw,
        "decoded image must match the original payload"
    );
    assert!(
        !files.join("system.new.dat.xz").exists(),
        "consumed compressed input should be removed"
    );
}

/// Regression: the existing brotli path must keep working after adding the
/// XZ branch, including the streaming `.dat.br` + `.transfer.list` case.
#[test]
fn get_raw_image_still_decodes_brotli_sdat() {
    let root = temp_dir::temp_dir();
    let files = root.join("files");
    fs::create_dir_all(&files).expect("files dir created");

    let raw = payload();
    let mut compressed = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
        writer.write_all(&raw).expect("brotli input written");
    }
    fs::write(files.join("system.transfer.list"), TRANSFER_LIST).expect("transfer list written");
    fs::write(files.join("system.new.dat.br"), compressed).expect("brotli dat written");

    let output = Path::new(&root).join("system.img");
    let found = get_raw_image("system", &files, &output).expect("get_raw_image succeeded");

    assert!(found, "brotli-compressed sdat must still be recognized");
    assert_eq!(fs::read(&output).expect("output readable"), raw);
}

/// Body used by the signed-image header tests; distinct from the header fill
/// so a wrong offset is immediately visible.
fn signed_payload() -> Vec<u8> {
    (0..4096).map(|i| (i % 251) as u8).collect()
}

/// Regression: the SSSS offset is a little-endian 32-bit value built from two
/// 16-bit halves at bytes 60..64. Swapping the halves or the byte order yields
/// a truncated or corrupt image.
#[test]
fn strips_ssss_header_using_the_60_to_63_offset() {
    let payload = signed_payload();
    let offset = u32::try_from(payload.len()).expect("payload fits u32");
    let mut image = vec![0u8; 0x80000];
    image[..4].copy_from_slice(b"SSSS");
    image[60..62].copy_from_slice(&(offset as u16).to_le_bytes());
    image[62..64].copy_from_slice(&((offset >> 16) as u16).to_le_bytes());
    image.extend_from_slice(&payload);

    let stripped = strip_signed_image_header(&image).expect("SSSS header parsed");
    assert_eq!(stripped, payload);
}

/// Regression: DumprX strips `0x4040` bytes for BFBF and for any other unknown
/// signed-image magic. A different skip length shifts every byte of the image.
#[test]
fn strips_bfbf_and_unknown_headers_by_0x4040() {
    let payload = signed_payload();

    let mut bfbf = vec![0u8; 0x4040];
    bfbf[..4].copy_from_slice(b"BFBF");
    bfbf.extend_from_slice(&payload);
    assert_eq!(
        strip_signed_image_header(&bfbf).expect("BFBF header parsed"),
        payload
    );

    let mut unknown = vec![0u8; 0x4040];
    unknown[..4].copy_from_slice(b"XXXX");
    unknown.extend_from_slice(&payload);
    assert_eq!(
        strip_signed_image_header(&unknown).expect("unknown header parsed"),
        payload
    );
}

/// Regression: renamed OEM partitions must end up with their canonical
/// `.img` name, otherwise the partition lookup later in the pipeline misses.
#[test]
fn renames_oem_partition_variants() {
    let root = temp_dir::temp_dir();
    let names = [
        "system_image.emmc.img",
        "vendor_new.img",
        "boot.img.ext4",
        "product-p",
        "recovery.bin",
        "vbmeta-sign.img",
        "untouched.img",
    ];
    for name in names {
        fs::write(root.join(name), name).expect("fixture written");
    }

    rename_oem_images(&root).expect("renaming succeeded");

    let expected = [
        "system.img",
        "vendor.img",
        "boot.img",
        "product.img",
        "recovery.img",
        "vbmeta.img",
        "untouched.img",
    ];
    for name in expected {
        assert!(root.join(name).is_file(), "missing renamed file: {name}");
    }
}

fn extent(start: u64, num: u64) -> Extent {
    Extent {
        start_block: Some(start),
        num_blocks: Some(num),
    }
}

fn operation(
    kind: OpType,
    src: Vec<Extent>,
    dst: Vec<Extent>,
    data_offset: u64,
    data_length: u64,
) -> InstallOperation {
    InstallOperation {
        r#type: kind as i32,
        data_offset: Some(data_offset),
        data_length: Some(data_length),
        src_extents: src,
        src_length: Some(4096),
        dst_extents: dst,
        dst_length: Some(4096),
        data_sha256_hash: None,
        src_sha256_hash: None,
    }
}

/// Regression: an incremental OTA containing MOVE and SOURCE_COPY must not
/// `bail!` as an unhandled operation. Operations are ordered: the first block
/// is written by REPLACE, then moved and copied into the following blocks.
#[test]
fn payload_applies_move_and_source_copy_in_order() {
    let root = temp_dir::temp_dir();
    let output = root.join("out");
    fs::create_dir_all(&output).expect("output dir created");

    let block = [0x5au8; 4096];
    let manifest = DeltaArchiveManifest {
        partitions: vec![PartitionUpdate {
            partition_name: "system".to_string(),
            new_partition_info: Some(PartitionInfo {
                size: Some(3 * 4096),
                hash: None,
            }),
            operations: vec![
                operation(OpType::Replace, vec![], vec![extent(0, 1)], 0, 4096),
                operation(OpType::Move, vec![extent(0, 1)], vec![extent(1, 1)], 0, 0),
                operation(
                    OpType::SourceCopy,
                    vec![extent(1, 1)],
                    vec![extent(2, 1)],
                    0,
                    0,
                ),
            ],
            ..Default::default()
        }],
        ..Default::default()
    };
    let manifest_bytes = manifest.encode_to_vec();

    let mut payload = Vec::new();
    payload.extend_from_slice(b"CrAU");
    payload.extend_from_slice(&2u64.to_be_bytes());
    payload.extend_from_slice(&(manifest_bytes.len() as u64).to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&manifest_bytes);
    payload.extend_from_slice(&block);

    extract_android_ota_payload_bytes(&payload, &output).expect("payload extracted");

    let image = fs::read(output.join("system.img")).expect("partition image written");
    assert_eq!(image.len(), 3 * 4096);
    assert_eq!(&image[..4096], &block, "REPLACE block");
    assert_eq!(&image[4096..8192], &block, "MOVE block");
    assert_eq!(&image[8192..], &block, "SOURCE_COPY block");
}
