use dumprs::formats::bootimg::extract_bootimg;
use dumprs::formats::kdz::parse_gpt_entries;
use dumprs::formats::liblp::lpunpack;
use dumprs::formats::payload::PayloadHeader;
use dumprs::formats::sdat2img::{sdat2img, sdat2img_from_reader};
use dumprs::formats::sparse::{is_sparse_file, unsparse_file};
use dumprs::utils::files::{
    flatten_dir, get_recursive_files_list, hardlink_or_copy, move_or_copy, rmtree_recursive,
    sort_files,
};
use dumprs::utils::partitions::{
    correct_ab_filenames, fix_aliases, get_partition_name, get_partition_names,
    get_partition_names_with_ab, get_partition_names_with_alias, get_partition_type,
    PartitionType,
};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

#[test]
fn test_partitions_metadata() {
    assert_eq!(get_partition_name("boot-verified"), "boot");
    assert_eq!(get_partition_name("dtbo-verified"), "dtbo");
    assert_eq!(get_partition_name("NON-HLOS"), "modem");
    assert_eq!(get_partition_name("system"), "system");

    assert_eq!(get_partition_type("system"), Some(PartitionType::Filesystem));
    assert_eq!(get_partition_type("boot"), Some(PartitionType::Bootimage));
    assert_eq!(get_partition_type("dtbo"), Some(PartitionType::Raw));
    assert_eq!(get_partition_type("super"), Some(PartitionType::Logical));
    assert_eq!(get_partition_type("nonexistent"), None);

    let all_names = get_partition_names();
    assert!(all_names.contains(&"system"));
    assert!(all_names.contains(&"vendor"));
    assert!(all_names.contains(&"boot"));

    let with_aliases = get_partition_names_with_alias();
    assert!(with_aliases.iter().any(|p| p == "NON-HLOS"));

    let with_ab = get_partition_names_with_ab();
    assert!(with_ab.iter().any(|p| p == "system_a"));
    assert!(with_ab.iter().any(|p| p == "system_b"));
}

#[test]
fn test_sdat2img_conversion() {
    let temp_dir = std::env::temp_dir().join("dumprs_test_sdat2img");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let transfer_list_path = temp_dir.join("system.transfer.list");
    let new_data_path = temp_dir.join("system.new.dat");
    let output_img_path = temp_dir.join("system.img");

    // Version 4 transfer list:
    let transfer_content = "4\n2\n0\n0\nnew 4,0,1,2,3\n";
    fs::write(&transfer_list_path, transfer_content).unwrap();

    let block1 = vec![0xAAu8; 4096];
    let block2 = vec![0xBBu8; 4096];
    let mut data = Vec::new();
    data.extend_from_slice(&block1);
    data.extend_from_slice(&block2);
    fs::write(&new_data_path, data).unwrap();

    sdat2img(&transfer_list_path, &new_data_path, &output_img_path).unwrap();

    let out_bytes = fs::read(&output_img_path).unwrap();
    assert_eq!(out_bytes.len(), 12288);
    assert_eq!(&out_bytes[0..4096], &block1[..]);
    assert_eq!(&out_bytes[4096..8192], &[0u8; 4096][..]);
    assert_eq!(&out_bytes[8192..12288], &block2[..]);

    let stream_out_path = temp_dir.join("system_stream.img");
    let mut reader = Cursor::new(fs::read(&new_data_path).unwrap());
    sdat2img_from_reader(&transfer_list_path, &mut reader, &stream_out_path).unwrap();
    assert_eq!(fs::read(&stream_out_path).unwrap(), out_bytes);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sparse_image_unsparse() {
    let temp_dir = std::env::temp_dir().join("dumprs_test_sparse");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let sparse_path = temp_dir.join("test.sparse.img");
    let raw_path = temp_dir.join("test.raw.img");

    // Construct valid Android sparse image:
    // Header (28 bytes):
    // magic: 0xed26ff3a
    // major: 1, minor: 0
    // file_hdr_sz: 28, chunk_hdr_sz: 12
    // blk_sz: 4096
    // total_blks: 1, total_chunks: 1, image_checksum: 0
    let mut sparse_bytes = Vec::new();
    sparse_bytes.extend_from_slice(&0xed26_ff3au32.to_le_bytes());
    sparse_bytes.extend_from_slice(&1u16.to_le_bytes());
    sparse_bytes.extend_from_slice(&0u16.to_le_bytes());
    sparse_bytes.extend_from_slice(&28u16.to_le_bytes());
    sparse_bytes.extend_from_slice(&12u16.to_le_bytes());
    sparse_bytes.extend_from_slice(&4096u32.to_le_bytes());
    sparse_bytes.extend_from_slice(&1u32.to_le_bytes());
    sparse_bytes.extend_from_slice(&1u32.to_le_bytes());
    sparse_bytes.extend_from_slice(&0u32.to_le_bytes());

    // Chunk header (12 bytes):
    // chunk_type: 0xcac1 (RAW)
    // reserved: 0
    // chunk_sz: 1 (blocks)
    // total_sz: 12 + 4096 = 4108
    sparse_bytes.extend_from_slice(&0xcac1u16.to_le_bytes());
    sparse_bytes.extend_from_slice(&0u16.to_le_bytes());
    sparse_bytes.extend_from_slice(&1u32.to_le_bytes());
    sparse_bytes.extend_from_slice(&4108u32.to_le_bytes());

    // Chunk payload (4096 bytes)
    let payload = vec![0x42u8; 4096];
    sparse_bytes.extend_from_slice(&payload);

    fs::write(&sparse_path, &sparse_bytes).unwrap();

    assert!(is_sparse_file(&sparse_path));

    let unsparsed = unsparse_file(&sparse_path, &raw_path).unwrap();
    assert!(unsparsed);
    assert_eq!(fs::read(&raw_path).unwrap(), payload);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_files_utils() {
    let temp_dir = std::env::temp_dir().join("dumprs_test_files");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("a/b/c")).unwrap();

    fs::write(temp_dir.join("root.txt"), "root").unwrap();
    fs::write(temp_dir.join("a/b/c/nested.txt"), "nested").unwrap();

    let files_rel = get_recursive_files_list(&temp_dir, true);
    assert_eq!(files_rel.len(), 2);

    flatten_dir(&temp_dir).unwrap();
    assert!(temp_dir.join("root.txt").exists());
    assert!(temp_dir.join("nested.txt").exists());

    let mut list = vec![
        PathBuf::from("vendor/build.prop"),
        PathBuf::from("system/build.prop"),
        PathBuf::from("all_files.txt"),
    ];
    sort_files(&mut list);
    assert_eq!(
        list,
        vec![
            PathBuf::from("all_files.txt"),
            PathBuf::from("system/build.prop"),
            PathBuf::from("vendor/build.prop")
        ]
    );
    let src_move = temp_dir.join("root.txt");
    let dst_move = temp_dir.join("moved.txt");
    move_or_copy(&src_move, &dst_move).unwrap();
    assert!(!src_move.exists());
    assert_eq!(fs::read_to_string(&dst_move).unwrap(), "root");

    let dst_link = temp_dir.join("linked.txt");
    hardlink_or_copy(&dst_move, &dst_link).unwrap();
    assert!(dst_move.exists());
    assert_eq!(fs::read_to_string(&dst_link).unwrap(), "root");

    rmtree_recursive(&temp_dir).unwrap();
    assert!(!temp_dir.exists());
}

#[test]
fn test_ab_and_alias_normalization() {
    let temp_dir = std::env::temp_dir().join("dumprs_test_ab_alias");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // Alias test: NON-HLOS.img -> modem.img
    fs::write(temp_dir.join("NON-HLOS.img"), "modem data").unwrap();
    fix_aliases(&temp_dir).unwrap();
    assert!(temp_dir.join("modem.img").exists());
    assert!(!temp_dir.join("NON-HLOS.img").exists());

    // A/B test: system_a.img -> system.img
    fs::write(temp_dir.join("system_a.img"), "system data").unwrap();
    correct_ab_filenames(&temp_dir).unwrap();
    assert!(temp_dir.join("system.img").exists());
    assert!(!temp_dir.join("system_a.img").exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_payload_header_decode() {
    let mut data = Vec::new();
    data.extend_from_slice(b"CrAU");
    data.extend_from_slice(&2u64.to_be_bytes());
    data.extend_from_slice(&100u64.to_be_bytes());
    data.extend_from_slice(&32u32.to_be_bytes());

    let mut cursor = Cursor::new(data);
    let header = PayloadHeader::read_from(&mut cursor).unwrap();
    assert_eq!(header.version, 2);
    assert_eq!(header.manifest_len, 100);
    assert_eq!(header.metadata_signature_len, 32);
    assert_eq!(header.header_size, 24);
}

#[test]
fn test_bootimg_header_extraction() {
    let temp_dir = std::env::temp_dir().join("dumprs_test_bootimg");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let boot_img_path = temp_dir.join("boot.img");
    let out_dir = temp_dir.join("boot_out");

    let page_size = 2048u32;
    let kernel_size = 10u32;
    let ramdisk_size = 15u32;

    let mut header = Vec::new();
    header.extend_from_slice(b"ANDROID!");
    header.extend_from_slice(&kernel_size.to_le_bytes());
    header.extend_from_slice(&0x10008000u32.to_le_bytes());
    header.extend_from_slice(&ramdisk_size.to_le_bytes());
    header.extend_from_slice(&0x11000000u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0x10000100u32.to_le_bytes());
    header.extend_from_slice(&page_size.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&[0u8; 16]);
    header.extend_from_slice(&[0u8; 512]);
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&[0u8; 1024]);

    header.resize(page_size as usize, 0);

    let mut kernel_data = b"FAKEKERNEL".to_vec();
    kernel_data.resize(page_size as usize, 0);

    let mut ramdisk_data = b"FAKERAMDISKDATA".to_vec();
    ramdisk_data.resize(page_size as usize, 0);

    let mut img_data = Vec::new();
    img_data.extend_from_slice(&header);
    img_data.extend_from_slice(&kernel_data);
    img_data.extend_from_slice(&ramdisk_data);

    fs::write(&boot_img_path, img_data).unwrap();

    extract_bootimg(&boot_img_path, &out_dir).unwrap();

    assert!(out_dir.join("info.txt").exists());
    assert_eq!(fs::read(out_dir.join("kernel")).unwrap(), b"FAKEKERNEL");
    assert_eq!(fs::read(out_dir.join("ramdisk.img")).unwrap(), b"FAKERAMDISKDATA");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_liblp_super_unpacking() {
    let temp_dir = std::env::temp_dir().join("dumprs_test_liblp");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let super_img_path = temp_dir.join("super.img");
    let out_dir = temp_dir.join("super_out");

    let mut super_bytes = vec![0u8; 32768]; // 32 KB image

    // Geometry at offset 4096:
    // magic: 0x616c_4467 (u32)
    // struct_size: 4096 (u32)
    // checksum: 32 bytes
    // metadata_max_size: 4096 (u32)
    // metadata_slot_count: 2 (u32)
    // logical_block_size: 4096 (u32)
    let geom_offset = 4096;
    super_bytes[geom_offset..geom_offset + 4].copy_from_slice(&0x616c_4467u32.to_le_bytes());
    super_bytes[geom_offset + 4..geom_offset + 8].copy_from_slice(&4096u32.to_le_bytes());
    super_bytes[geom_offset + 40..geom_offset + 44].copy_from_slice(&4096u32.to_le_bytes());
    super_bytes[geom_offset + 44..geom_offset + 48].copy_from_slice(&2u32.to_le_bytes());
    super_bytes[geom_offset + 48..geom_offset + 52].copy_from_slice(&4096u32.to_le_bytes());

    // Header at offset 8192:
    // magic: 0x414c_5030 (u32)
    // major: 10 (u16), minor: 0 (u16)
    // header_size: 128 (u32)
    // header_checksum: 32 bytes
    // tables_size: 256 (u32)
    // tables_checksum: 32 bytes
    // partitions descriptor: offset: 0, num_entries: 1, entry_size: 52 (3 x u32 = 12 bytes)
    // extents descriptor: offset: 52, num_entries: 1, entry_size: 24 (3 x u32 = 12 bytes)
    let hdr_offset = 12288;
    super_bytes[hdr_offset..hdr_offset + 4].copy_from_slice(&0x414c_5030u32.to_le_bytes());
    super_bytes[hdr_offset + 4..hdr_offset + 6].copy_from_slice(&10u16.to_le_bytes());
    super_bytes[hdr_offset + 6..hdr_offset + 8].copy_from_slice(&0u16.to_le_bytes());
    super_bytes[hdr_offset + 8..hdr_offset + 12].copy_from_slice(&128u32.to_le_bytes());
    super_bytes[hdr_offset + 44..hdr_offset + 48].copy_from_slice(&256u32.to_le_bytes());

    // Partitions descriptor at hdr_offset + 80:
    let desc_offset = hdr_offset + 80;
    super_bytes[desc_offset..desc_offset + 4].copy_from_slice(&0u32.to_le_bytes()); // offset 0
    super_bytes[desc_offset + 4..desc_offset + 8].copy_from_slice(&1u32.to_le_bytes()); // num_entries 1
    super_bytes[desc_offset + 8..desc_offset + 12].copy_from_slice(&52u32.to_le_bytes()); // entry_size 52

    // Extents descriptor at hdr_offset + 92:
    let ext_desc_offset = hdr_offset + 92;
    super_bytes[ext_desc_offset..ext_desc_offset + 4].copy_from_slice(&52u32.to_le_bytes()); // offset 52
    super_bytes[ext_desc_offset + 4..ext_desc_offset + 8].copy_from_slice(&1u32.to_le_bytes()); // num_entries 1
    super_bytes[ext_desc_offset + 8..ext_desc_offset + 12].copy_from_slice(&24u32.to_le_bytes()); // entry_size 24

    // Tables data starts at hdr_offset + 128 = 8320:
    let tables_start = hdr_offset + 128;
    // Partition entry 0:
    // name: "vendor" (36 bytes)
    // attributes: 0 (u32)
    // first_extent_index: 0 (u32)
    // num_extents: 1 (u32)
    // group_index: 0 (u32)
    super_bytes[tables_start..tables_start + 6].copy_from_slice(b"vendor");
    super_bytes[tables_start + 40..tables_start + 44].copy_from_slice(&0u32.to_le_bytes()); // first extent 0
    super_bytes[tables_start + 44..tables_start + 48].copy_from_slice(&1u32.to_le_bytes()); // num extents 1

    // Extent entry 0 at tables_start + 52:
    // num_sectors: 2 (u64) -> 1024 bytes
    // target_type: 0 (u32 LINEAR)
    // target_data: 24 (u64) -> sector 24 * 512 = byte 12288
    // target_source: 0 (u32)
    let ext_start = tables_start + 52;
    super_bytes[ext_start..ext_start + 8].copy_from_slice(&2u64.to_le_bytes());
    super_bytes[ext_start + 8..ext_start + 12].copy_from_slice(&0u32.to_le_bytes());
    super_bytes[ext_start + 12..ext_start + 20].copy_from_slice(&36u64.to_le_bytes());
    super_bytes[ext_start + 20..ext_start + 24].copy_from_slice(&0u32.to_le_bytes());

    // Payload data at sector 36 = byte 18432 (1024 bytes):
    let payload_offset = 36 * 512;
    super_bytes[payload_offset..payload_offset + 8].copy_from_slice(b"VENDOROK");

    fs::write(&super_img_path, &super_bytes).unwrap();

    lpunpack(&super_img_path, &out_dir).unwrap();

    assert!(out_dir.join("vendor.img").exists());
    let vendor_data = fs::read(out_dir.join("vendor.img")).unwrap();
    assert_eq!(vendor_data.len(), 1024);
    assert_eq!(&vendor_data[0..8], b"VENDOROK");

    // Also verify direct sparse super.img unpacking without intermediate unsparse file:
    // Chunk 0: DONT_CARE 1 block (4096 bytes), Chunk 1: RAW 7 blocks (28672 bytes)
    let sparse_super_path = temp_dir.join("super_sparse.img");
    let sparse_out_dir = temp_dir.join("super_sparse_out");
    let mut sparse_super = Vec::new();
    sparse_super.extend_from_slice(&0xed26_ff3au32.to_le_bytes());
    sparse_super.extend_from_slice(&1u16.to_le_bytes());
    sparse_super.extend_from_slice(&0u16.to_le_bytes());
    sparse_super.extend_from_slice(&28u16.to_le_bytes());
    sparse_super.extend_from_slice(&12u16.to_le_bytes());
    sparse_super.extend_from_slice(&4096u32.to_le_bytes());
    sparse_super.extend_from_slice(&8u32.to_le_bytes());
    sparse_super.extend_from_slice(&2u32.to_le_bytes());
    sparse_super.extend_from_slice(&0u32.to_le_bytes());
    // Chunk 0: DONT_CARE 1 block
    sparse_super.extend_from_slice(&0xcac3u16.to_le_bytes());
    sparse_super.extend_from_slice(&0u16.to_le_bytes());
    sparse_super.extend_from_slice(&1u32.to_le_bytes());
    sparse_super.extend_from_slice(&12u32.to_le_bytes());
    // Chunk 1: RAW 7 blocks
    sparse_super.extend_from_slice(&0xcac1u16.to_le_bytes());
    sparse_super.extend_from_slice(&0u16.to_le_bytes());
    sparse_super.extend_from_slice(&7u32.to_le_bytes());
    sparse_super.extend_from_slice(&(12u32 + 7 * 4096).to_le_bytes());
    sparse_super.extend_from_slice(&super_bytes[4096..]);
    fs::write(&sparse_super_path, &sparse_super).unwrap();

    lpunpack(&sparse_super_path, &sparse_out_dir).unwrap();
    let sparse_vendor = fs::read(sparse_out_dir.join("vendor.img")).unwrap();
    assert_eq!(sparse_vendor, vendor_data);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_kdz_gpt_parsing() {
    let mut data = vec![0u8; 8192];
    // Put EFI PART at offset 512
    let gpt_off = 512;
    data[gpt_off..gpt_off + 8].copy_from_slice(b"EFI PART");
    // entry_lba = 2 (byte 1024)
    data[gpt_off + 72..gpt_off + 80].copy_from_slice(&2u64.to_le_bytes());
    // num_entries = 2
    data[gpt_off + 80..gpt_off + 84].copy_from_slice(&2u32.to_le_bytes());
    // entry_size = 128
    data[gpt_off + 84..gpt_off + 88].copy_from_slice(&128u32.to_le_bytes());

    // Entry 0 at byte 1024:
    let e0 = 1024;
    data[e0..e0 + 16].copy_from_slice(&[0x11u8; 16]); // non-zero type guid
    data[e0 + 32..e0 + 40].copy_from_slice(&100u64.to_le_bytes()); // start_lba = 100
    data[e0 + 40..e0 + 48].copy_from_slice(&200u64.to_le_bytes()); // end_lba = 200
    // Name: "system" in UTF-16LE
    let sys_u16 = [b's' as u16, b'y' as u16, b's' as u16, b't' as u16, b'e' as u16, b'm' as u16];
    for (i, &c) in sys_u16.iter().enumerate() {
        data[e0 + 56 + i * 2..e0 + 56 + i * 2 + 2].copy_from_slice(&c.to_le_bytes());
    }

    let partitions = parse_gpt_entries(&data);
    assert_eq!(partitions.len(), 1);
    assert_eq!(partitions[0].name, "system");
    assert_eq!(partitions[0].start_lba, 100);
    assert_eq!(partitions[0].end_lba, 200);
}

#[test]
fn test_bootimg_ramdisk_cpio_symlink() {
    let temp_dir = std::env::temp_dir().join("dumprs_test_boot_symlink");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let boot_img_path = temp_dir.join("boot.img");
    let out_dir = temp_dir.join("boot_out");

    let page_size = 2048u32;
    let kernel_size = 8u32;

    // Create a mock CPIO payload with 1 symlink: "bin/sh" -> "toybox"
    // CPIO newc header: 110 bytes
    // magic: 070701
    // mode at 14..22: 0120777 (octal 0120777 = hex a1ff)
    // filesize at 54..62: 6 (bytes for "toybox")
    // namesize at 94..102: 7 (bytes for "bin/sh\0")
    let mut cpio = Vec::new();
    let mut hdr = format!(
        "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        1, // ino
        0o120777, // mode (symlink)
        0, 0, 1, 0,
        6, // filesize
        0, 0, 0, 0,
        7, // namesize
        0  // check
    ).into_bytes();
    hdr.resize(110, b'0');
    cpio.extend_from_slice(&hdr);
    cpio.extend_from_slice(b"bin/sh\0");
    // pad to 4 bytes: (110 + 7) = 117 -> pad 3 bytes
    cpio.extend_from_slice(&[0, 0, 0]);
    cpio.extend_from_slice(b"toybox");
    // pad filesize 6 to 4 bytes: 2 bytes pad
    cpio.extend_from_slice(&[0, 0]);

    // TRAILER!!!
    let mut trailer_hdr = format!(
        "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0
    ).into_bytes();
    trailer_hdr.resize(110, b'0');
    cpio.extend_from_slice(&trailer_hdr);
    cpio.extend_from_slice(b"TRAILER!!!\0");
    // (110 + 11) = 121 -> pad 3 bytes
    cpio.extend_from_slice(&[0, 0, 0]);

    let ramdisk_size = cpio.len() as u32;

    let mut header = Vec::new();
    header.extend_from_slice(b"ANDROID!");
    header.extend_from_slice(&kernel_size.to_le_bytes());
    header.extend_from_slice(&0x10008000u32.to_le_bytes());
    header.extend_from_slice(&ramdisk_size.to_le_bytes());
    header.extend_from_slice(&0x11000000u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0x10000100u32.to_le_bytes());
    header.extend_from_slice(&page_size.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&[0u8; 16]);
    header.extend_from_slice(&[0u8; 512]);
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&[0u8; 1024]);
    header.resize(page_size as usize, 0);

    let mut kernel_data = b"KERNELOK".to_vec();
    kernel_data.resize(page_size as usize, 0);

    cpio.resize(((ramdisk_size as usize + page_size as usize - 1) / page_size as usize) * page_size as usize, 0);

    let mut img_data = Vec::new();
    img_data.extend_from_slice(&header);
    img_data.extend_from_slice(&kernel_data);
    img_data.extend_from_slice(&cpio);

    fs::write(&boot_img_path, img_data).unwrap();

    extract_bootimg(&boot_img_path, &out_dir).unwrap();

    let symlink_path = out_dir.join("ramdisk/bin/sh");
    assert!(symlink_path.exists() || symlink_path.is_symlink());
    #[cfg(unix)]
    {
        let target = fs::read_link(&symlink_path).unwrap();
        assert_eq!(target.to_str().unwrap(), "toybox");
    }

    let _ = fs::remove_dir_all(&temp_dir);
}
