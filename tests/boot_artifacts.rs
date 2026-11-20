#[path = "common/builders.rs"]
mod builders;
#[path = "common/temp_dir.rs"]
mod temp_dir;

use dumprs::formats::boot_artifacts::kallsyms::{
    Symbol, decode_names, find_kallsyms, render_kallsyms,
};
use dumprs::formats::boot_artifacts::vmlinux_elf::write_elf;
use dumprs::formats::boot_artifacts::{
    avb::render_avb_info,
    dtb::{dtb_to_dts, split_dtb},
    generate,
    ikconfig::extract_ikconfig,
};
use dumprs::formats::bootimg::decode_os_version;
use object::{Object as _, ObjectSection as _, ObjectSymbol as _};
use std::fs;

#[test]
fn avb_info_matches_avbtool_layout() {
    let image = builders::vbmeta_with_footer();
    let actual = render_avb_info(&image, image.len() as u64).expect("vbmeta must parse");

    // Hand-written from the constants in tests/common/builders.rs and the
    // avbtool info_image format, not from the implementation.
    let expected = concat!(
        "Footer version:           1.1\n",
        "Image size:               576 bytes\n",
        "Original image size:      4096 bytes\n",
        "VBMeta offset:            0\n",
        "VBMeta size:              512 bytes\n",
        "--\n",
        "Minimum libavb version:   1.0\n",
        "Header Block:             256 bytes\n",
        "Authentication Block:     0 bytes\n",
        "Auxiliary Block:          256 bytes\n",
        "Algorithm:                SHA256_RSA2048\n",
        "Rollback Index:           7\n",
        "Flags:                    0\n",
        "Rollback Index Location:  3\n",
        "Release String:           'avbtool test'\n",
        "Descriptors:\n",
        "    Prop: com.android.build.system.os_version -> '13'\n",
        "    Hash descriptor:\n",
        "      Image Size:            1234 bytes\n",
        "      Hash Algorithm:        sha256\n",
        "      Partition Name:        system\n",
        "      Salt:                  00\n",
        "      Digest:                11\n",
        "      Flags:                 0\n",
        "    Kernel Cmdline descriptor:\n",
        "      Flags:                 0\n",
        "      Kernel Cmdline:        'root=/dev/dm-0'\n",
    );

    assert_eq!(actual, expected);
}

#[test]
fn ikconfig_decodes_supported_codecs() {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    use xz2::write::XzEncoder;

    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    gzip.write_all(builders::KERNEL_CONFIG).unwrap();
    let gzip = gzip.finish().unwrap();
    let mut xz = XzEncoder::new(Vec::new(), 6);
    xz.write_all(builders::KERNEL_CONFIG).unwrap();
    let xz = xz.finish().unwrap();

    for (name, compressed) in [("gzip", gzip), ("xz", xz)] {
        let mut data = b"IKCFG_ST".to_vec();
        data.extend_from_slice(&compressed);
        data.extend_from_slice(b"IKCFG_ED");
        let decoded = extract_ikconfig(&data)
            .expect("IKconfig must decode")
            .expect("IKconfig must be present");
        assert_eq!(decoded, builders::KERNEL_CONFIG, "codec: {name}");
    }

    assert_eq!(extract_ikconfig(b"no config here").unwrap(), None);
    assert_eq!(extract_ikconfig(b"IKCFG_ST").unwrap(), None);
}

#[test]
fn split_dtb_handles_concatenated_blobs() {
    let first = builders::dtb("first");
    let second = builders::dtb("second");
    let mut combined = first.clone();
    combined.extend_from_slice(&second);

    let parts = split_dtb(&combined).expect("both blobs must be found");
    assert_eq!(parts.len(), 2, "two concatenated DTBs");
    assert_eq!(parts[0], first.as_slice());
    assert_eq!(parts[1], second.as_slice());

    assert_eq!(split_dtb(b"garbage").unwrap(), Vec::<&[u8]>::new());
}

#[test]
fn dtb_to_dts_renders_node_and_property() {
    let dtb = builders::dtb("uart0");
    let dts = dtb_to_dts(&dtb).expect("DTB must render");
    assert!(
        dts.contains("uart0"),
        "DTS must contain the node name: {dts}"
    );
    assert!(
        dts.contains("compatible"),
        "DTS must contain the property: {dts}"
    );
    assert!(
        dts.contains("dumprs,test"),
        "DTS must contain the value: {dts}"
    );
}

#[test]
fn decode_os_version_table_driven() {
    // Values worked out by hand from unpackboot.sh:97-103.
    // 0x18000182 is the field of the Infinix X670 boot.img in the test corpus:
    // version = 0x18000182 >> 11 = 0x30000 -> 12.0.0, patch = 0x182 -> 2024:2.
    let cases = [
        (0x1800_0182u32, "12.0.0", "2024:2"),
        (0x0000_0182, "0.0.0", "2024:2"),
        (0x0000_0000, "", ""),
    ];
    for (raw, version, patch) in cases {
        let (v, p) = decode_os_version(raw);
        assert_eq!((v.as_str(), p.as_str()), (version, patch), "raw: {raw:#x}");
    }
}

#[test]
fn generate_writes_all_phase_one_artifacts() {
    let dir = temp_dir::temp_dir();
    let image = dir.join("boot.img");
    fs::write(&image, builders::vbmeta_with_footer()).expect("boot image written");

    let out = dir.join("boot");
    fs::create_dir_all(&out).expect("partition dir created");
    fs::write(out.join("kernel"), builders::ikconfig_gzip()).expect("kernel written");
    let mut dtbs = builders::dtb("first");
    dtbs.extend_from_slice(&builders::dtb("second"));
    fs::write(out.join("dtb.img"), dtbs).expect("dtb.img written");

    generate(&image, &out, "boot").expect("generation must succeed");

    let avb = fs::read_to_string(out.join("avb.txt")).expect("avb.txt written");
    assert!(avb.starts_with("Footer version:           1.1\n"));
    assert!(avb.contains("Hash descriptor:"));

    let config = fs::read(out.join("ikconfig")).expect("ikconfig written");
    assert_eq!(config, builders::KERNEL_CONFIG);

    let dtb_dir = out.join("dtb");
    assert_eq!(
        fs::read_dir(&dtb_dir).unwrap().count(),
        2,
        "dtb/ has 2 files"
    );
    let dts_dir = out.join("dts");
    assert_eq!(
        fs::read_dir(&dts_dir).unwrap().count(),
        2,
        "dts/ has 2 files"
    );
    let rendered = fs::read_to_string(dts_dir.join("0.dts")).expect("0.dts written");
    assert!(rendered.contains("first"));
}

#[test]
fn kallsyms_decodes_token_compressed_names() {
    let tokens = builders::kallsyms_token_table();
    let mut names = Vec::new();
    for name in ["T sym0000", "t local_func"] {
        names.push(name.len() as u8);
        for byte in name.bytes() {
            names.push(byte);
        }
    }
    let decoded = decode_names(&names, &tokens, 2).expect("names must decode");
    assert_eq!(decoded, vec!["T sym0000", "t local_func"]);
}

#[test]
fn kallsyms_find_on_synthetic_kernel() {
    let kernel = builders::synthetic_kernel();
    let symbols = find_kallsyms(&kernel).expect("kallsyms must be found");
    let expected_names = builders::kallsyms_names();
    assert_eq!(symbols.len(), expected_names.len());
    assert_eq!(symbols[0].name, expected_names[0][1..]);
    assert_eq!(symbols[0].kind, 'T');
    assert_eq!(symbols[0].address, builders::KALLSYMS_BASE);
    assert_eq!(symbols[1023].address, builders::KALLSYMS_BASE + 1023 * 4);
}

#[test]
fn kallsyms_renders_proc_format() {
    let symbols = vec![
        Symbol {
            address: 0xffff_0000_8000_1000,
            kind: 'T',
            name: "do_initcall".into(),
        },
        Symbol {
            address: 0xffff_0000_8000_2000,
            kind: 'd',
            name: "my_var".into(),
        },
    ];
    assert_eq!(
        render_kallsyms(&symbols),
        "ffff000080001000 T do_initcall\nffff000080002000 d my_var\n"
    );
}

#[test]
fn elf_carries_recovered_symbols() {
    let symbols = vec![Symbol {
        address: 0xffff_0000_8000_1000,
        kind: 'T',
        name: "do_initcall".into(),
    }];
    let dir = temp_dir::temp_dir();
    let output = dir.join("boot.elf");
    write_elf(&symbols, b"raw kernel bytes", &output).expect("ELF must be written");

    let bytes = fs::read(&output).expect("read ELF");
    let file = object::read::File::parse(&*bytes).expect("ELF must parse");
    let names: Vec<String> = file
        .symbols()
        .filter_map(|symbol| symbol.name().ok().map(str::to_string))
        .collect();
    assert!(names.iter().any(|name| name == "do_initcall"), "{names:?}");
}

#[test]
fn generate_writes_kallsyms_and_elf_from_kernel() {
    let dir = temp_dir::temp_dir();
    let image = dir.join("boot.img");
    fs::write(&image, builders::vbmeta_with_footer()).expect("boot image written");
    let out = dir.join("boot");
    fs::create_dir_all(&out).expect("partition dir created");
    let kernel = builders::synthetic_kernel();
    fs::write(out.join("kernel"), &kernel).expect("kernel written");

    generate(&image, &out, "boot").expect("generation must succeed");

    let kallsyms = fs::read_to_string(out.join("kernel_kallsyms.txt")).expect("kallsyms written");
    assert!(
        kallsyms.starts_with("ffff000080000000 T sym0000\n"),
        "{kallsyms}"
    );
    assert_eq!(kallsyms.lines().count(), builders::KALLSYMS_COUNT);

    let elf = fs::read(out.join("boot.elf")).expect("ELF written");
    let file = object::read::File::parse(&*elf).expect("ELF parses");
    let names: Vec<String> = file
        .symbols()
        .filter_map(|symbol| symbol.name().ok().map(str::to_string))
        .collect();
    assert!(names.iter().any(|name| name == "sym0000"), "{names:?}");
}

#[test]
fn lzop_container_decodes_raw_block() {
    for container in [builders::lzop_hello(), builders::lzop_hello_crc32()] {
        let decoded = dumprs::formats::boot_artifacts::ikconfig::decode_lzop(&container)
            .expect("LZOP container must decode");
        assert_eq!(decoded, b"hello, lzo world!");
    }
}

#[test]
fn lzop_rejects_bad_checksums() {
    let mut container = builders::lzop_hello();
    let len = container.len();
    container[len - 1] ^= 0xff;
    assert_eq!(
        dumprs::formats::boot_artifacts::ikconfig::decode_lzop(&container),
        None
    );

    let mut container = builders::lzop_hello_crc32();
    let header_checksum_at = 9 + 25;
    container[header_checksum_at] ^= 0xff;
    assert_eq!(
        dumprs::formats::boot_artifacts::ikconfig::decode_lzop(&container),
        None
    );
}

#[test]
fn base_relative_address_decoding() {
    use dumprs::formats::boot_artifacts::kallsyms::decode_relative_addresses;
    let offsets = [0i32, 4, -8, 16];
    assert_eq!(
        decode_relative_addresses(0x1000, &offsets, false),
        vec![0x1000, 0x1004, 0xff8, 0x1010]
    );
    assert_eq!(
        decode_relative_addresses(0x1000, &[-1i32, 0], true),
        vec![0x1000, 0]
    );
}

#[test]
fn kallsyms_finds_base_relative_table() {
    let kernel = builders::synthetic_base_relative_kernel();
    let symbols = find_kallsyms(&kernel).expect("base-relative kallsyms must be found");
    assert_eq!(symbols.len(), builders::KALLSYMS_COUNT);
    assert_eq!(symbols[0].address, builders::KALLSYMS_BASE);
    assert_eq!(symbols[0].name, "sym0000");
}

#[test]
fn elf_has_virtual_address_mapping() {
    let symbols = vec![
        Symbol {
            address: builders::KALLSYMS_BASE,
            kind: 'T',
            name: "_text".into(),
        },
        Symbol {
            address: builders::KALLSYMS_BASE + 0x100,
            kind: 'T',
            name: "do_work".into(),
        },
    ];
    let dir = temp_dir::temp_dir();
    let output = dir.join("boot.elf");
    write_elf(&symbols, b"raw kernel bytes", &output).expect("ELF written");

    let bytes = fs::read(&output).expect("read ELF");
    let file = object::read::File::parse(&*bytes).expect("ELF parses");
    use object::Object;
    let text = file
        .sections()
        .find(|s| s.name() == Ok(".kernel"))
        .expect(".kernel section");
    assert_eq!(text.address(), builders::KALLSYMS_BASE);
    assert_eq!(file.entry(), builders::KALLSYMS_BASE);
    assert_eq!(file.kind(), object::ObjectKind::Executable);
    let values: Vec<(String, u64)> = file
        .symbols()
        .filter_map(|s| s.name().ok().map(|name| (name.to_string(), s.address())))
        .collect();
    assert!(values.contains(&("do_work".to_string(), builders::KALLSYMS_BASE + 0x100)));
}
