use dumprs::formats::boot_artifacts::ikconfig::extract_ikconfig;
use dumprs::formats::boot_artifacts::kallsyms::{decode_names, decode_relative_addresses};
use proptest::prelude::*;

fn encode_names(names: &[String]) -> Vec<u8> {
    let mut blob = Vec::new();
    for name in names {
        blob.push(name.len() as u8);
        blob.extend_from_slice(name.as_bytes());
    }
    blob
}

proptest! {
    #[test]
    fn decode_names_roundtrips_token_tables(names in prop::collection::vec("[A-Za-z0-9_]{1,40}", 1..64)) {
        let tokens: Vec<Vec<u8>> = (0..256)
            .map(|index| {
                if index == 0 {
                    vec![]
                } else if index == b':' as usize {
                    vec![b'x', b'x']
                } else {
                    vec![index as u8]
                }
            })
            .collect();
        let blob = encode_names(&names);
        let decoded = decode_names(&blob, &tokens, names.len()).expect("names decode");
        prop_assert_eq!(decoded, names);
    }

    #[test]
    fn ikconfig_detects_every_supported_codec(config in "CONFIG_[A-Z_]{1,60}=y\\n") {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(config.as_bytes()).unwrap();
        let gzip = gzip.finish().unwrap();
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 0);
        xz.write_all(config.as_bytes()).unwrap();
        let xz = xz.finish().unwrap();
        let mut bzip = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        bzip.write_all(config.as_bytes()).unwrap();
        let bzip = bzip.finish().unwrap();
        let zstd = zstd::encode_all(config.as_bytes(), 0).unwrap();

        for compressed in [gzip, xz, bzip, zstd] {
            let mut image = b"IKCFG_ST".to_vec();
            image.extend_from_slice(&compressed);
            image.extend_from_slice(b"IKCFG_ED");
            let decoded = extract_ikconfig(&image).expect("codec decodes").expect("config present");
            prop_assert_eq!(decoded, config.as_bytes());
        }
    }

    #[test]
    fn relative_address_decode_matches_reference(
        base in 0x4000_0000u64..0xffff_0000_0000,
        offsets in prop::collection::vec(-1000i32..1000, 0..40),
        absolute_percpu in any::<bool>(),
    ) {
        let actual = decode_relative_addresses(base, &offsets, absolute_percpu);
        let expected: Vec<u64> = offsets
            .iter()
            .map(|&offset| {
                if absolute_percpu {
                    if offset < 0 {
                        base.wrapping_sub(1).wrapping_add((-(offset as i64)) as u64)
                    } else {
                        offset as u64
                    }
                } else {
                    base.wrapping_add(offset as u64)
                }
            })
            .collect();
        prop_assert_eq!(actual, expected);
    }
}
