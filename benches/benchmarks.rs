#[path = "../tests/common/bench.rs"]
mod bench_fixtures;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use dumprs::formats::boot_artifacts::dtb::{dtb_to_dts, split_dtb};
use dumprs::formats::boot_artifacts::ikconfig::extract_ikconfig;
use dumprs::formats::boot_artifacts::kallsyms::find_kallsyms;
use dumprs::formats::liblp::lpunpack;
use dumprs::formats::sdat2img::sdat2img;
use dumprs::formats::sparse::unsparse_file;
use std::fs;
use std::path::PathBuf;

fn create_sdat_fixture() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join("dumprs_bench_sdat");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let transfer_path = dir.join("test.transfer.list");
    let data_path = dir.join("test.new.dat");
    let out_path = dir.join("test.img");

    // 500 contiguous and split blocks
    let mut transfer = String::from("4\n500\n0\n0\n");
    for i in 0..50 {
        let start = i * 10;
        let end = start + 8;
        transfer.push_str(&format!("new 2,{},{}\n", start, end));
    }
    fs::write(&transfer_path, transfer).unwrap();

    // 50 * 8 = 400 blocks of 4096 bytes
    let block = vec![0x55u8; 4096];
    let mut payload = Vec::with_capacity(400 * 4096);
    for _ in 0..400 {
        payload.extend_from_slice(&block);
    }
    fs::write(&data_path, payload).unwrap();

    (dir, transfer_path, data_path, out_path)
}

fn create_sparse_fixture() -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join("dumprs_bench_sparse");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let sparse_path = dir.join("bench.sparse.img");
    let raw_path = dir.join("bench.raw.img");

    let num_chunks = 100u32;
    let block_size = 4096u32;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xed26_ff3au32.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&28u16.to_le_bytes());
    bytes.extend_from_slice(&12u16.to_le_bytes());
    bytes.extend_from_slice(&block_size.to_le_bytes());
    bytes.extend_from_slice(&num_chunks.to_le_bytes());
    bytes.extend_from_slice(&num_chunks.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    let payload_block = vec![0x77u8; block_size as usize];
    for _ in 0..num_chunks {
        bytes.extend_from_slice(&0xcac1u16.to_le_bytes()); // RAW
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&(12 + block_size).to_le_bytes());
        bytes.extend_from_slice(&payload_block);
    }

    fs::write(&sparse_path, bytes).unwrap();

    (dir, sparse_path, raw_path)
}

fn create_super_fixture() -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join("dumprs_bench_super");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let super_path = dir.join("super.img");
    let out_dir = dir.join("super_out");

    let mut bytes = vec![0u8; 128 * 1024]; // 128 KiB
    let geom_offset = 4096;
    bytes[geom_offset..geom_offset + 4].copy_from_slice(&0x616c_4467u32.to_le_bytes());
    bytes[geom_offset + 4..geom_offset + 8].copy_from_slice(&4096u32.to_le_bytes());
    bytes[geom_offset + 40..geom_offset + 44].copy_from_slice(&4096u32.to_le_bytes());
    bytes[geom_offset + 44..geom_offset + 48].copy_from_slice(&2u32.to_le_bytes());
    bytes[geom_offset + 48..geom_offset + 52].copy_from_slice(&4096u32.to_le_bytes());

    let hdr_offset = 12288;
    bytes[hdr_offset..hdr_offset + 4].copy_from_slice(&0x414c_5030u32.to_le_bytes());
    bytes[hdr_offset + 4..hdr_offset + 6].copy_from_slice(&10u16.to_le_bytes());
    bytes[hdr_offset + 6..hdr_offset + 8].copy_from_slice(&0u16.to_le_bytes());
    bytes[hdr_offset + 8..hdr_offset + 12].copy_from_slice(&128u32.to_le_bytes());
    bytes[hdr_offset + 44..hdr_offset + 48].copy_from_slice(&256u32.to_le_bytes());

    let desc_offset = hdr_offset + 80;
    bytes[desc_offset..desc_offset + 4].copy_from_slice(&0u32.to_le_bytes());
    bytes[desc_offset + 4..desc_offset + 8].copy_from_slice(&1u32.to_le_bytes());
    bytes[desc_offset + 8..desc_offset + 12].copy_from_slice(&52u32.to_le_bytes());

    let ext_desc_offset = hdr_offset + 92;
    bytes[ext_desc_offset..ext_desc_offset + 4].copy_from_slice(&52u32.to_le_bytes());
    bytes[ext_desc_offset + 4..ext_desc_offset + 8].copy_from_slice(&1u32.to_le_bytes());
    bytes[ext_desc_offset + 8..ext_desc_offset + 12].copy_from_slice(&24u32.to_le_bytes());

    let tables_start = hdr_offset + 128;
    bytes[tables_start..tables_start + 6].copy_from_slice(b"system");
    bytes[tables_start + 40..tables_start + 44].copy_from_slice(&0u32.to_le_bytes());
    bytes[tables_start + 44..tables_start + 48].copy_from_slice(&1u32.to_le_bytes());

    let ext_start = tables_start + 52;
    bytes[ext_start..ext_start + 8].copy_from_slice(&64u64.to_le_bytes()); // 32 KiB
    bytes[ext_start + 8..ext_start + 12].copy_from_slice(&0u32.to_le_bytes());
    bytes[ext_start + 12..ext_start + 20].copy_from_slice(&32u64.to_le_bytes()); // sector 32 = 16384
    bytes[ext_start + 20..ext_start + 24].copy_from_slice(&0u32.to_le_bytes());

    fs::write(&super_path, bytes).unwrap();

    (dir, super_path, out_dir)
}

fn bench_sdat2img(c: &mut Criterion) {
    let (dir, transfer, data, out) = create_sdat_fixture();

    c.bench_function("sdat2img_400blocks", |b| {
        b.iter(|| {
            sdat2img(black_box(&transfer), black_box(&data), black_box(&out)).unwrap();
        })
    });

    let _ = fs::remove_dir_all(dir);
}

fn bench_sparse(c: &mut Criterion) {
    let (dir, sparse, raw) = create_sparse_fixture();

    c.bench_function("unsparse_100chunks", |b| {
        b.iter(|| {
            unsparse_file(black_box(&sparse), black_box(&raw)).unwrap();
        })
    });

    let _ = fs::remove_dir_all(dir);
}

fn bench_liblp(c: &mut Criterion) {
    let (dir, super_img, out) = create_super_fixture();

    c.bench_function("lpunpack_system", |b| {
        b.iter(|| {
            lpunpack(black_box(&super_img), black_box(&out)).unwrap();
        })
    });

    let _ = fs::remove_dir_all(dir);
}

fn bench_boot_artifacts(c: &mut Criterion) {
    let mut combined = bench_fixtures::dtb("first");
    combined.extend_from_slice(&bench_fixtures::dtb("second"));
    c.bench_function("dtb_split_and_dts", |b| {
        b.iter(|| {
            let blobs = split_dtb(black_box(&combined)).unwrap();
            for blob in blobs {
                black_box(dtb_to_dts(blob).unwrap());
            }
        })
    });

    let mut scan = vec![0u8; 32 * 1024 * 1024];
    let config = bench_fixtures::ikconfig_gzip();
    let at = scan.len() - config.len() - 64;
    scan[at..at + config.len()].copy_from_slice(&config);
    c.bench_function("ikconfig_scan_32mib", |b| {
        b.iter(|| black_box(extract_ikconfig(black_box(&scan)).unwrap()))
    });

    let kernel = bench_fixtures::synthetic_kernel();
    c.bench_function("kallsyms_find_1024", |b| {
        b.iter(|| black_box(find_kallsyms(black_box(&kernel)).unwrap()))
    });
}

criterion_group!(
    benches,
    bench_sdat2img,
    bench_sparse,
    bench_liblp,
    bench_boot_artifacts
);
criterion_main!(benches);
