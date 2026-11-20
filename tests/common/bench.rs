//! Fixtures used only by the Criterion benchmark target.

pub const KALLSYMS_COUNT: usize = 1024;
pub const KALLSYMS_BASE: u64 = 0xffff_0000_8000_0000;

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

pub fn ikconfig_gzip() -> Vec<u8> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    let config = b"CONFIG_TEST=y\nCONFIG_IKCONFIG=y\n";
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(config).expect("gzip write");
    let compressed = encoder.finish().expect("gzip finish");
    let mut data = b"IKCFG_ST".to_vec();
    data.extend_from_slice(&compressed);
    data.extend_from_slice(b"IKCFG_ED");
    data
}

pub fn synthetic_kernel() -> Vec<u8> {
    let mut kernel = vec![0u8; 0x1000];
    for index in 0..KALLSYMS_COUNT {
        kernel.extend_from_slice(&(KALLSYMS_BASE + (index as u64) * 4).to_le_bytes());
    }
    kernel.extend_from_slice(&(KALLSYMS_COUNT as u32).to_le_bytes());
    while !kernel.len().is_multiple_of(4) {
        kernel.push(0);
    }

    let mut names = Vec::new();
    let mut markers = Vec::new();
    for index in 0..KALLSYMS_COUNT {
        let name = format!("Tsym{index:04}");
        if index % 256 == 0 {
            markers.push(names.len() as u32);
        }
        names.push(name.len() as u8);
        names.extend_from_slice(name.as_bytes());
    }
    kernel.extend_from_slice(&names);
    while !kernel.len().is_multiple_of(4) {
        kernel.push(0);
    }
    for marker in markers {
        kernel.extend_from_slice(&marker.to_le_bytes());
    }
    while !kernel.len().is_multiple_of(4) {
        kernel.push(0);
    }

    let mut table = Vec::new();
    let mut offsets = Vec::new();
    for index in 0..256u16 {
        offsets.push(table.len() as u16);
        if index == 0 {
            table.push(0);
        } else if index == b':' as u16 {
            table.extend_from_slice(b"xx\0");
        } else {
            table.push(index as u8);
            table.push(0);
        }
    }
    while !table.len().is_multiple_of(4) {
        table.push(0);
    }
    kernel.extend_from_slice(&table);
    for offset in offsets {
        kernel.extend_from_slice(&offset.to_le_bytes());
    }
    kernel
}
