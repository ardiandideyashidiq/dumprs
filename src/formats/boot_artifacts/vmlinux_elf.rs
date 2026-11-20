use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use super::kallsyms::Symbol as KallsymsSymbol;

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

fn put_u16(out: &mut [u8], offset: usize, value: u16, endian: Endian) {
    let bytes = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    out[offset..offset + 2].copy_from_slice(&bytes);
}

fn put_u32(out: &mut [u8], offset: usize, value: u32, endian: Endian) {
    let bytes = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    out[offset..offset + 4].copy_from_slice(&bytes);
}

fn put_u64(out: &mut [u8], offset: usize, value: u64, endian: Endian) {
    let bytes = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    out[offset..offset + 8].copy_from_slice(&bytes);
}

fn alignment(kernel: &[u8]) -> (u16, Endian) {
    if kernel.len() >= 20 && kernel.starts_with(b"\x7fELF") {
        let endian = if kernel[5] == 2 {
            Endian::Big
        } else {
            Endian::Little
        };
        let machine_bytes = [kernel[18], kernel[19]];
        let machine = match endian {
            Endian::Little => u16::from_le_bytes(machine_bytes),
            Endian::Big => u16::from_be_bytes(machine_bytes),
        };
        let machine = match machine {
            3 => 3,   // EM_386
            40 => 40, // EM_ARM
            62 => 62, // EM_X86_64
            _ => 183, // EM_AARCH64
        };
        (machine, endian)
    } else {
        (183, Endian::Little)
    }
}

fn binding(kind: char) -> u8 {
    match kind {
        'V' | 'W' | 'v' | 'w' => 2, // STB_WEAK
        'A' | 'T' | 'D' | 'B' | 'R' | 'G' | 'S' | 'N' | 'P' | 'I' => 1, // STB_GLOBAL
        _ => 0,                     // STB_LOCAL
    }
}

fn symbol_type(kind: char) -> u8 {
    if kind.eq_ignore_ascii_case(&'T') {
        2 // STT_FUNC
    } else {
        1 // STT_OBJECT
    }
}

/// Write an ELF64 image with the raw kernel in a virtual-address-mapped
/// `.kernel` section plus a symbol table carrying the recovered kallsyms
/// symbols. Mirrors the layout produced by vmlinux-to-elf's `ElfSymbolizer`.
pub fn write_elf(symbols: &[KallsymsSymbol], kernel: &[u8], output: &Path) -> Result<()> {
    let (machine, endian) = alignment(kernel);
    let base = symbols
        .iter()
        .map(|symbol| symbol.address)
        .min()
        .unwrap_or(0xffff_0000_8000_0000)
        & !0xf_ffffu64;
    let entry = symbols
        .iter()
        .find(|symbol| symbol.name == "_text" || symbol.name == "stext" || symbol.name == "_head")
        .or_else(|| symbols.first())
        .map(|symbol| symbol.address)
        .unwrap_or(base);

    let mut strtab = vec![0u8];
    let mut symbol_names = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        let offset = strtab.len();
        strtab.extend_from_slice(symbol.name.as_bytes());
        strtab.push(0);
        symbol_names.push(offset as u32);
    }

    let shstrtab: &[u8] = b"\0.kernel\0.symtab\0.strtab\0.shstrtab\0";
    let kernel_offset = 128usize;
    let symtab_offset = kernel_offset + kernel.len();
    let strtab_offset = symtab_offset + (symbols.len() + 1) * 24;
    let shstrtab_offset = strtab_offset + strtab.len();
    let shoff = (shstrtab_offset + shstrtab.len() + 7) & !7;

    let mut out = vec![0u8; shoff + 5 * 64];
    // ELF header
    out[0..4].copy_from_slice(b"\x7fELF");
    out[4] = 2; // ELFCLASS64
    out[5] = match endian {
        Endian::Little => 1,
        Endian::Big => 2,
    };
    out[6] = 1; // EV_CURRENT
    put_u16(&mut out, 16, 2, endian); // ET_EXEC
    put_u16(&mut out, 18, machine, endian);
    put_u32(&mut out, 20, 1, endian); // EV_CURRENT
    put_u64(&mut out, 24, entry, endian);
    put_u64(&mut out, 32, 64, endian); // e_phoff
    put_u64(&mut out, 40, shoff as u64, endian);
    put_u32(&mut out, 48, 0, endian);
    put_u16(&mut out, 52, 64, endian); // e_ehsize
    put_u16(&mut out, 54, 56, endian); // e_phentsize
    put_u16(&mut out, 56, 1, endian); // e_phnum
    put_u16(&mut out, 58, 64, endian); // e_shentsize
    put_u16(&mut out, 60, 5, endian); // e_shnum
    put_u16(&mut out, 62, 4, endian); // e_shstrndx

    // PT_LOAD for the kernel bytes.
    put_u32(&mut out, 64, 1, endian); // PT_LOAD
    put_u32(&mut out, 68, 7, endian); // PF_R | PF_W | PF_X
    put_u64(&mut out, 72, kernel_offset as u64, endian);
    put_u64(&mut out, 80, base, endian);
    put_u64(&mut out, 88, base, endian);
    put_u64(&mut out, 96, kernel.len() as u64, endian);
    put_u64(
        &mut out,
        104,
        (kernel.len() + 16 * 1024 * 1024) as u64,
        endian,
    );
    put_u64(&mut out, 112, 0x1000, endian);

    out[kernel_offset..kernel_offset + kernel.len()].copy_from_slice(kernel);
    out[symtab_offset..symtab_offset + 24].fill(0); // null symbol

    for (index, symbol) in symbols.iter().enumerate() {
        let offset = symtab_offset + (index + 1) * 24;
        let info = (binding(symbol.kind) << 4) | symbol_type(symbol.kind);
        let section = if symbol.kind == 'A' { 0xfff1 } else { 1 };
        put_u32(&mut out, offset, symbol_names[index], endian);
        out[offset + 4] = info;
        out[offset + 5] = 0;
        put_u16(&mut out, offset + 6, section, endian);
        put_u64(&mut out, offset + 8, symbol.address, endian);
        put_u64(&mut out, offset + 16, 0, endian);
    }
    out[strtab_offset..strtab_offset + strtab.len()].copy_from_slice(&strtab);
    out[shstrtab_offset..shstrtab_offset + shstrtab.len()].copy_from_slice(shstrtab);

    // Section headers: NULL, .kernel, .symtab, .strtab, .shstrtab
    let name_kernel = 1u32;
    let name_symtab = 9u32;
    let name_strtab = 17u32;
    let name_shstrtab = 25u32;
    let mut section = |index: usize,
                       name: u32,
                       kind: u32,
                       flags: u64,
                       addr: u64,
                       offset: usize,
                       size: u64,
                       link: u32,
                       info: u32,
                       align: u64,
                       entsize: u64| {
        let at = shoff + index * 64;
        put_u32(&mut out, at, name, endian);
        put_u32(&mut out, at + 4, kind, endian);
        put_u64(&mut out, at + 8, flags, endian);
        put_u64(&mut out, at + 16, addr, endian);
        put_u64(&mut out, at + 24, offset as u64, endian);
        put_u64(&mut out, at + 32, size, endian);
        put_u32(&mut out, at + 40, link, endian);
        put_u32(&mut out, at + 44, info, endian);
        put_u64(&mut out, at + 48, align, endian);
        put_u64(&mut out, at + 56, entsize, endian);
    };
    section(
        1,
        name_kernel,
        1,
        0x6,
        base,
        kernel_offset,
        kernel.len() as u64,
        0,
        0,
        16,
        0,
    );
    section(
        2,
        name_symtab,
        2,
        0,
        0,
        symtab_offset,
        ((symbols.len() + 1) * 24) as u64,
        3,
        1,
        8,
        24,
    );
    section(
        3,
        name_strtab,
        3,
        0,
        0,
        strtab_offset,
        strtab.len() as u64,
        0,
        0,
        1,
        0,
    );
    section(
        4,
        name_shstrtab,
        3,
        0,
        0,
        shstrtab_offset,
        shstrtab.len() as u64,
        0,
        0,
        1,
        0,
    );

    fs::write(output, &out).with_context(|| format!("writing ELF {}", output.display()))?;
    Ok(())
}
