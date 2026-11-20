# dumprs

High-performance Rust extractor for Android firmware and OTA images, based on [dumpyara](https://github.com/sebaubuntu-python/dumpyara).

> [!WARNING]
> **Work in Progress (WIP) & Experimental**: This project is under active development and has not yet been thoroughly tested across a wide variety of OEM firmware files and partition formats. Bugs, missing edge-case handling, or extraction errors may occur. Bug reports and sample payloads are welcome!

## Features

- **Blazing Fast**: Multi-threaded extraction powered by Rayon and memory-mapped I/O (`memmap2`).
- **Comprehensive Format Support**:
  - **OTA Payloads**: Full extraction of `payload.bin` (Brotli, Bzip2, LZ4, Zstandard).
  - **Super / Dynamic Partitions**: Direct unpacking of metadata and sub-partitions via `liblp`.
  - **Sparse Images**: Unsparsing of Android sparse (`.img`, `.simg`) formats.
  - **Sparse Data**: Unpacking of `.transfer.list` + `.new.dat` (raw, `.br`, `.xz`).
  - **Filesystem Unpacking**: Native userspace reading and extraction of `ext4` and `erofs` partitions.
  - **Vendor Archives**: Support for `.zip`, `.tar`, `.7z`, `.kdz`, and raw boot images.
- **Workflow Control**: Resume capability, partition filtering, and debug staging directories.
- **SELinux / Permission Sidecars**: Optional generation of `fs_config` and `file_contexts` for repacking workflows.
- **EROFS Repacking**: Rebuild an extracted partition tree into an EROFS image while preserving uid/gid/mode and SELinux labels from the sidecars.
- **Boot/kernel artifacts**: `avb.txt` (avbtool-compatible vbmeta dump), `ikconfig` (embedded kernel config, including gzip/xz/bzip2/LZMA/LZ4/LZOP/zstd payloads with LZOP checksum verification), `boot_kallsyms.txt` / `kernel_kallsyms.txt` (absolute and base-relative kallsyms), a virtual-address-mapped `boot.elf` carrying the recovered symbols, and split DTBs with DTS text — all written into the corresponding partition directory. Enabled by default; disable with `--skip-boot-artifacts`.

## Installation

### Prebuilt binaries (nightly)

Automated nightly builds are published for two Linux targets:

| Target | Architecture | Asset |
| :--- | :--- | :--- |
| `x86_64-unknown-linux-gnu` | x86_64 | `dumprs-linux-x86_64.tar.gz` |
| `aarch64-unknown-linux-gnu` | ARM64 / AArch64 | `dumprs-linux-aarch64.tar.gz` |

Each archive is accompanied by a `.sha256` checksum file. Both are attached to
the [`nightly` pre-release](https://github.com/ardiandideyashidiq/dumprs/releases/tag/nightly)
on the GitHub Releases page. Verify a download with:

```bash
sha256sum --check dumprs-linux-aarch64.tar.gz.sha256
```

### Build from source

Ensure you have Rust (2024 edition / latest stable) installed. The protobuf
descriptor is pre-generated (`update_metadata.desc`), so `protoc` is not required:

```bash
cargo build --release
```

Binary will be located at `target/release/dumprs`.

To cross-compile for ARM64 from an x86_64 Linux host, install the target and a
cross linker (the bundled C dependencies `bzip2-sys`, `lzma-sys`, and `zstd-sys`
need a C compiler for the target):

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt-get install -y gcc-aarch64-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu
```

Binary will be located at `target/aarch64-unknown-linux-gnu/release/dumprs`.

## Usage

```bash
dumprs [OPTIONS] <FILE>
```

### Examples

```bash
# Extract full OTA or firmware archive
dumprs ota.zip

# Extract to a specific output directory
dumprs payload.bin -o ./extracted_dump

# Extract only specific partitions
dumprs ota.zip -p system -p vendor -p product

# Resume previous extraction without reprocessing raw images
dumprs ota.zip --resume

# Keep intermediate extracted files for debugging
dumprs ota.zip --debug

# Extract and emit fs_config / file_contexts sidecars for repacking
dumprs ota.zip --emit-fs-metadata --fs-metadata-fstype erofs
```

### Repack an extracted partition

```bash
# After extracting with --emit-fs-metadata, rebuild a partition image.
dumprs repack \
  --input dump/system \
  --output system.erofs.img \
  --partition system \
  --fs-config dump/config/system/system_fs_config \
  --file-contexts dump/config/system/system_file_contexts
```

The writer currently supports EROFS. `fs_config` supplies uid/gid/mode and
`file_contexts` supplies the `security.selinux` xattr, so a round trip keeps the
original metadata. ext4, super, payload/OTA and f2fs writers are not yet
implemented.

### CLI Options

| Flag | Description |
| :--- | :--- |
| `<FILE>` | Path to a device OTA or firmware archive |
| `-o, --output <OUTPUT>` | Custom output folder (defaults to the file stem) |
| `-p, --partition <PARTITION>` | Extract only specified partition(s); can be repeated |
| `-r, --resume` | Resume from existing temporary directories without re-extracting |
| `--skip-extract` | Skip Step 1 (reuse existing `temp_extracted_archive`) |
| `--skip-prepare` | Skip Step 2 (reuse existing `temp_raw_images`) |
| `-d, --debug` | Retain temporary directories for debugging |
| `--skip-boot-artifacts` | Do not generate AVB / IKconfig / kallsyms / ELF / DTB-DTS artifacts |
| `--emit-fs-metadata` | Generate `fs_config` and `file_contexts` for extracted partitions |
| `--fs-metadata-fstype <FSTYPE>` | Sidecar conventions: `ext4` (default), `erofs`, or `f2fs` |
| `--fs-metadata-bin-only` | Only generate entries under `bin/` directories |
| `--fs-metadata-vbin <CONTEXT>` | Override vendor/odm `bin/` SELinux context |
| `--fs-metadata-sbin <CONTEXT>` | Override system `bin/` SELinux context |
| `--fs-metadata-dir <DIR>` | Root directory for generated `config/` files |
| `--fs-metadata-dry-run` | Count missing entries without writing files |
| `-h, --help` | Print help |

## Credits

- **[DumprX](https://github.com/ramabondanp/DumprX)** by [@ramabondanp](https://github.com/ramabondanp) (Rama Bondan Prakoso) & [@rokibhasansagar](https://github.com/rokibhasansagar) (Rokib Hasan Sagar) - Heuristics for device info distillation, scoped property precedence, Transsion / Xiaomi / Motorola / OPlus hardware and OS extraction, and Markdown dump card formatting.
- **[dumpyara](https://github.com/sebaubuntu-python/dumpyara)** by [@sebaubuntu-python](https://github.com/sebaubuntu-python) ([@SebaUbuntu](https://github.com/SebaUbuntu)) - The original Python-based firmware extractor architecture, multi-format pipeline design, and AOSP device tree conventions that inspired and shaped `dumprs`.
- **[Phoenix Firmware Dumper](https://github.com/DroidDumps)** by [DroidDumps](https://github.com/DroidDumps) - Foundational firmware dumping methodologies and community contributions.
- **Format & Tool Authors**:
  - `sdat2img` by [@xpirt](https://github.com/xpirt), [@luxi78](https://github.com/luxi78), [@howellzhu](https://github.com/howellzhu)
  - `simg2img` by [@anestisb](https://github.com/anestisb)
  - `extract_android_ota_payload` by [@cyxx](https://github.com/cyxx) and the Android Open Source Project (`update_engine`)
  - `liblp` & `lpunpack` by Google AOSP & [@LonelyFool](https://github.com/LonelyFool)
  - `kdztools` (`unkdz` / `undz`) by IOMonster ([@thecubed](https://github.com/thecubed)), [@ehem](https://github.com/ehem), and [@steadfasterX](https://github.com/steadfasterX)
  - `aospdtgen` / `twrpdtgen` by [@SebaUbuntu](https://github.com/SebaUbuntu)
  - `backhand` by [@wcampbell0x2a](https://github.com/wcampbell0x2a)
  - `erofs-rs` by EROFS developers
  - `termimad` by [@Canop](https://github.com/Canop)

## License

GPL-3.0-only. See [`LICENSE`](LICENSE) for the full text and
[`CREDITS.md`](CREDITS.md) for upstream attributions.

The `fs_config`/`file_contexts` generator in `src/utils/fs_metadata/` is
adapted from Danda420's GPL-3.0-only tools, so dumprs is distributed under the
same license.
