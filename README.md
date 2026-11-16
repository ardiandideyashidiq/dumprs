# dumprs

High-performance, pure-Rust extractor for Android firmware and OTA images, based on [dumpyara](https://github.com/sebaubuntu-python/dumpyara).

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

## Installation

Ensure you have Rust (2024 edition / latest stable) and `protoc` installed:

```bash
cargo build --release
```

Binary will be located at `target/release/dumprs`.

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
```

### CLI Options

| Flag | Description |
| :--- | :--- |
| `<FILE>` | Path to device OTA or firmware archive |
| `-o, --output <DIR>` | Custom output directory (defaults to file stem) |
| `-p, --partition <NAME>` | Extract only specified partition(s) (can be used multiple times) |
| `-r, --resume` | Resume extraction from existing temp directories |
| `--skip-extract` | Skip archive unpacking step (`temp_extracted_archive`) |
| `--skip-prepare` | Skip raw image preparation step (`temp_raw_images`) |
| `-d, --debug` | Retain temporary directories for debugging |
| `-h, --help` | Print help information |
| `-V, --version` | Print version |

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

Apache-2.0 or MIT
