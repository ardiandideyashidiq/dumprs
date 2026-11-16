# dumprs

High-performance, pure-Rust extractor for Android firmware and OTA images.

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

## License

Apache-2.0 or MIT
