# Credits

## Upstream tools

The `fs_config` and `file_contexts` generators in `src/utils/fs_metadata/`
are adapted from the following GPL-3.0-only projects by **Danda420**:

- [gen_file-context](https://github.com/Danda420/gen_file-context) —
  "A Tool to autogenerate missing file_contexts entries based on file/folder
  location and partition".
- [gen_fs-config](https://github.com/Danda420/gen_fs-config) —
  "A tool to automatically generate missing fs_config entries based on
  file/folder location".

Both projects are licensed under the GNU General Public License v3.0; their
license text is reproduced in [`LICENSE`](LICENSE). The adapted Rust code in
this repository is distributed under the same GPL-3.0-only license, with
modifications by `rdndds <rdndds@gmail.com>`.

## Filesystem writers

The EROFS writer uses [rust-fs-erofs](https://github.com/antimatter-studios/rust-fs-erofs)
by Christopher Thomas (MIT), a clean-room pure-Rust EROFS reader and builder.

## Boot artifacts

The boot/kernel artifact generators in `src/formats/boot_artifacts/` stand on
the following work:

- [dtoolkit](https://github.com/google/dtoolkit) by Google (Apache-2.0 OR MIT)
  for FDT/DTB parsing and DTS rendering.
- [object](https://github.com/gimli-rs/object) by the gimli-rs project
  (Apache-2.0 OR MIT) for ELF symbol output.
- [sha1](https://github.com/RustCrypto/hashes) (MIT OR Apache-2.0) for AVB
  public-key digests.
- [lzma-rs](https://github.com/gendx/lzma-rs) by gendx (MIT) for LZMA-compressed
  embedded kernel configs.
- [lzo](https://github.com/SecurityRonin/lzo) by Security Ronin (Apache-2.0)
  for the pure-Rust LZO1X decoder used with LZOP-compressed kernel configs.
- [adler2](https://github.com/oyvindln/adler2) (0BSD OR MIT OR Apache-2.0) and
  [crc32fast](https://github.com/srijs/rust-crc32fast) (MIT OR Apache-2.0) for
  LZOP header, block and final-data checksum verification.
- [proptest](https://github.com/proptest-rs/proptest) (MIT OR Apache-2.0) for
  the property tests guarding the boot artifact parsers.
- `avbtool.py` from AOSP `external/avb` for the `info_image` output format
  reproduced by `avb.rs`.
- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) by @marin-m
  (GPL-3.0) for the kallsyms discovery heuristics.

## OEM containers

- `splituapp.py` by SuperR @XDA, as bundled in GPL-3.0-only DumprX, for the
  `UPDATE.APP` entry layout reproduced by `src/formats/oem/update_app.rs`.
- The PAC record layout in `src/formats/oem/pac.rs` follows `pacExtractor.py`
  by [HemanthJabalpuri](https://github.com/HemanthJabalpuri/pacextractor),
  which is dedicated to the public domain.
- The `.nb0` header layout in `src/formats/oem/nb0.rs` follows `nb0_extractor.py`
  bundled with MIO-KITCHEN-SOURCE; it was reimplemented in Rust, with the
  source script's chunk-overwrite bug corrected.
- The AML record layout in `src/formats/oem/amlogic.rs` follows the published
  `aml-upgrade-package-extract.c` by [Portisch](https://github.com/Portisch/aml-upgrade-package-extract)
  (no license file in that repository); it was reimplemented in Rust rather
  than copied.
- The QFIL `rawprogram*.xml` sector assembly in `src/formats/oem/qfil.rs` was
  inferred from DumprX's `packsparseimg` behaviour and the format's published
  attribute names; no source from that tool is included.
- [roxmltree](https://github.com/razrfalcon/roxmltree) by Yevhenii Reizner
  (MIT OR Apache-2.0) for read-only parsing of QFIL rawprogram XML.

## Other projects

See the `Credits` section of [`README.md`](README.md) for the firmware
formats, tools, and communities that informed the rest of dumprs.
