# dumprs — agent notes

Pure-Rust, experimental extractor for Android firmware/OTA; GPL-3.0-only. The
README is a feature wishlist in places — trust the code (see "Docs vs code").

## Verify locally; CI only type-checks

CI (`.github/workflows/ci.yml`) runs **only**
`cargo check --target <x86_64|aarch64-unknown-linux-gnu> --all-targets`.
No tests, no clippy, no fmt. There is no `clippy.toml` and no `[lints]` in
`Cargo.toml`, so `-D warnings` is the de facto lint gate:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

Focused suites: `cargo test --test unit_tests`, `--test boot_artifacts`,
`--test proptests`.

## Tests that need external prerequisites

`tests/real_firmware.rs` is `#[ignore]`d by default. Run with:

```bash
cargo test --test real_firmware -- --ignored --nocapture
```

It needs `/home/rd/Projects/android/dumpyara/test` (firmware corpus),
`/home/rd/Projects/android/dumpyara/DumprX/utils/avbtool.py`, and oracle output
in `/tmp/opencode/scout/` for the 6.1 kernel. Missing prerequisites must print
`check did not run: …`, **not** fail red — keep it that way; never make them CI
dependencies. These are the parity checks: 4.19 kernel (absolute kallsyms,
119278 symbols) and Scout 6.1 (base-relative kallsyms, 102086 symbols).

`proptest` writes `tests/proptests.proptest-regressions` on failure; delete it
after fixing the generator instead of committing it.

## Pipeline state is on disk, not in memory

`src/dumprs.rs` is the real orchestrator (3 steps + finalize):
`extract_archive` → `prepare_images` → `extract_images_with_cleanup` → README/
`all_files.txt`. Intermediate dirs are `temp_extracted_archive/` and
`temp_raw_images/` under the output dir; stale outputs are quarantined into
`temp_raw_images/.stale/` on a fresh full dump. `--resume`, `--skip-extract`
and `--skip-prepare` reuse those dirs. On failure, temp dirs are deliberately
**kept** so `--resume` works — never add cleanup before `run_res?`.

## Boot artifacts

`src/formats/boot_artifacts/` is generated **per partition directory**, not at
the dump root. It is on by default; `--skip-boot-artifacts` disables it. The
two integration points are the `PartitionType::Bootimage` branch in
`steps/extract_images.rs` and the special `dtbo` pass there (`dtbo` is `Raw`,
so no boot-image branch handles it). `generate()` must keep reporting
individual generator failures via `tracing` rather than silently skipping.

## Docs vs code

- README claims payload extraction supports Brotli/LZ4/Zstd. `payload.rs` only
  handles `ZERO`, `REPLACE`, `REPLACE_XZ`, `REPLACE_BZ`; `MOVE`,
  `SOURCE_COPY`, `SOURCE_BSDIFF`, `BROTLI_BSDIFF` bail as unhandled.
- `.new.dat.xz` is documented but absent from `raw_image.rs` (only `.dat` and
  `.dat.br`). Do not claim these features as implemented.
- Boot-header CLI differs from DumprX: here `-p` = partition filter and
  `-r` = resume; DumprX uses them for push-only/readme-only.

## Test/bench helper gotchas

`tests/common/{builders,bench,temp_dir}.rs` are not a crate — each consumer
pulls them in with `#[path = "..."] mod ...;`. With `-D warnings`, every public
item in the included file must be used by **that** test/bench target, so do not
move helpers between `builders.rs` and `bench.rs` casually.

Benches use Criterion baselines:

```bash
cargo bench --bench benchmarks -- --save-baseline <name>
cargo bench --bench benchmarks -- --baseline <name>
```

Record a baseline before optimizing; the current one is `boot-artifacts-before`.

## Toolchain and release quirks

- `build.rs` regenerates protobuf Rust from checked-in `update_metadata.desc`;
  `protoc` is **not** required. The generated file is included from `OUT_DIR`.
- Cross-compiling aarch64 needs `gcc-aarch64-linux-gnu` and
  `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc` because
  `bzip2-sys`/`lzma-sys`/`zstd-sys` are C-backed.
- Push to `main` triggers `.github/workflows/nightly.yml`, which publishes a
  `nightly` prerelease with `dumprs-linux-{x86_64,aarch64}.tar.gz` + `.sha256`.
- Logging uses `RUST_LOG` (default `dumprs=info,warn`); `tracing` is compiled
  with `release_max_level_info`, so debug events vanish in release builds.
- Update `CREDITS.md` when adding a dependency with a distinct upstream license.
