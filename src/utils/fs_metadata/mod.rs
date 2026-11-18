//! Generation of Android `fs_config` and `file_contexts` sidecar files.
//!
//! The rule engine is adapted from two GPL-3.0-only tools by Danda420:
//!
//! - [`gen_file-context`](https://github.com/Danda420/gen_file-context)
//! - [`gen_fs-config`](https://github.com/Danda420/gen_fs-config)
//!
//! Their source is redistributed under GPL-3.0-only; see `LICENSE` and
//! `CREDITS.md`. Behaviour was preserved, while ordering determinism, error
//! handling and the bin-only mode were improved.

pub mod escape;
pub mod file_contexts;
pub mod fs_config;
pub mod reader;
pub mod types;

pub use file_contexts::generate_file_contexts;
pub use fs_config::generate_fs_config;
pub use types::{
    Config, ConfigBuilder, FilesystemType, FsMetadataOptions, GenerationMode, GenerationReport,
    PartitionKind, SelinuxContext,
};
