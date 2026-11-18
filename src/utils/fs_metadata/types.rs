//! Shared types for filesystem metadata generation.
//!
//! Adapted from Danda420's GPL-3.0-only `gen_file-context` and `gen_fs-config`.

use anyhow::{Result, ensure};
use std::fmt;
use std::path::{Path, PathBuf};

/// Filesystem whose sidecar files are being generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemType {
    /// ext4: directory entries get a second `path(/.*)?` rule.
    Ext4,
    /// erofs: directory entries get a single rule.
    Erofs,
    /// f2fs: directory entries get a single rule.
    F2fs,
}

impl FilesystemType {
    /// Parse a filesystem name, accepting the spellings used by RomTools.
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ext4" => Ok(Self::Ext4),
            "erofs" => Ok(Self::Erofs),
            "f2fs" => Ok(Self::F2fs),
            other => anyhow::bail!("unsupported filesystem type: {other}"),
        }
    }

    /// Suffix appended to directory paths in `file_contexts`.
    #[must_use]
    pub const fn folder_pattern(self) -> &'static str {
        match self {
            Self::Ext4 => "(/.*)?",
            Self::Erofs | Self::F2fs => "",
        }
    }
}

/// Which entries should be considered for generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GenerationMode {
    /// Walk the whole partition tree.
    #[default]
    All,
    /// Only walk paths containing a `bin` directory component.
    BinOnly,
}

/// Partition classification used by the context rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionKind {
    /// Vendor-like partition: `vendor`, `odm`, and their derivatives.
    VendorLike,
    /// Any other partition (system, product, system_ext, OPlus partitions).
    SystemLike,
}

impl PartitionKind {
    /// Classify a partition by name, matching RomTools' substring heuristic.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        if name.contains("vendor") || name.contains("odm") {
            Self::VendorLike
        } else {
            Self::SystemLike
        }
    }
}

/// A validated SELinux context string (`u:object_r:<domain>:s0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelinuxContext(String);

impl SelinuxContext {
    /// Build a context from a raw value. Values without `:` are wrapped in
    /// `u:object_r:…:s0`, matching the upstream `--vbin`/`--sbin` handling.
    #[must_use]
    pub fn new(value: &str) -> Self {
        let value = value.trim();
        if value.contains(':') {
            Self(value.to_owned())
        } else {
            Self(format!("u:object_r:{value}:s0"))
        }
    }

    /// Borrow the context text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SelinuxContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Default for SelinuxContext {
    fn default() -> Self {
        Self::new("system_file")
    }
}

/// Counters describing one generation pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenerationReport {
    /// Entries that were absent from the existing sidecar.
    pub missing: usize,
    /// Entries actually written (zero in dry-run mode).
    pub generated: usize,
    /// Entries already present and therefore skipped.
    pub skipped: usize,
}

/// Configuration for one generation pass.
#[derive(Debug, Clone)]
pub struct Config {
    /// Root of the extracted partition tree.
    pub extracted_dir: PathBuf,
    /// Sidecar file to read and append to.
    pub output: PathBuf,
    /// Filesystem conventions to use for directory rules.
    pub fstype: FilesystemType,
    /// Whether to generate all entries or only `bin/` entries.
    pub mode: GenerationMode,
    /// Context assigned to `bin/` executables in vendor-like partitions.
    pub vendor_bin_context: SelinuxContext,
    /// Context assigned to `bin/` executables in system-like partitions.
    pub system_bin_context: SelinuxContext,
    /// Count missing entries without writing the sidecar.
    pub dry_run: bool,
}

impl Config {
    /// Start building a configuration.
    pub fn builder(extracted_dir: impl Into<PathBuf>, output: impl Into<PathBuf>) -> ConfigBuilder {
        ConfigBuilder::new(extracted_dir, output)
    }

    /// Partition name derived from the extracted directory's file name.
    pub fn partition_name(&self) -> Result<String> {
        let name = self
            .extracted_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("partition directory has no valid name"))?;
        ensure!(!name.is_empty(), "partition directory name is empty");
        Ok(name.to_owned())
    }
}

/// Builder for [`Config`].
#[derive(Debug, Clone)]
#[must_use]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a builder with defaults: ext4, all entries, no dry-run.
    pub fn new(extracted_dir: impl Into<PathBuf>, output: impl Into<PathBuf>) -> Self {
        Self {
            config: Config {
                extracted_dir: extracted_dir.into(),
                output: output.into(),
                fstype: FilesystemType::Ext4,
                mode: GenerationMode::All,
                vendor_bin_context: SelinuxContext::new("vendor_qti_init_shell_exec"),
                system_bin_context: SelinuxContext::new("system_file"),
                dry_run: false,
            },
        }
    }

    /// Set the filesystem conventions.
    pub fn fstype(mut self, fstype: FilesystemType) -> Self {
        self.config.fstype = fstype;
        self
    }

    /// Restrict generation to `bin/` entries.
    pub fn mode(mut self, mode: GenerationMode) -> Self {
        self.config.mode = mode;
        self
    }

    /// Override the context for vendor/odm `bin/` files.
    pub fn vendor_bin_context(mut self, context: &str) -> Self {
        self.config.vendor_bin_context = SelinuxContext::new(context);
        self
    }

    /// Override the context for system `bin/` files.
    pub fn system_bin_context(mut self, context: &str) -> Self {
        self.config.system_bin_context = SelinuxContext::new(context);
        self
    }

    /// Enable or disable dry-run mode.
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.config.dry_run = dry_run;
        self
    }

    /// Validate and finish the configuration.
    pub fn build(self) -> Result<Config> {
        ensure!(
            self.config.extracted_dir.is_dir(),
            "partition directory does not exist: {}",
            self.config.extracted_dir.display()
        );
        Ok(self.config)
    }
}

/// Options exposed through the dumprs CLI for sidecar emission.
#[derive(Debug, Clone)]
pub struct FsMetadataOptions {
    /// Filesystem conventions used for directory rules.
    pub fstype: FilesystemType,
    /// Restrict generation to `bin/` entries.
    pub mode: GenerationMode,
    /// Override for the vendor/odm `bin/` context.
    pub vendor_bin_context: Option<String>,
    /// Override for the system `bin/` context.
    pub system_bin_context: Option<String>,
    /// Count entries without writing files.
    pub dry_run: bool,
    /// Optional override for the `config` directory root.
    pub config_root: Option<PathBuf>,
}

impl Default for FsMetadataOptions {
    fn default() -> Self {
        Self {
            fstype: FilesystemType::Ext4,
            mode: GenerationMode::All,
            vendor_bin_context: None,
            system_bin_context: None,
            dry_run: false,
            config_root: None,
        }
    }
}

/// Helpers shared by the two generators.
pub(crate) fn is_vendor_like(partition: &str) -> bool {
    PartitionKind::from_name(partition) == PartitionKind::VendorLike
}

/// Whether `path` has `component` as a non-final component.
pub(crate) fn has_component(path: &Path, component: &str) -> bool {
    path.components()
        .any(|c| c.as_os_str().eq_ignore_ascii_case(component))
}

/// Whether `path` has `component` followed by at least one more component.
pub(crate) fn has_component_with_child(path: &Path, component: &str) -> bool {
    let components: Vec<_> = path.components().collect();
    components
        .iter()
        .position(|c| c.as_os_str() == component)
        .is_some_and(|i| i + 1 < components.len())
}

/// Whether `path` has the component sequence `first/second` followed by a child.
pub(crate) fn has_components_with_child(path: &Path, first: &str, second: &str) -> bool {
    let components: Vec<_> = path.components().collect();
    components.iter().enumerate().any(|(i, c)| {
        c.as_os_str() == first
            && components
                .get(i + 1)
                .is_some_and(|c| c.as_os_str() == second)
            && i + 2 < components.len()
    })
}
