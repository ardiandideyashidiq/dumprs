//! EROFS image repacking from an extracted directory tree.
//!
//! The writer is provided by the MIT-licensed `rust-fs-erofs` crate. Metadata
//! comes from the `fs_config` and `file_contexts` sidecars produced by
//! [`crate::utils::fs_metadata`], so SELinux labels and ownership survive the
//! extract → edit → repack round trip.

use crate::utils::fs_metadata::sidecar::{FsConfigEntry, SidecarMetadata};
use anyhow::{Context, Result, anyhow};
use fs_erofs::mkfs::{BuildOptions, Content, Node, NodeMeta, XattrSpec, build_image_to};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::info;

/// Options for one EROFS repack operation.
#[derive(Debug, Clone)]
pub struct ErofsRepackOptions {
    /// Directory containing the extracted partition tree.
    pub input: PathBuf,
    /// Image file to write.
    pub output: PathBuf,
    /// Partition name used to interpret sidecar paths.
    pub partition: String,
    /// Optional `fs_config` sidecar.
    pub fs_config: Option<PathBuf>,
    /// Optional `file_contexts` sidecar.
    pub file_contexts: Option<PathBuf>,
    /// Block size as a power of two (12 = 4096 bytes).
    pub blkszbits: u8,
}

impl Default for ErofsRepackOptions {
    fn default() -> Self {
        Self {
            input: PathBuf::new(),
            output: PathBuf::new(),
            partition: "system".to_owned(),
            fs_config: None,
            file_contexts: None,
            blkszbits: 12,
        }
    }
}

/// Build an EROFS image and return its size in bytes.
///
/// # Errors
///
/// Returns an error if the input tree cannot be read, a sidecar is malformed,
/// the output cannot be created, or the writer rejects the tree.
pub fn repack_erofs(options: &ErofsRepackOptions) -> Result<u64> {
    anyhow::ensure!(options.input.is_dir(), "input directory does not exist");
    anyhow::ensure!(
        (9..=16).contains(&options.blkszbits),
        "invalid block size bits"
    );

    let metadata = SidecarMetadata::load(
        options.fs_config.as_deref(),
        options.file_contexts.as_deref(),
        &options.partition,
    )?;
    let root = build_node(&options.input, "", &metadata)?;

    let mut file = BufWriter::new(
        File::create(&options.output)
            .with_context(|| format!("failed to create {}", options.output.display()))?,
    );
    let size = build_image_to(root, options.blkszbits, BuildOptions::default(), &mut file)
        .map_err(|err| anyhow!("failed to build EROFS image: {err:?}"))?;
    file.flush()?;

    info!(
        partition = %options.partition,
        size,
        output = %options.output.display(),
        "erofs.repack.done"
    );
    Ok(size)
}

const TYPE_DIR: u16 = 0o040000;
const TYPE_FILE: u16 = 0o100000;
const TYPE_SYMLINK: u16 = 0o120000;
const TYPE_SPECIAL: u16 = 0o060000;

fn build_node(dir: &Path, relative: &str, metadata: &SidecarMetadata) -> Result<Node<'static>> {
    let mut entries = BTreeMap::new();
    let mut paths = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        paths.push(entry?.path());
    }
    paths.sort_unstable();

    for path in paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("non-UTF-8 file name in {}", path.display()))?
            .to_owned();
        let child_relative = if relative.is_empty() {
            name.clone()
        } else {
            format!("{relative}/{name}")
        };
        let file_type = path.symlink_metadata()?.file_type();
        let configured = metadata.config(&child_relative);
        let node_meta = node_meta(configured);
        let xattrs = selinux_xattrs(metadata.context(&child_relative))?;

        let node = if file_type.is_dir() {
            build_node(&path, &child_relative, metadata)?
        } else if file_type.is_symlink() {
            let target = fs::read_link(&path)?;
            Node::Symlink {
                mode: mode_with_type(configured, TYPE_SYMLINK, 0o777),
                target: target.to_string_lossy().into_owned(),
                meta: node_meta,
                xattrs,
            }
        } else if file_type.is_file() {
            let size = path.metadata()?.len();
            let source = path.clone();
            Node::StreamedFile {
                mode: mode_with_type(configured, TYPE_FILE, 0o644),
                content: Content::new(size, move || File::open(&source)),
                meta: node_meta,
                xattrs,
            }
        } else {
            Node::Special {
                mode: mode_with_type(configured, TYPE_SPECIAL, 0o644),
                meta: node_meta,
                xattrs,
            }
        };
        entries.insert(name, node);
    }

    let root_config = metadata.config(relative);
    Ok(Node::Dir {
        mode: mode_with_type(root_config, TYPE_DIR, 0o755),
        entries,
        meta: node_meta(root_config),
        xattrs: selinux_xattrs(metadata.context(relative))?,
    })
}

fn node_meta(configured: Option<&FsConfigEntry>) -> NodeMeta {
    let (uid, gid) = configured.map_or((0, 0), |entry| (entry.uid, entry.gid));
    NodeMeta {
        uid,
        gid,
        mtime: 0,
        mtime_nsec: 0,
    }
}

/// Sidecar modes may omit the file-type bits; add them when necessary.
fn mode_with_type(configured: Option<&FsConfigEntry>, kind: u16, default: u16) -> u16 {
    let raw = configured.map_or(default, |entry| entry.mode);
    if raw & 0o170000 == 0 { kind | raw } else { raw }
}

fn selinux_xattrs(context: Option<&str>) -> Result<Vec<XattrSpec>> {
    let Some(context) = context else {
        return Ok(Vec::new());
    };
    let mut value = context.as_bytes().to_vec();
    value.push(0);
    let spec = XattrSpec::from_full_name(b"security.selinux", value)
        .map_err(|err| anyhow!("invalid SELinux context xattr: {err:?}"))?;
    Ok(vec![spec])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_file_type_bits_when_missing() {
        assert_eq!(mode_with_type(None, TYPE_FILE, 0o644), 0o100644);
        assert_eq!(mode_with_type(None, TYPE_DIR, 0o755), 0o40755);
    }

    #[test]
    fn keeps_existing_type_bits() {
        let entry = FsConfigEntry {
            uid: 0,
            gid: 0,
            mode: 0o100755,
            capabilities: None,
            symlink_target: None,
        };
        assert_eq!(mode_with_type(Some(&entry), TYPE_FILE, 0o644), 0o100755);
    }

    #[test]
    fn builds_small_image() {
        let dir = std::env::temp_dir().join(format!("dumprs-erofs-{}", std::process::id()));
        let root = dir.join("system");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/tool"), b"hello").unwrap();
        let output = dir.join("system.erofs.img");
        let options = ErofsRepackOptions {
            input: root,
            output: output.clone(),
            partition: "system".to_owned(),
            ..Default::default()
        };
        let size = repack_erofs(&options).unwrap();
        assert!(size > 0);
        assert!(output.is_file());
        fs::remove_dir_all(dir).unwrap();
    }
}
