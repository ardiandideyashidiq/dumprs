//! Reading generated sidecars back into metadata for the repack writer.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Parsed `fs_config` entry for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsConfigEntry {
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Full `st_mode`-style permission bits (type + permission).
    pub mode: u16,
    /// Optional `capabilities=` value.
    pub capabilities: Option<String>,
    /// Symlink target, when the entry describes a symlink.
    pub symlink_target: Option<String>,
}

/// A `file_contexts` rule with a simplified matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRule {
    /// Unescaped path pattern without the partition prefix.
    pattern: String,
    /// Whether the pattern ends with `(/.*)?` and thus matches descendants.
    recursive: bool,
    /// SELinux context.
    context: String,
}

/// Metadata loaded from both sidecars.
#[derive(Debug, Clone, Default)]
pub struct SidecarMetadata {
    fs_config: HashMap<String, FsConfigEntry>,
    contexts: Vec<ContextRule>,
}

impl SidecarMetadata {
    /// Load both sidecars for a partition. Missing files yield empty metadata.
    pub fn load(
        fs_config_path: Option<&Path>,
        file_contexts_path: Option<&Path>,
        partition: &str,
    ) -> Result<Self> {
        let fs_config = match fs_config_path {
            Some(path) => parse_fs_config(path, partition)?,
            None => HashMap::new(),
        };
        let contexts = match file_contexts_path {
            Some(path) => parse_file_contexts(path, partition)?,
            None => Vec::new(),
        };
        Ok(Self {
            fs_config,
            contexts,
        })
    }

    /// Look up the configured metadata for a path relative to the partition root.
    #[must_use]
    pub fn config(&self, relative: &str) -> Option<&FsConfigEntry> {
        self.fs_config.get(relative)
    }

    /// Find the most specific SELinux context for a relative path.
    #[must_use]
    pub fn context(&self, relative: &str) -> Option<&str> {
        self.contexts
            .iter()
            .filter(|rule| {
                if rule.recursive {
                    rule.pattern.is_empty()
                        || relative == rule.pattern
                        || relative.starts_with(&rule.pattern)
                            && relative.as_bytes().get(rule.pattern.len()) == Some(&b'/')
                } else {
                    relative == rule.pattern
                }
            })
            .max_by_key(|rule| rule.pattern.len())
            .map(|rule| rule.context.as_str())
    }
}

/// Parse a `fs_config` sidecar into a path → entry map.
pub fn parse_fs_config(path: &Path, partition: &str) -> Result<HashMap<String, FsConfigEntry>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let prefix = format!("{partition}/");
    let mut result = HashMap::new();

    for (line_no, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let full_path = fields
            .next()
            .with_context(|| format!("{}:{}: missing path", path.display(), line_no + 1))?;
        let relative = full_path.strip_prefix(&prefix).unwrap_or(full_path);
        let uid = parse_decimal(fields.next(), path, line_no, "uid")?;
        let gid = parse_decimal(fields.next(), path, line_no, "gid")?;
        let mode = parse_octal(fields.next(), path, line_no, "mode")?;

        let mut capabilities = None;
        let mut symlink_target = None;
        for field in fields {
            if let Some(value) = field.strip_prefix("capabilities=") {
                capabilities = Some(value.to_owned());
            } else {
                symlink_target = Some(field.to_owned());
            }
        }
        result.insert(
            relative.to_owned(),
            FsConfigEntry {
                uid,
                gid,
                mode: mode as u16,
                capabilities,
                symlink_target,
            },
        );
    }
    Ok(result)
}

fn parse_decimal(field: Option<&str>, path: &Path, line_no: usize, name: &str) -> Result<u32> {
    let field =
        field.with_context(|| format!("{}:{}: missing {name}", path.display(), line_no + 1))?;
    field.parse::<u32>().with_context(|| {
        format!(
            "{}:{}: invalid {name}: {field}",
            path.display(),
            line_no + 1
        )
    })
}

fn parse_octal(field: Option<&str>, path: &Path, line_no: usize, name: &str) -> Result<u32> {
    let field =
        field.with_context(|| format!("{}:{}: missing {name}", path.display(), line_no + 1))?;
    u32::from_str_radix(field, 8).with_context(|| {
        format!(
            "{}:{}: invalid {name}: {field}",
            path.display(),
            line_no + 1
        )
    })
}

/// Parse a `file_contexts` sidecar into matcher rules.
pub fn parse_file_contexts(path: &Path, partition: &str) -> Result<Vec<ContextRule>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let prefix = format!("/{partition}/");
    let root_prefix = format!("/{partition}(/.*)?");
    let mut rules = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(pattern) = fields.next() else {
            continue;
        };
        let Some(context) = fields.next() else {
            continue;
        };

        let (recursive, stripped) = match pattern.strip_suffix("(/.*)?") {
            Some(base) => (true, base),
            None => (false, pattern),
        };
        let unescaped = unescape_regex(stripped);
        let root = format!("/{partition}");
        let relative = if unescaped == root_prefix || unescaped == root {
            String::new()
        } else {
            unescaped
                .strip_prefix(&prefix)
                .unwrap_or(&unescaped)
                .to_owned()
        };
        rules.push(ContextRule {
            pattern: relative,
            recursive,
            context: context.to_owned(),
        });
    }
    Ok(rules)
}

fn unescape_regex(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                result.push(next);
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("dumprs-sidecar-{}-{id}", std::process::id()))
    }

    #[test]
    fn parses_fs_config_entries() {
        let dir = temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fs_config");
        fs::write(
            &path,
            "system/bin/tool 0 2000 0755 capabilities=0x100000\nsystem/etc/x 0 0 0644\n",
        )
        .unwrap();
        let entries = parse_fs_config(&path, "system").unwrap();
        assert_eq!(entries["bin/tool"].gid, 2000);
        assert_eq!(entries["bin/tool"].mode, 0o755);
        assert_eq!(
            entries["bin/tool"].capabilities.as_deref(),
            Some("0x100000")
        );
        assert_eq!(entries["etc/x"].mode, 0o644);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn matches_nested_context_rules() {
        let dir = temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file_contexts");
        fs::write(
            &path,
            "/system(/.*)? u:object_r:system_file:s0\n/system/bin/tool u:object_r:tool_exec:s0\n",
        )
        .unwrap();
        let rules = parse_file_contexts(&path, "system").unwrap();
        let metadata = SidecarMetadata {
            fs_config: HashMap::new(),
            contexts: rules,
        };
        assert_eq!(
            metadata.context("bin/tool"),
            Some("u:object_r:tool_exec:s0")
        );
        assert_eq!(metadata.context("etc/x"), Some("u:object_r:system_file:s0"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_invalid_mode() {
        let dir = temp_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad");
        fs::write(&path, "system/x 0 0 not-octal\n").unwrap();
        assert!(parse_fs_config(&path, "system").is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
