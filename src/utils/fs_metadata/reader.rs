//! Reading existing sidecar entries for deduplication.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Read the first whitespace-separated token of every line.
///
/// Existing lines are never rewritten; only their keys are collected so the
/// generators can avoid emitting duplicates. Missing files are treated as an
/// empty set, matching upstream behaviour.
pub fn read_existing_keys(path: &Path) -> Result<HashSet<String>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to open {}", path.display()));
        }
    };

    let mut keys = HashSet::new();
    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("failed to read {}", path.display()))?;
        if let Some(key) = line.split_whitespace().next() {
            keys.insert(key.to_owned());
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn reads_first_token_of_each_line() {
        let dir = std::env::temp_dir().join(format!("dumprs-reader-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file_contexts");
        fs::write(
            &path,
            "/system/bin/foo u:object_r:system_file:s0\n\n# comment\n",
        )
        .unwrap();

        let keys = read_existing_keys(&path).unwrap();
        assert!(keys.contains("/system/bin/foo"));
        assert!(keys.contains("#"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_file_is_empty_set() {
        let path = Path::new("/nonexistent/dumprs/file_contexts");
        assert!(read_existing_keys(path).unwrap().is_empty());
    }
}
