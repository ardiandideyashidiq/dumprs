//! Regex escaping for `file_contexts` paths.

use std::borrow::Cow;

/// Characters that carry regex meaning in SELinux `file_contexts`.
const REGEX_SPECIAL: &[char] = &[
    '[', ']', '.', '^', '$', '*', '+', '?', '{', '}', '|', '(', ')',
];

/// Escape regex metacharacters in a path.
///
/// Returns a borrow when no escaping is needed, so the common case allocates
/// nothing. The character set matches RomTools' upstream behaviour (a literal
/// backslash is deliberately not escaped).
#[must_use]
pub fn escape_regex(value: &str) -> Cow<'_, str> {
    if !value.chars().any(|c| REGEX_SPECIAL.contains(&c)) {
        return Cow::Borrowed(value);
    }

    let mut escaped = String::with_capacity(value.len() * 2);
    for c in value.chars() {
        if REGEX_SPECIAL.contains(&c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    Cow::Owned(escaped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_plain_paths_borrowed() {
        let result = escape_regex("system/bin/foo");
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "system/bin/foo");
    }

    #[test]
    fn escapes_regex_metacharacters() {
        assert_eq!(escape_regex("app/a.b(c)").as_ref(), r"app/a\.b\(c\)");
    }

    #[test]
    fn handles_empty_input() {
        assert_eq!(escape_regex("").as_ref(), "");
    }
}
