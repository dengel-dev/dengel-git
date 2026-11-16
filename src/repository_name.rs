//! Canonical ASCII URL slugs for Git organizations and repositories.

/// The URL grammar uses ASCII, which is already in Unicode NFC.
pub fn normalize_slug(raw: &str) -> Option<String> {
    if raw.len() > 48
        || raw
            .split('-')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_slugs_preserve_the_address_grammar() {
        assert_eq!(normalize_slug("Team-42").as_deref(), Some("team-42"));
        for invalid in ["", "foo/bar", "foo--bar", "repo.git", "Föö"] {
            assert_eq!(normalize_slug(invalid), None);
        }
        assert_eq!(normalize_slug(&"a".repeat(49)), None);
    }
}
