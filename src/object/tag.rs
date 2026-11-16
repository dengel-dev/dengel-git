//! Annotated tag reference extraction - target oid and target kind, for
//! peeling (G2 ls-refs) and connectivity (G4). Everything else is opaque.
//!
//! Format source: git-reference/Documentation/git-mktag.adoc, "Tag
//! Format": "a very simple fixed format: four lines of `object <hash>` /
//! `type <typename>` / `tag <tagname>` / `tagger <tagger>`" followed by a
//! blank line and an optional free-form message. This is a stronger
//! citation than the commit case (gitdatamodel.adoc's commit example is
//! explicitly just an example) - git-mktag.adoc calls this order fixed,
//! so unlike commit::refs this parser requires "object" and "type" to be
//! exactly the first two lines rather than scanning defensively.

use super::{parse_oid_line, Kind, ObjectError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagRefs {
    pub object: String,
    pub kind: Kind,
}

/// Extracts the target from tag content (object body, no loose header).
pub fn refs(content: &[u8]) -> Result<TagRefs, ObjectError> {
    let mut lines = content.split(|&b| b == b'\n');

    let first = lines.next().unwrap_or(&[]);
    let object = parse_oid_line(first, b"object ").ok_or_else(|| ObjectError::Malformed {
        what: "tag",
        detail: format!(
            "first header line is not a valid object line: {:?}",
            String::from_utf8_lossy(first)
        ),
    })?;

    let second = lines.next().unwrap_or(&[]);
    let kind_bytes = second
        .strip_prefix(b"type ")
        .ok_or_else(|| ObjectError::Malformed {
            what: "tag",
            detail: format!(
                "second header line is not a type line: {:?}",
                String::from_utf8_lossy(second)
            ),
        })?;
    let kind_name = std::str::from_utf8(kind_bytes).map_err(|_| ObjectError::Malformed {
        what: "tag",
        detail: "type field is not utf8".to_string(),
    })?;
    let kind = Kind::from_name(kind_name).ok_or_else(|| ObjectError::Malformed {
        what: "tag",
        detail: format!("unknown object type: {:?}", kind_name),
    })?;

    Ok(TagRefs { object, kind })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OID: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn parses_object_and_type() {
        let content =
            format!("object {OID}\ntype commit\ntag v1.0.0\ntagger t <t@x> 0 +0000\n\nmsg\n");
        let refs = refs(content.as_bytes()).unwrap();
        assert_eq!(refs.object, OID);
        assert_eq!(refs.kind, Kind::Commit);
    }

    #[test]
    fn accepts_every_target_kind() {
        for (name, kind) in [
            ("blob", Kind::Blob),
            ("tree", Kind::Tree),
            ("commit", Kind::Commit),
            ("tag", Kind::Tag),
        ] {
            let content = format!("object {OID}\ntype {name}\n\n");
            assert_eq!(refs(content.as_bytes()).unwrap().kind, kind);
        }
    }

    #[test]
    fn missing_object_line_is_malformed() {
        let content = "type commit\n\n";
        assert!(refs(content.as_bytes()).is_err());
    }

    #[test]
    fn bad_kind_name_is_malformed() {
        let content = format!("object {OID}\ntype not-a-kind\n\n");
        assert!(refs(content.as_bytes()).is_err());
    }

    #[test]
    fn object_must_be_first_line() {
        let content = format!("type commit\nobject {OID}\n\n");
        assert!(refs(content.as_bytes()).is_err());
    }

    #[test]
    fn empty_content_is_malformed() {
        assert!(refs(&[]).is_err());
    }
}
