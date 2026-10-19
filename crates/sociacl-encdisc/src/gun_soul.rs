//! Private copy of the gun dest-ACL soul helpers.
//!
//! PR 6 deletes this module when encrypted discovery stops validating
//! legacy grant souls. It is not the typed see path.

fn escape_key(id: &str, slash: bool) -> String {
    let mut out = String::with_capacity(id.len());
    for ch in id.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '.' => out.push_str("~1"),
            '#' => out.push_str("~2"),
            '$' => out.push_str("~3"),
            '[' => out.push_str("~4"),
            ']' => out.push_str("~5"),
            '/' if slash => out.push_str("~6"),
            _ => out.push(ch),
        }
    }
    out
}

fn ascii_trim(text: &str) -> &str {
    text.trim_matches(|ch: char| matches!(ch, '\t' | '\n' | '\u{000B}' | '\u{000C}' | '\r' | ' '))
}

fn is_format_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

fn bare_principal(id: &str) -> Option<String> {
    if id.is_empty()
        || id == "."
        || id == ".."
        || id == "..."
        || id.chars().count() > 256
        || id.contains(".get(")
        || id.contains(['/', '#', '$', '[', ']', '~', ' '])
        || id
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || is_format_char(ch))
    {
        return None;
    }
    Some(id.to_string())
}

pub(crate) fn acl_key(id: &str) -> String {
    escape_key(ascii_trim(id), true)
}

pub(crate) fn acl_principal_key(id: &str) -> Option<String> {
    let id = ascii_trim(id);
    if id.is_empty() || id.contains(".get(") {
        return None;
    }
    let parts: Vec<&str> = id
        .split('/')
        .map(ascii_trim)
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() == 3 && parts[0] == "s3rch" && parts[1] == "users" {
        return bare_principal(parts[2]);
    }
    if id.contains('/') {
        return None;
    }
    bare_principal(id)
}

/// Five-segment dest-ACL grant soul, or `None` when a principal does not parse.
pub(crate) fn grant_soul(owner: &str, object: &str, accessor: &str) -> Option<String> {
    let owner = acl_principal_key(owner)?;
    let accessor = acl_principal_key(accessor)?;
    let object = acl_key(object);
    let segments = [
        "s3rch",
        "acl",
        owner.as_str(),
        object.as_str(),
        accessor.as_str(),
    ];
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    Some(segments.join("/"))
}
