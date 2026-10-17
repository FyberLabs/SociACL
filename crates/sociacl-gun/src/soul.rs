use sociacl_core::NodeId;

/// Locked s3r.ch Gun root. Do not invent a second graph.
pub const S3RCH_ROOT: &str = "s3rch";
/// Locked user collection: `gun.get('s3rch').get('users').get(wallet)`.
pub const S3RCH_USERS: &str = "users";
/// Locked feed collection: `gun.get('s3rch').get('items').get(encodeKey(id))`.
pub const S3RCH_ITEMS: &str = "items";
/// Locked seed meta: `gun.get('s3rch').get('meta')`. Not a Check object.
pub const S3RCH_META: &str = "meta";
/// Dest ACL collection. Sibling of items/users/meta. Not a Check
/// object. Grants HAM-merge here; they do not fork items or users.
pub const S3RCH_ACL: &str = "acl";

/// Injective path escape. `~` is the escape character.
/// `. # $ [ ]` each get their own form. `/` stays here so an item
/// soul does not gain a new spelling of a slash-bearing id.
pub fn encode_key(id: &str) -> String {
    escape_key(id, false)
}

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

/// Reverse of [`acl_key`]. A bad escape is not a set id.
pub(crate) fn unescape_acl_key(id: &str) -> Option<String> {
    let mut out = String::with_capacity(id.len());
    let mut chars = id.chars();
    while let Some(ch) = chars.next() {
        if ch != '~' {
            out.push(ch);
            continue;
        }
        let decoded = match chars.next()? {
            '0' => '~',
            '1' => '.',
            '2' => '#',
            '3' => '$',
            '4' => '[',
            '5' => ']',
            '6' => '/',
            _ => return None,
        };
        out.push(decoded);
    }
    Some(out)
}

/// Gun soul path. Maps onto an existing [`NodeId`].
///
/// Identity is a wallet: `s3rch/users/<wallet>`. A claim on that
/// identity graph is a protected object. This is not a second user
/// node and not a second graph schema.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GunSoul {
    segments: Vec<String>,
}

impl GunSoul {
    pub fn new(segments: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            segments: segments
                .into_iter()
                .map(|s| ascii_trim(s.as_ref()).to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        }
    }

    /// `gun.get('s3rch').get('users').get(wallet)`.
    pub fn s3rch_user(wallet: impl AsRef<str>) -> Self {
        Self::new([S3RCH_ROOT, S3RCH_USERS, wallet.as_ref()])
    }

    /// `gun.get('s3rch').get('items').get(encodeKey(id))`.
    pub fn s3rch_item(id: impl AsRef<str>) -> Self {
        Self::new([S3RCH_ROOT, S3RCH_ITEMS, &encode_key(id.as_ref())])
    }

    /// `gun.get('s3rch').get('meta')`.
    pub fn s3rch_meta() -> Self {
        Self::new([S3RCH_ROOT, S3RCH_META])
    }

    /// Owner dest-ACL root.
    /// `gun.get('s3rch').get('acl').get(aclPrincipalKey(owner))`.
    pub fn s3rch_acl(owner: impl AsRef<str>) -> Self {
        let Some(owner) = acl_principal_key(owner.as_ref()) else {
            return Self {
                segments: Vec::new(),
            };
        };
        Self::new([S3RCH_ROOT, S3RCH_ACL, &owner])
    }

    /// Jointly stated see grant under the object owner's dest ACL.
    /// Does not fork `items` or `users`.
    ///
    /// `gun.get('s3rch').get('acl').get(aclPrincipalKey(owner))
    ///     .get(aclKey(object)).get(aclPrincipalKey(accessor))`
    pub fn s3rch_acl_grant(
        owner: impl AsRef<str>,
        object: impl AsRef<str>,
        accessor: impl AsRef<str>,
    ) -> Self {
        let Some(owner) = acl_principal_key(owner.as_ref()) else {
            return Self {
                segments: Vec::new(),
            };
        };
        let Some(accessor) = acl_principal_key(accessor.as_ref()) else {
            return Self {
                segments: Vec::new(),
            };
        };
        Self::new([
            S3RCH_ROOT,
            S3RCH_ACL,
            &owner,
            &acl_key(object.as_ref()),
            &accessor,
        ])
    }

    /// Slash form. A string containing `.get(` is rejected.
    /// Does not verify the graph.
    pub fn parse(s: &str) -> Result<Self, crate::GunError> {
        let s = ascii_trim(s);
        if s.is_empty() || s.contains(".get(") {
            return Err(crate::GunError::HintCorrupt);
        }
        let soul = Self::new(s.split('/'));
        if soul.segments.is_empty() {
            return Err(crate::GunError::HintCorrupt);
        }
        Ok(soul)
    }

    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    pub fn as_node_id(&self) -> NodeId {
        NodeId::new(self.segments.join("/"))
    }

    pub fn is_s3rch_user(&self) -> bool {
        self.segments.len() == 3
            && self.segments[0] == S3RCH_ROOT
            && self.segments[1] == S3RCH_USERS
    }

    pub fn is_s3rch_item(&self) -> bool {
        self.segments.len() == 3
            && self.segments[0] == S3RCH_ROOT
            && self.segments[1] == S3RCH_ITEMS
    }

    pub fn is_s3rch_meta(&self) -> bool {
        self.segments.len() == 2 && self.segments[0] == S3RCH_ROOT && self.segments[1] == S3RCH_META
    }

    /// Any dest-ACL soul (`s3rch/acl/…`). Not a Check object.
    pub fn is_s3rch_acl(&self) -> bool {
        self.segments.len() >= 2 && self.segments[0] == S3RCH_ROOT && self.segments[1] == S3RCH_ACL
    }

    /// Five-segment grant node under dest ACL.
    pub fn is_s3rch_acl_grant(&self) -> bool {
        self.segments.len() == 5 && self.is_s3rch_acl()
    }

    pub fn wallet(&self) -> Option<&str> {
        if self.is_s3rch_user() {
            Some(self.segments[2].as_str())
        } else {
            None
        }
    }
}

/// Dest-ACL path key. The same escape as [`encode_key`], plus `/`,
/// so a grant soul stays five segments. `room.alpha`, `room_alpha`,
/// and `room/alpha` are three keys. Not a second spelling of an item.
pub fn acl_key(id: &str) -> String {
    escape_key(ascii_trim(id), true)
}

/// ASCII whitespace only. U+FEFF and U+0085 stay, so this trim matches
/// TypeScript. Unicode whitespace and format characters are rejected
/// later by [`bare_principal`].
pub(crate) fn ascii_trim(text: &str) -> &str {
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

/// A bare principal, or `None`. `.` may occur inside an id. The whole
/// id cannot be `.` or `..`. `/ # $ [ ] ~`, controls, Unicode
/// whitespace, format characters, and `.get(` are rejected. Longer
/// than 256 scalar values is rejected. Never `Some("")`.
fn bare_principal(id: &str) -> Option<String> {
    if id.is_empty()
        || id == "."
        || id == ".."
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

/// Owner / accessor key on dest ACL. An exact `s3rch/users/<wallet>`
/// collapses to that wallet. Anything else must be a bare principal.
/// `None` is not a soul segment. [`encode_key`] is for object keys.
pub fn acl_principal_key(id: &str) -> Option<String> {
    let id = ascii_trim(id);
    if id.is_empty() || id.contains(".get(") {
        return None;
    }
    let parts: Vec<&str> = id
        .split('/')
        .map(ascii_trim)
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() == 3 && parts[0] == S3RCH_ROOT && parts[1] == S3RCH_USERS {
        return bare_principal(parts[2]);
    }
    if id.contains('/') {
        return None;
    }
    bare_principal(id)
}

/// One accessor id. A user soul `s3rch/users/<wallet>` and the wallet
/// are this key. See and post writes, cancels, and lookups use it.
pub fn canonical_accessor_id(id: &str) -> Option<String> {
    acl_principal_key(id)
}

/// What a soul names on the locked graph. A user is a wallet.
/// A feed item or a held claim is the Check object. Not a second
/// identity node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum GunNodeKind {
    User,
    Feed,
    Claim,
}

/// Gun node mapped onto [`NodeId`]. Users use the locked
/// `s3rch/users/<wallet>` soul. Feed items use
/// `s3rch/items/<encodeKey(id)>`. Claims use the claim id (linked
/// from the user node; not a second user).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GunNode {
    pub soul: GunSoul,
    pub kind: GunNodeKind,
}

impl GunNode {
    pub fn user(wallet: impl AsRef<str>) -> Self {
        Self {
            soul: GunSoul::s3rch_user(wallet),
            kind: GunNodeKind::User,
        }
    }

    /// In-graph feed item. Same Check path as a held claim.
    pub fn feed(id: impl AsRef<str>) -> Self {
        Self {
            soul: GunSoul::s3rch_item(id),
            kind: GunNodeKind::Feed,
        }
    }

    /// Held claim. The CheckObjectId is the claim id itself
    /// (`ens:…` / `unstoppable:…` / `fc:…` / `lens:…` / `rss3:…`),
    /// linked from the user node's indicators. Do not invent
    /// `s3rch/users/<wallet>/claims/…`.
    pub fn claim(id: impl AsRef<str>) -> Self {
        Self {
            soul: GunSoul::new([id.as_ref()]),
            kind: GunNodeKind::Claim,
        }
    }

    pub fn as_node_id(&self) -> NodeId {
        self.soul.as_node_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_keys_for_dot_underscore_and_slash_stay_distinct() {
        let dot = acl_key("room.alpha");
        let under = acl_key("room_alpha");
        let slash = acl_key("room/alpha");
        assert_ne!(dot, under);
        assert_ne!(dot, slash);
        assert_ne!(under, slash);
        assert_eq!(encode_key("a/b"), "a/b");
        assert_ne!(acl_key("a/b"), acl_key("a_b"));
        assert_eq!(acl_key("room~1alpha"), "room~01alpha");
        assert_ne!(acl_key("room.alpha"), acl_key("room~1alpha"));
    }

    #[test]
    fn a_principal_is_not_run_through_the_object_escape() {
        assert_eq!(acl_principal_key("bob.name").as_deref(), Some("bob.name"));
        assert_eq!(
            acl_principal_key(acl_principal_key("bob.name").unwrap().as_str()).as_deref(),
            Some("bob.name")
        );
        assert_ne!(acl_key(&acl_key("room.alpha")), acl_key("room.alpha"));
    }

    #[test]
    fn a_gun_chain_is_not_the_inner_wallet() {
        let spoof = "0xattacker.get('s3rch').get('users').get('0xvictim')";
        assert!(GunSoul::parse(spoof).is_err());
        assert_eq!(canonical_accessor_id(spoof), None);
    }

    #[test]
    fn a_rejected_principal_is_not_a_grant_path() {
        assert_eq!(crate::grant_soul("0xalice", "doc", "0xbob/x"), None);
        assert_eq!(crate::grant_soul("0xalice/doc", "0xbob", "x"), None);
        assert_eq!(
            crate::grant_soul("0xalice", "doc", "0xbob")
                .unwrap()
                .as_str(),
            "s3rch/acl/0xalice/doc/0xbob"
        );
        assert_eq!(crate::acl_soul("../meta"), None);
        assert_eq!(canonical_accessor_id("a\u{0}b"), None);
        assert_eq!(crate::post_soul("0xalice", "doc", "a\u{0}b"), None);
        assert_eq!(canonical_accessor_id("bob~name"), None);
        assert_eq!(canonical_accessor_id("x~1get('s3rch')"), None);
        assert_eq!(canonical_accessor_id("."), None);
        assert_eq!(canonical_accessor_id(".."), None);
        assert_eq!(canonical_accessor_id("0x bob"), None);
        assert_eq!(canonical_accessor_id(&"a".repeat(257)), None);
        let capped = "a".repeat(256);
        assert_eq!(
            canonical_accessor_id(&capped).as_deref(),
            Some(capped.as_str())
        );
        assert_eq!(canonical_accessor_id("\u{FEFF}0xvictim"), None);
        assert_eq!(canonical_accessor_id("0xvictim\u{FEFF}"), None);
        assert_eq!(canonical_accessor_id("\u{0085}0xvictim"), None);
        assert_eq!(
            canonical_accessor_id("bob.name").as_deref(),
            Some("bob.name")
        );
        assert_eq!(
            canonical_accessor_id("s3rch/users/0xbob").as_deref(),
            Some("0xbob")
        );
    }
}
