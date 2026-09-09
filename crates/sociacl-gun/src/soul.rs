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

/// s3r.ch `encodeKey`: replace `. # $ [ ]` with `_`.
pub fn encode_key(id: &str) -> String {
    id.chars()
        .map(|c| match c {
            '.' | '#' | '$' | '[' | ']' => '_',
            _ => c,
        })
        .collect()
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
                .map(|s| s.as_ref().trim().to_string())
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
        Self::new([S3RCH_ROOT, S3RCH_ACL, &acl_principal_key(owner.as_ref())])
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
        Self::new([
            S3RCH_ROOT,
            S3RCH_ACL,
            &acl_principal_key(owner.as_ref()),
            &acl_key(object.as_ref()),
            &acl_principal_key(accessor.as_ref()),
        ])
    }

    /// Slash or `gun.get('a').get('b')` form. Does not verify the graph.
    pub fn parse(s: &str) -> Result<Self, crate::GunError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(crate::GunError::HintCorrupt);
        }
        let soul = if s.contains(".get(") {
            parse_gun_gets(s)?
        } else {
            Self::new(s.split('/'))
        };
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

fn parse_gun_gets(s: &str) -> Result<GunSoul, crate::GunError> {
    let mut segments = Vec::new();
    let mut rest = s.trim();
    while let Some(i) = rest.find(".get(") {
        rest = &rest[i + 5..];
        let quote = rest.chars().next().ok_or(crate::GunError::HintCorrupt)?;
        if quote != '\'' && quote != '"' {
            return Err(crate::GunError::HintCorrupt);
        }
        rest = &rest[1..];
        let end = rest.find(quote).ok_or(crate::GunError::HintCorrupt)?;
        let part = rest[..end].trim();
        if part.is_empty() {
            return Err(crate::GunError::HintCorrupt);
        }
        segments.push(part.to_string());
        rest = rest[end + 1..].trim_start();
        if rest.starts_with(')') {
            rest = rest[1..].trim_start();
        }
    }
    if segments.is_empty() {
        return Err(crate::GunError::HintCorrupt);
    }
    Ok(GunSoul { segments })
}

/// Dest-ACL path key. `encodeKey` then `/` → `_` so a grant soul
/// stays five segments when the object id still contains slashes
/// (`rss3:act/1_x`, `s3rch/items/…`). Not a second `encodeKey` for
/// items or users — those keep the locked replace-only rule.
pub fn acl_key(id: &str) -> String {
    encode_key(id.trim()).replace('/', "_")
}

/// Owner / accessor key on dest ACL. A locked user soul collapses
/// to the wallet. Anything else is [`acl_key`].
pub fn acl_principal_key(id: &str) -> String {
    let id = id.trim();
    if let Ok(soul) = GunSoul::parse(id) {
        if let Some(wallet) = soul.wallet() {
            return encode_key(wallet);
        }
    }
    acl_key(id)
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
