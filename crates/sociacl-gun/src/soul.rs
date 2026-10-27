use sociacl_core::NodeId;

/// Locked s3r.ch Gun root. Do not invent a second graph.
pub const S3RCH_ROOT: &str = "s3rch";
/// Locked feed collection segment. A Check object is not this path.
pub(crate) const S3RCH_ITEMS: &str = "items";
/// Locked seed meta: `gun.get('s3rch').get('meta')`. Not a Check object.
pub const S3RCH_META: &str = "meta";
/// Dest ACL collection. Sibling of items/users/meta. Not a Check
/// object. Grants HAM-merge here; they do not fork items or users.
pub const S3RCH_ACL: &str = "acl";
/// Forum collection. Status, needs, and role rows live here.
/// Chat does not. A forum path is not a dest-ACL grant soul.
pub const S3RCH_FORUMS: &str = "forums";

/// Gun soul path. Maps onto an existing [`NodeId`].
/// A parsed path is not a Check object id.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GunSoul {
    pub(crate) segments: Vec<String>,
}

impl GunSoul {
    pub fn new(segments: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            segments: segments
                .into_iter()
                .map(|segment| segment.as_ref().to_string())
                .filter(|segment| !segment.is_empty())
                .collect(),
        }
    }

    /// `gun.get('s3rch').get('meta')`.
    pub fn s3rch_meta() -> Self {
        Self::new([S3RCH_ROOT, S3RCH_META])
    }

    /// Slash form. A string containing `.get(` is rejected. Nothing is trimmed.
    pub fn parse(s: &str) -> Result<Self, crate::GunError> {
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

    /// Slash form of the parsed segments. Nothing is trimmed.
    pub fn join(&self) -> String {
        self.segments.join("/")
    }

    pub fn as_node_id(&self) -> NodeId {
        NodeId::new(self.segments.join("/"))
    }

    pub fn is_s3rch_user(&self) -> bool {
        self.segments.len() == 3 && self.segments[0] == S3RCH_ROOT && self.segments[1] == "users"
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

/// What a soul names on the locked graph. A held claim is the
/// claim text, not a second identity node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum GunNodeKind {
    Claim,
}

/// Gun node mapped onto [`NodeId`]. A claim uses the claim id
/// linked from the user node's indicators.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GunNode {
    pub soul: GunSoul,
    pub kind: GunNodeKind,
}

impl GunNode {
    /// Held claim. The Check object is `claim_` derived from this text.
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
