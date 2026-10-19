use sociacl_core::NodeId;

/// Locked s3r.ch Gun root. Do not invent a second graph.
pub const S3RCH_ROOT: &str = "s3rch";
/// Locked user collection: `gun.get('s3rch').get('users').get(wallet)`.
pub const S3RCH_USERS: &str = "users";
/// Locked feed collection: `gun.get('s3rch').get('items').get(<id>)`.
pub const S3RCH_ITEMS: &str = "items";
/// Locked seed meta: `gun.get('s3rch').get('meta')`. Not a Check object.
pub const S3RCH_META: &str = "meta";
/// Dest ACL collection. Sibling of items/users/meta. Not a Check
/// object. Grants HAM-merge here; they do not fork items or users.
pub const S3RCH_ACL: &str = "acl";

/// Gun soul path. Maps onto an existing [`NodeId`].
///
/// Identity is a wallet: `s3rch/users/<wallet>`. A claim on that
/// identity graph is a protected object. This is not a second user
/// node and not a second graph schema.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GunSoul {
    pub(crate) segments: Vec<String>,
}

impl GunSoul {
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
/// `s3rch/items/<id>`. Claims use the claim id (linked
/// from the user node; not a second user).
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GunNode {
    pub soul: GunSoul,
    pub kind: GunNodeKind,
}

impl GunNode {
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
