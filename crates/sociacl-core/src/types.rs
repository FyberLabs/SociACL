use std::fmt;
use std::sync::Arc;

/// Monotonic caller-supplied time. Seconds or ticks; the plane does not sleep.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp(pub u64);

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct NodeId(Arc<str>);

impl NodeId {
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(Arc::from(id.as_ref()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<&str> for NodeId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for NodeId {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&NodeId> for NodeId {
    fn from(id: &NodeId) -> Self {
        id.clone()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum NodeKind {
    Person,
    Agent,
    Device,
    Group,
    Circle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    pub id: NodeId,
    pub kind: NodeKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Device {
    pub id: NodeId,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectVersion(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Object {
    pub id: NodeId,
    pub owner: NodeId,
    pub version: ObjectVersion,
    pub destroyed: bool,
    /// Dropped on DESTROY. Placeholder for cryptographic erasure.
    pub content_key: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Relation {
    Owns,
    MemberOf,
    InCircle,
    ObjectGroup,
    ObjectCircle,
}

impl Relation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owns => "owns",
            Self::MemberOf => "member-of",
            Self::InCircle => "in-circle",
            Self::ObjectGroup => "object-group",
            Self::ObjectCircle => "object-circle",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "owns" => Some(Self::Owns),
            "member-of" => Some(Self::MemberOf),
            "in-circle" => Some(Self::InCircle),
            "object-group" => Some(Self::ObjectGroup),
            "object-circle" => Some(Self::ObjectCircle),
            _ => None,
        }
    }
}

/// Jointly stated edge. Live for Check only when both sides have stated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub relation: Relation,
    pub from_stated: bool,
    pub to_stated: bool,
}

impl Edge {
    pub fn is_jointly_stated(&self) -> bool {
        self.from_stated && self.to_stated
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PredicateId(Arc<str>);

impl PredicateId {
    pub const OWNER: &'static str = "owner";
    pub const SAME_GROUP: &'static str = "same-group";
    pub const NAMED_CIRCLE: &'static str = "named-circle";

    pub fn new(id: impl AsRef<str>) -> Self {
        Self(Arc::from(id.as_ref()))
    }

    pub fn owner() -> Self {
        Self::new(Self::OWNER)
    }

    pub fn same_group() -> Self {
        Self::new(Self::SAME_GROUP)
    }

    pub fn named_circle() -> Self {
        Self::new(Self::NAMED_CIRCLE)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_named(&self) -> bool {
        matches!(
            self.as_str(),
            Self::OWNER | Self::SAME_GROUP | Self::NAMED_CIRCLE
        )
    }
}

impl From<&str> for PredicateId {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl fmt::Display for PredicateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Action(Arc<str>);

impl Action {
    pub fn new(id: impl AsRef<str>) -> Self {
        Self(Arc::from(id.as_ref()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Action {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verb {
    Check,
    Remint,
    Discover,
    Elect,
    Destroy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Clock {
    KeepOperating,
    Elect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthnState {
    Live,
    Gone,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WillTemplate {
    MilitaryRank,
    CorporateSuccession,
    Custom(String),
}

impl WillTemplate {
    pub fn as_str(&self) -> &str {
        match self {
            Self::MilitaryRank => "military-rank",
            Self::CorporateSuccession => "corporate-succession",
            Self::Custom(s) => s,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WillDisposition {
    Heir(NodeId),
    StaySecret,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Will {
    pub object: NodeId,
    pub testator: NodeId,
    pub template: WillTemplate,
    pub disposition: WillDisposition,
    pub written_at: Timestamp,
    pub cancelable_by: Vec<NodeId>,
    pub canceled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    pub principal: NodeId,
    pub object: NodeId,
    pub zookie: crate::cache::Zookie,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoverResult {
    Heir(NodeId),
    StaySecret,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElectResult {
    pub new_owner: NodeId,
    pub clock: Clock,
    /// Live principals who may cancel. Not a public vacancy list.
    pub notify: Vec<NodeId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestroyResult {
    pub object: NodeId,
    pub erased: bool,
}

/// After a cut, only pre-positioned wills and client-held shares work.
/// New edges stated after `cut_at` must not grant.
///
/// Case C: type only. The plane does not evaluate offline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CutBoundary {
    pub cut_at: Timestamp,
}

/// Client-held share for continuity of command after the plane is gone.
///
/// Case C: type only. Reconstruction and offline Check are not implemented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHeldShare {
    pub object: NodeId,
    pub share_hash: [u8; 32],
}
