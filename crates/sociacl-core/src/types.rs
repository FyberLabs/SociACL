use std::collections::BTreeMap;
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

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Agent => "agent",
            Self::Device => "device",
            Self::Group => "group",
            Self::Circle => "circle",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "person" => Some(Self::Person),
            "agent" => Some(Self::Agent),
            "device" => Some(Self::Device),
            "group" => Some(Self::Group),
            "circle" => Some(Self::Circle),
            _ => None,
        }
    }
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

/// Protected-object kind. Devices can be Check targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    Data,
    Device,
}

impl ObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Device => "device",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "data" => Some(Self::Data),
            "device" => Some(Self::Device),
            _ => None,
        }
    }
}

/// Object property bag. `predicate` must name a Check predicate or Check fails closed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ObjectProperties {
    inner: BTreeMap<String, String>,
}

impl ObjectProperties {
    pub const PREDICATE: &'static str = "predicate";
    pub const GROUP: &'static str = "group";
    pub const CIRCLE: &'static str = "circle";
    pub const MODE: &'static str = "mode";

    pub fn new() -> Self {
        Self::default()
    }

    pub fn owner() -> Self {
        let mut p = Self::new();
        p.set(Self::PREDICATE, PredicateId::OWNER);
        p
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.inner.get(key).map(String::as_str)
    }

    pub fn set(&mut self, key: impl AsRef<str>, value: impl AsRef<str>) {
        self.inner
            .insert(key.as_ref().to_string(), value.as_ref().to_string());
    }

    pub fn named_predicate(&self) -> Option<PredicateId> {
        self.get(Self::PREDICATE).map(PredicateId::new)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.inner.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn posix_mode(&self) -> Option<PosixMode> {
        PosixMode::parse(self.get(Self::MODE)?)
    }
}

/// POSIX owner / group / other bits. Used only by `posix-mode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PosixBits {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl PosixBits {
    pub fn from_octal_digit(d: u32) -> Self {
        Self {
            read: d & 4 != 0,
            write: d & 2 != 0,
            execute: d & 1 != 0,
        }
    }

    pub fn allows(&self, action: &Action) -> bool {
        match action.as_str() {
            "read" | "r" => self.read,
            "write" | "w" => self.write,
            "execute" | "exec" | "x" => self.execute,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PosixMode {
    pub owner: PosixBits,
    pub group: PosixBits,
    pub other: PosixBits,
}

impl PosixMode {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let n = if let Some(rest) = s.strip_prefix("0o") {
            u32::from_str_radix(rest, 8).ok()?
        } else {
            u32::from_str_radix(s, 8).ok()?
        };
        if n > 0o777 {
            return None;
        }
        Some(Self {
            owner: PosixBits::from_octal_digit((n >> 6) & 7),
            group: PosixBits::from_octal_digit((n >> 3) & 7),
            other: PosixBits::from_octal_digit(n & 7),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Object {
    pub id: NodeId,
    pub kind: ObjectKind,
    pub owner: NodeId,
    pub version: ObjectVersion,
    pub destroyed: bool,
    /// Dropped on DESTROY. Placeholder for cryptographic erasure.
    pub content_key: Option<[u8; 32]>,
    pub properties: ObjectProperties,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Relation {
    Owns,
    MemberOf,
    InCircle,
    ObjectGroup,
    ObjectCircle,
    /// Person-to-person. One-sided is a follow/request, not a grant.
    Friend,
    /// Named jointly stated edge. Check uses it only if the object names `trustee`.
    Trustee,
}

impl Relation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owns => "owns",
            Self::MemberOf => "member-of",
            Self::InCircle => "in-circle",
            Self::ObjectGroup => "object-group",
            Self::ObjectCircle => "object-circle",
            Self::Friend => "friend",
            Self::Trustee => "trustee",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "owns" => Some(Self::Owns),
            "member-of" => Some(Self::MemberOf),
            "in-circle" => Some(Self::InCircle),
            "object-group" => Some(Self::ObjectGroup),
            "object-circle" => Some(Self::ObjectCircle),
            "friend" | "follow" => Some(Self::Friend),
            "trustee" => Some(Self::Trustee),
            _ => None,
        }
    }
}

/// Directed edge with joint articulation. Check grants only when both sides
/// have stated and the privilege-up delay has elapsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub relation: Relation,
    pub from_stated: bool,
    pub to_stated: bool,
    /// Instant both sides first became jointly stated. None if one-sided.
    pub joint_at: Option<Timestamp>,
    /// Instant this edge may grant. Create/elect set it to `now`.
    /// Privilege-up sets it to `now + privilege_up_delay`.
    pub effective_at: Option<Timestamp>,
}

impl Edge {
    pub fn direction(&self) -> (&NodeId, &NodeId) {
        (&self.from, &self.to)
    }

    pub fn is_jointly_stated(&self) -> bool {
        self.from_stated && self.to_stated
    }

    pub fn is_one_sided(&self) -> bool {
        self.from_stated != self.to_stated
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PredicateId(Arc<str>);

impl PredicateId {
    pub const OWNER: &'static str = "owner";
    pub const SAME_GROUP: &'static str = "same-group";
    pub const NAMED_CIRCLE: &'static str = "named-circle";
    pub const POSIX_MODE: &'static str = "posix-mode";
    pub const TRUSTEE: &'static str = "trustee";
    pub const HEIR_TEMPLATE: &'static str = "heir-template";

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

    pub fn posix_mode() -> Self {
        Self::new(Self::POSIX_MODE)
    }

    pub fn trustee() -> Self {
        Self::new(Self::TRUSTEE)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Fixed Check list. `heir-template` is never named.
    pub fn is_named(&self) -> bool {
        matches!(
            self.as_str(),
            Self::OWNER | Self::SAME_GROUP | Self::NAMED_CIRCLE | Self::POSIX_MODE | Self::TRUSTEE
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

impl Clock {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeepOperating => "keep-operating",
            Self::Elect => "elect",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "keep-operating" => Some(Self::KeepOperating),
            "elect" => Some(Self::Elect),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthnState {
    Live,
    Gone,
}

impl AuthnState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Gone => "gone",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "live" => Some(Self::Live),
            "gone" => Some(Self::Gone),
            _ => None,
        }
    }
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
    /// Will elects among a pre-enrolled circle. Discover does not pick.
    ElectAmong {
        circle: NodeId,
    },
    StaySecret,
}

/// Recorded when `elect` starts. The plane does not sleep. Commit may
/// install only after `ready_at`. Expiry does not install an owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingElect {
    pub object: NodeId,
    pub candidate: NodeId,
    pub notify: Vec<NodeId>,
    pub started_at: Timestamp,
    pub ready_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ElectState {
    /// Notified. Owner has not changed.
    Pending {
        candidate: NodeId,
        ready_at: Timestamp,
    },
    /// Installed after the wait. Jointly stated `owns` edge.
    Installed { new_owner: NodeId },
}

impl ElectState {
    pub fn heir(&self) -> &NodeId {
        match self {
            Self::Pending { candidate, .. } => candidate,
            Self::Installed { new_owner } => new_owner,
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    pub fn is_installed(&self) -> bool {
        matches!(self, Self::Installed { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElectResult {
    pub clock: Clock,
    /// Live principals who may cancel. Not a public vacancy list.
    pub notify: Vec<NodeId>,
    pub state: ElectState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestroyResult {
    pub object: NodeId,
    pub erased: bool,
}

/// After a cut, only pre-positioned wills and client-held shares work.
/// New edges stated after `cut_at` must not grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CutBoundary {
    pub cut_at: Timestamp,
}

/// Client-held share for continuity of command after the plane is gone.
///
/// Issued only while the holder already had a right to the object.
/// Reconstruction verifies `share_hash` over the local key. Not Shamir.
/// Check does not read this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHeldShare {
    pub object: NodeId,
    pub holder: NodeId,
    pub share_hash: [u8; 32],
    /// Local key the holder already had. None after Destroy.
    pub key_material: Option<[u8; 32]>,
    pub held_at: Timestamp,
}
