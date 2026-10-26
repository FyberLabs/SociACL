use sociacl_core::{NodeId, Timestamp};
use sociacl_ids::{derive_external_id, ObjectId, PrincipalId, SourceKey};

use crate::leaf::{normalize_permalink, split_tags, UrlLeaf};
use crate::GunError;

/// Locked feed source. `from_gun_node` refuses anything else.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FeedSource {
    Rss3,
    Rss,
    Atom,
}

impl FeedSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rss3 => "rss3",
            Self::Rss => "rss",
            Self::Atom => "atom",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "rss3" => Some(Self::Rss3),
            "rss" => Some(Self::Rss),
            "atom" => Some(Self::Atom),
            _ => None,
        }
    }
}

/// UX item. Tags are a list. Not stored in Gun as-is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeedItem {
    pub id: String,
    pub source: FeedSource,
    pub kind: String,
    pub author: String,
    pub body: String,
    pub ts: u64,
    pub permalink: String,
    pub tags: Vec<String>,
    pub provenance: String,
}

/// In-graph feed node. This is a native SociACL Check object.
/// Gun stores `tags` as a comma-separated string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GunFeedNode {
    pub id: String,
    pub source: String,
    pub kind: String,
    pub author: String,
    pub body: String,
    pub ts: u64,
    pub permalink: String,
    pub tags: String,
    pub provenance: String,
}

impl FeedItem {
    /// Dedupe: canonical id, else normalized permalink. Same as s3r.ch
    /// `canonicalKey`. The provider item id is not trimmed. `"x"` and
    /// `" x"` stay different, and the spaced id is rejected by
    /// `derive_external_id`.
    pub fn canonical_key(&self) -> Option<String> {
        if !self.id.is_empty() {
            return Some(self.id.clone());
        }
        let permalink = self.permalink.trim();
        if permalink.is_empty() {
            return None;
        }
        normalize_permalink(permalink)
            .ok()
            .or_else(|| Some(permalink.to_string()))
            .filter(|s| !s.is_empty())
    }

    /// Check object id. `ext_` derived from the source key and the provider item id.
    pub fn object_id(&self, source: &SourceKey) -> Result<ObjectId, GunError> {
        let item = self.canonical_key().ok_or(GunError::UrlLeafNotANode)?;
        derive_external_id(source, &item).map_err(|_| GunError::ObjectNotInGraph)
    }

    /// The plane node for this item. Not the Gun `s3rch/items/…` spelling.
    pub fn as_node_id(&self, source: &SourceKey) -> Option<NodeId> {
        self.object_id(source)
            .ok()
            .map(|id| NodeId::new(id.as_ref()))
    }

    /// Permalink is a URL leaf on the item. It is not the Check object.
    pub fn permalink_leaf(&self) -> Result<UrlLeaf, GunError> {
        UrlLeaf::parse(&self.permalink)
    }
}

impl GunFeedNode {
    /// Check object id for this Gun node. The provider item id is not trimmed.
    pub fn object_id(&self, source: &SourceKey) -> Result<ObjectId, GunError> {
        derive_external_id(source, &self.id).map_err(|_| GunError::ObjectNotInGraph)
    }

    pub fn as_node_id(&self, source: &SourceKey) -> Result<NodeId, GunError> {
        self.object_id(source)
            .map(|id| NodeId::new(id.as_ref()))
    }

    pub fn permalink_leaf(&self) -> Result<UrlLeaf, GunError> {
        UrlLeaf::parse(&self.permalink)
    }
}

/// s3r.ch `toGunNode`.
pub fn to_gun_node(item: &FeedItem) -> GunFeedNode {
    GunFeedNode {
        id: item.id.clone(),
        source: item.source.as_str().to_string(),
        kind: item.kind.clone(),
        author: item.author.clone(),
        body: item.body.clone(),
        ts: item.ts,
        permalink: item.permalink.clone(),
        tags: item.tags.join(","),
        provenance: item.provenance.clone(),
    }
}

/// s3r.ch `fromGunNode`. Unknown `source` is not a feed node.
pub fn from_gun_node(node: &GunFeedNode) -> Option<FeedItem> {
    if node.id.is_empty() {
        return None;
    }
    let source = FeedSource::parse(&node.source)?;
    let kind = as_text(&node.kind);
    Some(FeedItem {
        id: node.id.clone(),
        source,
        kind: if kind.is_empty() {
            "activity".to_string()
        } else {
            kind
        },
        author: as_text(&node.author),
        body: as_text(&node.body),
        ts: node.ts,
        permalink: as_text(&node.permalink),
        tags: split_tags(&node.tags),
        provenance: as_text(&node.provenance),
    })
}

fn as_text(s: &str) -> String {
    s.trim().to_string()
}

/// Locked user node. `indicators` are held-claim texts (`ens:…` /
/// `unstoppable:…` / `fc:…` / `lens:…` / `rss3:…`). Gun stores them
/// as a comma-separated string. This node is not a core-plane principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GunUserNode {
    pub id: String,
    pub indicators: Vec<String>,
    pub provenance: String,
    pub ts: u64,
}

impl GunUserNode {
    pub fn indicators_as_csv(&self) -> String {
        self.indicators.join(",")
    }

    pub fn indicators_from_csv(s: &str) -> Vec<String> {
        split_tags(s)
    }

    /// Held-claim CheckObjectIds linked from this user. Each id is
    /// the claim id itself. Same Mesh Check path as a feed item id.
    pub fn linked_claim_ids(&self) -> &[String] {
        &self.indicators
    }
}

/// Locked later claim kinds. Issuers prove a claim to the holder.
/// They are not grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum IdentityClaimKind {
    Wallet,
    Rss3,
    Ens,
    KycAttestation,
    Email,
    Phone,
}

impl IdentityClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Rss3 => "rss3",
            Self::Ens => "ens",
            Self::KycAttestation => "kyc_attestation",
            Self::Email => "email",
            Self::Phone => "phone",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "wallet" => Some(Self::Wallet),
            "rss3" => Some(Self::Rss3),
            "ens" => Some(Self::Ens),
            "kyc_attestation" => Some(Self::KycAttestation),
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            _ => None,
        }
    }

    /// Email / phone / KYC issuers are off-graph URLs until dest
    /// re-authorizes a Gun-native claim.
    pub fn issuer_is_url(self) -> bool {
        matches!(self, Self::KycAttestation | Self::Email | Self::Phone)
    }
}

/// Unsigned see-grant data. This value does not establish ownership or admit
/// a grant. Use signed mesh rows and an admitted object record for Check.
/// The object and the accessor are already-parsed ids. A wallet string
/// is not an accessor. A Gun item path is not the object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentitySeeGrant {
    pub object: ObjectId,
    pub accessor: PrincipalId,
    pub from: Timestamp,
    pub until: Timestamp,
}

impl IdentitySeeGrant {
    pub fn names_object(&self, object: &NodeId) -> bool {
        self.object.as_ref() == object.as_str()
    }

    pub fn names_accessor(&self, accessor: &NodeId) -> bool {
        self.accessor.as_ref() == accessor.as_str()
    }

    /// `now ∈ [from, until)` at dest Check. `until` is exclusive, same
    /// as keep-operating `delegate`. `from` is inclusive.
    pub fn live_at(&self, now: Timestamp) -> bool {
        now.0 >= self.from.0 && now.0 < self.until.0
    }
}

/// Locked later tab. UX only. Not a Check object.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FeedTab {
    Public,
    Mine,
    Network,
}

impl FeedTab {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Mine => "mine",
            Self::Network => "network",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "public" => Some(Self::Public),
            "mine" => Some(Self::Mine),
            "network" => Some(Self::Network),
            _ => None,
        }
    }
}

/// `gun.get('s3rch').get('meta')`. Seed peer cache. Not a Check object.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FeedMeta {
    pub seeded_at: Option<String>,
    pub sources_ok: u32,
    pub sources_tried: u32,
    pub error: Option<String>,
    pub count: u32,
}

/// Off-graph HTTP. Crossing is an edge handoff. Not a Gun node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OffGraphKind {
    Rss3,
    Rss,
    Atom,
    KycIssuer,
    EmailIssuer,
    PhoneIssuer,
}

impl OffGraphKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rss3 => "rss3",
            Self::Rss => "rss",
            Self::Atom => "atom",
            Self::KycIssuer => "kyc_issuer",
            Self::EmailIssuer => "email_issuer",
            Self::PhoneIssuer => "phone_issuer",
        }
    }
}

