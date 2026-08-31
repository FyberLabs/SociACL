use sociacl_core::{NodeId, Timestamp};

use crate::leaf::{normalize_permalink, split_tags, UrlLeaf};
use crate::soul::{encode_key, GunSoul};
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
    /// `canonicalKey`.
    pub fn canonical_key(&self) -> Option<String> {
        let id = self.id.trim();
        if !id.is_empty() {
            return Some(id.to_string());
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

    /// `gun.get('s3rch').get('items').get(encodeKey(id))`.
    pub fn as_node_id(&self) -> Option<NodeId> {
        self.canonical_key()
            .map(|id| GunSoul::s3rch_item(id).as_node_id())
    }

    /// Permalink is a URL leaf on the item. It is not the Check object.
    pub fn permalink_leaf(&self) -> Result<UrlLeaf, GunError> {
        UrlLeaf::parse(&self.permalink)
    }
}

impl GunFeedNode {
    pub fn as_node_id(&self) -> NodeId {
        GunSoul::s3rch_item(&self.id).as_node_id()
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
    let id = node.id.trim();
    if id.is_empty() {
        return None;
    }
    let source = FeedSource::parse(&node.source)?;
    Some(FeedItem {
        id: id.to_string(),
        source,
        kind: as_text(&node.kind),
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

/// Locked later user node. `gun.get('s3rch').get('users').get(wallet)`.
/// Indicators are a list here; Gun stores them as a comma-separated
/// string. Not a second user schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GunUserNode {
    pub id: String,
    pub indicators: Vec<String>,
    pub provenance: String,
    pub ts: u64,
}

impl GunUserNode {
    pub fn as_node_id(&self) -> NodeId {
        GunSoul::s3rch_user(&self.id).as_node_id()
    }

    pub fn indicators_as_csv(&self) -> String {
        self.indicators.join(",")
    }

    pub fn indicators_from_csv(s: &str) -> Vec<String> {
        split_tags(s)
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

/// Locked later see-grant. Maps onto keep-operating `delegate` read.
/// hopcap 1. Jointly stated. Revoke is immediate. Not Elect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentitySeeGrant {
    pub claim_id: String,
    pub accessor: NodeId,
    pub from: Timestamp,
    pub until: Timestamp,
}

impl IdentitySeeGrant {
    pub fn object_id(&self) -> NodeId {
        if self.claim_id.contains('/') || self.claim_id.contains(".get(") {
            GunSoul::parse(&self.claim_id)
                .map(|s| s.as_node_id())
                .unwrap_or_else(|_| NodeId::new(self.claim_id.trim()))
        } else {
            NodeId::new(self.claim_id.trim())
        }
    }

    pub fn live_at(&self, now: Timestamp) -> bool {
        now.0 >= self.from.0 && now.0 < self.until.0
    }
}

/// Seed / snapshot meta. Not a Check object.
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

/// Encode a Gun item key. Same as s3r.ch `encodeKey`.
pub fn item_key(id: impl AsRef<str>) -> String {
    encode_key(id.as_ref())
}
