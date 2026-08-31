use sociacl_core::NodeId;

use crate::GunError;

/// Non-Gun pointer. A permalink, RSS3 GI, RSS/Atom, or issuer HTTP
/// URL is a leaf, not a Gun node and not an ACL grant. Crossing it
/// is an edge handoff. Destination re-authorizes on the way back.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UrlLeaf {
    raw: String,
    normalized: String,
}

impl UrlLeaf {
    pub fn parse(url: impl AsRef<str>) -> Result<Self, GunError> {
        let raw = url.as_ref().trim().to_string();
        let normalized = normalize_permalink(&raw)?;
        Ok(Self { raw, normalized })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    /// Always false. A URL is not in-graph.
    pub fn is_gun_node(&self) -> bool {
        false
    }

    /// Always `None`. A leaf cannot be a Check object.
    pub fn as_node_id(&self) -> Option<NodeId> {
        None
    }
}

/// Locked s3r.ch item shape. Consume; do not fork. Gun stores `tags`
/// as a comma-separated string. Dedup key is `id` else the normalized
/// permalink. This is not a second graph schema and not an ACL grant.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ItemShape {
    pub id: Option<String>,
    pub source: Option<String>,
    pub kind: Option<String>,
    pub author: Option<String>,
    pub body: Option<String>,
    pub ts: Option<u64>,
    pub permalink: Option<UrlLeaf>,
    pub tags: Vec<String>,
    pub provenance: Option<String>,
}

impl ItemShape {
    /// Gun stores tags as a comma-separated string. Same normalize
    /// as s3r.ch: trim, lowercase, dedupe.
    pub fn tags_from_csv(s: &str) -> Vec<String> {
        split_tags(s)
    }

    pub fn tags_as_csv(&self) -> String {
        self.tags.join(",")
    }

    /// Dedup key: `id` else normalized permalink URL.
    pub fn dedup_key(&self) -> Option<String> {
        if let Some(id) = self.id.as_ref() {
            let id = id.trim();
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
        self.permalink.as_ref().map(|u| u.normalized().to_string())
    }
}

/// s3r.ch `splitTags` / `normalizeTags`: trim, lowercase, dedupe.
pub fn split_tags(value: &str) -> Vec<String> {
    normalize_tags(value.split(',').map(|t| t.to_string()))
}

pub fn normalize_tags(tags: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for raw in tags {
        let tag = raw.as_ref().trim().to_ascii_lowercase();
        if tag.is_empty() || !seen.insert(tag.clone()) {
            continue;
        }
        out.push(tag);
    }
    out
}

/// Lowercase scheme and host. Drop fragment. Drop a trailing slash
/// that is not the root. Only `http` and `https`.
pub fn normalize_permalink(raw: &str) -> Result<String, GunError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(GunError::InvalidUrl);
    }
    let s = s.split('#').next().unwrap_or(s);
    let (scheme, rest) = s.split_once("://").ok_or(GunError::InvalidUrl)?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(GunError::InvalidUrl);
    }
    if rest.is_empty() {
        return Err(GunError::InvalidUrl);
    }
    let (hostport, pathq) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if hostport.is_empty() {
        return Err(GunError::InvalidUrl);
    }
    let hostport = hostport.to_ascii_lowercase();
    let mut pathq = pathq.to_string();
    if pathq.ends_with('/') && pathq != "/" {
        pathq.pop();
    }
    if pathq.is_empty() {
        Ok(format!("{scheme}://{hostport}"))
    } else {
        Ok(format!("{scheme}://{hostport}{pathq}"))
    }
}
