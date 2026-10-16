//! Light Check used after a presentation is open.
//!
//! This is the destination decision for an opened private grant. It does
//! not change `sociacl-gun`, and it does not take a hop or a wrap. A hop
//! that names LightIFF, ITAR, or a SaaS channel is refused by the caller
//! before this function runs. A normal hop is not an argument here, so it
//! cannot flip `allowed`.

use crate::grant::{GrantStated, SignedGrantPayload};

/// Group or circle predicate. Direct edges only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupPredicate {
    SameGroup,
    NamedCircle,
}

impl GroupPredicate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameGroup => "same-group",
            Self::NamedCircle => "named-circle",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSetName {
    pub object: String,
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub stated: GrantStated,
    pub ham_state: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshMembership {
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub accessor: String,
    pub stated: GrantStated,
    pub ham_state: u64,
}

/// Plaintext grant the graph may still hold. It does not decide a private row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySeeGrant {
    pub claim_id: String,
    pub accessor: String,
    pub from: u64,
    pub until: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedGroup {
    pub predicate: GroupPredicate,
    pub set_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    pub allowed: bool,
    pub reason: String,
}

impl CheckResult {
    pub fn allow(reason: &str) -> Self {
        Self {
            allowed: true,
            reason: reason.to_string(),
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: reason.to_string(),
        }
    }
}

/// Live graph the destination reads. The presenter does not supply it.
pub trait SeeGraph {
    fn has_object(&self, object: &str) -> bool;
    fn owner_of(&self, object: &str) -> Option<&str>;
    fn see_grants(&self, object: &str) -> &[IdentitySeeGrant];
    fn object_version(&self, object: &str) -> Option<u64>;
    fn snapshot_hash(&self, object: &str) -> Option<&str>;
    fn object_set(&self, object: &str) -> Option<ObjectSetName> {
        let _ = object;
        None
    }
    fn membership(
        &self,
        predicate: GroupPredicate,
        set_id: &str,
        accessor: &str,
    ) -> Option<MeshMembership> {
        let _ = (predicate, set_id, accessor);
        None
    }
}

/// Direct group or circle edge. Hop is not an argument.
pub fn check_group_see(
    graph: &impl SeeGraph,
    predicate: GroupPredicate,
    object: &str,
    accessor: &str,
    now: u64,
) -> CheckResult {
    let _ = now;
    if closed_object(object).is_some() {
        return CheckResult::deny(closed_object(object).unwrap_or("missing"));
    }
    let Some(set) = graph.object_set(object) else {
        return CheckResult::deny("membership");
    };
    if set.predicate != predicate || set.set_id.is_empty() || set.stated != GrantStated::Live {
        return CheckResult::deny("membership");
    }
    let Some(edge) = graph.membership(predicate, &set.set_id, accessor) else {
        return CheckResult::deny("membership");
    };
    if edge.predicate != predicate
        || edge.set_id != set.set_id
        || edge.accessor != accessor
        || edge.stated != GrantStated::Live
    {
        return CheckResult::deny("membership");
    }
    CheckResult::allow(predicate.as_str())
}

/// Allow only from the opened payload, the owner path, or a live direct edge.
///
/// Plaintext `see_grants` are read and then ignored. A plaintext cancel
/// does not cancel a private row, and a plaintext grant does not mint one.
pub fn check_opened_grant(
    graph: &impl SeeGraph,
    payload: &SignedGrantPayload,
    accessor: &str,
    now: u64,
    group: Option<&PresentedGroup>,
) -> CheckResult {
    let _plaintext = graph.see_grants(&payload.object);
    if let Some(reason) = closed_object(&payload.object) {
        return CheckResult::deny(reason);
    }
    if !graph.has_object(&payload.object) {
        return CheckResult::deny("missing");
    }
    if accessor != payload.accessor {
        return CheckResult::deny("missing");
    }
    let payload_live =
        payload.stated == GrantStated::Live && payload.from <= now && now < payload.until;
    let is_owner = graph.owner_of(&payload.object) == Some(payload.owner.as_str())
        && accessor == payload.owner;

    if let Some(group) = group {
        if is_owner && payload_live {
            return CheckResult::allow("owner");
        }
        let edge = check_group_see(graph, group.predicate, &payload.object, accessor, now);
        if edge.allowed && payload_live {
            return edge;
        }
        if !payload_live {
            return CheckResult::deny(if payload.stated == GrantStated::Cancelled {
                "cancelled"
            } else {
                "window"
            });
        }
        return CheckResult::deny("membership");
    }

    if !payload_live {
        return CheckResult::deny(if payload.stated == GrantStated::Cancelled {
            "cancelled"
        } else {
            "window"
        });
    }
    if is_owner {
        return CheckResult::allow("owner");
    }
    CheckResult::allow("delegate")
}

fn closed_object(object: &str) -> Option<&'static str> {
    let object = object.trim();
    if object == "s3rch/meta" || object == "meta" {
        return Some("meta");
    }
    if object == "s3rch/acl" || object.starts_with("s3rch/acl/") {
        return Some("acl");
    }
    if object.starts_with("http://") || object.starts_with("https://") {
        return Some("url-leaf");
    }
    None
}

/// Named channels this tree does not implement.
pub fn hop_forbidden(name: &str) -> bool {
    let value = name.trim().to_ascii_lowercase();
    if value.is_empty() {
        return false;
    }
    matches!(
        value.as_str(),
        "lightiff"
            | "light-iff"
            | "light_iff"
            | "field-iff"
            | "fieldiff"
            | "field_iff"
            | "iff"
            | "waveform"
            | "itar"
            | "saas"
            | "flash"
            | "ping"
            | "nearby"
            | "loud"
            | "silence"
    ) || value.contains("lightiff")
        || value.contains("light-iff")
        || value.contains("light_iff")
        || value.contains("itar")
}

/// Optional hop. Bytes or a channel name. Never an allow by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HopFactor {
    Bytes(Vec<u8>),
    Channel { name: String },
}

impl HopFactor {
    pub fn forbidden(&self) -> bool {
        match self {
            Self::Bytes(bytes) => hop_forbidden(&String::from_utf8_lossy(bytes)),
            Self::Channel { name } => hop_forbidden(name),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffHint {
    pub principal: String,
    pub target: String,
    pub verb: Option<String>,
    pub context: Option<String>,
}
