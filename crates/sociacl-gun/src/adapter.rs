use sociacl_core::{
    Action, ActionMask, AttestationFactor, Capability, CheckRequest, CheckResult, Client,
    ElectResult, NodeId, Plane, SocialLightStatement, Timestamp, VerbError, Zookie,
};

use crate::{
    FeedItem, GunError, GunFeedNode, GunNode, GunSoul, HandoffHint, IdentitySeeGrant, SEE,
};

/// `see` is Check `read` on a Gun-native object (feed item or claim).
pub fn map_action(verb: &str) -> Action {
    match verb.trim() {
        SEE | "read" | "r" => Action::new("read"),
        "execute" | "exec" | "x" => Action::new("execute"),
        "write" | "w" => Action::new("write"),
        other => Action::new(other),
    }
}

/// Destination Check plus the presented hint. The hint never sets
/// `allowed` by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GunCheckResult {
    pub allowed: bool,
    pub reason: sociacl_core::PredicateId,
    pub zookie: Zookie,
    pub attestation_factor: Option<AttestationFactor>,
    /// Untrusted hint that was presented. Missing does not fail Check.
    pub hint: Option<HandoffHint>,
}

impl GunCheckResult {
    /// A hint is a factor at most. Always false.
    pub fn hint_is_grant(&self) -> bool {
        false
    }

    pub fn from_check(result: CheckResult, hint: Option<HandoffHint>) -> Self {
        Self {
            allowed: result.allowed,
            reason: result.reason,
            zookie: result.zookie,
            attestation_factor: result.attestation_factor,
            hint,
        }
    }
}

/// Decode / accept an untrusted hint. Does not verify. Does not mint.
pub fn accept_hint(hint: HandoffHint) -> HandoffHint {
    hint
}

/// Decode hint bytes. Does not verify. Does not mint.
pub fn accept_hint_bytes(bytes: &[u8]) -> Result<HandoffHint, GunError> {
    HandoffHint::decode(bytes)
}

/// Destination Plane Check against the live ACL. A hint alone fails
/// closed. A Social Light hop, if present, is the same optional factor
/// as keep-operating delegate: missing hop does not fail Check; a hop
/// alone does not mint.
pub fn check(
    plane: &Plane,
    action: impl AsRef<str>,
    object: impl Into<NodeId>,
    accessor: impl Into<NodeId>,
    hint: Option<&HandoffHint>,
    hop: Option<&SocialLightStatement>,
) -> Result<GunCheckResult, sociacl_core::CheckError> {
    let request = CheckRequest {
        action: map_action(action.as_ref()),
        object: object.into(),
        accessor: accessor.into(),
        predicate: None,
        zookie: None,
        attestation: None,
    };
    let result = match hop {
        Some(statement) => plane.check_social_light(request, statement)?,
        None => plane.check(request)?,
    };
    Ok(GunCheckResult::from_check(result, hint.cloned()))
}

/// `CHECK(see, object, accessor)` at now. Object is a Gun-native
/// feed item or held claim.
pub fn check_see(
    plane: &Plane,
    object: impl Into<NodeId>,
    accessor: impl Into<NodeId>,
    hint: Option<&HandoffHint>,
) -> Result<GunCheckResult, sociacl_core::CheckError> {
    check(plane, SEE, object, accessor, hint, None)
}

/// Dest Check AND the jointly-stated `[from, until)` window.
/// `from` denies until `plane.now()` is in range — dest `until`
/// alone is not enough. Hop can factor dest Check; it cannot mint.
pub fn check_see_grant(
    plane: &Plane,
    grant: &IdentitySeeGrant,
    object: impl Into<NodeId>,
    accessor: impl Into<NodeId>,
    hint: Option<&HandoffHint>,
) -> Result<GunCheckResult, sociacl_core::CheckError> {
    let object = object.into();
    let accessor = accessor.into();
    let dest = check_see(plane, object.clone(), accessor.clone(), hint)?;
    if !grant.names_object(&object)
        || !grant.names_accessor(&accessor)
        || !grant.live_at(plane.now())
    {
        return Ok(GunCheckResult {
            allowed: false,
            reason: dest.reason,
            zookie: dest.zookie,
            attestation_factor: dest.attestation_factor,
            hint: dest.hint,
        });
    }
    Ok(dest)
}

/// Execute-without-read uses the existing `delegate` mask. Not Elect.
pub fn check_execute(
    plane: &Plane,
    object: impl Into<NodeId>,
    accessor: impl Into<NodeId>,
    hint: Option<&HandoffHint>,
) -> Result<GunCheckResult, sociacl_core::CheckError> {
    check(plane, "execute", object, accessor, hint, None)
}

/// Remint may refresh only if the current ACL already names the
/// principal. A hint does not name them.
pub fn remint(
    plane: &Plane,
    object: impl Into<NodeId>,
    principal: impl Into<NodeId>,
    hint: Option<&HandoffHint>,
) -> Result<Capability, VerbError> {
    let _ = hint;
    plane.remint(object, principal)
}

/// Cancel stays on the destination ACL: owner undelegate / unstate.
pub fn cancel(
    plane: &mut Plane,
    owner: impl Into<NodeId>,
    principal: impl Into<NodeId>,
    object: impl Into<NodeId>,
) -> Result<(), VerbError> {
    plane.undelegate(owner, principal, object)
}

/// Elect from a hop / hint / delegate remains refuse-closed.
pub fn elect_from_hint(
    _plane: &mut Plane,
    _object: impl Into<NodeId>,
    _hint: &HandoffHint,
) -> Result<ElectResult, GunError> {
    Err(GunError::ElectFromHint)
}

/// Elect from a live delegate grant uses the existing refuse (keep-
/// operating suffices). Owner stays owner.
pub fn elect_from_delegate(
    plane: &mut Plane,
    object: impl Into<NodeId>,
) -> Result<ElectResult, VerbError> {
    plane.elect(object)
}

/// Case C Check against the frozen bundle. Same dest ACL. No mint.
pub fn client_check(
    client: &Client,
    action: impl AsRef<str>,
    object: impl Into<NodeId>,
    accessor: impl Into<NodeId>,
    hint: Option<&HandoffHint>,
    hop: Option<&SocialLightStatement>,
) -> Result<GunCheckResult, sociacl_core::CheckError> {
    let request = CheckRequest {
        action: map_action(action.as_ref()),
        object: object.into(),
        accessor: accessor.into(),
        predicate: None,
        zookie: None,
        attestation: None,
    };
    let result = match hop {
        Some(statement) => client.check_social_light(request, statement)?,
        None => client.check(request)?,
    };
    Ok(GunCheckResult::from_check(result, hint.cloned()))
}

pub fn client_remint(
    client: &Client,
    object: impl Into<NodeId>,
    principal: impl Into<NodeId>,
) -> Result<Capability, VerbError> {
    client.remint(object, principal)
}

/// Visible refuse. Case C has no mint path for new Gun grants.
pub fn client_mint_grant(
    _client: &mut Client,
    _owner: impl Into<NodeId>,
    _principal: impl Into<NodeId>,
    _object: impl Into<NodeId>,
    _actions: ActionMask,
    _until: Option<Timestamp>,
) -> Result<(), GunError> {
    Err(GunError::ClientHasNoMintPath)
}

pub fn client_elect_from_hint(
    _client: &mut Client,
    _object: impl Into<NodeId>,
    _hint: &HandoffHint,
) -> Result<ElectResult, GunError> {
    Err(GunError::ElectFromHint)
}

/// Enroll the locked wallet identity as a person. One user node.
pub fn add_wallet(plane: &mut Plane, wallet: impl AsRef<str>) -> NodeId {
    plane
        .add_person(GunSoul::s3rch_user(wallet).as_node_id())
        .id
}

/// Held claim on the destination plane. Default predicate is `owner`.
pub fn add_claim(plane: &mut Plane, claim: impl AsRef<str>, owner: impl Into<NodeId>) -> NodeId {
    plane
        .add_object(GunNode::claim(claim).as_node_id(), owner)
        .id
}

/// Admit a Gun-native feed item. Destination re-authorizes before
/// this put. A permalink / RSS3 / RSS / KYC URL is not the object.
pub fn add_item(
    plane: &mut Plane,
    item: &FeedItem,
    owner: impl Into<NodeId>,
) -> Result<NodeId, GunError> {
    let id = item.as_node_id().ok_or(GunError::UrlLeafNotANode)?;
    Ok(plane.add_object(id, owner).id)
}

pub fn add_feed_node(plane: &mut Plane, node: &GunFeedNode, owner: impl Into<NodeId>) -> NodeId {
    plane.add_object(node.as_node_id(), owner).id
}

/// `IdentitySeeGrant` is keep-operating `delegate` read with `until`.
/// Not Elect. Privilege-down is `cancel` / undelegate. `from` is
/// enforced at Check, not by delaying the dest edge.
pub fn apply_see_grant(
    plane: &mut Plane,
    owner: impl Into<NodeId>,
    grant: &IdentitySeeGrant,
) -> Result<(), VerbError> {
    let object = resolve_grant_object(plane, grant)?;
    plane.jointly_delegate(
        owner,
        grant.accessor_id(),
        object,
        ActionMask::read(),
        Some(grant.until),
    )
}

fn resolve_grant_object(plane: &Plane, grant: &IdentitySeeGrant) -> Result<NodeId, VerbError> {
    let object = grant.object_id();
    if plane.object(&object).is_some() {
        return Ok(object);
    }
    let item = GunSoul::s3rch_item(grant.claim_id.trim()).as_node_id();
    if plane.object(&item).is_some() {
        return Ok(item);
    }
    Err(VerbError::ObjectNotFound(object))
}
