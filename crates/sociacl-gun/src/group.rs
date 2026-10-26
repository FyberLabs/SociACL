//! Direct `same-group` and `named-circle` rows.
//!
//! Hopcap is 1. Membership is live only when both v2 assents verify
//! under each party's present key, or a witnessed cancel applies.
//! One-sided membership is stored and is not a grant. A hop, a hint,
//! a wrap, a request, or an inbox delivery never grants.
//!
//! A set id is a minted ObjectId of kind `set`. The set owner is the
//! signed principal, and it is the principal embedded in that id.

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;
use sociacl_ids::{
    history_state, length_prefixed, membership_soul, object_principal, object_set_soul,
    parse_object_id, parse_principal_id, resolve_current_key, verify_acl_attestation,
    verify_key_signature, verify_signed_at, MembershipPredicate, ObjectId, PrincipalId, Reason,
    ResolutionContext, SignedAtMode,
};

use crate::mesh::{MeshCheckResult, MeshSeeGraph};
use crate::{
    HandoffHint, HopFactor, MESH_REASON_CANCELLED, MESH_REASON_MISSING, MESH_REASON_OWNER,
};

const MEMBER_DOMAIN: &str = "sociacl-membership-assent-v2";
const OBJECT_SET_DOMAIN: &str = "sociacl-object-set-v2";
const CANCEL_DOMAIN: &str = "sociacl-cancel-v2";
const MAX_SAFE: u64 = 9_007_199_254_740_991;

/// `same-group` or `named-circle`. The accessor does not pick a richer one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
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

    fn ids(self) -> MembershipPredicate {
        match self {
            Self::SameGroup => MembershipPredicate::SameGroup,
            Self::NamedCircle => MembershipPredicate::NamedCircle,
        }
    }
}

/// Direct membership. Hopcap 1. `stated` 1 is live, 0 is not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshMembership {
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub accessor: String,
    pub stated: u8,
    pub ham_state: u64,
}

impl MeshMembership {
    pub fn is_live(&self) -> bool {
        self.stated == 1
    }
}

/// The group or circle an object names. One predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectSetName {
    pub object: String,
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub stated: u8,
    pub ham_state: u64,
}

impl ObjectSetName {
    pub fn is_live(&self) -> bool {
        self.stated == 1
    }
}

/// Group or circle argument kept for callers that name a presentation.
/// Check takes the minted set id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresentedGroup {
    pub predicate: GroupPredicate,
    pub set_id: String,
}

/// Opened payload window. `check_group_see` does not read this.
/// `from` is inclusive and `until` is exclusive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedGroupPayload {
    pub stated: u8,
    pub from: u64,
    pub until: u64,
}

impl DecodedGroupPayload {
    pub fn live_at(&self, now: u64) -> bool {
        self.stated == 1 && now >= self.from && now < self.until
    }
}

/// Member row inside an ACL snapshot. Direct grants are not this row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSnapshotMember {
    pub accessor: String,
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub stated: u8,
    pub ham_state: u64,
}

/// Object-to-set edge inside an ACL snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSnapshotObjectSet {
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub stated: u8,
    pub ham_state: u64,
}

/// Result of the group tail of a presentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupPresentation {
    pub allowed: bool,
    pub reason: String,
    pub hint: Option<HandoffHint>,
    pub hop: Option<HopFactor>,
    /// A stated-0 payload may be stored on the verifier record
    /// even when `allowed` is false.
    pub store_cancel: bool,
}

impl GroupPresentation {
    pub fn hint_is_grant(&self) -> bool {
        false
    }

    pub fn hop_is_grant(&self) -> bool {
        false
    }

    pub fn hop_factored(&self) -> bool {
        self.allowed && self.hop.is_some()
    }
}

#[derive(Clone, Debug)]
struct StoredAssent {
    stated: u8,
    ham_state: u64,
    issued_at: u64,
    bytes: Vec<u8>,
    sig: String,
    attest: Option<String>,
    observed: Vec<String>,
}

#[derive(Clone, Debug)]
struct StoredCancel {
    id: String,
    prior: Vec<String>,
    signer: PrincipalId,
    issued_at: u64,
    bytes: Vec<u8>,
    sig: String,
    attest: Option<String>,
    mode: SignedAtMode,
}

#[derive(Clone, Debug)]
struct MembershipRecord {
    predicate: GroupPredicate,
    set: ObjectId,
    member: PrincipalId,
    set_owner: PrincipalId,
    member_assent: Option<StoredAssent>,
    set_assent: Option<StoredAssent>,
    cancels: BTreeMap<String, StoredCancel>,
}

#[derive(Clone, Debug)]
struct ObjectSetRecord {
    owner: PrincipalId,
    predicate: GroupPredicate,
    set: ObjectId,
    assent: Option<StoredAssent>,
    cancels: BTreeMap<String, StoredCancel>,
}

#[derive(Clone, Debug)]
struct MembershipAssent {
    role: &'static str,
    predicate: GroupPredicate,
    set: ObjectId,
    member: PrincipalId,
    set_owner: PrincipalId,
    stated: u8,
    ham_state: u64,
    issued_at: u64,
    cancels: Vec<String>,
    sig: String,
    attest: Option<String>,
}

#[derive(Clone, Debug)]
struct ObjectSetAssent {
    owner: PrincipalId,
    object: ObjectId,
    predicate: GroupPredicate,
    set: ObjectId,
    stated: u8,
    ham_state: u64,
    issued_at: u64,
    cancels: Vec<String>,
    sig: String,
    attest: Option<String>,
}

#[derive(Clone, Debug)]
struct GroupCancel {
    kind: &'static str,
    row_soul: String,
    cancel_id: String,
    prior: Vec<String>,
    signer: PrincipalId,
    predicate: GroupPredicate,
    set: ObjectId,
    member: PrincipalId,
    set_owner: PrincipalId,
    object: Option<ObjectId>,
    issued_at: u64,
    sig: String,
    attest: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct GroupRows {
    memberships: HashMap<String, MembershipRecord>,
    object_sets: HashMap<String, ObjectSetRecord>,
}

impl GroupRows {
    /// Incoming assents and cancels are checked against the history the
    /// caller passes. Rows already in this graph are not rechecked.
    #[cfg(feature = "vectors")]
    pub(crate) fn merge_from(
        &mut self,
        other: &Self,
        object_owners: &HashMap<String, String>,
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) {
        for (soul, incoming) in &other.memberships {
            let member_assent = fresh_assent(
                &incoming.member,
                incoming.member_assent.as_ref(),
                resolver,
                ctx,
            );
            let set_assent = fresh_assent(
                &incoming.set_owner,
                incoming.set_assent.as_ref(),
                resolver,
                ctx,
            );
            let cancels = fresh_cancels(&incoming.cancels, resolver, ctx);
            match self.memberships.get_mut(soul) {
                None => {
                    if member_assent.is_none() && set_assent.is_none() && cancels.is_empty() {
                        continue;
                    }
                    self.memberships.insert(
                        soul.clone(),
                        MembershipRecord {
                            predicate: incoming.predicate,
                            set: incoming.set.clone(),
                            member: incoming.member.clone(),
                            set_owner: incoming.set_owner.clone(),
                            member_assent,
                            set_assent,
                            cancels,
                        },
                    );
                }
                Some(local) => {
                    if let Some(next) = member_assent {
                        if local
                            .member_assent
                            .as_ref()
                            .is_none_or(|prev| replaces(prev, &next))
                        {
                            local.member_assent = Some(next);
                        }
                    }
                    if let Some(next) = set_assent {
                        if local
                            .set_assent
                            .as_ref()
                            .is_none_or(|prev| replaces(prev, &next))
                        {
                            local.set_assent = Some(next);
                        }
                    }
                    for cancel in cancels.into_values() {
                        keep_cancel(&mut local.cancels, cancel);
                    }
                }
            }
        }
        for (id, incoming) in &other.object_sets {
            // No admitted record, or a different owner: drop the edge.
            // A later record does not revive it.
            if object_owners
                .get(id)
                .is_none_or(|owner| owner != incoming.owner.as_ref())
            {
                continue;
            }
            let assent = fresh_assent(&incoming.owner, incoming.assent.as_ref(), resolver, ctx);
            let cancels = fresh_cancels(&incoming.cancels, resolver, ctx);
            let Some(local) = self.object_sets.get(id) else {
                if assent.is_none() && cancels.is_empty() {
                    continue;
                }
                let mut next = incoming.clone();
                next.assent = assent;
                next.cancels = cancels;
                self.object_sets.insert(id.clone(), next);
                continue;
            };
            // A different set or predicate keeps only the winner's cancels.
            let same_edge = local.set == incoming.set && local.predicate == incoming.predicate;
            let incoming_wins = assent.as_ref().is_some_and(|next| {
                local
                    .assent
                    .as_ref()
                    .is_none_or(|prev| replaces(prev, next))
            });
            if incoming_wins {
                let mut next = incoming.clone();
                next.assent = assent;
                if same_edge {
                    let mut kept = local.cancels.clone();
                    for cancel in cancels.into_values() {
                        keep_cancel(&mut kept, cancel);
                    }
                    next.cancels = kept;
                } else {
                    next.cancels = cancels;
                }
                self.object_sets.insert(id.clone(), next);
            } else if same_edge {
                if let Some(local) = self.object_sets.get_mut(id) {
                    for cancel in cancels.into_values() {
                        keep_cancel(&mut local.cancels, cancel);
                    }
                }
            }
        }
    }
}

fn replaces(prev: &StoredAssent, next: &StoredAssent) -> bool {
    if next.ham_state != prev.ham_state {
        return next.ham_state > prev.ham_state;
    }
    if next.stated != prev.stated {
        return next.stated == 0;
    }
    next.bytes < prev.bytes
}

fn covers(observed: &[String], ids: &BTreeMap<String, StoredCancel>) -> bool {
    ids.keys().all(|id| observed.iter().any(|have| have == id))
}

fn membership_live(row: &MembershipRecord) -> bool {
    let Some(member) = &row.member_assent else {
        return false;
    };
    let Some(set) = &row.set_assent else {
        return false;
    };
    member.stated == 1
        && set.stated == 1
        && covers(&member.observed, &row.cancels)
        && covers(&set.observed, &row.cancels)
}

fn object_set_live(row: &ObjectSetRecord) -> bool {
    row.assent
        .as_ref()
        .is_some_and(|assent| assent.stated == 1 && covers(&assent.observed, &row.cancels))
}

fn membership_removed(row: &MembershipRecord) -> bool {
    if row
        .member_assent
        .as_ref()
        .is_some_and(|assent| assent.stated == 0)
        || row
            .set_assent
            .as_ref()
            .is_some_and(|assent| assent.stated == 0)
    {
        return true;
    }
    if row.cancels.is_empty() {
        return false;
    }
    let stated = |assent: &StoredAssent| assent.stated == 1;
    let any_stated = row.member_assent.as_ref().is_some_and(stated)
        || row.set_assent.as_ref().is_some_and(stated);
    if !any_stated {
        return true;
    }
    let uncovered =
        |assent: &StoredAssent| stated(assent) && !covers(&assent.observed, &row.cancels);
    row.member_assent.as_ref().is_some_and(uncovered)
        || row.set_assent.as_ref().is_some_and(uncovered)
}

#[cfg(feature = "vectors")]
fn party_ok(
    principal: &PrincipalId,
    bytes: &[u8],
    sig: &str,
    issued_at: u64,
    stated: Option<u8>,
    attest: Option<&str>,
    resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
    ctx: &ResolutionContext<'_>,
) -> Option<SignedAtMode> {
    let rotations = resolver(principal)?;
    verify_party(
        principal, &rotations, ctx, bytes, sig, issued_at, stated, attest,
    )
    .ok()
}

#[cfg(feature = "vectors")]
fn fresh_assent(
    principal: &PrincipalId,
    assent: Option<&StoredAssent>,
    resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
    ctx: &ResolutionContext<'_>,
) -> Option<StoredAssent> {
    let assent = assent?;
    party_ok(
        principal,
        &assent.bytes,
        &assent.sig,
        assent.issued_at,
        Some(assent.stated),
        assent.attest.as_deref(),
        resolver,
        ctx,
    )?;
    Some(assent.clone())
}

#[cfg(feature = "vectors")]
fn fresh_cancels(
    cancels: &BTreeMap<String, StoredCancel>,
    resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
    ctx: &ResolutionContext<'_>,
) -> BTreeMap<String, StoredCancel> {
    let mut next = BTreeMap::new();
    for cancel in cancels.values() {
        let Some(mode) = party_ok(
            &cancel.signer,
            &cancel.bytes,
            &cancel.sig,
            cancel.issued_at,
            None,
            cancel.attest.as_deref(),
            resolver,
            ctx,
        ) else {
            continue;
        };
        let mut copy = cancel.clone();
        copy.mode = mode;
        next.insert(copy.id.clone(), copy);
    }
    next
}

fn keep_cancel(cancels: &mut BTreeMap<String, StoredCancel>, cancel: StoredCancel) -> bool {
    let upgrade = cancels.get(&cancel.id).is_some_and(|held| {
        held.mode != SignedAtMode::Witnessed && cancel.mode == SignedAtMode::Witnessed
    });
    if cancels.contains_key(&cancel.id) && !upgrade {
        return false;
    }
    cancels.insert(cancel.id.clone(), cancel);
    true
}

fn u64_field(value: Option<&Value>) -> Result<u64, Reason> {
    let Some(n) = value.and_then(Value::as_u64) else {
        return Err(Reason::BadRecord);
    };
    if n > MAX_SAFE {
        return Err(Reason::BadRecord);
    }
    Ok(n)
}

fn text_field(value: Option<&Value>) -> Result<&str, Reason> {
    match value {
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(Reason::NotString),
        None => Err(Reason::NotString),
    }
}

fn predicate_of(value: Option<&Value>) -> Result<GroupPredicate, Reason> {
    match value.and_then(Value::as_str) {
        Some("same-group") => Ok(GroupPredicate::SameGroup),
        Some("named-circle") => Ok(GroupPredicate::NamedCircle),
        _ => Err(Reason::BadRecord),
    }
}

fn cancel_list(value: Option<&Value>) -> Result<Vec<String>, Reason> {
    let Some(Value::Array(items)) = value else {
        return Err(Reason::BadRecord);
    };
    let mut ids = Vec::new();
    for item in items {
        let Some(text) = item.as_str() else {
            return Err(Reason::BadRecord);
        };
        if text.len() != 64
            || !text
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(Reason::BadRecord);
        }
        if ids.iter().any(|id: &String| id == text) {
            return Err(Reason::BadRecord);
        }
        ids.push(text.to_string());
    }
    let mut sorted = ids.clone();
    sorted.sort();
    if ids != sorted {
        return Err(Reason::BadRecord);
    }
    Ok(ids)
}

fn parse_set_id(value: Option<&Value>) -> Result<(ObjectId, PrincipalId), Reason> {
    let id = parse_object_id(text_field(value)?)?;
    if !id.as_ref().starts_with("set_") {
        return Err(Reason::BadAlphabet);
    }
    let owner = object_principal(&id)?;
    Ok((id, owner))
}

fn domain_ok(map: &serde_json::Map<String, Value>, domain: &str) -> Result<(), Reason> {
    if let Some(found) = map.get("domain") {
        if found.as_str() != Some(domain) {
            return Err(Reason::LegacyRow);
        }
    }
    if !map.contains_key("sig") {
        return Err(Reason::LegacyRow);
    }
    Ok(())
}

fn sig_field(map: &serde_json::Map<String, Value>) -> Result<String, Reason> {
    match map.get("sig") {
        Some(Value::String(sig)) => Ok(sig.clone()),
        _ => Err(Reason::BadRecord),
    }
}

fn attest_field(map: &serde_json::Map<String, Value>) -> Result<Option<String>, Reason> {
    match map.get("attest") {
        None => Ok(None),
        Some(Value::String(token)) => Ok(Some(token.clone())),
        Some(_) => Err(Reason::BadRecord),
    }
}

fn stated_field(value: Option<&Value>) -> Result<u8, Reason> {
    let stated = u64_field(value)?;
    if stated > 1 {
        return Err(Reason::BadRecord);
    }
    Ok(stated as u8)
}

fn lp(fields: &[&str]) -> Result<Vec<u8>, Reason> {
    length_prefixed(fields)
}

fn bytes_with_cancels(head: &[&str], cancels: &[String]) -> Result<Vec<u8>, Reason> {
    let count = cancels.len().to_string();
    let mut fields: Vec<&str> = head.to_vec();
    fields.push(&count);
    for id in cancels {
        fields.push(id);
    }
    lp(&fields)
}

fn membership_bytes(row: &MembershipAssent) -> Result<Vec<u8>, Reason> {
    let stated = row.stated.to_string();
    let ham = row.ham_state.to_string();
    let issued = row.issued_at.to_string();
    bytes_with_cancels(
        &[
            MEMBER_DOMAIN,
            row.role,
            row.predicate.as_str(),
            row.set.as_ref(),
            row.member.as_ref(),
            row.set_owner.as_ref(),
            &stated,
            &ham,
            &issued,
        ],
        &row.cancels,
    )
}

fn object_set_bytes(row: &ObjectSetAssent) -> Result<Vec<u8>, Reason> {
    let stated = row.stated.to_string();
    let ham = row.ham_state.to_string();
    let issued = row.issued_at.to_string();
    bytes_with_cancels(
        &[
            OBJECT_SET_DOMAIN,
            row.owner.as_ref(),
            row.object.as_ref(),
            row.predicate.as_str(),
            row.set.as_ref(),
            &stated,
            &ham,
            &issued,
        ],
        &row.cancels,
    )
}

fn cancel_bytes(row: &GroupCancel) -> Result<Vec<u8>, Reason> {
    let issued = row.issued_at.to_string();
    let count = row.prior.len().to_string();
    let mut fields = vec![
        CANCEL_DOMAIN,
        row.kind,
        row.row_soul.as_str(),
        row.cancel_id.as_str(),
        issued.as_str(),
        count.as_str(),
    ];
    for id in &row.prior {
        fields.push(id);
    }
    lp(&fields)
}

fn parse_membership(row: &Value) -> Result<(MembershipAssent, Vec<u8>), Reason> {
    let map = row.as_object().ok_or(Reason::BadRecord)?;
    domain_ok(map, MEMBER_DOMAIN)?;
    let role = match map.get("role").and_then(Value::as_str) {
        Some("member") => "member",
        Some("set") => "set",
        _ => return Err(Reason::BadRecord),
    };
    let predicate = predicate_of(map.get("predicate"))?;
    let (set, embedded) = parse_set_id(map.get("set"))?;
    let member = parse_principal_id(text_field(map.get("member"))?)?;
    let set_owner = parse_principal_id(text_field(map.get("setOwner"))?)?;
    if set_owner != embedded {
        return Err(Reason::BadRecord);
    }
    let assent = MembershipAssent {
        role,
        predicate,
        set,
        member,
        set_owner,
        stated: stated_field(map.get("stated"))?,
        ham_state: u64_field(map.get("hamState"))?,
        issued_at: u64_field(map.get("issuedAt"))?,
        cancels: cancel_list(map.get("cancels"))?,
        sig: sig_field(map)?,
        attest: attest_field(map)?,
    };
    let bytes = membership_bytes(&assent)?;
    Ok((assent, bytes))
}

fn parse_object_set(row: &Value) -> Result<(ObjectSetAssent, Vec<u8>), Reason> {
    let map = row.as_object().ok_or(Reason::BadRecord)?;
    domain_ok(map, OBJECT_SET_DOMAIN)?;
    let owner = parse_principal_id(text_field(map.get("owner"))?)?;
    let object = parse_object_id(text_field(map.get("object"))?)?;
    let embedded = object_principal(&object)?;
    if embedded != owner {
        return Err(Reason::BadRecord);
    }
    let (set, _) = parse_set_id(map.get("set"))?;
    let assent = ObjectSetAssent {
        owner,
        object,
        predicate: predicate_of(map.get("predicate"))?,
        set,
        stated: stated_field(map.get("stated"))?,
        ham_state: u64_field(map.get("hamState"))?,
        issued_at: u64_field(map.get("issuedAt"))?,
        cancels: cancel_list(map.get("cancels"))?,
        sig: sig_field(map)?,
        attest: attest_field(map)?,
    };
    let bytes = object_set_bytes(&assent)?;
    Ok((assent, bytes))
}

fn parse_cancel(row: &Value) -> Result<(GroupCancel, Vec<u8>), Reason> {
    let map = row.as_object().ok_or(Reason::BadRecord)?;
    domain_ok(map, CANCEL_DOMAIN)?;
    let kind = match map.get("kind").and_then(Value::as_str) {
        Some("membership") => "membership",
        Some("object-set") => "object-set",
        _ => return Err(Reason::BadRecord),
    };
    let predicate = predicate_of(map.get("predicate"))?;
    let (set, embedded) = parse_set_id(map.get("set"))?;
    let member = parse_principal_id(text_field(map.get("member"))?)?;
    let set_owner = parse_principal_id(text_field(map.get("setOwner"))?)?;
    if set_owner != embedded {
        return Err(Reason::BadRecord);
    }
    let signer = parse_principal_id(text_field(map.get("signer"))?)?;
    let prior = cancel_list(map.get("prior"))?;
    let cancel_id = text_field(map.get("cancelId"))?.to_string();
    if cancel_id.len() != 64
        || !cancel_id
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        || prior.iter().any(|id| id == &cancel_id)
    {
        return Err(Reason::BadRecord);
    }
    let row_soul = text_field(map.get("rowSoul"))?.to_string();
    let issued_at = u64_field(map.get("issuedAt"))?;
    let object = if kind == "object-set" {
        Some(parse_object_id(text_field(map.get("object"))?)?)
    } else {
        None
    };
    let expected = if kind == "membership" {
        if signer != member && signer != set_owner {
            return Err(Reason::BadRecord);
        }
        membership_soul(&set_owner, predicate.ids(), &set, &member).to_string()
    } else {
        let object = object.clone().ok_or(Reason::BadRecord)?;
        let object_owner = object_principal(&object)?;
        if signer != object_owner {
            return Err(Reason::BadRecord);
        }
        object_set_soul(&object_owner, &object, predicate.ids(), &set).to_string()
    };
    if row_soul != expected {
        return Err(Reason::BadRecord);
    }
    let cancel = GroupCancel {
        kind,
        row_soul,
        cancel_id,
        prior,
        signer,
        predicate,
        set,
        member,
        set_owner,
        object,
        issued_at,
        sig: sig_field(map)?,
        attest: attest_field(map)?,
    };
    let bytes = cancel_bytes(&cancel)?;
    Ok((cancel, bytes))
}

fn verify_party(
    principal: &PrincipalId,
    rotations: &[Value],
    ctx: &ResolutionContext<'_>,
    bytes: &[u8],
    sig: &str,
    issued_at: u64,
    stated: Option<u8>,
    attest: Option<&str>,
) -> Result<SignedAtMode, Reason> {
    match verify_signed_at(principal, rotations, ctx, bytes, sig, issued_at) {
        Ok(signed) => Ok(signed.mode),
        Err(Reason::UnwitnessedRetiredKey) => {
            if stated.is_some_and(|stated| stated != 0) {
                if let Some(token) = attest {
                    verify_acl_attestation(token, ctx.jwks, issued_at, bytes)?;
                }
                return Err(Reason::UnwitnessedRetiredKey);
            }
            let Some(token) = attest else {
                return Err(Reason::UnwitnessedRetiredKey);
            };
            let account = resolve_current_key(principal, rotations, ctx).result?;
            let seen = verify_acl_attestation(token, ctx.jwks, issued_at, bytes)?;
            if seen.principal != *principal {
                return Err(Reason::BadAttestation);
            }
            let state = history_state(principal, &account.rotations, issued_at, ctx.now);
            verify_key_signature(&state.key, sig, bytes)?;
            Ok(SignedAtMode::Witnessed)
        }
        Err(reason) => Err(reason),
    }
}

fn stored_assent(
    stated: u8,
    ham_state: u64,
    issued_at: u64,
    bytes: Vec<u8>,
    sig: String,
    attest: Option<String>,
    observed: Vec<String>,
) -> StoredAssent {
    StoredAssent {
        stated,
        ham_state,
        issued_at,
        bytes,
        sig,
        attest,
        observed,
    }
}

fn stored_cancel(cancel: &GroupCancel, bytes: Vec<u8>, mode: SignedAtMode) -> StoredCancel {
    StoredCancel {
        id: cancel.cancel_id.clone(),
        prior: cancel.prior.clone(),
        signer: cancel.signer.clone(),
        issued_at: cancel.issued_at,
        bytes,
        sig: cancel.sig.clone(),
        attest: cancel.attest.clone(),
        mode,
    }
}

fn deny(reason: &str, hint: Option<HandoffHint>, hop: Option<HopFactor>) -> MeshCheckResult {
    MeshCheckResult {
        allowed: false,
        reason: reason.to_string(),
        hint,
        hop,
    }
}

impl MeshSeeGraph {
    /// Admit one membership assent. History comes from `resolver`.
    /// A stated-1 assent signed by a retired key is refused.
    pub fn admit_membership(
        &mut self,
        row: &Value,
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) -> Result<bool, Reason> {
        let (assent, bytes) = parse_membership(row)?;
        let signer = if assent.role == "member" {
            &assent.member
        } else {
            &assent.set_owner
        };
        let Some(rotations) = resolver(signer) else {
            return Err(Reason::MissingHistory);
        };
        verify_party(
            signer,
            &rotations,
            ctx,
            &bytes,
            &assent.sig,
            assent.issued_at,
            Some(assent.stated),
            assent.attest.as_deref(),
        )?;
        let soul = membership_soul(
            &assent.set_owner,
            assent.predicate.ids(),
            &assent.set,
            &assent.member,
        )
        .to_string();
        let next = stored_assent(
            assent.stated,
            assent.ham_state,
            assent.issued_at,
            bytes,
            assent.sig,
            assent.attest,
            assent.cancels,
        );
        let held = self
            .group
            .rows
            .memberships
            .entry(soul)
            .or_insert_with(|| MembershipRecord {
                predicate: assent.predicate,
                set: assent.set.clone(),
                member: assent.member.clone(),
                set_owner: assent.set_owner.clone(),
                member_assent: None,
                set_assent: None,
                cancels: BTreeMap::new(),
            });
        let prev = if assent.role == "member" {
            &held.member_assent
        } else {
            &held.set_assent
        };
        if prev.as_ref().is_some_and(|prev| !replaces(prev, &next)) {
            return Ok(false);
        }
        if assent.role == "member" {
            held.member_assent = Some(next);
        } else {
            held.set_assent = Some(next);
        }
        Ok(true)
    }

    /// Admit one object-set row signed by the object owner.
    pub fn admit_object_set(
        &mut self,
        row: &Value,
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) -> Result<bool, Reason> {
        let (edge, bytes) = parse_object_set(row)?;
        let Some(rotations) = resolver(&edge.owner) else {
            return Err(Reason::MissingHistory);
        };
        verify_party(
            &edge.owner,
            &rotations,
            ctx,
            &bytes,
            &edge.sig,
            edge.issued_at,
            Some(edge.stated),
            edge.attest.as_deref(),
        )?;
        let next = stored_assent(
            edge.stated,
            edge.ham_state,
            edge.issued_at,
            bytes,
            edge.sig,
            edge.attest,
            edge.cancels,
        );
        let id = edge.object.as_ref().to_string();
        // A different set or predicate starts empty. The previous edge's cancels do not follow.
        let cancels = match self.group.rows.object_sets.get(&id) {
            Some(prev)
                if prev
                    .assent
                    .as_ref()
                    .is_some_and(|prev| !replaces(prev, &next)) =>
            {
                return Ok(false);
            }
            Some(prev) if prev.set == edge.set && prev.predicate == edge.predicate => {
                prev.cancels.clone()
            }
            _ => BTreeMap::new(),
        };
        self.group.rows.object_sets.insert(
            id,
            ObjectSetRecord {
                owner: edge.owner,
                predicate: edge.predicate,
                set: edge.set,
                assent: Some(next),
                cancels,
            },
        );
        Ok(true)
    }

    /// Admit one group cancel. A retired key is accepted only when witnessed.
    pub fn admit_group_cancel(
        &mut self,
        row: &Value,
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) -> Result<bool, Reason> {
        let (cancel, bytes) = parse_cancel(row)?;
        let Some(rotations) = resolver(&cancel.signer) else {
            return Err(Reason::MissingHistory);
        };
        let mode = verify_party(
            &cancel.signer,
            &rotations,
            ctx,
            &bytes,
            &cancel.sig,
            cancel.issued_at,
            None,
            cancel.attest.as_deref(),
        )?;
        let stored = stored_cancel(&cancel, bytes, mode);
        if cancel.kind == "membership" {
            let soul = membership_soul(
                &cancel.set_owner,
                cancel.predicate.ids(),
                &cancel.set,
                &cancel.member,
            )
            .to_string();
            return self.insert_membership_cancel(soul, stored);
        }
        let Some(object) = &cancel.object else {
            return Err(Reason::BadRecord);
        };
        self.insert_object_cancel(object.as_ref(), &cancel, stored)
    }

    fn insert_membership_cancel(
        &mut self,
        soul: String,
        cancel: StoredCancel,
    ) -> Result<bool, Reason> {
        let Some(held) = self.group.rows.memberships.get_mut(&soul) else {
            return Err(Reason::Unknown);
        };
        if held.cancels.contains_key(&cancel.id) {
            return Ok(keep_cancel(&mut held.cancels, cancel));
        }
        if cancel.prior.iter().any(|id| !held.cancels.contains_key(id)) {
            return Err(Reason::BadRecord);
        }
        held.cancels.insert(cancel.id.clone(), cancel);
        Ok(true)
    }

    fn insert_object_cancel(
        &mut self,
        object: &str,
        cancel: &GroupCancel,
        stored: StoredCancel,
    ) -> Result<bool, Reason> {
        let Some(held) = self.group.rows.object_sets.get_mut(object) else {
            return Err(Reason::Unknown);
        };
        if held.set != cancel.set || held.predicate != cancel.predicate {
            return Err(Reason::Unknown);
        };
        if held.cancels.contains_key(&stored.id) {
            return Ok(keep_cancel(&mut held.cancels, stored));
        }
        if stored.prior.iter().any(|id| !held.cancels.contains_key(id)) {
            return Err(Reason::BadRecord);
        }
        held.cancels.insert(stored.id.clone(), stored);
        Ok(true)
    }

    /// Drop this principal's group rows that the new checkpoint rejects.
    /// A stated-1 assent signed by a retired key is dropped. A witnessed
    /// cancel on that object-set record stays, so the next edge for the
    /// same set and predicate still sees it. An unwitnessed retired-key
    /// cancel is dropped. Only a witnessed cancel survives.
    pub fn reverify_group(
        &mut self,
        principal: &PrincipalId,
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) -> Result<usize, Reason> {
        let Some(rotations) = resolver(principal) else {
            return Err(Reason::MissingHistory);
        };
        let mut dropped = 0;
        let souls: Vec<String> = self.group.rows.memberships.keys().cloned().collect();
        for soul in souls {
            let empty = {
                let Some(row) = self.group.rows.memberships.get_mut(&soul) else {
                    continue;
                };
                for role in ["member", "set"] {
                    let (signer_matches, stated, issued_at, bytes, sig, attest) = {
                        let assent = if role == "member" {
                            row.member_assent.as_ref()
                        } else {
                            row.set_assent.as_ref()
                        };
                        let signer = if role == "member" {
                            &row.member
                        } else {
                            &row.set_owner
                        };
                        let Some(assent) = assent else {
                            continue;
                        };
                        if signer != principal {
                            continue;
                        }
                        (
                            true,
                            assent.stated,
                            assent.issued_at,
                            assent.bytes.clone(),
                            assent.sig.clone(),
                            assent.attest.clone(),
                        )
                    };
                    if !signer_matches {
                        continue;
                    }
                    let again = verify_party(
                        principal,
                        &rotations,
                        ctx,
                        &bytes,
                        &sig,
                        issued_at,
                        Some(stated),
                        attest.as_deref(),
                    );
                    if again.is_err() {
                        if role == "member" {
                            row.member_assent = None;
                        } else {
                            row.set_assent = None;
                        }
                        dropped += 1;
                    }
                }
                let cancel_ids: Vec<String> = row
                    .cancels
                    .iter()
                    .filter(|(_, cancel)| cancel.signer == *principal)
                    .map(|(id, _)| id.clone())
                    .collect();
                for id in cancel_ids {
                    let Some(cancel) = row.cancels.get(&id) else {
                        continue;
                    };
                    let again = verify_party(
                        &cancel.signer,
                        &rotations,
                        ctx,
                        &cancel.bytes,
                        &cancel.sig,
                        cancel.issued_at,
                        None,
                        cancel.attest.as_deref(),
                    );
                    if again.is_err() {
                        row.cancels.remove(&id);
                        dropped += 1;
                    }
                }
                row.member_assent.is_none() && row.set_assent.is_none() && row.cancels.is_empty()
            };
            if empty {
                self.group.rows.memberships.remove(&soul);
            }
        }
        let objects: Vec<String> = self
            .group
            .rows
            .object_sets
            .iter()
            .filter(|(_, row)| row.owner == *principal)
            .map(|(id, _)| id.clone())
            .collect();
        for id in objects {
            let failed = {
                let Some(row) = self.group.rows.object_sets.get(&id) else {
                    continue;
                };
                match row.assent.as_ref() {
                    None => false,
                    Some(assent) => verify_party(
                        &row.owner,
                        &rotations,
                        ctx,
                        &assent.bytes,
                        &assent.sig,
                        assent.issued_at,
                        Some(assent.stated),
                        assent.attest.as_deref(),
                    )
                    .is_err(),
                }
            };
            if failed {
                if let Some(row) = self.group.rows.object_sets.get_mut(&id) {
                    row.assent = None;
                }
                dropped += 1;
            }
            let cancel_ids: Vec<String> = self
                .group
                .rows
                .object_sets
                .get(&id)
                .map(|row| {
                    row.cancels
                        .iter()
                        .filter(|(_, cancel)| cancel.signer == *principal)
                        .map(|(cancel_id, _)| cancel_id.clone())
                        .collect()
                })
                .unwrap_or_default();
            let Some(row) = self.group.rows.object_sets.get_mut(&id) else {
                continue;
            };
            for cancel_id in cancel_ids {
                let Some(cancel) = row.cancels.get(&cancel_id) else {
                    continue;
                };
                let again = verify_party(
                    &cancel.signer,
                    &rotations,
                    ctx,
                    &cancel.bytes,
                    &cancel.sig,
                    cancel.issued_at,
                    None,
                    cancel.attest.as_deref(),
                );
                if again.is_err() {
                    row.cancels.remove(&cancel_id);
                    dropped += 1;
                }
            }
            let empty = self
                .group
                .rows
                .object_sets
                .get(&id)
                .is_some_and(|row| row.assent.is_none() && row.cancels.is_empty());
            if empty {
                self.group.rows.object_sets.remove(&id);
            }
        }
        Ok(dropped)
    }

    /// `CHECK(see)` when the object names `same-group` or `named-circle`.
    ///
    /// The owner is the principal embedded in the object id, and the admitted
    /// signed owner must be that same principal. An unsigned label is not
    /// the owner. Otherwise both assents must be stated 1 and every stored
    /// cancel must be covered. Hop missing does not fail. Hop alone never allows.
    ///
    /// Stored-id group Check. A raw string is not a parameter.
    ///
    /// ```compile_fail
    /// let graph = sociacl_gun::MeshSeeGraph::new();
    /// graph.check_group_see(sociacl_gun::GroupPredicate::SameGroup, "room", "0xbob", 0, None, None);
    /// ```
    pub fn check_group_see(
        &self,
        predicate: GroupPredicate,
        object: &ObjectId,
        accessor: &PrincipalId,
        now: u64,
        hint: Option<&HandoffHint>,
        hop: Option<&HopFactor>,
    ) -> MeshCheckResult {
        let _ = now;
        let hint = hint.cloned();
        let hop = hop.cloned();
        let Ok(embedded) = object_principal(object) else {
            return deny(MESH_REASON_MISSING, hint, hop);
        };
        let Some(admitted) = self.object_owner(object) else {
            return deny(MESH_REASON_MISSING, hint, hop);
        };
        if *admitted != embedded {
            return deny(MESH_REASON_MISSING, hint, hop);
        }
        if embedded == *accessor {
            return MeshCheckResult {
                allowed: true,
                reason: MESH_REASON_OWNER.into(),
                hint,
                hop,
            };
        }
        let Some(edge) = self.group.rows.object_sets.get(object.as_ref()) else {
            return deny(MESH_REASON_MISSING, hint, hop);
        };
        if !object_set_live(edge) || edge.predicate != predicate || edge.owner != embedded {
            return deny(MESH_REASON_MISSING, hint, hop);
        }
        let Ok(set_owner) = object_principal(&edge.set) else {
            return deny(MESH_REASON_MISSING, hint, hop);
        };
        let soul = membership_soul(&set_owner, predicate.ids(), &edge.set, accessor).to_string();
        let Some(membership) = self.group.rows.memberships.get(&soul) else {
            return deny(MESH_REASON_MISSING, hint, hop);
        };
        if !membership_live(membership)
            || membership.member != *accessor
            || membership.set_owner != set_owner
        {
            return deny(MESH_REASON_MISSING, hint, hop);
        }
        MeshCheckResult {
            allowed: true,
            reason: predicate.as_str().into(),
            hint,
            hop,
        }
    }

    /// Group tail of a presentation. `set` is the minted set id.
    /// No set, and no live object-set, falls through to see.
    pub fn check_group_presentation(
        &self,
        set: Option<&ObjectId>,
        object: &ObjectId,
        accessor: &PrincipalId,
        payload: Option<&DecodedGroupPayload>,
        now: u64,
        hint: Option<&HandoffHint>,
        hop: Option<&HopFactor>,
    ) -> GroupPresentation {
        let store_cancel = payload.is_some_and(|payload| payload.stated == 0);
        let hinted = hint.cloned();
        let hopped = hop.cloned();
        let live = payload.is_some_and(|payload| payload.live_at(now));
        let finish = |allowed: bool, reason: String| GroupPresentation {
            allowed,
            reason,
            hint: hinted.clone(),
            hop: hopped.clone(),
            store_cancel,
        };
        let named = self
            .group
            .rows
            .object_sets
            .get(object.as_ref())
            .is_some_and(object_set_live);
        let Some(set) = set else {
            if named {
                return finish(false, MESH_REASON_MISSING.into());
            }
            let dest = self.check_see(object, accessor, now, hint, hop);
            if dest.allowed && live {
                return finish(true, dest.reason);
            }
            let reason = if live {
                dest.reason
            } else {
                MESH_REASON_CANCELLED.into()
            };
            return finish(false, reason);
        };
        let presented = set.as_ref().starts_with("set_") && object_principal(set).is_ok();
        let matched = self
            .group
            .rows
            .object_sets
            .get(object.as_ref())
            .is_some_and(|edge| presented && object_set_live(edge) && edge.set == *set);
        if !matched {
            return finish(false, MESH_REASON_MISSING.into());
        }
        let predicate = self
            .group
            .rows
            .object_sets
            .get(object.as_ref())
            .map(|edge| edge.predicate)
            .unwrap_or(GroupPredicate::SameGroup);
        let see = self.check_group_see(predicate, object, accessor, now, hint, hop);
        if see.allowed && live {
            return finish(true, see.reason);
        }
        let reason = if live {
            see.reason
        } else {
            MESH_REASON_CANCELLED.into()
        };
        finish(false, reason)
    }

    /// True when the snapshot hides a removal or a newer object-set edge.
    /// An edge that is not live is a removal unless the snapshot is stated 0
    /// at a ham_state at least as high as the stored assent.
    /// A one-sided stated-1 membership is not a removal. A stated-0 assent
    /// or an uncovered cancel is.
    /// Member ham does not stand in for the object-set edge.
    pub fn snapshot_understates_group(
        &self,
        object: &ObjectId,
        members: &[GroupSnapshotMember],
        object_set: Option<&GroupSnapshotObjectSet>,
    ) -> bool {
        let Some(current) = self.group.rows.object_sets.get(object.as_ref()) else {
            return object_set.is_some();
        };
        let Some(snap) = object_set else {
            return true;
        };
        let ham = current
            .assent
            .as_ref()
            .map(|assent| assent.ham_state)
            .unwrap_or(0);
        if !object_set_live(current) {
            if snap.stated != 0
                || snap.ham_state < ham
                || snap.predicate != current.predicate
                || snap.set_id != current.set.as_ref()
            {
                return true;
            }
        } else if snap.ham_state < ham
            || snap.predicate != current.predicate
            || snap.set_id != current.set.as_ref()
            || snap.stated
                != current
                    .assent
                    .as_ref()
                    .map(|assent| assent.stated)
                    .unwrap_or(0)
        {
            return true;
        }
        self.group.rows.memberships.values().any(|row| {
            if row.predicate != current.predicate
                || row.set != current.set
                || !membership_removed(row)
            {
                return false;
            }
            let ham = row
                .member_assent
                .as_ref()
                .map(|assent| assent.ham_state)
                .unwrap_or(0)
                .max(
                    row.set_assent
                        .as_ref()
                        .map(|assent| assent.ham_state)
                        .unwrap_or(0),
                );
            let hidden = members.iter().find(|member| {
                member.accessor == row.member.as_ref()
                    && member.predicate == row.predicate
                    && member.set_id == row.set.as_ref()
            });
            hidden.is_none_or(|member| member.stated != 0 || member.ham_state < ham)
        })
    }
}
