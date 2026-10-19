//! Mesh dest ACL: Gun-native see grants that HAM-merge across peers.
//!
//! Grants live under `s3rch/acl/…`, not under `items` or `users`.
//! Each peer evaluates [`MeshSeeGraph::check_see`] against its locally
//! HAM-merged graph at `now`. Cancel is owner-only and must be
//! visible as privilege-down on the next Check after merge. There is
//! no cached allow.

use std::collections::{HashMap, HashSet};

use serde_json::Value;
use sociacl_core::Timestamp;
use sociacl_ids::{
    grant_soul as id_grant_soul, parse_object_record, parse_see_grant, resolve_current_key,
    verify_acl_attestation, verify_object_record, verify_see_grant, ObjectId, PrincipalId, Reason,
    ResolutionContext, SignedAtMode,
};

use crate::soul::GunSoul;
use crate::{HandoffHint, HopFactor, IdentitySeeGrant};

/// Predicate / deny reasons on the mesh consume surface.
pub const MESH_REASON_OWNER: &str = "owner";
pub const MESH_REASON_DELEGATE: &str = "delegate";
pub const MESH_REASON_MISSING: &str = "missing";
pub const MESH_REASON_META: &str = "meta";
pub const MESH_REASON_ACL: &str = "acl";
pub const MESH_REASON_URL_LEAF: &str = "url-leaf";
pub const MESH_REASON_CANCELLED: &str = "cancelled";

/// Jointly stated see grant stored as Gun-native data.
///
/// `stated` is 1 (live) or 0 (cancelled). HAM-merges across peers.
/// Privilege-down is `stated = 0` with a higher HAM state.
/// `from` inclusive, `until` exclusive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshSeeGrant {
    pub object: String,
    pub accessor: String,
    pub from: Timestamp,
    pub until: Timestamp,
    pub stated: u8,
}

impl MeshSeeGrant {
    pub fn live(
        object: impl Into<String>,
        accessor: impl Into<String>,
        from: u64,
        until: u64,
    ) -> Self {
        Self {
            object: object.into(),
            accessor: accessor.into(),
            from: Timestamp(from),
            until: Timestamp(until),
            stated: 1,
        }
    }

    pub fn is_stated(&self) -> bool {
        self.stated == 1
    }

    pub fn live_at(&self, now: Timestamp) -> bool {
        self.is_stated() && now.0 >= self.from.0 && now.0 < self.until.0
    }
}

impl From<&IdentitySeeGrant> for MeshSeeGrant {
    fn from(grant: &IdentitySeeGrant) -> Self {
        Self {
            object: grant.claim_id.clone(),
            accessor: grant.accessor.as_str().to_string(),
            from: grant.from,
            until: grant.until,
            stated: 1,
        }
    }
}

/// One dest-ACL grant node. Soul does not fork items or users.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GunAclEdge {
    pub soul: GunSoul,
    pub owner: String,
    pub grant: MeshSeeGrant,
    /// Gun HAM state. Higher wins. Cancel must bump this.
    pub ham_state: u64,
}

/// TS `CheckResult` on the mesh graph. A present hint or hop never
/// sets `allowed`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshCheckResult {
    pub allowed: bool,
    pub reason: String,
    pub hint: Option<HandoffHint>,
    pub hop: Option<HopFactor>,
}

impl MeshCheckResult {
    pub fn hint_is_grant(&self) -> bool {
        false
    }

    pub fn hop_is_grant(&self) -> bool {
        false
    }

    /// Hop was presented on an already-named live grant or owner path.
    /// Never true because of hop alone.
    pub fn hop_factored(&self) -> bool {
        self.allowed && self.hop.is_some()
    }

    /// A wrap is never an input that sets `allowed`.
    pub fn wrap_is_grant(&self) -> bool {
        false
    }

    /// An inbox delivery is never an input that sets `allowed`.
    pub fn inbox_is_grant(&self) -> bool {
        false
    }

    /// An access request is never an input that sets `allowed`.
    pub fn request_is_grant(&self) -> bool {
        false
    }
}

/// A hop, a hint, a wrap, a request, or an inbox delivery never grants.
/// Any other label is also not a grant.
pub fn factor_grants(_kind: &str) -> bool {
    false
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MeshObject {
    pub(crate) id: String,
    pub(crate) owner: String,
}

/// Locally HAM-merged dest ACL a peer Checks at `now`.
///
/// Friend edges may be recorded and are never walked (hopcap 1).
/// Mine overlay stays off this graph until an admitted object record.
///
/// Group and circle rows live on this same graph. They do not fork
/// items or users, and they are not see-grant souls.
/// Label graph still used by group. It is not the typed see, post, or request API.
#[derive(Clone, Debug, Default)]
pub(crate) struct LabelGraph {
    pub(crate) objects: HashMap<String, MeshObject>,
    pub(crate) grants: HashMap<String, GunAclEdge>,
    pub(crate) friends: HashSet<(String, String)>,
    pub(crate) groups: crate::group::GroupRows,
}

/// Admitted object owner. `record` is the canonical signed snapshot,
/// rechecked when the owner rotates. A later record replaces it only
/// when `issued_at` is strictly newer, this snapshot no longer verifies,
/// and the new signer is not a key `history` marks retired.
#[derive(Clone, Debug)]
struct ObjectAdmission {
    owner: PrincipalId,
    issued_at: u64,
    record: Value,
    /// Rotation records that admitted this snapshot.
    history: Vec<Value>,
}

#[derive(Clone, Debug, Default)]
pub struct MeshSeeGraph {
    pub(crate) labels: LabelGraph,
    owners: HashMap<String, ObjectAdmission>,
    admitted: HashMap<String, AdmittedSee>,
    pub(crate) post_rows: HashMap<String, crate::post::AdmittedPost>,
}

/// Admitted see row. The private seal keeps an unverified row out of Check.
#[derive(Clone, Debug)]
pub struct VerifiedRow {
    pub mode: SignedAtMode,
    pub stated: u8,
    pub ham_state: u64,
    pub from: u64,
    pub until: u64,
    pub issued_at: u64,
    pub owner: PrincipalId,
    pub object: ObjectId,
    pub accessor: PrincipalId,
    pub attest: bool,
    /// Canonical signing bytes of the stored row.
    pub bytes: Vec<u8>,
    #[allow(dead_code)]
    pub(crate) seal: (),
}

#[derive(Clone, Debug)]
struct AdmittedSee {
    mode: SignedAtMode,
    stated: u8,
    ham_state: u64,
    from: u64,
    until: u64,
    issued_at: u64,
    owner: PrincipalId,
    object: ObjectId,
    accessor: PrincipalId,
    bytes: Vec<u8>,
    source: Value,
    witness: bool,
}

/// True when `signer` is a `prevKey` of a stored rotation already in force at `issued_at`.
/// An unreadable stored history fails closed and blocks the replacement.
fn signer_retired(
    stored: &[Value],
    signer: &PrincipalId,
    issued_at: u64,
    owner: &PrincipalId,
    ctx: &ResolutionContext<'_>,
) -> bool {
    let Ok(account) = resolve_current_key(owner, stored, ctx).result else {
        return true;
    };
    account
        .rotations
        .iter()
        .any(|row| row.prev_key == *signer && row.issued_at < issued_at)
}

impl MeshSeeGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a signed object record. The owner is the record, never an argument.
    /// History comes from `resolver` called with the parsed owner.
    /// The same owner later is a no-op while the stored record still verifies.
    /// A stored record is replaced only when the new `issued_at` is strictly
    /// newer, the stored record no longer verifies, and the new signer is not
    /// a key the stored history marks retired.
    pub fn put_object(
        &mut self,
        record: &Value,
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) -> Result<bool, Reason> {
        let (parsed, _) = parse_object_record(record)?;
        let Some(rotations) = resolver(&parsed.owner) else {
            return Err(Reason::MissingHistory);
        };
        let verified = verify_object_record(record, &rotations, ctx)?;
        let id = verified.record.object.as_ref().to_string();
        let snapshot = snapshot_object(&verified.record);
        if let Some(existing) = self.owners.get(&id) {
            if verified.record.issued_at <= existing.issued_at {
                return Ok(false);
            }
            if verify_object_record(&existing.record, &rotations, ctx).is_ok() {
                return Ok(false);
            }
            if signer_retired(
                &existing.history,
                &verified.key,
                verified.record.issued_at,
                &verified.record.owner,
                ctx,
            ) {
                return Ok(false);
            }
        }
        self.labels.put_object(
            verified.record.object.as_ref(),
            verified.record.owner.as_ref(),
        );
        self.owners.insert(
            id,
            ObjectAdmission {
                owner: verified.record.owner,
                issued_at: verified.record.issued_at,
                record: snapshot,
                history: rotations,
            },
        );
        Ok(true)
    }

    /// Test hook. Plants a label owner without a signed record.
    /// Production builds omit this. Tests enable the `vectors` feature.
    #[cfg(feature = "vectors")]
    #[doc(hidden)]
    pub fn vector_label_owner(&mut self, object: &str, owner: &str) {
        self.labels.put_object(object, owner);
    }

    /// Admit one see row. The row is parsed once; the signature covers that value.
    /// History comes from `resolver` called with the parsed owner.
    /// Missing rotation history is `missing-history`, not an empty history.
    pub fn admit_row(
        &mut self,
        row: &Value,
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) -> Result<(VerifiedRow, bool), Reason> {
        let (grant, _) = parse_see_grant(row)?;
        let Some(rotations) = resolver(&grant.owner) else {
            return Err(Reason::MissingHistory);
        };
        let verified = verify_see_grant(&snapshot_see(&grant), &rotations, ctx)?;
        let key = id_grant_soul(
            &verified.grant.owner,
            &verified.grant.object,
            &verified.grant.accessor,
        )
        .to_string();
        let next = admitted_from(&verified, &snapshot_see(&grant), ctx);
        let kept = match self.admitted.get(&key) {
            Some(prev) => replaces(prev, &next),
            None => true,
        };
        if kept {
            self.admitted.insert(key.clone(), next);
        }
        let stored = self.admitted.get(&key).expect("admitted row");
        Ok((view_row(stored), kept))
    }

    /// Write a see row and, when present, a post row.
    /// Both are verified against `rotations` before either insert.
    /// A missing see row is left as stored. A row that would not replace writes neither.
    pub(crate) fn commit_grant_rows(
        &mut self,
        see: Option<&Value>,
        post: Option<&Value>,
        rotations: &[Value],
        ctx: &ResolutionContext<'_>,
    ) -> Result<(Option<VerifiedRow>, Option<VerifiedRow>), Reason> {
        let see_prepared = if let Some(row) = see {
            let (parsed, _) = parse_see_grant(row)?;
            let verified = verify_see_grant(&snapshot_see(&parsed), rotations, ctx)?;
            let see_key =
                id_grant_soul(&parsed.owner, &parsed.object, &parsed.accessor).to_string();
            let see_next = admitted_from(&verified, &snapshot_see(&parsed), ctx);
            let see_kept = match self.admitted.get(&see_key) {
                Some(prev) => replaces(prev, &see_next),
                None => true,
            };
            Some((see_key, see_next, see_kept))
        } else {
            None
        };
        let post_prepared = match post {
            Some(row) => Some(self.prepare_post(row, rotations, ctx)?),
            None => None,
        };
        if see_prepared.as_ref().is_some_and(|prepared| !prepared.2)
            || post_prepared.as_ref().is_some_and(|prepared| !prepared.3)
        {
            return Err(Reason::NotKept);
        }
        let see_row = if let Some((key, next, _)) = see_prepared {
            self.admitted.insert(key, next.clone());
            Some(view_row(&next))
        } else {
            None
        };
        let post_row = if let Some((key, next, view, _)) = post_prepared {
            self.post_rows.insert(key, next);
            Some(view)
        } else {
            None
        };
        Ok((see_row, post_row))
    }

    /// Drop this principal's grants and object records that the new checkpoint
    /// no longer accepts. A cancel stays only when it is present or witnessed
    /// under that checkpoint. An object record stays only when the current key
    /// still signs it. Missing history drops both and returns `missing-history`.
    pub fn reverify_principal(
        &mut self,
        principal: &PrincipalId,
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) -> Result<usize, Reason> {
        let Some(rotations) = resolver(principal) else {
            self.admitted.retain(|_, row| row.owner != *principal);
            self.drop_owner_records(principal);
            self.post_rows.retain(|_, row| row.owner != *principal);
            return Err(Reason::MissingHistory);
        };
        let keys: Vec<String> = self
            .admitted
            .iter()
            .filter(|(_, row)| row.owner == *principal)
            .map(|(key, _)| key.clone())
            .collect();
        let mut dropped = 0;
        for key in keys {
            let Some(row) = self.admitted.get(&key) else {
                continue;
            };
            match verify_see_grant(&row.source, &rotations, ctx) {
                Ok(verified) => {
                    self.admitted
                        .insert(key, admitted_from(&verified, &row.source, ctx));
                }
                Err(_) => {
                    self.admitted.remove(&key);
                    dropped += 1;
                }
            }
        }
        let object_ids: Vec<String> = self
            .owners
            .iter()
            .filter(|(_, row)| row.owner == *principal)
            .map(|(id, _)| id.clone())
            .collect();
        for id in object_ids {
            let Some(row) = self.owners.get(&id) else {
                continue;
            };
            if verify_object_record(&row.record, &rotations, ctx).is_err() {
                self.owners.remove(&id);
                self.labels.remove_object(&id);
                dropped += 1;
            }
        }
        dropped += self.reverify_posts(principal, &rotations, ctx);
        Ok(dropped)
    }

    fn drop_owner_records(&mut self, principal: &PrincipalId) {
        let ids: Vec<String> = self
            .owners
            .iter()
            .filter(|(_, row)| row.owner == *principal)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.owners.remove(&id);
            self.labels.remove_object(&id);
        }
    }

    /// The admitted owner record, when one has been verified.
    pub fn admitted_owner(&self, object: &ObjectId) -> Option<(&PrincipalId, u64)> {
        self.owners
            .get(object.as_ref())
            .map(|row| (&row.owner, row.issued_at))
    }

    /// The admitted object owner, when check and post admission need it.
    pub(crate) fn object_owner(&self, object: &ObjectId) -> Option<&PrincipalId> {
        self.owners.get(object.as_ref()).map(|row| &row.owner)
    }

    /// The admitted row for the current owner, object, and accessor.
    pub fn admitted_view(&self, object: &ObjectId, accessor: &PrincipalId) -> Option<VerifiedRow> {
        let owner = self.owners.get(object.as_ref())?;
        let key = id_grant_soul(&owner.owner, object, accessor).to_string();
        self.admitted.get(&key).map(view_row)
    }

    /// Stored-id Check. A raw string is not a parameter.
    ///
    /// ```compile_fail
    /// let graph = sociacl_gun::MeshSeeGraph::new();
    /// graph.check_see("room", "0xbob", 0, None, None);
    /// ```
    pub fn check_see(
        &self,
        object: &ObjectId,
        accessor: &PrincipalId,
        now: u64,
        hint: Option<&HandoffHint>,
        hop: Option<&HopFactor>,
    ) -> MeshCheckResult {
        let hint = hint.cloned();
        let hop = hop.cloned();
        let Some(admission) = self.owners.get(object.as_ref()) else {
            return MeshCheckResult {
                allowed: false,
                reason: "unknown".into(),
                hint,
                hop,
            };
        };
        if admission.owner == *accessor {
            return MeshCheckResult {
                allowed: true,
                reason: MESH_REASON_OWNER.into(),
                hint,
                hop,
            };
        }
        let key = id_grant_soul(&admission.owner, object, accessor).to_string();
        if let Some(row) = self.admitted.get(&key) {
            if row.stated == 1 && now >= row.from && now < row.until {
                return MeshCheckResult {
                    allowed: true,
                    reason: MESH_REASON_DELEGATE.into(),
                    hint,
                    hop,
                };
            }
        }
        MeshCheckResult {
            allowed: false,
            reason: MESH_REASON_DELEGATE.into(),
            hint,
            hop,
        }
    }
}

fn snapshot_see(grant: &sociacl_ids::SeeGrant) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("owner".into(), Value::String(grant.owner.to_string()));
    map.insert("object".into(), Value::String(grant.object.to_string()));
    map.insert("accessor".into(), Value::String(grant.accessor.to_string()));
    map.insert("stated".into(), Value::from(u64::from(grant.stated)));
    map.insert("from".into(), Value::from(grant.from));
    map.insert("until".into(), Value::from(grant.until));
    map.insert("hamState".into(), Value::from(grant.ham_state));
    map.insert("issuedAt".into(), Value::from(grant.issued_at));
    map.insert("sig".into(), Value::String(grant.sig.clone()));
    if let Some(attest) = &grant.attest {
        map.insert("attest".into(), Value::String(attest.clone()));
    }
    Value::Object(map)
}

fn snapshot_object(record: &sociacl_ids::ObjectRecord) -> Value {
    serde_json::json!({
        "object": record.object.as_ref(),
        "owner": record.owner.as_ref(),
        "issuedAt": record.issued_at,
        "sig": record.sig,
    })
}

fn witness_ok(grant: &sociacl_ids::SeeGrant, bytes: &[u8], ctx: &ResolutionContext<'_>) -> bool {
    let Some(token) = grant.attest.as_deref() else {
        return false;
    };
    verify_acl_attestation(token, ctx.jwks, grant.issued_at, bytes)
        .is_ok_and(|attest| attest.principal == grant.owner)
}

fn admitted_from(
    verified: &sociacl_ids::VerifiedSee,
    source: &Value,
    ctx: &ResolutionContext<'_>,
) -> AdmittedSee {
    AdmittedSee {
        mode: verified.mode,
        stated: verified.grant.stated,
        ham_state: verified.grant.ham_state,
        from: verified.grant.from,
        until: verified.grant.until,
        issued_at: verified.grant.issued_at,
        owner: verified.grant.owner.clone(),
        object: verified.grant.object.clone(),
        accessor: verified.grant.accessor.clone(),
        bytes: verified.bytes.clone(),
        source: source.clone(),
        witness: witness_ok(&verified.grant, &verified.bytes, ctx),
    }
}

fn view_row(row: &AdmittedSee) -> VerifiedRow {
    VerifiedRow {
        mode: row.mode,
        stated: row.stated,
        ham_state: row.ham_state,
        from: row.from,
        until: row.until,
        issued_at: row.issued_at,
        owner: row.owner.clone(),
        object: row.object.clone(),
        accessor: row.accessor.clone(),
        attest: has_attest(row),
        bytes: row.bytes.clone(),
        seal: (),
    }
}

fn has_attest(row: &AdmittedSee) -> bool {
    row.source.get("attest").and_then(Value::as_str).is_some()
}

fn strictly_inside(inner_from: u64, inner_until: u64, outer_from: u64, outer_until: u64) -> bool {
    inner_from >= outer_from
        && inner_until <= outer_until
        && (inner_from > outer_from || inner_until < outer_until)
}

fn replaces(prev: &AdmittedSee, next: &AdmittedSee) -> bool {
    if next.ham_state != prev.ham_state {
        return next.ham_state > prev.ham_state;
    }
    if (next.stated == 0) != (prev.stated == 0) {
        return next.stated == 0;
    }
    let next_inside = strictly_inside(next.from, next.until, prev.from, prev.until);
    let prev_inside = strictly_inside(prev.from, prev.until, next.from, next.until);
    if next_inside != prev_inside {
        return next_inside;
    }
    if next.bytes != prev.bytes {
        return next.bytes < prev.bytes;
    }
    next.witness && !prev.witness
}
