//! Stored-id post path. One soul, domain `sociacl-post-grant-v2`.
//!
//! Admission verifies. Check does not. A post allow requires the
//! admitted see graph to allow the same triple. The owner is that
//! object's admitted record. Hint and hop are echoed and never grant.
//! HAM matches see: higher `ham_state`, then a cancel, then strict
//! containment, then the smaller signed bytes, then a validating witness.

use serde_json::Value;
use sociacl_ids::{
    post_soul as id_post_soul, verify_acl_attestation, verify_post_grant, ObjectId, PrincipalId,
    Reason, ResolutionContext, SeeGrant, SignedAtMode,
};

use crate::mesh::VerifiedRow;
use crate::{
    HandoffHint, HopFactor, MeshCheckResult, MeshSeeGraph, MESH_REASON_CANCELLED,
    MESH_REASON_MISSING, MESH_REASON_OWNER,
};

/// Reason when a non-owner's live post grant allows.
pub const MESH_REASON_POST: &str = "post";

/// Admitted post row. The private fields stay on the graph.
#[derive(Clone, Debug)]
pub(crate) struct AdmittedPost {
    pub(crate) mode: SignedAtMode,
    pub(crate) stated: u8,
    pub(crate) ham_state: u64,
    pub(crate) from: u64,
    pub(crate) until: u64,
    pub(crate) owner: PrincipalId,
    pub(crate) bytes: Vec<u8>,
    pub(crate) source: Value,
    pub(crate) witness: bool,
}

fn snapshot_post(grant: &SeeGrant) -> Value {
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

fn witness_ok(grant: &SeeGrant, bytes: &[u8], ctx: &ResolutionContext<'_>) -> bool {
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
) -> AdmittedPost {
    AdmittedPost {
        mode: verified.mode,
        stated: verified.grant.stated,
        ham_state: verified.grant.ham_state,
        from: verified.grant.from,
        until: verified.grant.until,
        owner: verified.grant.owner.clone(),
        bytes: verified.bytes.clone(),
        source: source.clone(),
        witness: witness_ok(&verified.grant, &verified.bytes, ctx),
    }
}

fn view_post(row: &AdmittedPost, grant: &SeeGrant) -> VerifiedRow {
    VerifiedRow {
        mode: row.mode,
        stated: row.stated,
        ham_state: row.ham_state,
        from: row.from,
        until: row.until,
        issued_at: grant.issued_at,
        owner: row.owner.clone(),
        object: grant.object.clone(),
        accessor: grant.accessor.clone(),
        attest: row.source.get("attest").and_then(Value::as_str).is_some(),
        seal: (),
    }
}

fn strictly_inside(inner_from: u64, inner_until: u64, outer_from: u64, outer_until: u64) -> bool {
    inner_from >= outer_from
        && inner_until <= outer_until
        && (inner_from > outer_from || inner_until < outer_until)
}

fn replaces(prev: &AdmittedPost, next: &AdmittedPost) -> bool {
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

impl MeshSeeGraph {
    /// Recheck post rows under the new checkpoint. A failed verify drops the row.
    pub(crate) fn reverify_posts(
        &mut self,
        principal: &PrincipalId,
        rotations: &[Value],
        ctx: &ResolutionContext<'_>,
    ) -> usize {
        let keys: Vec<String> = self
            .post_rows
            .iter()
            .filter(|(_, row)| row.owner == *principal)
            .map(|(key, _)| key.clone())
            .collect();
        let mut dropped = 0;
        for key in keys {
            let Some(row) = self.post_rows.get(&key) else {
                continue;
            };
            match verify_post_grant(&row.source, rotations, ctx) {
                Ok(verified) => {
                    self.post_rows
                        .insert(key, admitted_from(&verified, &row.source, ctx));
                }
                Err(_) => {
                    self.post_rows.remove(&key);
                    dropped += 1;
                }
            }
        }
        dropped
    }

    /// Admit one post row. The owner is the admitted object record.
    /// A missing object is `unknown`. A different row owner is `bad-record`.
    pub fn admit_post(
        &mut self,
        row: &Value,
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) -> Result<(VerifiedRow, bool), Reason> {
        let (grant, _) = sociacl_ids::parse_post_grant(row)?;
        let Some(rotations) = resolver(&grant.owner) else {
            return Err(Reason::MissingHistory);
        };
        let verified = verify_post_grant(&snapshot_post(&grant), &rotations, ctx)?;
        let Some(owner) = self.object_owner(&verified.grant.object).cloned() else {
            return Err(Reason::Unknown);
        };
        if owner != verified.grant.owner {
            return Err(Reason::BadRecord);
        }
        let key =
            id_post_soul(&owner, &verified.grant.object, &verified.grant.accessor).to_string();
        let next = admitted_from(&verified, &snapshot_post(&verified.grant), ctx);
        let kept = match self.post_rows.get(&key) {
            Some(prev) => replaces(prev, &next),
            None => true,
        };
        if kept {
            self.post_rows.insert(key.clone(), next);
        }
        let stored = self.post_rows.get(&key).expect("admitted post");
        let (stored_grant, _) = sociacl_ids::parse_post_grant(&stored.source)?;
        Ok((view_post(stored, &stored_grant), kept))
    }

    /// The admitted post row for this object and accessor, under the admitted owner.
    pub fn admitted_post(&self, object: &ObjectId, accessor: &PrincipalId) -> Option<VerifiedRow> {
        let owner = self.object_owner(object)?;
        let key = id_post_soul(owner, object, accessor).to_string();
        let row = self.post_rows.get(&key)?;
        let (grant, _) = sociacl_ids::parse_post_grant(&row.source).ok()?;
        Some(view_post(row, &grant))
    }

    /// Stored-id post Check. A raw string is not a parameter.
    /// See is the typed admitted graph. A label see grant is not enough.
    ///
    /// ```compile_fail
    /// let graph = sociacl_gun::MeshSeeGraph::new();
    /// graph.check_post("room", "0xbob", 0, None, None);
    /// ```
    pub fn check_post(
        &self,
        object: &ObjectId,
        accessor: &PrincipalId,
        now: u64,
        hint: Option<&HandoffHint>,
        hop: Option<&HopFactor>,
    ) -> MeshCheckResult {
        let see = self.check_see(object, accessor, now, hint, hop);
        if !see.allowed || see.reason == MESH_REASON_OWNER {
            return see;
        }
        let Some(owner) = self.object_owner(object) else {
            return MeshCheckResult {
                allowed: false,
                reason: "unknown".into(),
                hint: see.hint,
                hop: see.hop,
            };
        };
        let key = id_post_soul(owner, object, accessor).to_string();
        if let Some(row) = self.post_rows.get(&key) {
            if row.stated == 0 {
                return MeshCheckResult {
                    allowed: false,
                    reason: MESH_REASON_CANCELLED.into(),
                    hint: see.hint,
                    hop: see.hop,
                };
            }
            if row.stated == 1 && now >= row.from && now < row.until {
                return MeshCheckResult {
                    allowed: true,
                    reason: MESH_REASON_POST.into(),
                    hint: see.hint,
                    hop: see.hop,
                };
            }
        }
        MeshCheckResult {
            allowed: false,
            reason: MESH_REASON_MISSING.into(),
            hint: see.hint,
            hop: see.hop,
        }
    }
}
