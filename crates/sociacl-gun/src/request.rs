//! Access requests are hints. Approving one writes owner-signed v2 see
//! and post rows, and only after both rows have been checked.
//! A hop, a hint, a wrap, a request, or an inbox delivery never grants.

use serde_json::{json, Value};
use sociacl_core::Timestamp;
use sociacl_ids::{
    parse_access_request, parse_principal_id, post_grant_bytes, resolve_current_key,
    see_grant_bytes, sign_with_keyring, verify_post_grant, verify_see_grant, verify_signed_at,
    PrincipalId, Reason, ResolutionContext, SeeGrant,
};

use crate::mesh::{MeshSeeGraph, VerifiedRow};
use crate::GroupPredicate;

/// Rows written for one approved request. `post` is absent for scope `read`.
#[derive(Clone, Debug)]
pub struct ApprovedRequest {
    pub request_id: String,
    pub see: VerifiedRow,
    pub post: Option<VerifiedRow>,
}

fn deny(reason: Reason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "bad-record".to_string())
}

fn ham_next(current: Option<u64>) -> Result<u64, String> {
    let next = current.unwrap_or(0).checked_add(1).ok_or("see-ceiling")?;
    if next > 9_007_199_254_740_991 {
        return Err("see-ceiling".to_string());
    }
    Ok(next)
}

fn signed_row(
    mut grant: SeeGrant,
    scalar: &[u8],
    key: &PrincipalId,
    bytes_of: fn(&SeeGrant) -> Vec<u8>,
) -> Result<Value, String> {
    let sig = sign_with_keyring(scalar, &bytes_of(&grant), key).map_err(deny)?;
    grant.sig = sig;
    Ok(json!({
        "owner": grant.owner.as_ref(),
        "object": grant.object.as_ref(),
        "accessor": grant.accessor.as_ref(),
        "stated": grant.stated,
        "from": grant.from,
        "until": grant.until,
        "hamState": grant.ham_state,
        "issuedAt": grant.issued_at,
        "sig": grant.sig,
    }))
}

impl MeshSeeGraph {
    /// Owner's client. The requester signature is present authority only.
    /// See and post ceilings are checked before either row is written.
    /// `issued_at` on the new rows is `ctx.now`.
    pub fn grant_approved_request(
        &mut self,
        owner: &PrincipalId,
        request: &Value,
        from: u64,
        until: u64,
        members: Option<(GroupPredicate, u64)>,
        scalar: &[u8],
        resolver: &dyn Fn(&PrincipalId) -> Option<Vec<Value>>,
        ctx: &ResolutionContext<'_>,
    ) -> Result<ApprovedRequest, String> {
        let (req, bytes) = parse_access_request(request).map_err(deny)?;
        if req.status == "withdrawn" {
            return Err("withdrawn".to_string());
        }
        if until <= from || from > 9_007_199_254_740_991 || until > 9_007_199_254_740_991 {
            return Err("bad-record".to_string());
        }
        let Some(owner_history) = resolver(owner) else {
            return Err("missing-history".to_string());
        };
        let Some(requester_history) = resolver(&req.requester) else {
            return Err("missing-history".to_string());
        };
        verify_signed_at(
            &req.requester,
            &requester_history,
            ctx,
            &bytes,
            &req.sig,
            req.issued_at,
        )
        .map_err(deny)?;
        let Some(admitted_owner) = self.object_owner(&req.object).cloned() else {
            return Err("unknown".to_string());
        };
        if admitted_owner != *owner {
            return Err("owner-mismatch".to_string());
        }
        if let Some((predicate, now)) = members {
            let see = self.check_group_see(
                predicate,
                req.object.as_ref(),
                req.requester.as_ref(),
                Timestamp(now),
                None,
                None,
            );
            if !see.allowed {
                return Err("not-member".to_string());
            }
        }
        let see_ham = match ham_next(self.admitted_view(&req.object, &req.requester).map(|row| row.ham_state))
        {
            Ok(ham) => ham,
            Err(_) => return Err("see-ceiling".to_string()),
        };
        let post_ham = if req.scope == "read+post" {
            match ham_next(self.admitted_post(&req.object, &req.requester).map(|row| row.ham_state)) {
                Ok(ham) => Some(ham),
                Err(_) => return Err("post-ceiling".to_string()),
            }
        } else {
            None
        };
        if ctx.now > 9_007_199_254_740_991 {
            return Err("bad-record".to_string());
        }
        let current = resolve_current_key(owner, &owner_history, ctx)
            .result
            .map_err(deny)?;
        let see_fields = SeeGrant {
            owner: owner.clone(),
            object: req.object.clone(),
            accessor: req.requester.clone(),
            stated: 1,
            from,
            until,
            ham_state: see_ham,
            issued_at: ctx.now,
            sig: String::new(),
            attest: None,
        };
        let see_row = signed_row(see_fields, scalar, &current.current_key, see_grant_bytes)?;
        verify_see_grant(&see_row, &owner_history, ctx).map_err(deny)?;
        let post_row = if let Some(ham) = post_ham {
            let row = signed_row(
                SeeGrant {
                    owner: owner.clone(),
                    object: req.object.clone(),
                    accessor: req.requester.clone(),
                    stated: 1,
                    from,
                    until,
                    ham_state: ham,
                    issued_at: ctx.now,
                    sig: String::new(),
                    attest: None,
                },
                scalar,
                &current.current_key,
                post_grant_bytes,
            )?;
            verify_post_grant(&row, &owner_history, ctx).map_err(deny)?;
            Some(row)
        } else {
            None
        };
        let (see, post) = self
            .commit_grant_rows(&see_row, post_row.as_ref(), resolver, ctx)
            .map_err(deny)?;
        Ok(ApprovedRequest {
            request_id: req.request_id,
            see,
            post,
        })
    }
}

/// Parse an owner argument the same way the edge does. A non-string is `not-string`.
pub fn request_owner(value: &Value) -> Result<PrincipalId, String> {
    match value.as_str() {
        Some(text) => parse_principal_id(text).map_err(deny),
        None => Err("not-string".to_string()),
    }
}
