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
use crate::{GroupPredicate, MESH_REASON_OWNER};

/// Rows written for one approved request. `post` is absent for scope `read`.
#[derive(Clone, Debug)]
pub struct ApprovedRequest {
    pub request_id: String,
    pub see: VerifiedRow,
    pub post: Option<VerifiedRow>,
    /// The stored row already matched. No new signature and no ham bump.
    pub unchanged: bool,
}

fn same_live(
    row: &VerifiedRow,
    owner: &PrincipalId,
    object: &sociacl_ids::ObjectId,
    accessor: &PrincipalId,
    from: u64,
    until: u64,
) -> bool {
    row.stated == 1
        && row.owner == *owner
        && row.object == *object
        && row.accessor == *accessor
        && row.from == from
        && row.until == until
}

fn ham_next(current: Option<u64>, ceiling: Reason) -> Result<u64, Reason> {
    let next = current.unwrap_or(0).checked_add(1).ok_or(ceiling)?;
    if next > 9_007_199_254_740_991 {
        return Err(ceiling);
    }
    Ok(next)
}

fn signed_row(
    mut grant: SeeGrant,
    scalar: &[u8],
    key: &PrincipalId,
    bytes_of: fn(&SeeGrant) -> Vec<u8>,
) -> Result<Value, Reason> {
    let sig = sign_with_keyring(scalar, &bytes_of(&grant), key)?;
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
    ) -> Result<ApprovedRequest, Reason> {
        let (req, bytes) = parse_access_request(request)?;
        if req.status == "withdrawn" {
            return Err(Reason::Withdrawn);
        }
        if until <= from || from > 9_007_199_254_740_991 || until > 9_007_199_254_740_991 {
            return Err(Reason::BadRecord);
        }
        let Some(owner_history) = resolver(owner) else {
            return Err(Reason::MissingHistory);
        };
        let Some(requester_history) = resolver(&req.requester) else {
            return Err(Reason::MissingHistory);
        };
        verify_signed_at(
            &req.requester,
            &requester_history,
            ctx,
            &bytes,
            &req.sig,
            req.issued_at,
        )?;
        let Some(admitted_owner) = self.object_owner(&req.object).cloned() else {
            return Err(Reason::Unknown);
        };
        if admitted_owner != *owner {
            return Err(Reason::OwnerMismatch);
        }
        let see_stored = self.admitted_view(&req.object, &req.requester);
        let post_stored = if req.scope == "read+post" {
            self.admitted_post(&req.object, &req.requester)
        } else {
            None
        };
        let see_same = see_stored
            .as_ref()
            .is_some_and(|row| same_live(row, owner, &req.object, &req.requester, from, until));
        let post_same = req.scope != "read+post"
            || post_stored
                .as_ref()
                .is_some_and(|row| same_live(row, owner, &req.object, &req.requester, from, until));
        if see_same && post_same {
            return Ok(ApprovedRequest {
                request_id: req.request_id,
                see: see_stored.expect("matching see"),
                post: if req.scope == "read+post" {
                    post_stored
                } else {
                    None
                },
                unchanged: true,
            });
        }
        if let Some((predicate, now)) = members {
            let Some(label_owner) = self.labels.owner_of(req.object.as_ref()) else {
                return Err(Reason::NotMember);
            };
            let Ok(label) = parse_principal_id(&label_owner) else {
                return Err(Reason::NotMember);
            };
            if label != *owner {
                return Err(Reason::NotMember);
            }
            let see = self.check_group_see(
                predicate,
                req.object.as_ref(),
                req.requester.as_ref(),
                Timestamp(now),
                None,
                None,
            );
            if !see.allowed || see.reason == MESH_REASON_OWNER || see.reason != predicate.as_str() {
                return Err(Reason::NotMember);
            }
            if see_stored.as_ref().is_some_and(|row| row.stated == 0) {
                return Err(Reason::NotKept);
            }
            if req.scope == "read+post" && post_stored.as_ref().is_some_and(|row| row.stated == 0) {
                return Err(Reason::NotKept);
            }
        }
        let see_ham = if see_same {
            None
        } else {
            Some(ham_next(
                see_stored.as_ref().map(|row| row.ham_state),
                Reason::SeeCeiling,
            )?)
        };
        let post_ham = if req.scope == "read+post" && !post_same {
            Some(ham_next(
                post_stored.as_ref().map(|row| row.ham_state),
                Reason::PostCeiling,
            )?)
        } else {
            None
        };
        if ctx.now > 9_007_199_254_740_991 {
            return Err(Reason::BadRecord);
        }
        let current = resolve_current_key(owner, &owner_history, ctx).result?;
        if current.rotations.iter().map(|row| row.issued_at).max() == Some(ctx.now) {
            return Err(Reason::RotationBoundary);
        }
        let see_row = if let Some(ham) = see_ham {
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
                see_grant_bytes,
            )?;
            verify_see_grant(&row, &owner_history, ctx)?;
            Some(row)
        } else {
            None
        };
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
            verify_post_grant(&row, &owner_history, ctx)?;
            Some(row)
        } else {
            None
        };
        let (wrote_see, wrote_post) =
            self.commit_grant_rows(see_row.as_ref(), post_row.as_ref(), &owner_history, ctx)?;
        Ok(ApprovedRequest {
            request_id: req.request_id,
            see: if see_same {
                see_stored.expect("matching see")
            } else {
                wrote_see.expect("written see")
            },
            post: if req.scope == "read+post" {
                if post_same {
                    post_stored
                } else {
                    wrote_post
                }
            } else {
                None
            },
            unchanged: false,
        })
    }
}

/// Parse an owner argument the same way the edge does. A non-string is `not-string`.
pub fn request_owner(value: &Value) -> Result<PrincipalId, Reason> {
    match value.as_str() {
        Some(text) => parse_principal_id(text),
        None => Err(Reason::NotString),
    }
}
