//! Signed access-request encoding and the owner-client approval helper.
//!
//! A request is an untrusted hint. Accepting one does not write a grant
//! and does not set `allowed`. The owner's own client calls
//! [`MeshSeeGraph::grant_approved_request`] after it has approved a
//! pending request. That call writes a see grant, and a post grant when
//! the scope is `read+post`. Members auto-approve is `check_group_see`
//! on that same client. There is no hosted evaluator. Explicit deny and
//! the policy queue are not this crate.
//!
//! The request id is the SHA-256 of a length-prefixed domain plus the
//! canonical accessor id and a canonical object key. `0xbob` and
//! `s3rch/users/0xbob` are one accessor (`canonical_accessor_id`).
//! A string containing `.get(` is rejected, not parsed. `room:alpha`
//! and `s3rch/items/room:alpha` are one object when the raw id may
//! alias to that item soul. An underscore in the raw id stays.
//! `a/b` is not `a_b`. `a_b` and `s3rch/items/a_b` are one object.
//! `room.alpha`, `room_alpha`, and `room/alpha` are different keys.
//! `s3rch/items/room~1alpha` is the item soul of `room.alpha` and
//! shares that request id. A principal is not an object escape.
//! A held claim id does not alias. Requester and source are Unicode
//! scalar values. U+0085 and U+FEFF are rejected.
//! Scope, message, and status are not part of the id. Scope is only
//! `read` or `read+post`. Status is only `pending` or `withdrawn`.
//! Other spellings are rejected.
//!
//! Grant rows use the in-graph object id (`canonical_object_id`) and
//! the canonical accessor id, the same ids see and post already write.
//! The requester signs the request bytes. The owner's client verifies
//! that signature against the requester's enrolled key before any
//! write. Grant rows stay unsigned. The post row's
//! `post_grant_signing_bytes` are what a later owner signature can
//! cover. A hop, a hint, a wrap, a request, or an inbox delivery never
//! grants. Hopcap stays 1.

use sha2::{Digest, Sha256};
use sociacl_core::{AttestationSig, IssuerSecret, Timestamp};

use crate::mesh::{closed_reason, is_item_shaped, may_alias_to_item_soul};
use crate::soul::{acl_key, canonical_accessor_id, encode_key, unescape_acl_key, GunSoul};
use crate::{
    post_grant_signing_bytes, GroupPredicate, GunAclEdge, GunError, GunPostEdge, MeshPostGrant,
    MeshSeeGrant, MeshSeeGraph,
};

/// Length-prefixed domain for [`access_request_signing_bytes`].
pub const ACCESS_REQUEST_DOMAIN: &str = "s3rch-access-request-v1";

/// Length-prefixed domain for [`access_request_id`].
pub const ACCESS_REQUEST_ID_DOMAIN: &str = "s3rch-request";

/// Scope that writes a see grant only.
pub const ACCESS_SCOPE_READ: &str = "read";

/// Scope that writes a see grant and a post grant.
pub const ACCESS_SCOPE_READ_POST: &str = "read+post";

/// Requester status. A pending request can be approved by the owner client.
pub const ACCESS_STATUS_PENDING: &str = "pending";

/// Requester status. A withdrawal writes no grant.
pub const ACCESS_STATUS_WITHDRAWN: &str = "withdrawn";

/// Maximum message length in Unicode scalar values. Empty is allowed.
pub const ACCESS_MESSAGE_MAX: usize = 280;

/// Largest integer JavaScript `Number.isSafeInteger` accepts.
const JS_SAFE_INTEGER_MAX: u64 = (1 << 53) - 1;

/// Untrusted access request. Not a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    pub requester: String,
    pub source: String,
    pub scope: String,
    pub message: String,
    pub status: String,
    /// Ed25519 signature over [`access_request_signing_bytes`].
    /// Empty is not a grant. Not an owner signature on a grant row.
    pub signature: Vec<u8>,
}

/// Canonical request. `requester` is the accessor id. `source` is the
/// object key that collapses spelling variants. `id` is 64 lowercase hex.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedAccessRequest {
    pub requester: String,
    pub source: String,
    pub scope: String,
    pub message: String,
    pub status: String,
    pub id: String,
    pub signing_bytes: Vec<u8>,
}

/// Members auto-approve on the owner's client. `check_group_see` is the
/// gate. Hop and hint are not inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembersAutoApprove {
    pub predicate: GroupPredicate,
    pub now: Timestamp,
}

/// Owner-written rows for one approved request. Unsigned. The post
/// signing bytes are present only for `read+post`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerGrantRows {
    pub request_id: String,
    pub request_signing_bytes: Vec<u8>,
    pub see: GunAclEdge,
    pub post: Option<GunPostEdge>,
    pub post_signing_bytes: Option<Vec<u8>>,
}

/// Canonical accessor id from #51. Empty is rejected.
/// The raw string is Unicode scalar values (`str`). U+0085 and U+FEFF
/// are rejected so this trim matches JavaScript.
pub fn canonical_request_accessor(requester: &str) -> Result<String, GunError> {
    if requester.contains(".get(") {
        return Err(GunError::AccessRequestField);
    }
    reject_trim_mismatch(requester)?;
    canonical_accessor_id(requester).ok_or(GunError::AccessRequestField)
}

/// Object key for a request id.
///
/// `aclKey` is injective, so `.` and `/` do not share a key with `_`.
/// An item soul collapses to the `aclKey` of its raw id when that raw
/// id may alias to the soul. `a_b` and `s3rch/items/a_b` are one key.
/// `a/b` is not. A held claim id without `/` does not collapse to an
/// item soul. A string
/// containing `.get(` is rejected. `s3rch/meta`, dest ACL, and a URL
/// leaf are rejected.
/// U+0085 and U+FEFF are rejected. The in-graph spelling used on grant
/// rows is still `canonical_object_id`.
pub fn canonical_request_object(source: &str) -> Result<String, GunError> {
    if source.contains(".get(") {
        return Err(GunError::AccessRequestField);
    }
    reject_trim_mismatch(source)?;
    let id = source.trim();
    if id.is_empty() || closed_reason(id).is_some() {
        return Err(GunError::AccessRequestField);
    }
    if let Some(inner) = reducible_item_inner(id) {
        let key = acl_key(&inner);
        if key.is_empty() {
            return Err(GunError::AccessRequestField);
        }
        return Ok(key);
    }
    let key = acl_key(id);
    if key.is_empty() {
        return Err(GunError::AccessRequestField);
    }
    Ok(key)
}

/// SHA-256 (lowercase hex) of the length-prefixed id domain, the
/// canonical accessor, and the canonical object key. Scope, message,
/// and status are not inputs. Two spellings of one pair share this id.
pub fn access_request_id(requester: &str, source: &str) -> Result<String, GunError> {
    let accessor = canonical_request_accessor(requester)?;
    let object = canonical_request_object(source)?;
    let bytes = length_prefixed(&[ACCESS_REQUEST_ID_DOMAIN.to_string(), accessor, object])?;
    Ok(sha256_hex(&bytes))
}

/// Length-prefixed bytes the requester signs.
///
/// Order: domain `s3rch-access-request-v1`, the request id, scope,
/// message, status. Lengths are uint32 little-endian. This function
/// does not verify a signature and does not grant.
pub fn access_request_signing_bytes(request: &AccessRequest) -> Result<Vec<u8>, GunError> {
    let id = access_request_id(&request.requester, &request.source)?;
    let scope = canonical_scope(&request.scope)?;
    let status = canonical_status(&request.status)?;
    let message = canonical_message(&request.message)?;
    length_prefixed(&[
        ACCESS_REQUEST_DOMAIN.to_string(),
        id,
        scope,
        message,
        status,
    ])
}

/// Canonicalize a request. Does not read a graph and does not grant.
pub fn accept_access_request(request: &AccessRequest) -> Result<AcceptedAccessRequest, GunError> {
    let requester = canonical_request_accessor(&request.requester)?;
    let source = canonical_request_object(&request.source)?;
    let scope = canonical_scope(&request.scope)?;
    let status = canonical_status(&request.status)?;
    let message = canonical_message(&request.message)?;
    let signing_bytes = access_request_signing_bytes(request)?;
    let id = access_request_id(&request.requester, &request.source)?;
    Ok(AcceptedAccessRequest {
        requester,
        source,
        scope,
        message,
        status,
        id,
        signing_bytes,
    })
}

/// Ed25519 signature over [`access_request_signing_bytes`].
/// The requester holds the secret. This does not grant.
pub fn sign_access_request(
    secret: &IssuerSecret,
    request: &AccessRequest,
) -> Result<Vec<u8>, GunError> {
    let bytes = access_request_signing_bytes(request)?;
    Ok(secret.sign(&bytes).0.to_vec())
}

impl MeshSeeGraph {
    /// Owner's client. Writes grant rows for an approved pending request.
    ///
    /// `members` runs `check_group_see` and writes only when that allows.
    /// Without `members`, the caller is the owner's client asserting it
    /// already approved. A withdrawn request writes nothing. A caller who
    /// is not the object owner writes nothing. A request, hop, hint, wrap,
    /// or inbox delivery is not an approval. Rows use the stored object
    /// id and the canonical accessor id. The requester signature is
    /// checked against the enrolled key before any write. Grant rows
    /// stay unsigned.
    pub fn grant_approved_request(
        &mut self,
        owner: impl AsRef<str>,
        request: &AccessRequest,
        from: u64,
        until: u64,
        members: Option<MembersAutoApprove>,
    ) -> Result<OwnerGrantRows, GunError> {
        let accepted = accept_access_request(request)?;
        verify_request_signature(
            self,
            &accepted.requester,
            &accepted.signing_bytes,
            &request.signature,
        )?;
        if accepted.status != ACCESS_STATUS_PENDING {
            return Err(GunError::AccessRequestWithdrawn);
        }
        canonical_window(from, until)?;
        let owner = owner.as_ref().trim();
        let (stored_id, object_owner) = self
            .object_record(&request.source)
            .map(|(id, object_owner)| (id.to_string(), object_owner.to_string()))
            .ok_or(GunError::ObjectNotInGraph)?;
        if canonical_accessor_id(&object_owner) != canonical_accessor_id(owner) {
            return Err(GunError::AclOwnerOnly);
        }
        if let Some(rule) = members {
            let see = self.check_group_see(
                rule.predicate,
                &stored_id,
                &accepted.requester,
                rule.now,
                None,
                None,
            );
            if !see.allowed {
                return Err(GunError::AccessRequestNotMember);
            }
        }
        let accessor = accepted.requester.clone();
        if let Some(edge) = self.folded_see(&stored_id, &accessor, owner) {
            if edge.ham_state.saturating_add(1) > JS_SAFE_INTEGER_MAX {
                return Err(GunError::SeeGrantCeiling);
            }
        }
        if accepted.scope == ACCESS_SCOPE_READ_POST {
            if let Some(edge) = self.folded_post(&stored_id, &accessor, owner) {
                if edge.ham_state.saturating_add(1) > JS_SAFE_INTEGER_MAX {
                    return Err(GunError::PostGrantField);
                }
            }
        }
        self.state_see_grant(
            &object_owner,
            MeshSeeGrant::live(&stored_id, &accessor, from, until),
        )?;
        let see_live = self
            .grant_edge(&stored_id, &accessor)
            .map(|edge| edge.grant.stated == 1)
            .unwrap_or(false);
        if !see_live {
            return Err(GunError::SeeGrantCeiling);
        }
        let post = if accepted.scope == ACCESS_SCOPE_READ_POST {
            self.state_post_grant(
                &object_owner,
                MeshPostGrant::live(&stored_id, &accessor, from, until),
            )?;
            Some(
                self.post_edge(&stored_id, &accessor)
                    .cloned()
                    .ok_or(GunError::ObjectNotInGraph)?,
            )
        } else {
            None
        };
        let see = self
            .grant_edge(&stored_id, &accessor)
            .cloned()
            .ok_or(GunError::ObjectNotInGraph)?;
        let post_signing_bytes = match &post {
            Some(edge) => Some(post_grant_signing_bytes(&edge.grant, edge.ham_state)?),
            None => None,
        };
        Ok(OwnerGrantRows {
            request_id: accepted.id,
            request_signing_bytes: accepted.signing_bytes,
            see,
            post,
            post_signing_bytes,
        })
    }
}

fn verify_request_signature(
    graph: &MeshSeeGraph,
    requester: &str,
    bytes: &[u8],
    signature: &[u8],
) -> Result<(), GunError> {
    let Some(key) = graph.enrolled_key(requester) else {
        return Err(GunError::AccessRequestSignature);
    };
    let Ok(sig) = AttestationSig::from_slice(signature) else {
        return Err(GunError::AccessRequestSignature);
    };
    if !key.verify(bytes, &sig) {
        return Err(GunError::AccessRequestSignature);
    }
    Ok(())
}

fn canonical_scope(scope: &str) -> Result<String, GunError> {
    match scope {
        ACCESS_SCOPE_READ | ACCESS_SCOPE_READ_POST => Ok(scope.to_string()),
        _ => Err(GunError::AccessRequestField),
    }
}

fn canonical_status(status: &str) -> Result<String, GunError> {
    match status {
        ACCESS_STATUS_PENDING | ACCESS_STATUS_WITHDRAWN => Ok(status.to_string()),
        _ => Err(GunError::AccessRequestField),
    }
}

fn canonical_message(message: &str) -> Result<String, GunError> {
    if message.chars().count() > ACCESS_MESSAGE_MAX {
        return Err(GunError::AccessRequestField);
    }
    Ok(message.to_string())
}

/// Rust strips U+0085 and keeps U+FEFF. JavaScript does the opposite.
/// Either character in a requester or source is rejected.
fn reject_trim_mismatch(text: &str) -> Result<(), GunError> {
    if text.chars().any(|ch| ch == '\u{0085}' || ch == '\u{FEFF}') {
        return Err(GunError::AccessRequestField);
    }
    Ok(())
}

fn canonical_window(from: u64, until: u64) -> Result<(), GunError> {
    if from > JS_SAFE_INTEGER_MAX || until > JS_SAFE_INTEGER_MAX || from >= until {
        return Err(GunError::AccessRequestField);
    }
    Ok(())
}

/// Item soul `s3rch/items/<encodeKey(raw)>`. The inner segment is
/// decoded once, then the caller applies `acl_key` to that raw id.
fn reducible_item_inner(id: &str) -> Option<String> {
    let soul = GunSoul::parse(id).ok()?;
    if !soul.is_s3rch_item() {
        return None;
    }
    let encoded = soul.segments().get(2)?.clone();
    if encoded.is_empty() || encoded.contains('/') {
        return None;
    }
    let raw = unescape_acl_key(&encoded)?;
    if raw.is_empty() || raw.contains('/') || encode_key(&raw) != encoded {
        return None;
    }
    if !may_alias_to_item_soul(&raw) || is_item_shaped(&raw) {
        return None;
    }
    let expected = GunSoul::s3rch_item(&raw).as_node_id();
    if expected.as_str() != id.trim() {
        return None;
    }
    Some(raw)
}

fn length_prefixed(fields: &[String]) -> Result<Vec<u8>, GunError> {
    let mut out = Vec::new();
    for field in fields {
        let raw = field.as_bytes();
        let len = u32::try_from(raw.len()).map_err(|_| GunError::AccessRequestField)?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(raw);
    }
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}
