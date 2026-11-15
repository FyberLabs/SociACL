//! Independent group key snapshots. Inputs must come from current admitted
//! membership and identity histories; a snapshot never grants media access.
use crate::{canonical, EncDiscError, GroupPredicate};
use sociacl_ids::{object_principal, ObjectId, PrincipalId};
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyMember {
    pub accessor: String,
    pub stated: u64,
    pub ham_state: u64,
    pub signing_pub: String,
    pub encryption_pub: String,
    pub identity_head: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeySnapshot {
    pub predicate: GroupPredicate,
    pub set_id: String,
    pub set_owner: String,
    pub owner_signing_pub: String,
    pub owner_encryption_pub: String,
    pub owner_identity_head: u64,
    /// Strict byte order, including retained withdrawals. No implicit owner row.
    pub members: Vec<GroupKeyMember>,
}

fn principal(value: &str) -> Result<(), EncDiscError> {
    value.parse::<PrincipalId>().map(|_| ()).map_err(|_| EncDiscError::EpochRejected)
}

pub fn group_key_snapshot_bytes(snapshot: &GroupKeySnapshot) -> Result<Vec<u8>, EncDiscError> {
    let set = snapshot.set_id.parse::<ObjectId>().map_err(|_| EncDiscError::EpochRejected)?;
    let owner = object_principal(&set).map_err(|_| EncDiscError::EpochRejected)?;
    if !snapshot.set_id.starts_with("set_") || owner.as_ref() != snapshot.set_owner
        || snapshot.owner_identity_head > MAX_SAFE || snapshot.members.len() > 64 {
        return Err(EncDiscError::EpochRejected);
    }
    for value in [&snapshot.set_owner, &snapshot.owner_signing_pub, &snapshot.owner_encryption_pub] {
        principal(value)?;
    }
    let mut fields = vec!["s3rch-group-key-snapshot-v1".to_string(), snapshot.predicate.as_str().to_string(),
        snapshot.set_id.clone(), snapshot.set_owner.clone(), snapshot.owner_signing_pub.clone(),
        snapshot.owner_encryption_pub.clone(), snapshot.owner_identity_head.to_string(), snapshot.members.len().to_string()];
    let mut previous: Option<&str> = None;
    for member in &snapshot.members {
        if member.stated > 1 || member.ham_state > MAX_SAFE || member.identity_head > MAX_SAFE
            || previous.is_some_and(|value| value.as_bytes() >= member.accessor.as_bytes()) {
            return Err(EncDiscError::EpochRejected);
        }
        for value in [&member.accessor, &member.signing_pub, &member.encryption_pub] { principal(value)?; }
        if member.accessor == snapshot.set_owner && (member.signing_pub != snapshot.owner_signing_pub
            || member.encryption_pub != snapshot.owner_encryption_pub || member.identity_head != snapshot.owner_identity_head) {
            return Err(EncDiscError::EpochRejected);
        }
        previous = Some(&member.accessor);
        fields.extend([member.accessor.clone(), member.stated.to_string(), member.ham_state.to_string(),
            member.signing_pub.clone(), member.encryption_pub.clone(), member.identity_head.to_string()]);
    }
    canonical::length_prefixed(&fields.iter().map(String::as_str).collect::<Vec<_>>())
}

pub fn group_key_snapshot_id(snapshot: &GroupKeySnapshot) -> Result<String, EncDiscError> {
    Ok(canonical::sha256_hex(&group_key_snapshot_bytes(snapshot)?))
}
