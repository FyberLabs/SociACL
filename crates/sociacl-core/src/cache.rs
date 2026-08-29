use std::cell::RefCell;
use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::types::{Action, NodeId, ObjectVersion, PredicateId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SnapshotHash(pub [u8; 32]);

impl SnapshotHash {
    pub fn digest(parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        let out = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        Self(bytes)
    }
}

/// Snapshot of jointly stated edges bound to an object version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub object: NodeId,
    pub object_version: ObjectVersion,
    pub hash: SnapshotHash,
}

/// Zanzibar-style freshness token. Bound to object version (new-enemy).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zookie {
    pub object: NodeId,
    pub object_version: ObjectVersion,
    pub snapshot_hash: SnapshotHash,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheKey {
    pub object: NodeId,
    pub object_version: ObjectVersion,
    pub snapshot_hash: SnapshotHash,
    pub accessor: NodeId,
    pub predicate: PredicateId,
    pub action: Action,
}

/// Hash cache keyed like a zookie. Implementations must not return an allow
/// for a key whose object version is older than the object being checked.
pub trait HashCache {
    fn get(&self, key: &CacheKey) -> Option<bool>;
    fn insert(&self, key: CacheKey, allowed: bool);
}

#[derive(Clone, Debug, Default)]
pub struct MemoryHashCache {
    map: RefCell<HashMap<CacheKey, bool>>,
}

impl HashCache for MemoryHashCache {
    fn get(&self, key: &CacheKey) -> Option<bool> {
        self.map.borrow().get(key).copied()
    }

    fn insert(&self, key: CacheKey, allowed: bool) {
        self.map.borrow_mut().insert(key, allowed);
    }
}
