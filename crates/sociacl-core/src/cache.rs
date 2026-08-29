use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};

use sha2::{Digest, Sha256};

use crate::types::{Action, NodeId, ObjectVersion, Relation};

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

/// Snapshot of edges that currently grant, bound to an object version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub object: NodeId,
    pub object_version: ObjectVersion,
    pub hash: SnapshotHash,
}

/// Zanzibar-style freshness token. Bound to this object's version (new-enemy).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zookie {
    pub object: NodeId,
    pub object_version: ObjectVersion,
    pub snapshot_hash: SnapshotHash,
}

/// Owner plus named group/circle/trustee anchors on the object.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheAnchors {
    pub owner: NodeId,
    pub extra: BTreeSet<NodeId>,
}

/// Relation set used by the object's named predicate.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct EdgeTypeSet {
    relations: BTreeSet<Relation>,
}

impl EdgeTypeSet {
    pub fn from_predicate(predicate: &str) -> Self {
        let relations = match predicate {
            crate::types::PredicateId::OWNER => [Relation::Owns].into_iter().collect(),
            crate::types::PredicateId::SAME_GROUP => [Relation::ObjectGroup, Relation::MemberOf]
                .into_iter()
                .collect(),
            crate::types::PredicateId::NAMED_CIRCLE => {
                [Relation::ObjectCircle, Relation::InCircle, Relation::Friend]
                    .into_iter()
                    .collect()
            }
            crate::types::PredicateId::POSIX_MODE => {
                [Relation::Owns, Relation::MemberOf].into_iter().collect()
            }
            crate::types::PredicateId::TRUSTEE => [Relation::Trustee].into_iter().collect(),
            _ => BTreeSet::new(),
        };
        Self { relations }
    }

    pub fn iter(&self) -> impl Iterator<Item = Relation> + '_ {
        self.relations.iter().copied()
    }
}

/// Keyed by (accessor, owner-or-anchors, edge-types, hopcap, snapshot).
/// `action` is also stored so `posix-mode` bits are not reused across verbs.
/// Object version lives on the snapshot / zookie, not as a second TTL.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CacheKey {
    pub accessor: NodeId,
    pub anchors: CacheAnchors,
    pub edge_types: EdgeTypeSet,
    pub hopcap: u32,
    pub snapshot: SnapshotHash,
    pub action: Action,
}

/// Hash cache keyed like a zookie. Implementations must not return an allow
/// for a key whose snapshot is older than the object being checked.
pub trait HashCache {
    fn get(&self, key: &CacheKey) -> Option<bool>;
    fn insert(&self, key: CacheKey, allowed: bool);
    fn hits(&self) -> u64;
    fn misses(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct MemoryHashCache {
    map: RefCell<HashMap<CacheKey, bool>>,
    hits: Cell<u64>,
    misses: Cell<u64>,
}

impl HashCache for MemoryHashCache {
    fn get(&self, key: &CacheKey) -> Option<bool> {
        match self.map.borrow().get(key).copied() {
            Some(v) => {
                self.hits.set(self.hits.get().saturating_add(1));
                Some(v)
            }
            None => {
                self.misses.set(self.misses.get().saturating_add(1));
                None
            }
        }
    }

    fn insert(&self, key: CacheKey, allowed: bool) {
        self.map.borrow_mut().insert(key, allowed);
    }

    fn hits(&self) -> u64 {
        self.hits.get()
    }

    fn misses(&self) -> u64 {
        self.misses.get()
    }
}
