use crate::cache::{CacheKey, HashCache, Zookie};
use crate::error::CheckError;
use crate::graph::Plane;
use crate::types::{Action, NodeId, PredicateId, Relation};

/// CHECK(action, object, accessor) plus a named predicate and optional zookie.
#[derive(Clone, Debug)]
pub struct CheckRequest {
    pub action: Action,
    pub object: NodeId,
    pub accessor: NodeId,
    pub predicate: PredicateId,
    pub zookie: Option<Zookie>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub allowed: bool,
    /// Names the predicate, not the path.
    pub reason: PredicateId,
    pub zookie: Zookie,
}

impl Plane {
    pub fn check(&self, request: CheckRequest) -> Result<CheckResult, CheckError> {
        if !request.predicate.is_named() {
            return Err(CheckError::UnknownPredicate(request.predicate));
        }
        if !self.nodes.contains_key(&request.accessor) {
            return Err(CheckError::AccessorNotFound(request.accessor));
        }
        let object = self
            .objects
            .get(&request.object)
            .ok_or_else(|| CheckError::ObjectNotFound(request.object.clone()))?;
        if object.destroyed {
            return Err(CheckError::ObjectDestroyed(request.object.clone()));
        }

        let snapshot = self
            .snapshot(&request.object)
            .ok_or_else(|| CheckError::ObjectNotFound(request.object.clone()))?;

        // New-enemy: a zookie bound to an older object version is not a
        // cached allow. We only consult the cache for the current version
        // and current snapshot hash.
        let key = CacheKey {
            object: request.object.clone(),
            object_version: snapshot.object_version,
            snapshot_hash: snapshot.hash,
            accessor: request.accessor.clone(),
            predicate: request.predicate.clone(),
            action: request.action.clone(),
        };

        let stale_zookie = request
            .zookie
            .as_ref()
            .map(|z| z.object_version < snapshot.object_version)
            .unwrap_or(false);

        let allowed = if !stale_zookie {
            if let Some(hit) = self.cache.get(&key) {
                hit
            } else {
                let allowed =
                    self.eval_predicate(&request.predicate, &request.object, &request.accessor);
                self.cache.insert(key, allowed);
                allowed
            }
        } else {
            let allowed =
                self.eval_predicate(&request.predicate, &request.object, &request.accessor);
            self.cache.insert(key, allowed);
            allowed
        };

        Ok(CheckResult {
            allowed,
            reason: request.predicate,
            zookie: Zookie {
                object: request.object,
                object_version: snapshot.object_version,
                snapshot_hash: snapshot.hash,
            },
        })
    }

    pub fn check_named(
        &self,
        action: impl Into<Action>,
        object: impl Into<NodeId>,
        accessor: impl Into<NodeId>,
        predicate: impl Into<PredicateId>,
    ) -> Result<CheckResult, CheckError> {
        self.check(CheckRequest {
            action: action.into(),
            object: object.into(),
            accessor: accessor.into(),
            predicate: predicate.into(),
            zookie: None,
        })
    }

    fn eval_predicate(&self, predicate: &PredicateId, object: &NodeId, accessor: &NodeId) -> bool {
        match predicate.as_str() {
            PredicateId::OWNER => self.has_live(accessor, object, Relation::Owns),
            PredicateId::SAME_GROUP => self.eval_same_group(object, accessor),
            PredicateId::NAMED_CIRCLE => self.eval_named_circle(object, accessor),
            _ => false,
        }
    }

    fn eval_same_group(&self, object: &NodeId, accessor: &NodeId) -> bool {
        self.live_edges()
            .filter(|e| e.relation == Relation::ObjectGroup && e.from == *object)
            .any(|e| self.has_live(accessor, &e.to, Relation::MemberOf))
    }

    /// Named circle, hopcap 1: accessor has a direct in-circle edge to a
    /// circle the object names. No friend walk, no nested circle.
    fn eval_named_circle(&self, object: &NodeId, accessor: &NodeId) -> bool {
        self.live_edges()
            .filter(|e| e.relation == Relation::ObjectCircle && e.from == *object)
            .any(|e| self.has_live(accessor, &e.to, Relation::InCircle))
    }
}
