use crate::attestation::{Attestation, AttestationFactor};
use crate::cache::{CacheAnchors, CacheKey, EdgeTypeSet, HashCache, Zookie};
use crate::error::{AttestationError, CheckError};
use crate::graph::Plane;
use crate::types::{Action, NodeId, Object, ObjectKind, ObjectProperties, PredicateId, Relation};

/// CHECK(action, object, accessor). Predicate is object-driven. Callers may
/// pass an explicit id; it must match the object's named predicate.
/// `action` is interpreted by `posix-mode` bits and by a `delegate` mask.
#[derive(Clone, Debug)]
pub struct CheckRequest {
    pub action: Action,
    pub object: NodeId,
    pub accessor: NodeId,
    pub predicate: Option<PredicateId>,
    pub zookie: Option<Zookie>,
    /// Optional attestation factor. Missing does not fail Check.
    /// Must not mint an edge, owner, or heir. Check never reads a will.
    pub attestation: Option<Attestation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckResult {
    pub allowed: bool,
    /// Names the predicate, not the path.
    pub reason: PredicateId,
    pub zookie: Zookie,
    /// Present only when Check consumed a valid enrolled factor.
    /// Never sets `allowed` by itself.
    pub attestation_factor: Option<AttestationFactor>,
}

/// Parsed Check target. Properties select the predicate.
pub struct ParsedObject<'a> {
    pub kind: ObjectKind,
    pub owner: &'a NodeId,
    pub properties: &'a ObjectProperties,
    pub version: crate::types::ObjectVersion,
    pub destroyed: bool,
}

impl<'a> ParsedObject<'a> {
    fn from_object(object: &'a Object) -> Self {
        Self {
            kind: object.kind,
            owner: &object.owner,
            properties: &object.properties,
            version: object.version,
            destroyed: object.destroyed,
        }
    }

    fn named_predicate(&self, object: &NodeId) -> Result<PredicateId, CheckError> {
        let Some(pred) = self.properties.named_predicate() else {
            return Err(CheckError::ObjectPredicateMissing(object.clone()));
        };
        if !pred.is_named() {
            return Err(CheckError::UnknownPredicate(pred));
        }
        Ok(pred)
    }
}

impl Plane {
    pub fn check(&self, request: CheckRequest) -> Result<CheckResult, CheckError> {
        if !self.nodes.contains_key(&request.accessor) {
            return Err(CheckError::AccessorNotFound(request.accessor));
        }
        let object = self
            .objects
            .get(&request.object)
            .ok_or_else(|| CheckError::ObjectNotFound(request.object.clone()))?;
        let parsed = ParsedObject::from_object(object);
        if parsed.destroyed {
            return Err(CheckError::ObjectDestroyed(request.object.clone()));
        }
        let _kind = parsed.kind;

        let named = parsed.named_predicate(&request.object)?;
        if let Some(requested) = request.predicate.as_ref() {
            if requested.as_str() != named.as_str() {
                if !requested.is_named() {
                    return Err(CheckError::UnknownPredicate(requested.clone()));
                }
                return Err(CheckError::PredicateMismatch {
                    requested: requested.clone(),
                    named,
                });
            }
        }

        // Check does not import will evaluation. A will on this object
        // cannot become a predicate here.
        let snapshot = self
            .snapshot(&request.object)
            .ok_or_else(|| CheckError::ObjectNotFound(request.object.clone()))?;

        let attestation_factor = self.consume_check_factor(&request, &snapshot)?;

        let mut extra = std::collections::BTreeSet::new();
        if let Some(g) = self.named_group(&request.object) {
            extra.insert(g);
        }
        if let Some(c) = self.named_circle(&request.object) {
            extra.insert(c);
        }
        let key = CacheKey {
            accessor: request.accessor.clone(),
            anchors: CacheAnchors {
                owner: parsed.owner.clone(),
                extra,
            },
            edge_types: EdgeTypeSet::from_predicate(named.as_str()),
            hopcap: crate::HOPCAP,
            snapshot: snapshot.hash,
            action: request.action.clone(),
        };

        // New-enemy: a zookie bound to an older object version is not a
        // cached allow. Re-evaluate the current snapshot.
        let stale_zookie = request
            .zookie
            .as_ref()
            .map(|z| z.object_version < snapshot.object_version)
            .unwrap_or(false);

        // Grant expiry is checked against `now` even if a prior allow
        // is cached. `until` is not a dead-hand ownership timer.
        let until_elapsed = named.as_str() == PredicateId::DELEGATE
            && self.edges.iter().any(|e| {
                e.from == request.accessor
                    && e.to == request.object
                    && e.relation == Relation::Delegate
                    && e.until.map(|u| self.now().0 >= u.0).unwrap_or(false)
            });

        let allowed = if until_elapsed {
            false
        } else if !stale_zookie {
            if let Some(hit) = self.cache.get(&key) {
                hit
            } else {
                let allowed = self.eval_predicate(
                    &named,
                    &request.object,
                    &request.accessor,
                    &request.action,
                );
                self.cache.insert(key, allowed);
                allowed
            }
        } else {
            let allowed =
                self.eval_predicate(&named, &request.object, &request.accessor, &request.action);
            self.cache.insert(key, allowed);
            allowed
        };

        Ok(CheckResult {
            allowed,
            reason: named,
            zookie: Zookie {
                object: request.object,
                object_version: snapshot.object_version,
                snapshot_hash: snapshot.hash,
            },
            attestation_factor,
        })
    }

    /// Identity or device liveness from an enrolled issuer, bound to this
    /// snapshot, about the accessor. Never a grant. Station loudness is
    /// refused. Missing attestation skips this.
    fn consume_check_factor(
        &self,
        request: &CheckRequest,
        snapshot: &crate::cache::Snapshot,
    ) -> Result<Option<AttestationFactor>, CheckError> {
        let Some(att) = request.attestation.as_ref() else {
            return Ok(None);
        };
        self.accept_attestation(att)
            .map_err(CheckError::AttestationRejected)?;
        if !att.claim.check_may_consume() {
            return Err(CheckError::AttestationRejected(
                AttestationError::CheckMustNotConsume(att.claim.as_str().to_string()),
            ));
        }
        if att.subject != request.accessor {
            return Err(CheckError::AttestationRejected(
                AttestationError::SubjectMismatch(att.subject.clone()),
            ));
        }
        let bound = match &att.binding {
            crate::attestation::AttestationBinding::Snapshot { object, hash } => {
                att.binding.matches_snapshot(object, *hash)
                    && *object == request.object
                    && *hash == snapshot.hash
            }
            crate::attestation::AttestationBinding::ObjectVersion { object, version } => {
                *object == request.object && *version == snapshot.object_version
            }
        };
        if !bound {
            return Err(CheckError::AttestationRejected(
                AttestationError::BindingMismatch,
            ));
        }
        Ok(Some(AttestationFactor {
            issuer: att.issuer.clone(),
            claim: att.claim,
            binding: att.binding.clone(),
        }))
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
            predicate: Some(predicate.into()),
            zookie: None,
            attestation: None,
        })
    }

    /// Object-driven Check. Uses the predicate the object names.
    pub fn check_object(
        &self,
        action: impl Into<Action>,
        object: impl Into<NodeId>,
        accessor: impl Into<NodeId>,
    ) -> Result<CheckResult, CheckError> {
        self.check(CheckRequest {
            action: action.into(),
            object: object.into(),
            accessor: accessor.into(),
            predicate: None,
            zookie: None,
            attestation: None,
        })
    }

    fn eval_predicate(
        &self,
        predicate: &PredicateId,
        object: &NodeId,
        accessor: &NodeId,
        action: &Action,
    ) -> bool {
        match predicate.as_str() {
            PredicateId::OWNER => self.has_live(accessor, object, Relation::Owns),
            PredicateId::SAME_GROUP => self.eval_same_group(object, accessor),
            PredicateId::NAMED_CIRCLE => self.eval_named_circle(object, accessor),
            PredicateId::POSIX_MODE => self.eval_posix_mode(object, accessor, action),
            PredicateId::TRUSTEE => self.has_live(accessor, object, Relation::Trustee),
            PredicateId::DELEGATE => self.eval_delegate(object, accessor, action),
            _ => false,
        }
    }

    /// Object names `delegate`; jointly stated live grant; action in
    /// the mask; until not elapsed. Not posix-mode. Owner stays owner.
    fn eval_delegate(&self, object: &NodeId, accessor: &NodeId, action: &Action) -> bool {
        let Some(edge) = self.delegate_edge(accessor, object) else {
            return false;
        };
        self.delegate_grant_holds(edge, Some(action))
    }

    fn eval_same_group(&self, object: &NodeId, accessor: &NodeId) -> bool {
        let Some(group) = self.named_group(object) else {
            return false;
        };
        self.has_live(accessor, &group, Relation::MemberOf)
    }

    /// Named circle, hopcap 1: accessor has a direct in-circle edge to the
    /// circle the object names. No friend walk, no nested circle.
    fn eval_named_circle(&self, object: &NodeId, accessor: &NodeId) -> bool {
        let Some(circle) = self.named_circle(object) else {
            return false;
        };
        self.has_live(accessor, &circle, Relation::InCircle)
    }

    fn eval_posix_mode(&self, object: &NodeId, accessor: &NodeId, action: &Action) -> bool {
        let Some(obj) = self.objects.get(object) else {
            return false;
        };
        let Some(mode) = obj.properties.posix_mode() else {
            return false;
        };
        if accessor == &obj.owner || self.has_live(accessor, object, Relation::Owns) {
            return mode.owner.allows(action);
        }
        if let Some(group) = self.named_group(object) {
            if self.has_live(accessor, &group, Relation::MemberOf) {
                return mode.group.allows(action);
            }
        }
        mode.other.allows(action)
    }
}
