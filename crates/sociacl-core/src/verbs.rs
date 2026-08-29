use crate::attestation::{Attestation, EnrollmentKind};
use crate::check::CheckRequest;
use crate::error::{AttestationError, VerbError};
use crate::graph::Plane;
use crate::types::{
    Action, AuthnState, Capability, Clock, DestroyResult, DiscoverResult, ElectResult, NodeId,
    Relation,
};
use crate::will::{WillClause, WillDisposition};

impl Plane {
    /// Authn holds, authz stale. New capability from ACLs that already name
    /// this principal. Not an election. Does not read a will.
    pub fn remint(
        &self,
        object: impl Into<NodeId>,
        principal: impl Into<NodeId>,
    ) -> Result<Capability, VerbError> {
        self.remint_inner(object.into(), principal.into(), None)
    }

    /// Remint with an enrolled-station (or identity/device) liveness factor.
    /// The attestation does not name a new principal. ACL must already name them.
    pub fn remint_with_attestation(
        &self,
        object: impl Into<NodeId>,
        principal: impl Into<NodeId>,
        attestation: &Attestation,
    ) -> Result<Capability, VerbError> {
        self.remint_inner(object.into(), principal.into(), Some(attestation))
    }

    fn remint_inner(
        &self,
        object: NodeId,
        principal: NodeId,
        attestation: Option<&Attestation>,
    ) -> Result<Capability, VerbError> {
        self.require_object(&object)?;
        if !self.nodes.contains_key(&principal) {
            return Err(VerbError::PrincipalNotFound(principal));
        }
        if self.authn(&principal) != AuthnState::Live {
            return Err(VerbError::AuthnNotLive(principal));
        }
        if let Some(att) = attestation {
            self.accept_attestation(att)
                .map_err(VerbError::AttestationRejected)?;
            if !att.claim.remint_may_consume() {
                return Err(VerbError::AttestationRejected(
                    AttestationError::RemintMustNotConsume(att.claim.as_str().to_string()),
                ));
            }
            if att.subject != principal {
                return Err(VerbError::AttestationRejected(
                    AttestationError::SubjectMismatch(att.subject.clone()),
                ));
            }
            if att.claim == crate::attestation::AttestationClaim::StationLiveness {
                match self.enrollment(&att.issuer).map(|e| e.kind) {
                    Some(EnrollmentKind::Station) => {}
                    _ => {
                        return Err(VerbError::AttestationRejected(
                            AttestationError::NotEnrolled(att.issuer.clone()),
                        ));
                    }
                }
            }
        }
        if !self.acl_names(&object, &principal) {
            return Err(VerbError::AclDoesNotNamePrincipal(principal, object));
        }
        let result = self
            .check(CheckRequest {
                action: Action::new("remint"),
                object: object.clone(),
                accessor: principal.clone(),
                predicate: None,
                zookie: None,
                attestation: None,
            })
            .map_err(|_| VerbError::AclDoesNotNamePrincipal(principal.clone(), object.clone()))?;
        if !result.allowed {
            return Err(VerbError::AclDoesNotNamePrincipal(principal, object));
        }
        Ok(Capability {
            principal,
            object,
            zookie: result.zookie,
        })
    }

    /// Authn gone. Report the will. No vacancy ad. Does not install an owner.
    pub fn discover(&self, object: impl Into<NodeId>) -> Result<DiscoverResult, VerbError> {
        let object = object.into();
        self.require_object(&object)?;
        let will = self.live_will(&object)?;
        if let Some(WillDisposition::Heir(heir)) = will.disposition() {
            return Ok(DiscoverResult::Heir(heir));
        }
        if let Some(circle) = will.body.rank_circle() {
            return Ok(DiscoverResult::ElectAmong {
                circle: circle.clone(),
            });
        }
        if matches!(will.disposition(), Some(WillDisposition::StaySecret)) {
            return Ok(DiscoverResult::StaySecret);
        }
        Err(VerbError::NoElectPath(object))
    }

    /// Authn gone. Slow Elect clock. Refuses if keep-operating would suffice
    /// or if no pre-written will names an elect path. Never starts because
    /// of an attestation.
    pub fn elect(&mut self, object: impl Into<NodeId>) -> Result<ElectResult, VerbError> {
        let object = object.into();
        let owner = {
            let obj = self.require_object(&object)?;
            obj.owner.clone()
        };
        if self.authn(&owner) == AuthnState::Live {
            return Err(VerbError::KeepOperatingSuffices(object));
        }
        let will = self.live_will(&object)?.clone();
        if !will.body.has_elect_path() {
            if will.body.has_destroy() {
                return Err(VerbError::WillPrescribesDestroy(object));
            }
            return Err(VerbError::NoElectPath(object));
        }
        if let Some(WillDisposition::StaySecret) = will.disposition() {
            return Err(VerbError::WillPrescribesDestroy(object));
        }

        let notify = self.elect_notify(&will);
        let threshold = match will.body.elect() {
            Some(WillClause::Elect { threshold, .. }) => *threshold,
            _ => 1,
        };
        if notify.len() < threshold as usize {
            return Err(VerbError::CannotElectWithoutCancelers(object));
        }

        let heir = self.resolve_heir(&will, &object)?;
        if let Some(obj) = self.objects.get_mut(&object) {
            obj.owner = heir.clone();
        }
        self.edges
            .retain(|e| !(e.relation == Relation::Owns && e.to == object));
        self.edges.push(crate::types::Edge {
            from: heir.clone(),
            to: object.clone(),
            relation: Relation::Owns,
            from_stated: true,
            to_stated: true,
            joint_at: Some(self.immediately_effective_at()),
            effective_at: Some(self.immediately_effective_at()),
        });
        self.bump_version(&object);
        Ok(ElectResult {
            new_owner: heir,
            clock: Clock::Elect,
            notify,
        })
    }

    /// Elect is a verb, not an oracle reaction. Always refused.
    pub fn elect_from_attestation(
        &mut self,
        _object: impl Into<NodeId>,
        _attestation: &Attestation,
    ) -> Result<ElectResult, VerbError> {
        Err(VerbError::ElectDoesNotFireOnAttestation)
    }

    fn elect_notify(&self, will: &crate::will::Will) -> Vec<NodeId> {
        let mut ids = will.cancelable_by.clone();
        if let Some(WillClause::Elect { notify, .. }) = will.body.elect() {
            ids.extend(notify.iter().cloned());
        }
        ids.sort();
        ids.dedup();
        ids.into_iter()
            .filter(|p| self.authn(p) == AuthnState::Live)
            .collect()
    }

    fn resolve_heir(&self, will: &crate::will::Will, object: &NodeId) -> Result<NodeId, VerbError> {
        if let Some(heir) = will.body.named_heir() {
            return Ok(heir.clone());
        }
        if let Some(successors) = will.body.successor_list() {
            if let Some(heir) = successors.iter().find(|id| self.nodes.contains_key(*id)) {
                return Ok(heir.clone());
            }
        }
        if let Some(circle) = will.body.rank_circle() {
            let members = self.circle_members_ordered(circle);
            let still: Vec<NodeId> = members
                .into_iter()
                .filter(|m| self.enrollment(m).is_some() && self.still_attesting(m))
                .collect();
            if let Some(heir) = still.into_iter().next() {
                return Ok(heir);
            }
            // Nobody still-attesting: fail closed. Silence is not a vote.
            return Err(VerbError::NoElectPath(object.clone()));
        }
        Err(VerbError::NoElectPath(object.clone()))
    }

    /// No heir, or will says stay secret. Cryptographic erasure of content_key.
    pub fn destroy(&mut self, object: impl Into<NodeId>) -> Result<DestroyResult, VerbError> {
        let object = object.into();
        self.require_object(&object)?;
        let will = self.live_will(&object)?.clone();
        if will.body.named_heir().is_some() {
            return Err(VerbError::HasHeir(object));
        }
        if will.body.has_elect_path() && self.resolve_heir(&will, &object).is_ok() {
            return Err(VerbError::HasHeir(object));
        }
        if !will.body.has_destroy() {
            return Err(VerbError::NoDestroyPath(object));
        }
        if let Some(obj) = self.objects.get_mut(&object) {
            obj.content_key = None;
            obj.destroyed = true;
            obj.version.0 = obj.version.0.saturating_add(1);
        }
        Ok(DestroyResult {
            object,
            erased: true,
        })
    }

    fn require_object(&self, object: &NodeId) -> Result<&crate::types::Object, VerbError> {
        let obj = self
            .objects
            .get(object)
            .ok_or_else(|| VerbError::ObjectNotFound(object.clone()))?;
        if obj.destroyed {
            return Err(VerbError::ObjectDestroyed(object.clone()));
        }
        Ok(obj)
    }

    fn live_will(&self, object: &NodeId) -> Result<&crate::will::Will, VerbError> {
        let will = self
            .wills
            .get(object)
            .ok_or_else(|| VerbError::NoWill(object.clone()))?;
        if will.canceled {
            return Err(VerbError::WillCanceled(object.clone()));
        }
        Ok(will)
    }
}
