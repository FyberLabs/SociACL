use crate::attestation::{Attestation, EnrollmentKind};
use crate::cache::Zookie;
use crate::error::{AttestationError, VerbError};
use crate::graph::Plane;
use crate::types::{
    AuthnState, Capability, Clock, DestroyResult, DiscoverResult, ElectResult, ElectState, NodeId,
    PendingElect, Relation,
};
use crate::will::{Will, WillClause, WillDisposition};

impl Plane {
    /// Authn holds, authz stale. New capability from ACLs that already name
    /// this principal. Not an election. Does not read a will to pick an owner.
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
            // A will that names remint issuers restricts the factor. It is
            // not a grant and does not pick an owner.
            if let Some(issuers) = self
                .precut_will(&object)
                .and_then(|w| w.body.remint_issuers())
            {
                if !issuers.contains(&att.issuer) {
                    return Err(VerbError::RemintIssuerNotNamed(att.issuer.clone()));
                }
            }
        }
        if !self.acl_names(&object, &principal) {
            return Err(VerbError::AclDoesNotNamePrincipal(principal, object));
        }
        let snapshot = self
            .snapshot(&object)
            .ok_or_else(|| VerbError::ObjectNotFound(object.clone()))?;
        Ok(Capability {
            principal,
            object: object.clone(),
            zookie: Zookie {
                object,
                object_version: snapshot.object_version,
                snapshot_hash: snapshot.hash,
            },
        })
    }

    /// Authn gone. Report the will. No vacancy ad. Does not install an owner.
    pub fn discover(&self, object: impl Into<NodeId>) -> Result<DiscoverResult, VerbError> {
        let object = object.into();
        self.require_object(&object)?;
        let will = self.live_will(&object)?;
        if let Some(heir) = will.body.named_heir() {
            return Ok(DiscoverResult::Heir(heir.clone()));
        }
        if let Some(successors) = will.body.successor_list() {
            if let Some(first) = successors.first() {
                return Ok(DiscoverResult::Heir(first.clone()));
            }
        }
        if let Some(circle) = will.body.rank_circle() {
            return Ok(DiscoverResult::ElectAmong {
                circle: circle.clone(),
            });
        }
        if matches!(will.disposition(), Some(WillDisposition::StaySecret))
            || will.body.has_destroy()
        {
            return Ok(DiscoverResult::StaySecret);
        }
        Err(VerbError::NoElectPath(object))
    }

    /// Start the Elect ceremony. Notify, wait, do not install.
    ///
    /// Refuses if keep-operating would suffice, if there is no live
    /// uncanceled pre-cut will with an elect path, or if the will says
    /// stay secret. Silence is not a vote.
    pub fn elect(&mut self, object: impl Into<NodeId>) -> Result<ElectResult, VerbError> {
        let object = object.into();
        self.refuse_if_keep_operating(&object)?;
        if self.pending_elects.contains_key(&object) {
            return Err(VerbError::ElectPending(object));
        }
        let will = self.live_will(&object)?.clone();
        self.refuse_if_no_elect_path(&will, &object)?;

        let notify = self.elect_notify(&will);
        let threshold = match will.body.elect() {
            Some(WillClause::Elect { threshold, .. }) => *threshold,
            _ => 1,
        };
        if notify.len() < threshold as usize {
            return Err(VerbError::CannotElectWithoutCancelers(object));
        }

        let heir = self.resolve_heir(&will, &object)?;
        let started_at = self.now();
        let ready_at = crate::types::Timestamp(started_at.0.saturating_add(self.elect_wait().0));
        let pending = PendingElect {
            object: object.clone(),
            candidate: heir.clone(),
            notify: notify.clone(),
            started_at,
            ready_at,
        };
        self.pending_elects.insert(object, pending);
        Ok(ElectResult {
            clock: Clock::Elect,
            notify,
            state: ElectState::Pending {
                candidate: heir,
                ready_at,
            },
        })
    }

    /// Install the pending candidate after the Elect wait. Not a timer fire.
    pub fn commit_elect(&mut self, object: impl Into<NodeId>) -> Result<ElectResult, VerbError> {
        let object = object.into();
        self.require_object(&object)?;
        self.refuse_if_keep_operating(&object)?;
        let will = self.live_will(&object)?.clone();
        self.refuse_if_no_elect_path(&will, &object)?;
        let pending = self
            .pending_elects
            .get(&object)
            .cloned()
            .ok_or_else(|| VerbError::ElectNotPending(object.clone()))?;
        if self.now().0 < pending.ready_at.0 {
            return Err(VerbError::ElectWaitNotElapsed(object));
        }

        let heir = pending.candidate;
        let notify = pending.notify;
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
            actions: crate::types::ActionMask::none(),
            until: None,
        });
        self.bump_version(&object);
        self.pending_elects.remove(&object);
        Ok(ElectResult {
            clock: Clock::Elect,
            notify,
            state: ElectState::Installed { new_owner: heir },
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

    fn refuse_if_keep_operating(&self, object: &NodeId) -> Result<(), VerbError> {
        let owner = self.require_object(object)?.owner.clone();
        if self.authn(&owner) == AuthnState::Live {
            return Err(VerbError::KeepOperatingSuffices(object.clone()));
        }
        Ok(())
    }

    fn refuse_if_no_elect_path(&self, will: &Will, object: &NodeId) -> Result<(), VerbError> {
        if !will.body.has_elect_path() {
            if will.body.has_destroy() {
                return Err(VerbError::WillPrescribesDestroy(object.clone()));
            }
            return Err(VerbError::NoElectPath(object.clone()));
        }
        if let Some(WillDisposition::StaySecret) = will.disposition() {
            return Err(VerbError::WillPrescribesDestroy(object.clone()));
        }
        Ok(())
    }

    fn elect_notify(&self, will: &Will) -> Vec<NodeId> {
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

    fn resolve_heir(&self, will: &Will, object: &NodeId) -> Result<NodeId, VerbError> {
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

    /// A named living / still-attesting heir is not a destroy grant.
    fn discoverable_heir(&self, will: &Will, object: &NodeId) -> Option<NodeId> {
        if let Some(heir) = will.body.named_heir() {
            return Some(heir.clone());
        }
        self.resolve_heir(will, object).ok()
    }

    /// No heir that can be discovered, or will says stay secret.
    /// Cryptographic erasure of content_key.
    pub fn destroy(&mut self, object: impl Into<NodeId>) -> Result<DestroyResult, VerbError> {
        let object = object.into();
        self.require_object(&object)?;
        let will = self.live_will(&object)?.clone();
        if self.discoverable_heir(&will, &object).is_some() {
            return Err(VerbError::HasHeir(object));
        }
        if !will.body.has_destroy() && !will.body.has_elect_path() {
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

    fn live_will(&self, object: &NodeId) -> Result<&Will, VerbError> {
        let will = self
            .wills
            .get(object)
            .ok_or_else(|| VerbError::NoWill(object.clone()))?;
        if will.canceled {
            return Err(VerbError::WillCanceled(object.clone()));
        }
        if self.will_is_post_cut(will) {
            return Err(VerbError::PostCutWill(object.clone()));
        }
        Ok(will)
    }

    /// Remint may read remint-issuer names as a restriction. A canceled or
    /// post-cut will does not restrict and does not grant.
    fn precut_will(&self, object: &NodeId) -> Option<&Will> {
        let will = self.wills.get(object)?;
        if will.canceled || self.will_is_post_cut(will) {
            return None;
        }
        Some(will)
    }

    fn will_is_post_cut(&self, will: &Will) -> bool {
        let Some(cut) = self.cut else {
            return false;
        };
        will.written_at.0 > cut.cut_at.0 || will.joint_at.0 > cut.cut_at.0
    }
}
