use crate::check::CheckRequest;
use crate::error::VerbError;
use crate::graph::Plane;
use crate::types::{
    Action, AuthnState, Capability, Clock, DestroyResult, DiscoverResult, ElectResult, NodeId,
    Relation, WillDisposition,
};

impl Plane {
    /// Authn holds, authz stale. New capability from ACLs that already name
    /// this principal. Not an election.
    pub fn remint(
        &self,
        object: impl Into<NodeId>,
        principal: impl Into<NodeId>,
    ) -> Result<Capability, VerbError> {
        let object = object.into();
        let principal = principal.into();
        self.require_object(&object)?;
        if !self.nodes.contains_key(&principal) {
            return Err(VerbError::PrincipalNotFound(principal));
        }
        if self.authn(&principal) != AuthnState::Live {
            return Err(VerbError::AuthnNotLive(principal));
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
        match &will.disposition {
            WillDisposition::Heir(heir) => Ok(DiscoverResult::Heir(heir.clone())),
            WillDisposition::StaySecret => Ok(DiscoverResult::StaySecret),
        }
    }

    /// Authn gone. Slow Elect clock. Refuses if keep-operating would suffice
    /// or if no pre-written will names an heir.
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
        let heir = match &will.disposition {
            WillDisposition::Heir(heir) => heir.clone(),
            WillDisposition::StaySecret => {
                return Err(VerbError::WillPrescribesDestroy(object));
            }
        };
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
        let notify = will
            .cancelable_by
            .iter()
            .filter(|p| self.authn(p) == AuthnState::Live)
            .cloned()
            .collect();
        Ok(ElectResult {
            new_owner: heir,
            clock: Clock::Elect,
            notify,
        })
    }

    /// No heir, or will says stay secret. Cryptographic erasure of content_key.
    pub fn destroy(&mut self, object: impl Into<NodeId>) -> Result<DestroyResult, VerbError> {
        let object = object.into();
        self.require_object(&object)?;
        let will = self.live_will(&object)?;
        match &will.disposition {
            WillDisposition::Heir(_) => return Err(VerbError::HasHeir(object)),
            WillDisposition::StaySecret => {}
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

    fn live_will(&self, object: &NodeId) -> Result<&crate::types::Will, VerbError> {
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
