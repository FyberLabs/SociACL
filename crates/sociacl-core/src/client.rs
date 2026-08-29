//! Case C client path. Keep-operating against a pre-cut bundle.
//!
//! Check and Remint use the frozen snapshot. Elect and commit_elect
//! refuse: the radio being quiet is not a reason to elect. Discover
//! reports the bundled will without installing. Destroy may erase
//! local key material. Two post-cut clients do not union.

use std::collections::HashMap;

use crate::attestation::Attestation;
use crate::bundle::CutBundle;
use crate::cache::Zookie;
use crate::check::{CheckRequest, CheckResult};
use crate::error::VerbError;
use crate::graph::Plane;
use crate::types::{
    Action, AuthnState, Capability, ClientHeldShare, DestroyResult, DiscoverResult, ElectResult,
    NodeId, NodeKind, Object, PredicateId,
};

/// Offline evaluator sealed at the cut. Does not talk to a live plane.
#[derive(Debug)]
pub struct Client {
    bundle: CutBundle,
    plane: Plane,
    shares: HashMap<NodeId, ClientHeldShare>,
}

impl Client {
    pub fn open(bundle: CutBundle) -> Result<Self, VerbError> {
        bundle.refuse_post_cut()?;
        let mut plane = Plane::new();
        plane.set_now(bundle.cut.cut_at);
        plane.set_cut(bundle.cut.cut_at);
        for (id, kind) in &bundle.nodes {
            plane.nodes.insert(id.clone(), *kind);
        }
        for (id, state) in &bundle.authn {
            plane.authn.insert(id.clone(), *state);
        }
        for obj in &bundle.objects {
            plane.objects.insert(obj.id.clone(), obj.clone());
        }
        plane.edges = bundle.edges.clone();
        for will in &bundle.wills {
            plane.wills.insert(will.object().clone(), will.clone());
        }
        for enr in &bundle.enrollments {
            plane.enrollments.insert(enr.issuer.clone(), enr.clone());
        }
        plane.attestations = bundle.attestations.clone();

        let mut shares = HashMap::new();
        for share in &bundle.shares {
            share.reconstruct()?;
            if share.held_at.0 > bundle.cut.cut_at.0 {
                return Err(VerbError::PostCutMaterial);
            }
            shares.insert(share.object.clone(), share.clone());
        }

        Ok(Self {
            bundle,
            plane,
            shares,
        })
    }

    pub fn bundle(&self) -> &CutBundle {
        &self.bundle
    }

    pub fn holder(&self) -> &NodeId {
        &self.bundle.holder
    }

    pub fn object(&self, id: &NodeId) -> Option<&Object> {
        self.plane.object(id)
    }

    pub fn held_share(&self, object: &NodeId) -> Option<&ClientHeldShare> {
        self.shares.get(object)
    }

    /// Verify the pre-cut share and return the local key.
    pub fn reconstruct_share(&self, object: impl Into<NodeId>) -> Result<[u8; 32], VerbError> {
        let object = object.into();
        let share = self
            .shares
            .get(&object)
            .ok_or_else(|| VerbError::NoHeldShare(self.bundle.holder.clone(), object.clone()))?;
        share.reconstruct()
    }

    pub fn local_key(&self, object: &NodeId) -> Option<[u8; 32]> {
        self.shares.get(object).and_then(|s| s.key_material)
    }

    pub fn exported_zookie(&self, object: &NodeId) -> Option<&Zookie> {
        self.bundle.zookie(object)
    }

    pub fn check(&self, request: CheckRequest) -> Result<CheckResult, crate::error::CheckError> {
        self.plane.check(request)
    }

    pub fn check_named(
        &self,
        action: impl Into<Action>,
        object: impl Into<NodeId>,
        accessor: impl Into<NodeId>,
        predicate: impl Into<PredicateId>,
    ) -> Result<CheckResult, crate::error::CheckError> {
        self.plane.check_named(action, object, accessor, predicate)
    }

    pub fn check_object(
        &self,
        action: impl Into<Action>,
        object: impl Into<NodeId>,
        accessor: impl Into<NodeId>,
    ) -> Result<CheckResult, crate::error::CheckError> {
        self.plane.check_object(action, object, accessor)
    }

    /// Keep-operating. Fresh zookie from the frozen ACL. No new owner.
    pub fn remint(
        &self,
        object: impl Into<NodeId>,
        principal: impl Into<NodeId>,
    ) -> Result<Capability, VerbError> {
        self.plane.remint(object, principal)
    }

    pub fn remint_with_attestation(
        &self,
        object: impl Into<NodeId>,
        principal: impl Into<NodeId>,
        attestation: &Attestation,
    ) -> Result<Capability, VerbError> {
        self.plane
            .remint_with_attestation(object, principal, attestation)
    }

    /// Report the bundled will. Does not install an owner.
    pub fn discover(&self, object: impl Into<NodeId>) -> Result<DiscoverResult, VerbError> {
        self.plane.discover(object)
    }

    /// Always refused. Missing plane and silence are not Elect.
    pub fn elect(&mut self, _object: impl Into<NodeId>) -> Result<ElectResult, VerbError> {
        Err(VerbError::ClientRefusesElect)
    }

    /// Always refused. A wait on a quiet radio does not install.
    pub fn commit_elect(&mut self, _object: impl Into<NodeId>) -> Result<ElectResult, VerbError> {
        Err(VerbError::ClientRefusesElect)
    }

    /// Elect does not fire on an attestation. Same as the live plane.
    pub fn elect_from_attestation(
        &mut self,
        _object: impl Into<NodeId>,
        _attestation: &Attestation,
    ) -> Result<ElectResult, VerbError> {
        Err(VerbError::ElectDoesNotFireOnAttestation)
    }

    /// Erase local key material when the pre-cut will says stay secret
    /// or no heir can be discovered. Does not install an owner.
    pub fn destroy(&mut self, object: impl Into<NodeId>) -> Result<DestroyResult, VerbError> {
        let object = object.into();
        let owner_before = self
            .plane
            .object(&object)
            .map(|o| o.owner.clone())
            .ok_or_else(|| VerbError::ObjectNotFound(object.clone()))?;
        let result = self.plane.destroy(&object)?;
        if let Some(share) = self.shares.get_mut(&object) {
            share.key_material = None;
        }
        if let Some(obj) = self.plane.objects.get(&object) {
            if obj.owner != owner_before {
                return Err(VerbError::ClientRefusesElect);
            }
        }
        Ok(result)
    }

    /// Split-brain stays degraded. A union of post-cut memberships is
    /// how the attacker shape becomes the healed graph. Refused here.
    pub fn rejoin(&self, _other: &Client) -> Result<Client, VerbError> {
        Err(VerbError::RejoinUnionRefused)
    }

    pub fn node_kind(&self, id: &NodeId) -> Option<NodeKind> {
        self.plane.node_kind(id)
    }

    pub fn authn(&self, id: &NodeId) -> AuthnState {
        self.plane.authn(id)
    }

    pub fn acl_names(&self, object: &NodeId, principal: &NodeId) -> bool {
        self.plane.acl_names(object, principal)
    }
}
