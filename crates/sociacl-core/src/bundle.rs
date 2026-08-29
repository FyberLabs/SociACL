//! Pre-cut bundle: what a remaining principal already had on disk.
//!
//! Export copies the last granting snapshot, the live will, pre-cut
//! enrollments, and shares the holder already had a right to hold.
//! It is not a fetch from a dead plane. Post-cut edges, enrollments,
//! attestations, and wills are omitted and refused if presented.

use sha2::{Digest, Sha256};

use crate::attestation::{Attestation, Enrollment};
use crate::cache::{Snapshot, Zookie};
use crate::client::Client;
use crate::error::VerbError;
use crate::graph::Plane;
use crate::types::{
    AuthnState, ClientHeldShare, CutBoundary, Edge, NodeId, NodeKind, Object, Timestamp,
};
use crate::will::Will;

/// Frozen disk image for Case C. Privilege-up has already elapsed on
/// every copied edge. Privilege-down that already ran is already gone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutBundle {
    pub cut: CutBoundary,
    pub holder: NodeId,
    pub objects: Vec<Object>,
    pub snapshots: Vec<Snapshot>,
    pub zookies: Vec<Zookie>,
    pub edges: Vec<Edge>,
    pub nodes: Vec<(NodeId, NodeKind)>,
    pub authn: Vec<(NodeId, AuthnState)>,
    pub wills: Vec<Will>,
    pub enrollments: Vec<Enrollment>,
    pub attestations: Vec<Attestation>,
    pub shares: Vec<ClientHeldShare>,
}

impl CutBundle {
    /// Load the bundle as a client. Refuses post-cut material.
    pub fn open(self) -> Result<Client, VerbError> {
        Client::open(self)
    }

    pub fn object(&self, id: &NodeId) -> Option<&Object> {
        self.objects.iter().find(|o| o.id == *id)
    }

    pub fn share(&self, object: &NodeId) -> Option<&ClientHeldShare> {
        self.shares.iter().find(|s| s.object == *object)
    }

    pub fn zookie(&self, object: &NodeId) -> Option<&Zookie> {
        self.zookies.iter().find(|z| z.object == *object)
    }

    pub fn will(&self, object: &NodeId) -> Option<&Will> {
        self.wills.iter().find(|w| w.object() == object)
    }

    pub(crate) fn refuse_post_cut(&self) -> Result<(), VerbError> {
        let cut = self.cut.cut_at.0;
        for edge in &self.edges {
            if let Some(joint_at) = edge.joint_at {
                if joint_at.0 > cut {
                    return Err(VerbError::PostCutMaterial);
                }
            }
        }
        for will in &self.wills {
            if will.written_at.0 > cut || will.joint_at.0 > cut {
                return Err(VerbError::PostCutMaterial);
            }
        }
        for enr in &self.enrollments {
            if enr.enrolled_at.0 > cut {
                return Err(VerbError::PostCutMaterial);
            }
        }
        for att in &self.attestations {
            if att.issued_at.0 > cut {
                return Err(VerbError::PostCutMaterial);
            }
        }
        for share in &self.shares {
            if share.held_at.0 > cut {
                return Err(VerbError::PostCutMaterial);
            }
        }
        Ok(())
    }
}

impl ClientHeldShare {
    pub fn issue(
        object: impl Into<NodeId>,
        holder: impl Into<NodeId>,
        key: [u8; 32],
        held_at: Timestamp,
    ) -> Self {
        let object = object.into();
        let holder = holder.into();
        let share_hash = share_digest(&object, &holder, &key, held_at);
        Self {
            object,
            holder,
            share_hash,
            key_material: Some(key),
            held_at,
        }
    }

    pub fn reconstruct(&self) -> Result<[u8; 32], VerbError> {
        let key = self
            .key_material
            .ok_or_else(|| VerbError::ShareReconstruct(self.object.clone()))?;
        if share_digest(&self.object, &self.holder, &key, self.held_at) != self.share_hash {
            return Err(VerbError::ShareReconstruct(self.object.clone()));
        }
        Ok(key)
    }
}

pub(crate) fn share_digest(
    object: &NodeId,
    holder: &NodeId,
    key: &[u8; 32],
    held_at: Timestamp,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(object.as_bytes());
    hasher.update(holder.as_bytes());
    hasher.update(key);
    hasher.update(held_at.0.to_le_bytes());
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

impl Plane {
    /// Copy what `holder` already had a right to hold. Seals `cut_at` at
    /// the existing cut, or at `now` if the plane has not recorded one.
    pub fn export_bundle(&self, holder: impl Into<NodeId>) -> Result<CutBundle, VerbError> {
        let holder = holder.into();
        if !self.nodes.contains_key(&holder) {
            return Err(VerbError::PrincipalNotFound(holder));
        }
        let cut_at = self.export_cut_at();
        let cut = CutBoundary { cut_at };

        let mut objects = Vec::new();
        let mut snapshots = Vec::new();
        let mut zookies = Vec::new();
        let mut wills = Vec::new();
        let mut shares = Vec::new();

        let mut held: Vec<NodeId> = self
            .objects
            .values()
            .filter(|o| !o.destroyed && self.acl_names(&o.id, &holder))
            .map(|o| o.id.clone())
            .collect();
        held.sort();
        if held.is_empty() {
            return Err(VerbError::NothingToExport(holder));
        }

        for id in &held {
            let obj = self
                .objects
                .get(id)
                .ok_or_else(|| VerbError::ObjectNotFound(id.clone()))?;
            let snapshot = self
                .snapshot(id)
                .ok_or_else(|| VerbError::ObjectNotFound(id.clone()))?;
            zookies.push(Zookie {
                object: id.clone(),
                object_version: snapshot.object_version,
                snapshot_hash: snapshot.hash,
            });
            snapshots.push(snapshot);
            if let Some(will) = self.wills.get(id) {
                if !will.canceled && !self.bundle_will_is_post_cut(will, cut_at) {
                    wills.push(will.clone());
                }
            }
            if let Some(key) = obj.content_key {
                shares.push(ClientHeldShare::issue(
                    id.clone(),
                    holder.clone(),
                    key,
                    cut_at,
                ));
            }
            objects.push(obj.clone());
        }

        let edges: Vec<Edge> = self.effective_edges().cloned().collect();
        let mut nodes: Vec<(NodeId, NodeKind)> = self
            .nodes
            .iter()
            .map(|(id, kind)| (id.clone(), *kind))
            .collect();
        nodes.sort_by(|a, b| a.0.cmp(&b.0));
        let mut authn: Vec<(NodeId, AuthnState)> = self
            .authn
            .iter()
            .map(|(id, state)| (id.clone(), *state))
            .collect();
        authn.sort_by(|a, b| a.0.cmp(&b.0));

        let mut enrollments: Vec<Enrollment> = self
            .enrollments
            .values()
            .filter(|e| e.enrolled_at.0 <= cut_at.0)
            .cloned()
            .collect();
        enrollments.sort_by(|a, b| a.issuer.cmp(&b.issuer));

        let attestations: Vec<Attestation> = self
            .attestations
            .iter()
            .filter(|a| {
                a.issued_at.0 <= cut_at.0
                    && self
                        .enrollments
                        .get(&a.issuer)
                        .map(|e| e.enrolled_at.0 <= cut_at.0)
                        .unwrap_or(false)
                    && self.accept_attestation(a).is_ok()
            })
            .cloned()
            .collect();

        let bundle = CutBundle {
            cut,
            holder,
            objects,
            snapshots,
            zookies,
            edges,
            nodes,
            authn,
            wills,
            enrollments,
            attestations,
            shares,
        };
        bundle.refuse_post_cut()?;
        Ok(bundle)
    }

    /// Recorded cut, or `now` pushed forward to cover statements the
    /// live plane already accepted. A will helper that stamps
    /// `written_at = 1` while `now` is 0 is still pre-cut.
    fn export_cut_at(&self) -> Timestamp {
        if let Some(cut) = self.cut {
            return cut.cut_at;
        }
        let mut t = self.now();
        for will in self.wills.values() {
            t.0 = t.0.max(will.written_at.0).max(will.joint_at.0);
        }
        for edge in &self.edges {
            if let Some(joint_at) = edge.joint_at {
                t.0 = t.0.max(joint_at.0);
            }
            if let Some(effective_at) = edge.effective_at {
                t.0 = t.0.max(effective_at.0);
            }
        }
        for enr in self.enrollments.values() {
            t.0 = t.0.max(enr.enrolled_at.0);
        }
        for att in &self.attestations {
            t.0 = t.0.max(att.issued_at.0);
        }
        t
    }

    fn bundle_will_is_post_cut(&self, will: &Will, cut_at: Timestamp) -> bool {
        if self.cut.is_none() {
            return false;
        }
        will.written_at.0 > cut_at.0 || will.joint_at.0 > cut_at.0
    }
}
