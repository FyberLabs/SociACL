//! Network membership. Proves ownership and membership. Does not
//! encode how a network routes, elects a leader, runs BFT, discovers
//! peers, scales, or recovers.

use crate::error::VerbError;
use crate::graph::Plane;
use crate::types::{AuthnState, CensureReason, CensureRecord, NodeId, NodeKind, Relation};

impl Plane {
    /// Jointly stated hop-1 membership. Privilege-up waits for the delay.
    /// Not a peer-discovery advertisement.
    pub fn admit_member(
        &mut self,
        member: impl Into<NodeId>,
        network: impl Into<NodeId>,
    ) -> Result<(), VerbError> {
        let member = member.into();
        let network = network.into();
        if self.nodes.get(&network) != Some(&NodeKind::Network) {
            return Err(VerbError::ObjectNotFound(network));
        }
        if !self.nodes.contains_key(&member) {
            return Err(VerbError::PrincipalNotFound(member));
        }
        self.jointly_state(&member, &network, Relation::InNetwork);
        Ok(())
    }

    /// Owner or the member themselves unstates membership immediately.
    /// Records an audit reason. Check does not read the record.
    /// Not a BFT vote and not an Elect.
    pub fn censure(
        &mut self,
        speaker: impl Into<NodeId>,
        network: impl Into<NodeId>,
        member: impl Into<NodeId>,
        reason: CensureReason,
    ) -> Result<CensureRecord, VerbError> {
        let speaker = speaker.into();
        let network = network.into();
        let member = member.into();
        if self.nodes.get(&network) != Some(&NodeKind::Network) {
            return Err(VerbError::ObjectNotFound(network));
        }
        if !self.nodes.contains_key(&member) {
            return Err(VerbError::PrincipalNotFound(member));
        }
        if self.authn(&speaker) != AuthnState::Live {
            return Err(VerbError::AuthnNotLive(speaker));
        }

        let owner = self.objects.get(&network).map(|o| o.owner.clone());
        let is_self = speaker == member;
        let is_owner = owner.as_ref() == Some(&speaker);
        if is_self {
            if !reason.member_may_state() {
                return Err(VerbError::CannotCensure(speaker));
            }
        } else if is_owner {
            if !reason.owner_may_state() {
                return Err(VerbError::CannotCensure(speaker));
            }
        } else {
            return Err(VerbError::CannotCensure(speaker));
        }

        self.unstate_edge(&speaker, &member, &network, Relation::InNetwork);
        let record = CensureRecord {
            network,
            member,
            speaker,
            reason,
            at: self.now(),
        };
        self.audit.push(record.clone());
        Ok(record)
    }

    /// Audit records for a network. Not Expand/ListUsers of current members.
    pub fn audit(&self, network: impl Into<NodeId>) -> Vec<&CensureRecord> {
        let network = network.into();
        self.audit.iter().filter(|r| r.network == network).collect()
    }

    pub fn is_member(&self, member: impl Into<NodeId>, network: impl Into<NodeId>) -> bool {
        let member = member.into();
        let network = network.into();
        self.has_live(&member, &network, Relation::InNetwork)
    }
}
