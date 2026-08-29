//! Social Light is an attestation channel. Not a grant.
//!
//! A flash or badge ping carries a signed statement from a pre-enrolled
//! issuer. It does not mint an edge, owner, or heir. Nearby is not a
//! friend. SociACL is the authority plane. The two compose. They do
//! not merge names.
//!
//! Named public-safe kinds only. LightIFF, field IFF, waveforms, and
//! challenge-response are not implemented here and must not be.

use crate::attestation::{Attestation, AttestationClaim};
use crate::check::{CheckRequest, CheckResult};
use crate::client::Client;
use crate::error::{AttestationError, CheckError, VerbError};
use crate::graph::Plane;
use crate::types::{Capability, ElectResult, NodeId, NodeKind};

/// How a statement arrived. Not what it grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AttestationChannel {
    /// Living person at a convention badge. Discover may report them.
    /// An optional share-token is voluntary and is not a capability.
    ConventionBadge,
    /// Enrolled station observed liveness. Remint or Check may use it
    /// as a factor on a principal the ACL already names.
    EnrolledStation,
}

impl AttestationChannel {
    pub fn parse(s: &str) -> Result<Self, AttestationError> {
        match s {
            "convention-badge" => Ok(Self::ConventionBadge),
            "enrolled-station" => Ok(Self::EnrolledStation),
            "lightiff" | "light-iff" | "field-iff" | "iff" | "waveform" | "frequency"
            | "challenge-response" | "flash" | "ping" | "loud" | "nearby" | "proximity" => {
                Err(AttestationError::ForbiddenChannel(s.to_string()))
            }
            other => Err(AttestationError::UnnamedChannel(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConventionBadge => "convention-badge",
            Self::EnrolledStation => "enrolled-station",
        }
    }

    pub fn check_may_consume(self) -> bool {
        matches!(self, Self::ConventionBadge | Self::EnrolledStation)
    }

    pub fn remint_may_consume(self) -> bool {
        matches!(self, Self::EnrolledStation)
    }

    pub fn discover_may_report(self) -> bool {
        matches!(self, Self::ConventionBadge)
    }
}

/// Statement that arrived over Social Light. The attestation is the
/// authority-plane object. The channel is the carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocialLightStatement {
    pub channel: AttestationChannel,
    pub attestation: Attestation,
    /// Voluntary badge offer. Not a key and not a grant.
    pub share_token: Option<String>,
}

/// What presenting a Social Light statement can report. Never an owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocialLightView {
    LivingPerson {
        principal: NodeId,
        share_token: Option<String>,
    },
    StationFactor {
        subject: NodeId,
    },
}

impl SocialLightStatement {
    pub fn new(channel: AttestationChannel, attestation: Attestation) -> Self {
        Self {
            channel,
            attestation,
            share_token: None,
        }
    }

    pub fn with_share_token(mut self, token: impl Into<String>) -> Self {
        self.share_token = Some(token.into());
        self
    }

    pub fn convention_badge(attestation: Attestation) -> Self {
        Self::new(AttestationChannel::ConventionBadge, attestation)
    }

    pub fn enrolled_station(attestation: Attestation) -> Self {
        Self::new(AttestationChannel::EnrolledStation, attestation)
    }
}

impl Plane {
    /// Verify the statement on the existing attestation path. Does not
    /// mint an edge.
    pub fn accept_social_light(
        &self,
        statement: &SocialLightStatement,
    ) -> Result<(), AttestationError> {
        self.accept_attestation(&statement.attestation)
    }

    pub fn check_social_light(
        &self,
        mut request: CheckRequest,
        statement: &SocialLightStatement,
    ) -> Result<CheckResult, CheckError> {
        if !statement.channel.check_may_consume() {
            return Err(CheckError::AttestationRejected(
                AttestationError::ChannelMustNotConsume(statement.channel.as_str().to_string()),
            ));
        }
        request.attestation = Some(statement.attestation.clone());
        self.check(request)
    }

    pub fn remint_social_light(
        &self,
        object: impl Into<NodeId>,
        principal: impl Into<NodeId>,
        statement: &SocialLightStatement,
    ) -> Result<Capability, VerbError> {
        if !statement.channel.remint_may_consume() {
            return Err(VerbError::AttestationRejected(
                AttestationError::ChannelMustNotConsume(statement.channel.as_str().to_string()),
            ));
        }
        self.remint_with_attestation(object, principal, &statement.attestation)
    }

    /// Report the badge principal. Does not install an heir.
    pub fn discover_social_light(
        &self,
        statement: &SocialLightStatement,
    ) -> Result<SocialLightView, VerbError> {
        if !statement.channel.discover_may_report() {
            return Err(VerbError::AttestationRejected(
                AttestationError::ChannelMustNotConsume(statement.channel.as_str().to_string()),
            ));
        }
        self.accept_attestation(&statement.attestation)
            .map_err(VerbError::AttestationRejected)?;
        if statement.attestation.claim != AttestationClaim::IdentityLive {
            return Err(VerbError::AttestationRejected(
                AttestationError::CheckMustNotConsume(
                    statement.attestation.claim.as_str().to_string(),
                ),
            ));
        }
        let principal = statement.attestation.subject.clone();
        if self.node_kind(&principal) != Some(NodeKind::Person) {
            return Err(VerbError::PrincipalNotFound(principal));
        }
        Ok(SocialLightView::LivingPerson {
            principal,
            share_token: statement.share_token.clone(),
        })
    }

    /// A flash does not start Elect.
    pub fn elect_from_social_light(
        &mut self,
        _object: impl Into<NodeId>,
        _statement: &SocialLightStatement,
    ) -> Result<ElectResult, VerbError> {
        Err(VerbError::ElectDoesNotFireOnAttestation)
    }
}

impl Client {
    pub fn check_social_light(
        &self,
        request: CheckRequest,
        statement: &SocialLightStatement,
    ) -> Result<CheckResult, CheckError> {
        self.plane.check_social_light(request, statement)
    }

    pub fn remint_social_light(
        &self,
        object: impl Into<NodeId>,
        principal: impl Into<NodeId>,
        statement: &SocialLightStatement,
    ) -> Result<Capability, VerbError> {
        self.plane.remint_social_light(object, principal, statement)
    }

    pub fn discover_social_light(
        &self,
        statement: &SocialLightStatement,
    ) -> Result<SocialLightView, VerbError> {
        self.plane.discover_social_light(statement)
    }

    pub fn elect_from_social_light(
        &mut self,
        _object: impl Into<NodeId>,
        _statement: &SocialLightStatement,
    ) -> Result<ElectResult, VerbError> {
        Err(VerbError::ElectDoesNotFireOnAttestation)
    }
}
