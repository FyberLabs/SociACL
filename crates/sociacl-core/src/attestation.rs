//! Signed statements. Not grants.
//!
//! An oracle accepts a statement only from a pre-enrolled issuer. Check may
//! use identity or device liveness as a factor on an already-named predicate.
//! Remint may use enrolled-station liveness for a principal the ACL already
//! names. Elect does not fire because someone attested silence or a station
//! was loud. After a cut, only pre-cut attestations from pre-cut enrollments
//! count.

use sha2::{Digest, Sha256};

use crate::cache::SnapshotHash;
use crate::error::AttestationError;
use crate::types::{NodeId, ObjectVersion, Timestamp};

/// Digest of the canonical statement. Edge code replaces this with a real
/// signature scheme; the plane checks that the digest matches the fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AttestationSig(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EnrollmentKind {
    Station,
    Principal,
    Device,
}

impl EnrollmentKind {
    pub fn parse(s: &str) -> Result<Self, AttestationError> {
        match s {
            "station" => Ok(Self::Station),
            "principal" => Ok(Self::Principal),
            "device" => Ok(Self::Device),
            other => Err(AttestationError::UnnamedEnrollmentKind(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Station => "station",
            Self::Principal => "principal",
            Self::Device => "device",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enrollment {
    pub issuer: NodeId,
    pub kind: EnrollmentKind,
    pub enrolled_at: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AttestationClaim {
    /// This human or agent is still the one named on the badge.
    IdentityLive,
    /// This device is still this device.
    DeviceLive,
    /// An enrolled station observed liveness. Not silence. Not loudness.
    StationLiveness,
}

impl AttestationClaim {
    pub fn parse(s: &str) -> Result<Self, AttestationError> {
        match s {
            "identity-live" | "still-this-principal" => Ok(Self::IdentityLive),
            "device-live" | "still-this-device" => Ok(Self::DeviceLive),
            "station-liveness" => Ok(Self::StationLiveness),
            "silence" | "silent" | "dead" | "death" | "vacancy" | "loud" | "proximity"
            | "flash" | "ping" => Err(AttestationError::ForbiddenClaim(s.to_string())),
            other => Err(AttestationError::UnnamedClaim(other.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdentityLive => "identity-live",
            Self::DeviceLive => "device-live",
            Self::StationLiveness => "station-liveness",
        }
    }

    /// Check may use identity or device liveness as a factor. Not station loudness.
    pub fn check_may_consume(self) -> bool {
        matches!(self, Self::IdentityLive | Self::DeviceLive)
    }

    /// Remint may use enrolled-station liveness, or identity/device liveness,
    /// for a principal the ACL already names.
    pub fn remint_may_consume(self) -> bool {
        matches!(
            self,
            Self::StationLiveness | Self::IdentityLive | Self::DeviceLive
        )
    }

    /// Elect may look at identity/device liveness when choosing among a
    /// pre-enrolled circle. It must not start because of a statement.
    pub fn elect_may_consume_for_choice(self) -> bool {
        matches!(self, Self::IdentityLive | Self::DeviceLive)
    }

    pub fn is_liveness_identity(self) -> bool {
        matches!(self, Self::IdentityLive | Self::DeviceLive)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AttestationBinding {
    ObjectVersion {
        object: NodeId,
        version: ObjectVersion,
    },
    Snapshot {
        object: NodeId,
        hash: SnapshotHash,
    },
}

impl AttestationBinding {
    pub fn matches_version(&self, object: &NodeId, version: ObjectVersion) -> bool {
        match self {
            Self::ObjectVersion {
                object: bound,
                version: v,
            } => bound == object && *v == version,
            Self::Snapshot { object: bound, .. } => bound == object,
        }
    }

    pub fn matches_snapshot(&self, object: &NodeId, hash: SnapshotHash) -> bool {
        match self {
            Self::Snapshot {
                object: bound,
                hash: h,
            } => bound == object && *h == hash,
            Self::ObjectVersion { object: bound, .. } => bound == object,
        }
    }
}

/// Signed statement: who said it, about whom, what claim, when, which
/// enrolled issuer, bound to which snapshot or object version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attestation {
    pub issuer: NodeId,
    pub subject: NodeId,
    pub claim: AttestationClaim,
    pub issued_at: Timestamp,
    /// Enrolled issuer record. Must equal `issuer`.
    pub enrollment: NodeId,
    pub binding: AttestationBinding,
    pub signature: AttestationSig,
}

impl Attestation {
    pub fn new(
        issuer: impl Into<NodeId>,
        subject: impl Into<NodeId>,
        claim: AttestationClaim,
        issued_at: Timestamp,
        binding: AttestationBinding,
    ) -> Self {
        let issuer = issuer.into();
        let mut att = Self {
            enrollment: issuer.clone(),
            issuer,
            subject: subject.into(),
            claim,
            issued_at,
            binding,
            signature: AttestationSig([0; 32]),
        };
        att.signature = att.digest();
        att
    }

    pub fn digest(&self) -> AttestationSig {
        let mut hasher = Sha256::new();
        hasher.update(self.issuer.as_bytes());
        hasher.update(self.subject.as_bytes());
        hasher.update(self.claim.as_str().as_bytes());
        hasher.update(self.issued_at.0.to_le_bytes());
        hasher.update(self.enrollment.as_bytes());
        match &self.binding {
            AttestationBinding::ObjectVersion { object, version } => {
                hasher.update(b"ver");
                hasher.update(object.as_bytes());
                hasher.update(version.0.to_le_bytes());
            }
            AttestationBinding::Snapshot { object, hash } => {
                hasher.update(b"snap");
                hasher.update(object.as_bytes());
                hasher.update(hash.0);
            }
        }
        let out = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        AttestationSig(bytes)
    }

    pub fn verify(&self) -> bool {
        self.signature == self.digest() && self.enrollment == self.issuer
    }
}

/// Record that Check used an attestation as a factor. Never a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationFactor {
    pub issuer: NodeId,
    pub claim: AttestationClaim,
    pub binding: AttestationBinding,
}
