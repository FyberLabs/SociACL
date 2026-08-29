//! Signed statements. Not grants.
//!
//! An oracle accepts a statement only from a pre-enrolled issuer whose
//! verify key was recorded at enroll. Check may use identity or device
//! liveness as a factor on an already-named predicate. Remint may use
//! enrolled-station liveness for a principal the ACL already names.
//! Elect does not fire because someone attested silence or a station
//! was loud. After a cut, only pre-cut attestations from pre-cut
//! enrollments count.
//!
//! The plane stores verify keys. The issuer (test helper or edge) holds
//! the signing key. CutBundle never carries issuer secrets.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::cache::SnapshotHash;
use crate::error::AttestationError;
use crate::types::{NodeId, ObjectVersion, Timestamp};

/// Ed25519 signature over [`Attestation::digest`]. Not the digest itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AttestationSig(pub [u8; 64]);

impl AttestationSig {
    pub const LEN: usize = 64;

    pub fn empty() -> Self {
        Self([0u8; 64])
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, AttestationError> {
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| AttestationError::BadSignature)?;
        Ok(Self(arr))
    }
}

/// Ed25519 verify key recorded on an enrollment. The plane stores these.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct VerifyKey(pub [u8; 32]);

impl VerifyKey {
    pub const LEN: usize = 32;

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, AttestationError> {
        if bytes == [0u8; 32] {
            return Err(AttestationError::InvalidVerifyKey);
        }
        VerifyingKey::from_bytes(&bytes).map_err(|_| AttestationError::InvalidVerifyKey)?;
        Ok(Self(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, AttestationError> {
        if bytes.is_empty() {
            return Err(AttestationError::InvalidVerifyKey);
        }
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AttestationError::InvalidVerifyKey)?;
        Self::from_bytes(arr)
    }

    pub fn is_valid(self) -> bool {
        self.0 != [0u8; 32] && VerifyingKey::from_bytes(&self.0).is_ok()
    }

    fn dalek(self) -> Result<VerifyingKey, AttestationError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| AttestationError::InvalidVerifyKey)
    }
}

/// Issuer signing key. Held by the edge or a test. Never stored on
/// [`crate::Plane`] or [`crate::CutBundle`].
#[derive(Clone)]
pub struct IssuerSecret([u8; 32]);

impl fmt::Debug for IssuerSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerSecret(..)")
    }
}

impl IssuerSecret {
    pub const LEN: usize = 32;

    /// Fresh issuer key. The caller keeps it; the plane does not.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self(signing.to_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, AttestationError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AttestationError::InvalidVerifyKey)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn verify_key(&self) -> VerifyKey {
        VerifyKey(self.signing().verifying_key().to_bytes())
    }

    fn signing(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }

    pub fn sign(&self, message: &[u8]) -> AttestationSig {
        AttestationSig(self.signing().sign(message).to_bytes())
    }
}

/// Holder secret for a durable Case C bundle. The caller keeps it.
/// The file does not. Used to wrap share keys and sign the frame.
/// Same 32-byte Ed25519 shape as [`IssuerSecret`]. An enrolled issuer
/// key may be reused via [`HolderSecret::from_issuer`].
#[derive(Clone)]
pub struct HolderSecret([u8; 32]);

impl fmt::Debug for HolderSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HolderSecret(..)")
    }
}

impl HolderSecret {
    pub const LEN: usize = 32;

    pub fn generate() -> Self {
        Self(IssuerSecret::generate().0)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, AttestationError> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AttestationError::InvalidVerifyKey)?;
        Ok(Self(arr))
    }

    pub fn from_issuer(secret: &IssuerSecret) -> Self {
        Self(secret.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn verify_key(&self) -> VerifyKey {
        VerifyKey(self.signing().verifying_key().to_bytes())
    }

    fn signing(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }

    pub fn sign(&self, message: &[u8]) -> AttestationSig {
        AttestationSig(self.signing().sign(message).to_bytes())
    }

    pub fn verify(&self, message: &[u8], signature: &AttestationSig) -> bool {
        let Ok(vk) = self.verify_key().dalek() else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&signature.0) else {
            return false;
        };
        vk.verify_strict(message, &sig).is_ok()
    }
}

impl From<&IssuerSecret> for HolderSecret {
    fn from(secret: &IssuerSecret) -> Self {
        Self::from_issuer(secret)
    }
}

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
    pub public_key: VerifyKey,
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
    /// Unsigned statement. Call [`Self::sign`] with the issuer secret.
    /// The plane will not accept a digest stuffed into `signature`.
    pub fn new(
        issuer: impl Into<NodeId>,
        subject: impl Into<NodeId>,
        claim: AttestationClaim,
        issued_at: Timestamp,
        binding: AttestationBinding,
    ) -> Self {
        let issuer = issuer.into();
        Self {
            enrollment: issuer.clone(),
            issuer,
            subject: subject.into(),
            claim,
            issued_at,
            binding,
            signature: AttestationSig::empty(),
        }
    }

    pub fn sign(mut self, secret: &IssuerSecret) -> Self {
        self.signature = secret.sign(&self.digest());
        self
    }

    /// Canonical message. This is what the issuer signs.
    pub fn digest(&self) -> [u8; 32] {
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
        bytes
    }

    /// Check the signature against an enrolled verify key. Not
    /// `signature == digest()`.
    pub fn verify(&self, public_key: &VerifyKey) -> bool {
        if self.enrollment != self.issuer {
            return false;
        }
        let Ok(vk) = public_key.dalek() else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.signature.0) else {
            return false;
        };
        vk.verify_strict(&self.digest(), &sig).is_ok()
    }
}

/// Record that Check used an attestation as a factor. Never a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationFactor {
    pub issuer: NodeId,
    pub claim: AttestationClaim,
    pub binding: AttestationBinding,
}
