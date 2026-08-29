//! Versioned encoding for a durable [`CutBundle`].
//!
//! Explicit length-prefixed fields, not Debug. Share keys are wrapped to
//! the holder secret. The frame is Ed25519-signed by that secret. A
//! SHA-256 trailer alone is not enough; v1 and v2 unsigned frames fail
//! closed.

use sha2::{Digest, Sha256};

use crate::attestation::{
    Attestation, AttestationBinding, AttestationClaim, AttestationSig, Enrollment, EnrollmentKind,
    HolderSecret, VerifyKey,
};
use crate::bundle::{share_digest, CutBundle};
use crate::cache::{Snapshot, SnapshotHash, Zookie};
use crate::error::VerbError;
use crate::types::{
    AuthnState, ClientHeldShare, CutBoundary, Edge, NodeId, NodeKind, Object, ObjectKind,
    ObjectProperties, ObjectVersion, Relation, Timestamp,
};
use crate::will::{DestroyMaterial, Will, WillBody, WillClause, WillSubject};

pub const MAGIC: &[u8; 4] = b"SACL";
/// v1 stored a 32-byte digest as an attestation signature.
/// v2 signed attestations but left share keys and the frame unsigned.
/// Those frames fail closed here.
pub const VERSION: u16 = 3;
const DIGEST_LEN: usize = 32;
const SIG_LEN: usize = AttestationSig::LEN;
const TRAILER_LEN: usize = DIGEST_LEN + SIG_LEN;

const MAX_STR: u32 = 4096;
const MAX_ITEMS: u32 = 65_536;
const MAX_BYTES: u32 = 256;

pub fn encode(bundle: &CutBundle, secret: &HolderSecret) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(bundle.cut.cut_at.0);
    w.str(bundle.holder.as_str());

    w.u32(bundle.nodes.len() as u32);
    for (id, kind) in &bundle.nodes {
        w.str(id.as_str());
        w.str(kind.as_str());
    }

    w.u32(bundle.authn.len() as u32);
    for (id, state) in &bundle.authn {
        w.str(id.as_str());
        w.str(state.as_str());
    }

    w.u32(bundle.objects.len() as u32);
    for obj in &bundle.objects {
        encode_object(&mut w, obj);
    }

    w.u32(bundle.snapshots.len() as u32);
    for snap in &bundle.snapshots {
        w.str(snap.object.as_str());
        w.u64(snap.object_version.0);
        w.fixed32(&snap.hash.0);
    }

    w.u32(bundle.zookies.len() as u32);
    for z in &bundle.zookies {
        w.str(z.object.as_str());
        w.u64(z.object_version.0);
        w.fixed32(&z.snapshot_hash.0);
    }

    w.u32(bundle.edges.len() as u32);
    for edge in &bundle.edges {
        encode_edge(&mut w, edge);
    }

    w.u32(bundle.wills.len() as u32);
    for will in &bundle.wills {
        encode_will(&mut w, will);
    }

    w.u32(bundle.enrollments.len() as u32);
    for enr in &bundle.enrollments {
        w.str(enr.issuer.as_str());
        w.str(enr.kind.as_str());
        w.u64(enr.enrolled_at.0);
        w.bytes(&enr.public_key.0);
    }

    w.u32(bundle.attestations.len() as u32);
    for att in &bundle.attestations {
        encode_attestation(&mut w, att);
    }

    w.u32(bundle.shares.len() as u32);
    for share in &bundle.shares {
        encode_share(&mut w, share, secret);
    }

    frame(&w.0, secret)
}

pub fn decode(bytes: &[u8], secret: &HolderSecret) -> Result<CutBundle, VerbError> {
    let payload = unframe(bytes, secret)?;
    let mut r = Reader::new(payload);

    let cut_at = Timestamp(r.u64()?);
    let holder = NodeId::new(r.str()?);

    let n = r.count()?;
    let mut nodes = Vec::with_capacity(n);
    for _ in 0..n {
        let id = NodeId::new(r.str()?);
        let kind = NodeKind::parse(r.str()?).ok_or(VerbError::BundleCorrupt)?;
        nodes.push((id, kind));
    }

    let n = r.count()?;
    let mut authn = Vec::with_capacity(n);
    for _ in 0..n {
        let id = NodeId::new(r.str()?);
        let state = AuthnState::parse(r.str()?).ok_or(VerbError::BundleCorrupt)?;
        authn.push((id, state));
    }

    let n = r.count()?;
    let mut objects = Vec::with_capacity(n);
    for _ in 0..n {
        objects.push(decode_object(&mut r)?);
    }

    let n = r.count()?;
    let mut snapshots = Vec::with_capacity(n);
    for _ in 0..n {
        snapshots.push(Snapshot {
            object: NodeId::new(r.str()?),
            object_version: ObjectVersion(r.u64()?),
            hash: SnapshotHash(r.fixed32()?),
        });
    }

    let n = r.count()?;
    let mut zookies = Vec::with_capacity(n);
    for _ in 0..n {
        zookies.push(Zookie {
            object: NodeId::new(r.str()?),
            object_version: ObjectVersion(r.u64()?),
            snapshot_hash: SnapshotHash(r.fixed32()?),
        });
    }

    let n = r.count()?;
    let mut edges = Vec::with_capacity(n);
    for _ in 0..n {
        edges.push(decode_edge(&mut r)?);
    }

    let n = r.count()?;
    let mut wills = Vec::with_capacity(n);
    for _ in 0..n {
        wills.push(decode_will(&mut r)?);
    }

    let n = r.count()?;
    let mut enrollments = Vec::with_capacity(n);
    for _ in 0..n {
        enrollments.push(Enrollment {
            issuer: NodeId::new(r.str()?),
            kind: EnrollmentKind::parse(r.str()?).map_err(|_| VerbError::BundleCorrupt)?,
            enrolled_at: Timestamp(r.u64()?),
            public_key: VerifyKey::from_slice(&r.bytes()?).map_err(|_| VerbError::BundleCorrupt)?,
        });
    }

    let n = r.count()?;
    let mut attestations = Vec::with_capacity(n);
    for _ in 0..n {
        attestations.push(decode_attestation(&mut r)?);
    }

    let n = r.count()?;
    let mut shares = Vec::with_capacity(n);
    for _ in 0..n {
        shares.push(decode_share(&mut r, secret)?);
    }

    r.finish()?;
    for obj in &mut objects {
        if let Some(share) = shares.iter().find(|s| s.object == obj.id) {
            obj.content_key = share.key_material;
        }
    }
    Ok(CutBundle {
        cut: CutBoundary { cut_at },
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
    })
}

fn frame(payload: &[u8], secret: &HolderSecret) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 + 4 + payload.len() + TRAILER_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    let digest = Sha256::digest(&out);
    let sig = secret.sign(digest.as_slice());
    out.extend_from_slice(&digest);
    out.extend_from_slice(&sig.0);
    out
}

fn unframe<'a>(bytes: &'a [u8], secret: &HolderSecret) -> Result<&'a [u8], VerbError> {
    const HEADER: usize = 4 + 2 + 4;
    if bytes.len() < HEADER + TRAILER_LEN {
        return Err(VerbError::BundleCorrupt);
    }
    if &bytes[..4] != MAGIC {
        return Err(VerbError::BundleCorrupt);
    }
    let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if version != VERSION {
        return Err(VerbError::UnsupportedBundleVersion(version));
    }
    let payload_len = u32::from_le_bytes(bytes[6..10].try_into().unwrap()) as usize;
    let end = HEADER
        .checked_add(payload_len)
        .ok_or(VerbError::BundleCorrupt)?;
    let digest_end = end
        .checked_add(DIGEST_LEN)
        .ok_or(VerbError::BundleCorrupt)?;
    let sig_end = digest_end
        .checked_add(SIG_LEN)
        .ok_or(VerbError::BundleCorrupt)?;
    if bytes.len() != sig_end {
        return Err(VerbError::BundleCorrupt);
    }
    let expected = Sha256::digest(&bytes[..end]);
    if expected.as_slice() != &bytes[end..digest_end] {
        return Err(VerbError::BundleCorrupt);
    }
    let sig = AttestationSig::from_slice(&bytes[digest_end..sig_end])
        .map_err(|_| VerbError::BundleSignature)?;
    if sig.0 == [0u8; SIG_LEN] || !secret.verify(expected.as_slice(), &sig) {
        return Err(VerbError::BundleSignature);
    }
    Ok(&bytes[HEADER..end])
}

fn encode_object(w: &mut Writer, obj: &Object) {
    w.str(obj.id.as_str());
    w.str(obj.kind.as_str());
    w.str(obj.owner.as_str());
    w.u64(obj.version.0);
    w.bool(obj.destroyed);
    // Durable objects never carry the plaintext key. The share wrap
    // is the only copy that leaves the process.
    w.bool(false);
    let props: Vec<(&str, &str)> = obj.properties.iter().collect();
    w.u32(props.len() as u32);
    for (k, v) in props {
        w.str(k);
        w.str(v);
    }
}

fn decode_object(r: &mut Reader<'_>) -> Result<Object, VerbError> {
    let id = NodeId::new(r.str()?);
    let kind = ObjectKind::parse(r.str()?).ok_or(VerbError::BundleCorrupt)?;
    let owner = NodeId::new(r.str()?);
    let version = ObjectVersion(r.u64()?);
    let destroyed = r.bool()?;
    if r.bool()? {
        return Err(VerbError::BundleCorrupt);
    }
    let content_key = None;
    let n = r.count()?;
    let mut properties = ObjectProperties::new();
    for _ in 0..n {
        properties.set(r.str()?, r.str()?);
    }
    Ok(Object {
        id,
        kind,
        owner,
        version,
        destroyed,
        content_key,
        properties,
    })
}

fn encode_edge(w: &mut Writer, edge: &Edge) {
    w.str(edge.from.as_str());
    w.str(edge.to.as_str());
    w.str(edge.relation.as_str());
    w.bool(edge.from_stated);
    w.bool(edge.to_stated);
    match edge.joint_at {
        Some(t) => {
            w.bool(true);
            w.u64(t.0);
        }
        None => w.bool(false),
    }
    match edge.effective_at {
        Some(t) => {
            w.bool(true);
            w.u64(t.0);
        }
        None => w.bool(false),
    }
}

fn decode_edge(r: &mut Reader<'_>) -> Result<Edge, VerbError> {
    Ok(Edge {
        from: NodeId::new(r.str()?),
        to: NodeId::new(r.str()?),
        relation: Relation::parse(r.str()?).ok_or(VerbError::BundleCorrupt)?,
        from_stated: r.bool()?,
        to_stated: r.bool()?,
        joint_at: if r.bool()? {
            Some(Timestamp(r.u64()?))
        } else {
            None
        },
        effective_at: if r.bool()? {
            Some(Timestamp(r.u64()?))
        } else {
            None
        },
    })
}

fn encode_will(w: &mut Writer, will: &Will) {
    w.str(&will.name);
    w.str(will.subject.kind_str());
    w.str(will.subject.id().as_str());
    w.str(will.testator.as_str());
    w.u64(will.written_at.0);
    w.u64(will.joint_at.0);
    w.bool(will.canceled);
    w.u32(will.cancelable_by.len() as u32);
    for id in &will.cancelable_by {
        w.str(id.as_str());
    }
    w.u32(will.body.clauses.len() as u32);
    for clause in &will.body.clauses {
        encode_clause(w, clause);
    }
}

fn decode_will(r: &mut Reader<'_>) -> Result<Will, VerbError> {
    let name = r.str()?.to_string();
    let kind = r.str()?;
    let id = NodeId::new(r.str()?);
    let subject = match kind {
        "object" => WillSubject::Object(id),
        "group" => WillSubject::Group(id),
        "network" => WillSubject::Network(id),
        "device-class" => WillSubject::DeviceClass(id),
        _ => return Err(VerbError::BundleCorrupt),
    };
    let testator = NodeId::new(r.str()?);
    let written_at = Timestamp(r.u64()?);
    let joint_at = Timestamp(r.u64()?);
    let canceled = r.bool()?;
    let n = r.count()?;
    let mut cancelable_by = Vec::with_capacity(n);
    for _ in 0..n {
        cancelable_by.push(NodeId::new(r.str()?));
    }
    let n = r.count()?;
    let mut clauses = Vec::with_capacity(n);
    for _ in 0..n {
        clauses.push(decode_clause(r)?);
    }
    Ok(Will {
        name,
        subject,
        testator,
        body: WillBody { clauses },
        written_at,
        joint_at,
        cancelable_by,
        canceled,
    })
}

fn encode_clause(w: &mut Writer, clause: &WillClause) {
    w.str(clause.name());
    match clause {
        WillClause::KeepOperating { circle } => w.str(circle.as_str()),
        WillClause::Remint { issuers } => {
            w.u32(issuers.len() as u32);
            for id in issuers {
                w.str(id.as_str());
            }
        }
        WillClause::Discover { heir } => w.str(heir.as_str()),
        WillClause::Elect {
            circle,
            clock,
            threshold,
            notify,
            wait,
            cancel,
        } => {
            w.str(circle.as_str());
            w.str(clock.as_str());
            w.u32(*threshold);
            w.u32(notify.len() as u32);
            for id in notify {
                w.str(id.as_str());
            }
            w.bool(*wait);
            w.bool(*cancel);
        }
        WillClause::Destroy {
            if_no_heir,
            material,
        } => {
            w.bool(*if_no_heir);
            w.str(material.as_str());
        }
        WillClause::HighestStillAttestingRank { circle } => w.str(circle.as_str()),
        WillClause::NamedSuccessorList { successors } => {
            w.u32(successors.len() as u32);
            for id in successors {
                w.str(id.as_str());
            }
        }
    }
}

fn decode_clause(r: &mut Reader<'_>) -> Result<WillClause, VerbError> {
    match r.str()? {
        "keep-operating" => Ok(WillClause::KeepOperating {
            circle: NodeId::new(r.str()?),
        }),
        "remint" => {
            let n = r.count()?;
            let mut issuers = Vec::with_capacity(n);
            for _ in 0..n {
                issuers.push(NodeId::new(r.str()?));
            }
            Ok(WillClause::Remint { issuers })
        }
        "discover" => Ok(WillClause::Discover {
            heir: NodeId::new(r.str()?),
        }),
        "elect" => {
            let circle = NodeId::new(r.str()?);
            let clock = crate::types::Clock::parse(r.str()?).ok_or(VerbError::BundleCorrupt)?;
            let threshold = r.u32()?;
            let n = r.count()?;
            let mut notify = Vec::with_capacity(n);
            for _ in 0..n {
                notify.push(NodeId::new(r.str()?));
            }
            Ok(WillClause::Elect {
                circle,
                clock,
                threshold,
                notify,
                wait: r.bool()?,
                cancel: r.bool()?,
            })
        }
        "destroy" => {
            let if_no_heir = r.bool()?;
            let material = match r.str()? {
                "keys" => DestroyMaterial::Keys,
                "content" => DestroyMaterial::Content,
                _ => return Err(VerbError::BundleCorrupt),
            };
            Ok(WillClause::Destroy {
                if_no_heir,
                material,
            })
        }
        "highest-still-attesting-rank" => Ok(WillClause::HighestStillAttestingRank {
            circle: NodeId::new(r.str()?),
        }),
        "named-successor-list" => {
            let n = r.count()?;
            let mut successors = Vec::with_capacity(n);
            for _ in 0..n {
                successors.push(NodeId::new(r.str()?));
            }
            Ok(WillClause::NamedSuccessorList { successors })
        }
        _ => Err(VerbError::BundleCorrupt),
    }
}

fn encode_attestation(w: &mut Writer, att: &Attestation) {
    w.str(att.issuer.as_str());
    w.str(att.subject.as_str());
    w.str(att.claim.as_str());
    w.u64(att.issued_at.0);
    w.str(att.enrollment.as_str());
    match &att.binding {
        AttestationBinding::ObjectVersion { object, version } => {
            w.str("object-version");
            w.str(object.as_str());
            w.u64(version.0);
        }
        AttestationBinding::Snapshot { object, hash } => {
            w.str("snapshot");
            w.str(object.as_str());
            w.fixed32(&hash.0);
        }
    }
    w.bytes(&att.signature.0);
}

fn decode_attestation(r: &mut Reader<'_>) -> Result<Attestation, VerbError> {
    let issuer = NodeId::new(r.str()?);
    let subject = NodeId::new(r.str()?);
    let claim = AttestationClaim::parse(r.str()?).map_err(|_| VerbError::BundleCorrupt)?;
    let issued_at = Timestamp(r.u64()?);
    let enrollment = NodeId::new(r.str()?);
    let binding = match r.str()? {
        "object-version" => AttestationBinding::ObjectVersion {
            object: NodeId::new(r.str()?),
            version: ObjectVersion(r.u64()?),
        },
        "snapshot" => AttestationBinding::Snapshot {
            object: NodeId::new(r.str()?),
            hash: SnapshotHash(r.fixed32()?),
        },
        _ => return Err(VerbError::BundleCorrupt),
    };
    Ok(Attestation {
        issuer,
        subject,
        claim,
        issued_at,
        enrollment,
        binding,
        signature: AttestationSig::from_slice(&r.bytes()?).map_err(|_| VerbError::BundleCorrupt)?,
    })
}

fn encode_share(w: &mut Writer, share: &ClientHeldShare, secret: &HolderSecret) {
    w.str(share.object.as_str());
    w.str(share.holder.as_str());
    w.fixed32(&share.share_hash);
    match share.key_material {
        Some(key) => {
            w.bool(true);
            w.fixed32(&wrap_share_key(
                secret,
                &share.object,
                &share.holder,
                share.held_at,
                &key,
            ));
        }
        None => w.bool(false),
    }
    w.u64(share.held_at.0);
}

fn decode_share(r: &mut Reader<'_>, secret: &HolderSecret) -> Result<ClientHeldShare, VerbError> {
    let object = NodeId::new(r.str()?);
    let holder = NodeId::new(r.str()?);
    let share_hash = r.fixed32()?;
    let sealed = if r.bool()? { Some(r.fixed32()?) } else { None };
    let held_at = Timestamp(r.u64()?);
    let key_material = match sealed {
        Some(sealed) => {
            let key = unwrap_share_key(secret, &object, &holder, held_at, &sealed);
            if share_digest(&object, &holder, &key, held_at) != share_hash {
                return Err(VerbError::ShareReconstruct(object));
            }
            Some(key)
        }
        None => None,
    };
    Ok(ClientHeldShare {
        object,
        holder,
        share_hash,
        key_material,
        held_at,
    })
}

fn wrap_stream(
    secret: &HolderSecret,
    object: &NodeId,
    holder: &NodeId,
    held_at: Timestamp,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"sociacl-share-wrap-v3");
    hasher.update(secret.as_bytes());
    hasher.update(object.as_bytes());
    hasher.update(holder.as_bytes());
    hasher.update(held_at.0.to_le_bytes());
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

fn xor32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn wrap_share_key(
    secret: &HolderSecret,
    object: &NodeId,
    holder: &NodeId,
    held_at: Timestamp,
    key: &[u8; 32],
) -> [u8; 32] {
    xor32(key, &wrap_stream(secret, object, holder, held_at))
}

fn unwrap_share_key(
    secret: &HolderSecret,
    object: &NodeId,
    holder: &NodeId,
    held_at: Timestamp,
    sealed: &[u8; 32],
) -> [u8; 32] {
    xor32(sealed, &wrap_stream(secret, object, holder, held_at))
}

struct Writer(Vec<u8>);

impl Writer {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn bool(&mut self, v: bool) {
        self.0.push(if v { 1 } else { 0 });
    }

    fn fixed32(&mut self, bytes: &[u8; 32]) {
        self.0.extend_from_slice(bytes);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.u32(bytes.len() as u32);
        self.0.extend_from_slice(bytes);
    }

    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, i: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VerbError> {
        let end = self.i.checked_add(n).ok_or(VerbError::BundleCorrupt)?;
        if end > self.buf.len() {
            return Err(VerbError::BundleCorrupt);
        }
        let slice = &self.buf[self.i..end];
        self.i = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, VerbError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, VerbError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    fn bool(&mut self) -> Result<bool, VerbError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(VerbError::BundleCorrupt),
        }
    }

    fn fixed32(&mut self) -> Result<[u8; 32], VerbError> {
        let b = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        Ok(out)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, VerbError> {
        let len = self.u32()?;
        if len > MAX_BYTES {
            return Err(VerbError::BundleCorrupt);
        }
        Ok(self.take(len as usize)?.to_vec())
    }

    fn str(&mut self) -> Result<&'a str, VerbError> {
        let len = self.u32()?;
        if len > MAX_STR {
            return Err(VerbError::BundleCorrupt);
        }
        let bytes = self.take(len as usize)?;
        std::str::from_utf8(bytes).map_err(|_| VerbError::BundleCorrupt)
    }

    fn count(&mut self) -> Result<usize, VerbError> {
        let n = self.u32()?;
        if n > MAX_ITEMS {
            return Err(VerbError::BundleCorrupt);
        }
        Ok(n as usize)
    }

    fn finish(&self) -> Result<(), VerbError> {
        if self.i == self.buf.len() {
            Ok(())
        } else {
            Err(VerbError::BundleCorrupt)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Plane;
    use crate::types::PredicateId;

    #[test]
    fn recomputed_digest_without_holder_signature_fails() {
        let mut plane = Plane::new();
        let alice = plane.add_person("alice").id;
        let doc = plane.add_object("doc", &alice).id;
        plane
            .set_object_property(&doc, "predicate", PredicateId::OWNER)
            .unwrap();
        let secret = HolderSecret::generate();
        let bytes = plane.export_bundle_bytes(&alice, &secret).unwrap();
        let mut rewritten = bytes.clone();
        let mid = rewritten.len() / 2;
        rewritten[mid] ^= 0xff;
        let digest_start = rewritten.len() - TRAILER_LEN;
        let sig_start = rewritten.len() - SIG_LEN;
        let digest = Sha256::digest(&rewritten[..digest_start]);
        rewritten[digest_start..sig_start].copy_from_slice(&digest);
        assert_eq!(
            decode(&rewritten, &secret).unwrap_err(),
            VerbError::BundleSignature
        );
    }
}
