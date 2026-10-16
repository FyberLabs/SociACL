//! Destination re-check of one blinded row.
//!
//! Order, and nothing here mints:
//! decode the payload, match the presentation fields, recompute the
//! commitment, compare an item digest, require `graph.ownerOf`, require
//! the enrolled pubs, verify the owner signature, verify the status proof
//! against the read key, then accept a presenter binding or a branded
//! channel. A nonce is spent only after those checks pass. The revision
//! record may move from a verified proof. Check runs after that. A hop,
//! a hint, or a wrap does not set `allowed`.

use crate::account::EnrolledSeaPub;
use crate::canonical::{self, grant_payload_bytes};
use crate::epoch::{
    epoch_read_key, status_is_fresh, AclSnapshotBody, EpochReplicaView, EpochStatusProof,
};
use crate::error::EncDiscError;
use crate::grant::{
    self, decode_grant_bytes, presentation_matches, row_entry_matches, BlindedGrantRow,
    GrantPresentation, GrantStated, SignedGrantPayload,
};
use crate::presenter::{
    challenge_for, spend_nonce, verify_presenter_binding, AuthenticatedPresenterChannel,
    PresenterBinding, VerifierChallengeState,
};
use crate::sea;
use crate::see::{
    check_opened_grant, CheckResult, HandoffHint, HopFactor, PresentedGroup, SeeGraph,
};

/// Highest signed revision this verifier has accepted for one pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierGrantRevision {
    pub object: String,
    pub accessor: String,
    pub grant_revision: u64,
    pub stated: GrantStated,
    pub payload_digest: String,
}

/// Verifier-held grant order. The presenter does not supply it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierGrantRevisionState {
    pub current: Vec<VerifierGrantRevision>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedGrantDecision {
    pub result: CheckResult,
    pub challenges: VerifierChallengeState,
    pub revisions: VerifierGrantRevisionState,
}

/// Inputs for one destination re-check. The graph is a separate argument.
pub struct PresentedGrantInput {
    pub row: BlindedGrantRow,
    pub presentation: GrantPresentation,
    pub accessor: String,
    pub now: u64,
    pub skew_allowance_ms: u64,
    pub challenges: VerifierChallengeState,
    pub revisions: VerifierGrantRevisionState,
    pub epoch_view: EpochReplicaView,
    pub policy_max_age_ms: u64,
    pub enrollment: Vec<EnrolledSeaPub>,
    pub snapshot: AclSnapshotBody,
    pub current_acl: AclSnapshotBody,
    pub binding: Option<PresenterBinding>,
    pub channel: Option<AuthenticatedPresenterChannel>,
    pub status: Option<EpochStatusProof>,
    pub group: Option<PresentedGroup>,
    pub fetched_item_digest: Option<String>,
    pub hint: Option<HandoffHint>,
    pub hop: Option<HopFactor>,
}

pub fn check_presented_grant(
    graph: &impl SeeGraph,
    input: PresentedGrantInput,
) -> PresentedGrantDecision {
    let challenges = input.challenges.clone();
    let revisions = input.revisions.clone();
    let deny = |reason: &str| PresentedGrantDecision {
        result: CheckResult::deny(reason),
        challenges: challenges.clone(),
        revisions: revisions.clone(),
    };

    // A hint is untrusted. It is not an input to `allowed`.
    let _hint = &input.hint;
    if input.hop.as_ref().is_some_and(HopFactor::forbidden) {
        return deny("forbidden");
    }

    let payload = match decode_grant_bytes(&input.presentation.grant_bytes) {
        Ok(payload) => payload,
        Err(_) => return deny("payload"),
    };
    if input.accessor != payload.accessor || !presentation_matches(&input.presentation, &payload) {
        return deny("payload");
    }
    if !row_entry_matches(&input.row).unwrap_or(false) {
        return deny("entry");
    }
    if grant::require_blinding(&input.presentation.blinding).is_err() {
        return deny("commitment");
    }
    let commitment =
        match canonical::grant_commitment_hash(&input.presentation.blinding, &payload.body()) {
            Ok(hash) => hash,
            Err(_) => return deny("commitment"),
        };
    if commitment != input.row.commitment.hash {
        return deny("commitment");
    }
    if let Some(reason) = item_digest(&payload, input.fetched_item_digest.as_deref()) {
        return deny(reason);
    }

    let Some(graph_owner) = graph.owner_of(&payload.object) else {
        return deny("owner");
    };
    if graph_owner != payload.owner || graph_owner != input.presentation.owner {
        return deny("owner");
    }
    let Some(owner_enrolled) = find_enrolled(&input.enrollment, &payload.owner) else {
        return deny("enrollment");
    };
    if owner_enrolled.sea_pub != input.presentation.sea_pub
        || (!owner_enrolled.identity_pub.is_empty()
            && owner_enrolled.identity_pub != owner_enrolled.sea_pub)
    {
        return deny("enrollment");
    }
    let Some(reader_enrolled) = find_enrolled(&input.enrollment, &payload.accessor) else {
        return deny("enrollment");
    };

    let message = match grant_payload_bytes(&payload.body()) {
        Ok(message) => message,
        Err(_) => return deny("payload"),
    };
    if sea::verify_sea(
        &owner_enrolled.sea_pub,
        &message,
        &input.presentation.signature,
    )
    .is_err()
    {
        return deny("signature");
    }

    let Some(status) = input.status.as_ref() else {
        return deny("status");
    };
    if let Some(reason) = status_matches(
        graph,
        &payload,
        &input.accessor,
        status,
        &input.epoch_view,
        &input.snapshot,
        &input.current_acl,
        input.now,
        input.skew_allowance_ms,
        input.policy_max_age_ms,
        &owner_enrolled.sea_pub,
    ) {
        return deny(reason);
    }
    if let Some(reason) = group_shape(graph, &payload.object, input.group.as_ref()) {
        return deny(reason);
    }

    if let Some(reason) = accept_presenter(
        &input.binding,
        input.channel.as_ref(),
        &input.challenges,
        &input.row.commitment.hash,
        &payload.accessor,
        &reader_enrolled.sea_pub,
        input.now,
    ) {
        return deny(reason);
    }

    let mut challenges = input.challenges;
    if let Some(binding) = &input.binding {
        spend_nonce(&mut challenges, &binding.nonce);
    }
    let (accepted, revisions) = apply_revision(&input.revisions, &payload, status);
    if !accepted {
        return PresentedGrantDecision {
            result: CheckResult::deny("revision"),
            challenges,
            revisions,
        };
    }
    let result = check_opened_grant(
        graph,
        &payload,
        &input.accessor,
        input.now,
        input.group.as_ref(),
    );
    PresentedGrantDecision {
        result,
        challenges,
        revisions,
    }
}

fn item_digest(payload: &SignedGrantPayload, fetched: Option<&str>) -> Option<&'static str> {
    if payload.names_item() {
        match fetched {
            Some(digest) if digest == payload.item_ciphertext_digest => None,
            _ => Some("item-digest"),
        }
    } else if fetched.is_some() {
        Some("item-digest")
    } else {
        None
    }
}

fn status_matches(
    graph: &impl SeeGraph,
    payload: &SignedGrantPayload,
    accessor: &str,
    status: &EpochStatusProof,
    view: &EpochReplicaView,
    snapshot: &AclSnapshotBody,
    current: &AclSnapshotBody,
    now: u64,
    skew_allowance_ms: u64,
    policy_max_age_ms: u64,
    owner_pub: &str,
) -> Option<&'static str> {
    if status.object != payload.object
        || status.zookie.object != payload.object
        || view.object != payload.object
        || status.accessor != accessor
        || status.accessor != payload.accessor
    {
        return Some("status");
    }
    if canonical::require_revision_id(&status.revision_id).is_err() {
        return Some("status");
    }
    let message = match canonical::epoch_status_bytes(&status.body()) {
        Ok(message) => message,
        Err(_) => return Some("status"),
    };
    if sea::verify_sea(owner_pub, &message, &status.signature).is_err() {
        return Some("signature");
    }
    let Some(read_key) = epoch_read_key(view, snapshot, current, now) else {
        return Some("epoch");
    };
    if status.epoch != payload.epoch || status.epoch != read_key.epoch {
        return Some("epoch");
    }
    if status.revision_id != read_key.revision_id {
        return Some("epoch");
    }
    if !status_is_fresh(status, now, skew_allowance_ms, policy_max_age_ms) {
        return Some("freshness");
    }
    if graph.object_version(&payload.object) != Some(status.zookie.object_version) {
        return Some("zookie");
    }
    if graph.snapshot_hash(&payload.object) != Some(status.zookie.snapshot_hash.as_str()) {
        return Some("zookie");
    }
    None
}

fn group_shape(
    graph: &impl SeeGraph,
    object: &str,
    group: Option<&PresentedGroup>,
) -> Option<&'static str> {
    match (group, graph.object_set(object)) {
        (None, None) => None,
        (Some(group), Some(set))
            if set.predicate == group.predicate && set.set_id == group.set_id =>
        {
            None
        }
        _ => Some("group"),
    }
}

fn accept_presenter(
    binding: &Option<PresenterBinding>,
    channel: Option<&AuthenticatedPresenterChannel>,
    challenges: &VerifierChallengeState,
    commitment_hash: &str,
    accessor: &str,
    enrolled_reader_pub: &str,
    now: u64,
) -> Option<&'static str> {
    if binding.is_none() && channel.is_none() {
        return Some("binding");
    }
    if let Some(channel) = channel {
        if !channel.has_transport_brand()
            || channel.accessor() != accessor
            || channel.reader_pub() != enrolled_reader_pub
        {
            return Some("channel");
        }
    }
    if let Some(binding) = binding {
        let challenge = match challenge_for(challenges, &binding.nonce) {
            Ok(challenge) => challenge,
            Err(_) => return Some("binding"),
        };
        if let Err(error) = verify_presenter_binding(
            binding,
            challenge,
            commitment_hash,
            enrolled_reader_pub,
            now,
        ) {
            return Some(if error == EncDiscError::PubMismatch {
                "enrollment"
            } else {
                "binding"
            });
        }
    }
    None
}

fn find_enrolled<'a>(accounts: &'a [EnrolledSeaPub], account: &str) -> Option<&'a EnrolledSeaPub> {
    let mut found = None;
    for row in accounts {
        if row.account == account {
            if found.is_some() {
                return None;
            }
            found = Some(row);
        }
    }
    found
}

/// Apply the proof, then the payload. `false` means the payload lost.
///
/// A higher proof, or `stated: 0` at the same revision as a stored live
/// row, is written even when the payload is rejected. An empty stored
/// digest is unknown. It is not the smallest digest.
fn apply_revision(
    revisions: &VerifierGrantRevisionState,
    payload: &SignedGrantPayload,
    proof: &EpochStatusProof,
) -> (bool, VerifierGrantRevisionState) {
    let digest = match grant::grant_digest(payload) {
        Ok(digest) => digest,
        Err(_) => return (false, revisions.clone()),
    };
    let index = revisions
        .current
        .iter()
        .position(|row| row.object == payload.object && row.accessor == payload.accessor);
    let original = index.map(|index| revisions.current[index].clone());

    let working = match &original {
        None => proof_record(payload, proof),
        Some(record) if proof.grant_revision > record.grant_revision => {
            proof_record(payload, proof)
        }
        Some(_) if proof.grant_revision < original.as_ref().unwrap().grant_revision => {
            return (false, revisions.clone());
        }
        Some(record)
            if proof.grant_revision == record.grant_revision
                && proof.stated == GrantStated::Live
                && record.stated == GrantStated::Cancelled =>
        {
            return (false, revisions.clone());
        }
        Some(record)
            if proof.grant_revision == record.grant_revision
                && proof.stated == GrantStated::Cancelled
                && record.stated == GrantStated::Live =>
        {
            VerifierGrantRevision {
                object: record.object.clone(),
                accessor: record.accessor.clone(),
                grant_revision: record.grant_revision,
                stated: GrantStated::Cancelled,
                payload_digest: String::new(),
            }
        }
        Some(record) => record.clone(),
    };
    let changed = match &original {
        None => true,
        Some(record) => {
            working.grant_revision != record.grant_revision
                || working.stated != record.stated
                || working.payload_digest != record.payload_digest
        }
    };

    if payload.grant_revision != working.grant_revision
        || (payload.stated == GrantStated::Live && working.stated == GrantStated::Cancelled)
    {
        return (false, commit(revisions, index, &working, changed));
    }
    if payload.stated == GrantStated::Cancelled && working.stated == GrantStated::Live {
        let stored = VerifierGrantRevision {
            stated: GrantStated::Cancelled,
            payload_digest: digest,
            ..working
        };
        return (true, commit(revisions, index, &stored, true));
    }
    if working.payload_digest.is_empty() || digest.as_str() < working.payload_digest.as_str() {
        let stored = VerifierGrantRevision {
            stated: payload.stated,
            payload_digest: digest,
            grant_revision: payload.grant_revision,
            ..working
        };
        return (true, commit(revisions, index, &stored, true));
    }
    if digest.as_str() > working.payload_digest.as_str() {
        return (false, commit(revisions, index, &working, changed));
    }
    (true, commit(revisions, index, &working, changed))
}

fn proof_record(payload: &SignedGrantPayload, proof: &EpochStatusProof) -> VerifierGrantRevision {
    VerifierGrantRevision {
        object: payload.object.clone(),
        accessor: payload.accessor.clone(),
        grant_revision: proof.grant_revision,
        stated: proof.stated,
        payload_digest: String::new(),
    }
}

fn commit(
    revisions: &VerifierGrantRevisionState,
    index: Option<usize>,
    record: &VerifierGrantRevision,
    write: bool,
) -> VerifierGrantRevisionState {
    if !write {
        return revisions.clone();
    }
    let mut next = revisions.clone();
    match index {
        Some(index) => next.current[index] = record.clone(),
        None => next.current.push(record.clone()),
    }
    next
}
