//! One private inbox lane per reader, and the write policy.
//!
//! Each account has one [`RecipientInbox`]. The lane id is an opaque
//! soul. It is not the accessor id and not `grantSoul`. There is no
//! second lane per device, sender, or epoch, and no shared bucket.
//!
//! `entryId` is the hash of the whole canonical entry. A daily shard
//! is a rescan of that same lane, then dedup by `entryId`. A per-device
//! cursor is not an argument. A shard-close watermark is not
//! implemented: issue #22 defers a trusted close that would skip a day.
//!
//! [`filter_inbox_append`] is the reader's hook. The default policy is
//! `public-filtered`. `named-writers` is the allowlist. The accepting
//! relay learns the authenticated writer id for that `entryId`. The
//! stored row has no writer pub. A peer that only replicates the row
//! does not learn the writer, and that replica is not an admitted
//! append until this verifier records the id.
//!
//! An append is not a grant. An opened wrap is not a grant. Surviving
//! rows still go through Check. This module does not set `allowed`.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::account::{EnrolledSeaPub, RecipientInbox};
use crate::canonical::{self, inbox_entry_bytes};
use crate::error::EncDiscError;
use crate::grant::{row_entry_matches, BlindedGrantRow};
use crate::see::hop_forbidden;
use crate::writer::WriterAppendAuth;

/// Canonical entry longer than this is a local `spam` drop.
///
/// The spec names oversized rows as a local drop and does not lock the
/// count. This ceiling is the reference filter. It is not a Gun field
/// and a writer cannot raise it.
pub const INBOX_ENTRY_MAX_BYTES: usize = 65_536;

/// Who may append. Public stays the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InboxWritePolicy {
    #[default]
    PublicFiltered,
    NamedWriters,
}

impl InboxWritePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicFiltered => "public-filtered",
            Self::NamedWriters => "named-writers",
        }
    }

    pub fn parse(text: &str) -> Result<Self, EncDiscError> {
        match text {
            "public-filtered" => Ok(Self::PublicFiltered),
            "named-writers" => Ok(Self::NamedWriters),
            _ => Err(EncDiscError::InboxRejected),
        }
    }
}

/// Reader-chosen hook. `writers` is the allowlist for `named-writers`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxWriteHook {
    pub policy: InboxWritePolicy,
    pub writers: Vec<String>,
}

impl Default for InboxWriteHook {
    fn default() -> Self {
        Self {
            policy: InboxWritePolicy::PublicFiltered,
            writers: Vec::new(),
        }
    }
}

/// Verifier-issued proof-of-work challenge. The writer does not choose it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionChallenge {
    pub nonce: String,
    pub difficulty: u32,
    pub expires_at: u64,
}

/// What the writer shows. Quotas and difficulty are not fields here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionEvidence {
    ProofOfWork { nonce: String, solution: String },
    Stamp { issuer: String, signature: String },
}

/// One sender's remaining appends. The writer does not supply this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderQuota {
    pub sender: String,
    pub remaining: u64,
}

/// Verifier-held admission state. The writer does not supply it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct VerifierAdmissionState {
    pub challenges: Vec<AdmissionChallenge>,
    pub stamp_issuers: Vec<String>,
    pub spent: Vec<String>,
    pub known_senders: Vec<String>,
    pub sender_quotas: Vec<SenderQuota>,
    pub first_contact_remaining: u64,
    pub admitted: Vec<String>,
    pub lane_remaining: u64,
}

/// Evidence beside an append. First contact is not a field here.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct InboxAdmission {
    pub evidence: Option<AdmissionEvidence>,
}

/// Local drop label. Not a Check reason and not a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboxWriteFilter {
    Ok,
    Spam,
    UnnamedWriter,
    WriterAuth,
    StampRequired,
    StampMismatch,
    Replay,
    SenderQuota,
    ReaderCapacity,
}

impl InboxWriteFilter {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Spam => "spam",
            Self::UnnamedWriter => "unnamed-writer",
            Self::WriterAuth => "writer-auth",
            Self::StampRequired => "stamp-required",
            Self::StampMismatch => "stamp-mismatch",
            Self::Replay => "replay",
            Self::SenderQuota => "sender-quota",
            Self::ReaderCapacity => "reader-capacity",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxWriteDecision {
    pub allow_append: bool,
    pub filter: InboxWriteFilter,
}

impl InboxWriteDecision {
    fn from_filter(filter: InboxWriteFilter) -> Self {
        Self {
            allow_append: filter == InboxWriteFilter::Ok,
            filter,
        }
    }
}

/// Hook result. `learned_writer` is the accepting relay's observation.
///
/// It is set only when the append is allowed. It is not a field of the
/// stored row. A refused append leaves it empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxAppendResult {
    pub decision: InboxWriteDecision,
    pub state: VerifierAdmissionState,
    pub learned_writer: Option<String>,
}

impl InboxAppendResult {
    /// An admitted append does not make Check allow.
    pub fn grants_see(&self) -> bool {
        false
    }

    pub fn learned_writer(&self) -> Option<&str> {
        self.learned_writer.as_deref()
    }
}

/// One reader's lanes. A second lane, or one lane shared by two
/// readers, is rejected.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReaderInboxes {
    by_accessor: BTreeMap<String, String>,
    by_lane: BTreeMap<String, String>,
}

impl ReaderInboxes {
    pub fn admit(&mut self, inbox: &RecipientInbox) -> Result<(), EncDiscError> {
        if inbox.accessor.is_empty() || hop_forbidden(&inbox.accessor) {
            return Err(EncDiscError::InboxRejected);
        }
        if !lane_id_is_opaque(&inbox.accessor, &inbox.lane_id) {
            return Err(EncDiscError::BadLane);
        }
        if let Some(existing) = self.by_accessor.get(&inbox.accessor) {
            if existing != &inbox.lane_id {
                return Err(EncDiscError::InboxRejected);
            }
            return Ok(());
        }
        if self.by_lane.contains_key(&inbox.lane_id) {
            return Err(EncDiscError::InboxRejected);
        }
        self.by_accessor
            .insert(inbox.accessor.clone(), inbox.lane_id.clone());
        self.by_lane
            .insert(inbox.lane_id.clone(), inbox.accessor.clone());
        Ok(())
    }

    pub fn lane_for(&self, accessor: &str) -> Option<&str> {
        self.by_accessor.get(accessor).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.by_accessor.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_accessor.is_empty()
    }
}

/// True when `lane_id` is not the accessor and not a `grantSoul`.
pub fn lane_id_is_opaque(accessor: &str, lane_id: &str) -> bool {
    if lane_id.is_empty() || lane_id == accessor || hop_forbidden(lane_id) {
        return false;
    }
    if lane_id == "s3rch/acl" || lane_id.starts_with("s3rch/acl/") {
        return false;
    }
    true
}

/// Append-only lane store. A different body does not replace an id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxLane {
    lane_id: String,
    entries: Vec<BlindedGrantRow>,
}

impl InboxLane {
    pub fn open(lane_id: &str) -> Result<Self, EncDiscError> {
        if lane_id.is_empty() || hop_forbidden(lane_id) {
            return Err(EncDiscError::BadLane);
        }
        Ok(Self {
            lane_id: lane_id.to_string(),
            entries: Vec::new(),
        })
    }

    pub fn lane_id(&self) -> &str {
        &self.lane_id
    }

    pub fn entries(&self) -> &[BlindedGrantRow] {
        &self.entries
    }

    pub fn get(&self, entry_id: &str) -> Option<&BlindedGrantRow> {
        self.entries.iter().find(|row| row.entry_id == entry_id)
    }

    /// Reject a body that does not hash to `entryId`. Do not replace.
    pub fn append(&mut self, row: BlindedGrantRow) -> Result<(), EncDiscError> {
        if row.lane_id != self.lane_id {
            return Err(EncDiscError::InboxRejected);
        }
        if !row_entry_matches(&row)? {
            return Err(EncDiscError::RowRejected);
        }
        if let Some(existing) = self.get(&row.entry_id) {
            if existing != &row {
                return Err(EncDiscError::RowRejected);
            }
            return Ok(());
        }
        self.entries.push(row);
        Ok(())
    }

    pub fn grants_see(&self) -> bool {
        false
    }
}

/// Whole-shard rescan input. `day` is `YYYY-MM-DD`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DailyShardScan {
    pub lane_id: String,
    pub day: String,
    pub seen: Vec<String>,
}

/// Fresh rows from one rescan. Deduped by `entryId`. Not a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardScan {
    pub fresh: Vec<BlindedGrantRow>,
    pub seen: Vec<String>,
}

impl ShardScan {
    pub fn grants_see(&self) -> bool {
        false
    }
}

/// A per-device cursor is not part of this contract.
pub fn shard_scan_uses_device_cursor() -> bool {
    false
}

/// Issue #22 defers a trusted shard-close watermark. This crate does
/// not skip a day.
pub fn shard_close_watermark_implemented() -> bool {
    false
}

/// Devices of one account share that account's lane.
pub fn lanes_per_device() -> bool {
    false
}

/// Rescan one UTC day of the one lane and dedup by `entryId`.
///
/// `rows` is the whole shard. A saved high-water mark is not an
/// argument, so a late append into an already scanned day is found on
/// the next call. A row for another lane fails closed.
pub fn scan_daily_shard(
    scan: &DailyShardScan,
    rows: &[BlindedGrantRow],
) -> Result<ShardScan, EncDiscError> {
    require_utc_day(&scan.day)?;
    if scan.lane_id.is_empty() || hop_forbidden(&scan.lane_id) {
        return Err(EncDiscError::InboxRejected);
    }
    let mut seen = scan.seen.clone();
    let mut known: BTreeSet<String> = seen.iter().cloned().collect();
    let mut fresh = Vec::new();
    for row in rows {
        if row.lane_id != scan.lane_id {
            return Err(EncDiscError::InboxRejected);
        }
        if !row_entry_matches(row)? {
            return Err(EncDiscError::RowRejected);
        }
        if !known.insert(row.entry_id.clone()) {
            continue;
        }
        fresh.push(row.clone());
        seen.push(row.entry_id.clone());
    }
    Ok(ShardScan { fresh, seen })
}

/// The relay that accepts an append learns `learned_writer`.
///
/// A peer that only holds the stored row does not. This function has
/// no writer to return from the row.
pub fn writer_from_stored_row(_row: &BlindedGrantRow) -> Option<String> {
    None
}

/// True when the visible row bytes contain the writer id or writer pub.
pub fn stored_row_reveals_writer(row: &BlindedGrantRow, writer: &str, writer_pub: &str) -> bool {
    let mut blob = String::new();
    blob.push_str(&row.lane_id);
    blob.push_str(&row.entry_id);
    blob.push_str(&row.grant_ciphertext);
    blob.push_str(&row.commitment.hash);
    if let Some(wrap) = &row.wrap {
        blob.push_str(wrap.scope.as_str());
        blob.push_str(wrap.target.as_str());
        blob.push_str(&wrap.target_id);
        blob.push_str(&wrap.revision_id);
        blob.push_str(&wrap.wrapped_key);
        if let Some(object) = &wrap.object {
            blob.push_str(object);
        }
        if let Some(group) = &wrap.group {
            blob.push_str(group);
        }
    }
    (!writer.is_empty() && blob.contains(writer))
        || (!writer_pub.is_empty() && blob.contains(writer_pub))
}

/// A replicated row is admitted only when this verifier recorded its id.
pub fn replicated_row_admitted(row: &BlindedGrantRow, state: &VerifierAdmissionState) -> bool {
    state.admitted.iter().any(|id| id == &row.entry_id)
}

enum SpendKey {
    Nonce(String),
    Stamp(String),
}

/// Decide one append. Fail closed. Do not grant.
///
/// Writer authentication runs before `knownSenders`, the allowlist, and
/// the quotas. A missing channel and a missing signature are
/// `writer-auth`. An `entryId` already in `admitted` is `replay` and
/// does not spend a fresh nonce. The counters move only on `ok`.
/// The accepting relay learns the writer id. The stored row does not.
pub fn filter_inbox_append(
    hook: &InboxWriteHook,
    row: &BlindedGrantRow,
    state: &VerifierAdmissionState,
    now: u64,
    enrollment: &[EnrolledSeaPub],
    writer_auth: Option<&WriterAppendAuth>,
    admission: Option<&InboxAdmission>,
) -> Result<InboxAppendResult, EncDiscError> {
    validate_state(state)?;
    require_row(row)?;
    let encoded = inbox_entry_bytes(&crate::grant::inbox_body_of(row))?;
    if encoded.len() > INBOX_ENTRY_MAX_BYTES {
        return Ok(refuse(state, InboxWriteFilter::Spam));
    }

    let writer = match authenticate(writer_auth, &row.entry_id, enrollment) {
        Ok(writer) => writer,
        Err(filter) => return Ok(refuse(state, filter)),
    };

    if state.admitted.iter().any(|id| id == &row.entry_id) {
        return Ok(refuse(state, InboxWriteFilter::Replay));
    }

    if hook.policy == InboxWritePolicy::NamedWriters
        && !hook.writers.iter().any(|name| name == &writer)
    {
        return Ok(refuse(state, InboxWriteFilter::UnnamedWriter));
    }

    let evidence = admission.and_then(|item| item.evidence.as_ref());
    let spend_key = match evidence {
        Some(evidence) => Some(match check_evidence(evidence, row, state, now) {
            Ok(key) => key,
            Err(filter) => return Ok(refuse(state, filter)),
        }),
        None => None,
    };

    let known = state.known_senders.iter().any(|sender| sender == &writer);
    if !known && spend_key.is_none() {
        return Ok(refuse(state, InboxWriteFilter::StampRequired));
    }

    if !known && state.first_contact_remaining == 0 {
        return Ok(refuse(state, InboxWriteFilter::SenderQuota));
    }
    let own_remaining = if known {
        sender_remaining(state, &writer).unwrap_or(0)
    } else {
        state.first_contact_remaining
    };
    if own_remaining == 0 {
        return Ok(refuse(state, InboxWriteFilter::SenderQuota));
    }
    if state.lane_remaining == 0 {
        return Ok(refuse(state, InboxWriteFilter::ReaderCapacity));
    }

    let mut next = state.clone();
    if known {
        let Some(quota) = next
            .sender_quotas
            .iter_mut()
            .find(|quota| quota.sender == writer)
        else {
            return Err(EncDiscError::InboxRejected);
        };
        quota.remaining -= 1;
    } else {
        next.sender_quotas.push(SenderQuota {
            sender: writer.clone(),
            remaining: state.first_contact_remaining - 1,
        });
        next.known_senders.push(writer.clone());
    }
    next.lane_remaining -= 1;
    if let Some(key) = spend_key {
        spend(&mut next, &key);
    }
    next.admitted.push(row.entry_id.clone());
    Ok(InboxAppendResult {
        decision: InboxWriteDecision::from_filter(InboxWriteFilter::Ok),
        state: next,
        learned_writer: Some(writer),
    })
}

fn refuse(state: &VerifierAdmissionState, filter: InboxWriteFilter) -> InboxAppendResult {
    InboxAppendResult {
        decision: InboxWriteDecision::from_filter(filter),
        state: state.clone(),
        learned_writer: None,
    }
}

fn validate_state(state: &VerifierAdmissionState) -> Result<(), EncDiscError> {
    let mut quotas = BTreeSet::new();
    for quota in &state.sender_quotas {
        if quota.sender.is_empty() || !quotas.insert(quota.sender.clone()) {
            return Err(EncDiscError::InboxRejected);
        }
        if !state
            .known_senders
            .iter()
            .any(|sender| sender == &quota.sender)
        {
            return Err(EncDiscError::InboxRejected);
        }
    }
    let mut nonces = BTreeSet::new();
    for challenge in &state.challenges {
        if challenge.nonce.is_empty() || !nonces.insert(challenge.nonce.clone()) {
            return Err(EncDiscError::InboxRejected);
        }
    }
    Ok(())
}

fn require_row(row: &BlindedGrantRow) -> Result<(), EncDiscError> {
    if row.lane_id.is_empty() || hop_forbidden(&row.lane_id) {
        return Err(EncDiscError::InboxRejected);
    }
    if row.grant_ciphertext.is_empty() {
        return Err(EncDiscError::RowRejected);
    }
    if canonical::require_digest_hex(&row.entry_id).is_err()
        || canonical::require_digest_hex(&row.commitment.hash).is_err()
    {
        return Err(EncDiscError::RowRejected);
    }
    if !row_entry_matches(row)? {
        return Err(EncDiscError::RowRejected);
    }
    Ok(())
}

fn authenticate(
    auth: Option<&WriterAppendAuth>,
    entry_id: &str,
    enrollment: &[EnrolledSeaPub],
) -> Result<String, InboxWriteFilter> {
    let Some(auth) = auth else {
        return Err(InboxWriteFilter::WriterAuth);
    };
    match auth {
        WriterAppendAuth::Channel(channel) => {
            if !channel.has_transport_brand() {
                return Err(InboxWriteFilter::WriterAuth);
            }
            let writer = channel.writer();
            if writer.is_empty() || hop_forbidden(writer) {
                return Err(InboxWriteFilter::WriterAuth);
            }
            let Some(enrolled) = enrolled_pub(enrollment, writer) else {
                return Err(InboxWriteFilter::WriterAuth);
            };
            if channel.writer_pub() != enrolled {
                return Err(InboxWriteFilter::WriterAuth);
            }
            Ok(writer.to_string())
        }
        WriterAppendAuth::Signature(proof) => {
            if proof.writer.is_empty() || hop_forbidden(&proof.writer) {
                return Err(InboxWriteFilter::WriterAuth);
            }
            let Some(enrolled) = enrolled_pub(enrollment, &proof.writer) else {
                return Err(InboxWriteFilter::WriterAuth);
            };
            if proof.writer_pub != enrolled {
                return Err(InboxWriteFilter::WriterAuth);
            }
            let Ok(message) = canonical::writer_append_bytes(entry_id) else {
                return Err(InboxWriteFilter::WriterAuth);
            };
            if crate::sea::verify_sea(enrolled, &message, &proof.signature).is_err() {
                return Err(InboxWriteFilter::WriterAuth);
            }
            Ok(proof.writer.clone())
        }
    }
}

fn enrolled_pub<'a>(enrollment: &'a [EnrolledSeaPub], account: &str) -> Option<&'a str> {
    let record = enrollment.iter().find(|item| item.account == account)?;
    if record.sea_pub.is_empty() {
        return None;
    }
    Some(record.sea_pub.as_str())
}

fn check_evidence(
    evidence: &AdmissionEvidence,
    row: &BlindedGrantRow,
    state: &VerifierAdmissionState,
    now: u64,
) -> Result<SpendKey, InboxWriteFilter> {
    match evidence {
        AdmissionEvidence::ProofOfWork { nonce, solution } => {
            if nonce.is_empty() {
                return Err(InboxWriteFilter::StampMismatch);
            }
            if state.spent.iter().any(|spent| spent == nonce) {
                return Err(InboxWriteFilter::Replay);
            }
            let Some(challenge) = state.challenges.iter().find(|item| item.nonce == *nonce) else {
                return Err(InboxWriteFilter::StampMismatch);
            };
            if now >= challenge.expires_at {
                return Err(InboxWriteFilter::StampMismatch);
            }
            let digest = canonical::inbox_pow_digest(nonce, &row.entry_id, solution)
                .map_err(|_| InboxWriteFilter::StampMismatch)?;
            if canonical::leading_zero_bits(&digest) < challenge.difficulty {
                return Err(InboxWriteFilter::StampMismatch);
            }
            Ok(SpendKey::Nonce(nonce.clone()))
        }
        AdmissionEvidence::Stamp { issuer, signature } => {
            if signature.is_empty() || issuer.is_empty() {
                return Err(InboxWriteFilter::StampMismatch);
            }
            if state.spent.iter().any(|spent| spent == signature) {
                return Err(InboxWriteFilter::Replay);
            }
            if !state.stamp_issuers.iter().any(|item| item == issuer) {
                return Err(InboxWriteFilter::StampMismatch);
            }
            let message = canonical::inbox_stamp_bytes(&row.entry_id)
                .map_err(|_| InboxWriteFilter::StampMismatch)?;
            if crate::sea::verify_sea(issuer, &message, signature).is_err() {
                return Err(InboxWriteFilter::StampMismatch);
            }
            Ok(SpendKey::Stamp(signature.clone()))
        }
    }
}

fn sender_remaining(state: &VerifierAdmissionState, sender: &str) -> Option<u64> {
    state
        .sender_quotas
        .iter()
        .find(|quota| quota.sender == sender)
        .map(|quota| quota.remaining)
}

fn spend(state: &mut VerifierAdmissionState, key: &SpendKey) {
    let token = match key {
        SpendKey::Nonce(nonce) => {
            state
                .challenges
                .retain(|challenge| &challenge.nonce != nonce);
            nonce.clone()
        }
        SpendKey::Stamp(signature) => signature.clone(),
    };
    if !state.spent.iter().any(|spent| spent == &token) {
        state.spent.push(token);
    }
}

fn require_utc_day(day: &str) -> Result<(), EncDiscError> {
    let bytes = day.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(EncDiscError::InboxRejected);
    }
    if !bytes
        .iter()
        .enumerate()
        .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        return Err(EncDiscError::InboxRejected);
    }
    let year: u32 = day[0..4].parse().map_err(|_| EncDiscError::InboxRejected)?;
    let month: u32 = day[5..7].parse().map_err(|_| EncDiscError::InboxRejected)?;
    let dom: u32 = day[8..10]
        .parse()
        .map_err(|_| EncDiscError::InboxRejected)?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(EncDiscError::InboxRejected),
    };
    if dom == 0 || dom > max {
        return Err(EncDiscError::InboxRejected);
    }
    Ok(())
}
