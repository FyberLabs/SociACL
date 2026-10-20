//! In-place migration from plaintext `MeshSeeGrant` rows.
//!
//! Applying a protocol version encrypts the existing body under a new
//! DEK. The object id stays. Each current reader gets one wrap and one
//! blinded row on that reader's one lane. Plaintext for a reader drops
//! only after that reader's authenticated wrap receipt. One receipt
//! does not clear anyone else. The shared soul stays plaintext until
//! every current reader has acknowledged.
//!
//! A reader does not re-encrypt the shared item and does not issue
//! wraps. A wrap is not a grant. Privilege-down is not delayed: a
//! reader who is already `stated: 0` is not wrapped and does not have
//! to acknowledge. The migration does not widen a window or add an
//! accessor. Items the owner keeps on the public plaintext path are
//! not rewritten. Whether that path stays is open. A plaintext replica
//! already stored elsewhere is a historical leak.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::account::{AccountSeaSecret, EnrolledSeaPub};
use crate::canonical::{self, ItemAuthFields};
use crate::epoch::{
    epoch_read_key, write_disposition, AclSnapshotBody, EpochReplicaView, WriteDisposition,
};
use crate::error::EncDiscError;
use crate::grant::{
    self, commit_grant, seal_blinded_row, AuthorFastUnwrap, BlindedGrantRow, GrantStated,
    MeshSeeGrant, SignedGrantPayload,
};
use crate::hexutil::{self, decode_hex, encode_hex};
use crate::inbox::lane_id_is_opaque;
use crate::rotation::GrantStorage;
use crate::sea;
use crate::wrap::{self, ItemDek, WrapScope, WrapTarget, WrappedKey};

const FORMAT_ITEM: u8 = 1;
const DOMAIN_MIGRATED_ITEM: &str = "s3rch-migrated-item-v1";
const DOMAIN_GRANT_CIPHERTEXT: &str = "s3rch-grant-ciphertext-v1";

/// One current reader on the owner's migration record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderMigration {
    pub accessor: String,
    pub acknowledged: bool,
    /// `reader_version >= version_gate`. The gate alone does not drop plaintext.
    pub at_gate: bool,
}

/// Owner's migration record. There is no single flag for every reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolMigration {
    pub object: String,
    pub from_version: u64,
    pub to_version: u64,
    pub rewrapped: Vec<WrappedKey>,
    pub readers: Vec<ReaderMigration>,
    pub version_gate: u64,
}

/// Merged plaintext edge. The caller does not add an accessor to widen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationGrant {
    pub soul: String,
    pub owner: String,
    pub grant: MeshSeeGrant,
    pub ham_state: u64,
}

/// Reader version the verifier holds. `at_gate` on the record must match it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderVersion {
    pub accessor: String,
    pub version: u64,
    pub epub: String,
}

/// Authenticated wrap receipt. A boolean on the record is not this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapReceipt {
    pub accessor: String,
    pub signature: String,
}

/// Structural admission input. SEA verification stays in [`accept_migration`].
pub struct MigrationAdmissionInput<'a> {
    pub migration: &'a ProtocolMigration,
    pub owner: &'a str,
    pub caller: &'a str,
    pub now: u64,
    pub storage: GrantStorage,
    pub grants: &'a [MigrationGrant],
    pub payloads: &'a [SignedGrantPayload],
    pub receipts: &'a [WrapReceipt],
    pub reader_versions: &'a [ReaderVersion],
    pub soul_ham_state: u64,
}

/// What admission decided. An opened wrap still does not grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationOutcome {
    pub object: String,
    pub plaintext_retained: Vec<String>,
    pub plaintext_dropped: Vec<String>,
    pub soul_replaced: bool,
    pub soul_ham_state: u64,
    pub cancelled: Vec<MigrationGrant>,
    pub skipped_public: bool,
    /// Private-row admission publishes ciphertext before any receipt.
    pub ciphertext_published: bool,
}

impl MigrationOutcome {
    pub fn grants_see(&self) -> bool {
        false
    }

    pub fn delays_privilege_down(&self) -> bool {
        false
    }

    pub fn version_gate_drops_plaintext(&self) -> bool {
        false
    }

    pub fn widened(&self) -> bool {
        false
    }

    /// In-place replacement does not claw back a replica already stored.
    pub fn claws_back_historical_replica(&self) -> bool {
        false
    }

    pub fn historical_replica_remains(&self) -> bool {
        true
    }
}

/// Enrolled reader the owner may wrap. One lane, the account lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationReader {
    pub enrolled: EnrolledSeaPub,
    pub lane_id: String,
    pub version: u64,
}

/// Replica view the migration must name.
///
/// `epoch` and `revision_id` have to be this view's current read key,
/// and that key has to be open for a new write. A pending successor
/// or a displaced revision is rejected. The owner prepares again when
/// the current key is open.
pub struct MigrationEpoch<'a> {
    pub view: &'a EpochReplicaView,
    pub winning: &'a AclSnapshotBody,
    pub settled: &'a AclSnapshotBody,
    pub current: &'a AclSnapshotBody,
}

/// Owner-local result of encrypting in place. Not a Gun row.
#[derive(Clone)]
pub struct EncryptedMigration {
    pub migration: ProtocolMigration,
    pub readers: Vec<MigrationReader>,
    pub item_blob: Vec<u8>,
    pub author: AuthorFastUnwrap,
    pub rows: Vec<BlindedGrantRow>,
    pub plaintext: Vec<u8>,
    pub soul_ham_state: u64,
    pub epoch: u64,
}

/// Owner-only preparation. A public-plain item is not rewritten.
pub enum PreparedMigration {
    SkippedPublic { object: String },
    Encrypted(EncryptedMigration),
}

/// Admit a migration record. The version gate does not drop plaintext.
///
/// A reader whose grant is already cancelled is not a current reader.
/// That cancel does not wait for a receipt. A wider window, an extra
/// accessor, or a caller who is not the owner fails closed.
pub fn apply_protocol_migration(
    input: &MigrationAdmissionInput<'_>,
) -> Result<MigrationOutcome, EncDiscError> {
    if input.caller.is_empty()
        || input.owner.is_empty()
        || input.caller != input.owner
        || input.migration.object.is_empty()
        || input.migration.object != input_object(input)?
    {
        return Err(EncDiscError::MigrationRejected);
    }
    safe_int(input.now)?;
    safe_int(input.migration.from_version)?;
    safe_int(input.migration.to_version)?;
    safe_int(input.migration.version_gate)?;
    safe_int(input.soul_ham_state)?;
    if input.migration.from_version >= input.migration.to_version {
        return Err(EncDiscError::MigrationRejected);
    }
    let current = current_grants(
        input.grants,
        &input.migration.object,
        input.owner,
        input.now,
    )?;
    if input.storage == GrantStorage::PublicPlain {
        return skip_public(input, &current);
    }
    if input.storage != GrantStorage::PrivateRow {
        return Err(EncDiscError::MigrationRejected);
    }
    let versions = align_readers(input, &current)?;
    align_receipts(input, &current)?;
    let epoch = align_payloads(input, &current)?;
    align_wraps(input, &versions, epoch)?;
    finish(input, &current)
}

/// Encrypt the existing body and issue wraps. Plaintext stays on the soul.
///
/// Only the owner calls this. Readers in `readers` must be exactly the
/// current live grants. The returned record has every `acknowledged`
/// flag clear.
pub fn prepare_protocol_migration(
    owner_secret: &AccountSeaSecret,
    object: &str,
    plaintext: &[u8],
    from_version: u64,
    to_version: u64,
    version_gate: u64,
    epoch: u64,
    revision_id: &str,
    now: u64,
    soul_ham_state: u64,
    storage: GrantStorage,
    grants: &[MigrationGrant],
    readers: &[MigrationReader],
    prior_revision: &[(String, u64)],
    epoch_view: &MigrationEpoch<'_>,
) -> Result<PreparedMigration, EncDiscError> {
    if object.is_empty() || owner_secret.account().is_empty() {
        return Err(EncDiscError::MigrationRejected);
    }
    if grants
        .iter()
        .any(|grant| grant.owner != owner_secret.account())
    {
        return Err(EncDiscError::MigrationRejected);
    }
    safe_int(from_version)?;
    safe_int(to_version)?;
    safe_int(version_gate)?;
    safe_int(epoch)?;
    safe_int(now)?;
    safe_int(soul_ham_state)?;
    if from_version >= to_version {
        return Err(EncDiscError::MigrationRejected);
    }
    canonical::require_revision_id(revision_id).map_err(|_| EncDiscError::MigrationRejected)?;
    let current = current_grants(grants, object, owner_secret.account(), now)?;
    if storage == GrantStorage::PublicPlain {
        if !readers.is_empty() {
            return Err(EncDiscError::MigrationRejected);
        }
        return Ok(PreparedMigration::SkippedPublic {
            object: object.to_string(),
        });
    }
    if storage != GrantStorage::PrivateRow {
        return Err(EncDiscError::MigrationRejected);
    }
    require_open_revision(epoch_view, object, epoch, revision_id, now)?;
    let readers = align_enrolled(&current, readers)?;
    for (name, revision) in prior_revision {
        safe_int(*revision)?;
        if !current.iter().any(|grant| grant.grant.accessor == *name) {
            return Err(EncDiscError::MigrationRejected);
        }
    }
    let dek = ItemDek::generate();
    let signature = sign_item(
        owner_secret,
        object,
        epoch,
        to_version,
        plaintext,
        revision_id,
    )?;
    let item_blob = seal_item(&dek, to_version, epoch, revision_id, &signature, plaintext)?;
    let digest = canonical::sha256_hex(&item_blob);
    let author = AuthorFastUnwrap::store(object, epoch, revision_id, &encode_hex(dek.as_bytes()))
        .map_err(|_| EncDiscError::MigrationRejected)?;
    let named = wrap::NamedSet::try_from_accessors(
        readers
            .iter()
            .map(|reader| reader.enrolled.account.as_str()),
    )
    .map_err(|_| EncDiscError::MigrationRejected)?;
    let enrolled: Vec<EnrolledSeaPub> = readers
        .iter()
        .map(|reader| reader.enrolled.clone())
        .collect();
    let wraps = if enrolled.is_empty() {
        Vec::new()
    } else {
        wrap::wrap_item_dek_to_readers(&dek, epoch, object, revision_id, &enrolled, &named)
            .map_err(|_| EncDiscError::MigrationRejected)?
    };
    let mut rows = Vec::with_capacity(readers.len());
    let mut record_readers = Vec::with_capacity(readers.len());
    for reader in &readers {
        let grant = current
            .iter()
            .find(|edge| edge.grant.accessor == reader.enrolled.account)
            .ok_or(EncDiscError::MigrationRejected)?;
        let prior = prior_for(&reader.enrolled.account, prior_revision, &current)?;
        let revision = prior.saturating_add(1);
        safe_int(revision)?;
        if revision == 0 {
            return Err(EncDiscError::MigrationRejected);
        }
        let payload = SignedGrantPayload {
            object: object.to_string(),
            accessor: reader.enrolled.account.clone(),
            from: grant.grant.from,
            until: grant.grant.until,
            stated: GrantStated::Live,
            epoch,
            owner: owner_secret.account().to_string(),
            grant_revision: revision,
            item_ciphertext_digest: digest.clone(),
        };
        let grant_signature = owner_secret
            .sign_grant(&payload)
            .map_err(|_| EncDiscError::MigrationRejected)?;
        let blinding = grant::fresh_blinding();
        let commitment =
            commit_grant(&blinding, &payload).map_err(|_| EncDiscError::MigrationRejected)?;
        let grant_bytes =
            grant::encode_grant_bytes(&payload).map_err(|_| EncDiscError::MigrationRejected)?;
        let grant_blob = seal_grant_ciphertext(&dek, &blinding, &grant_signature, &grant_bytes)?;
        let wrap = wraps
            .iter()
            .find(|wrap| wrap.target_id == reader.enrolled.epub)
            .cloned()
            .ok_or(EncDiscError::MigrationRejected)?;
        let row = seal_blinded_row(
            &reader.lane_id,
            &encode_hex(&grant_blob),
            commitment,
            Some(wrap),
        )
        .map_err(|_| EncDiscError::MigrationRejected)?;
        if grant::row_exposes_opening(&row, owner_secret.sea_pub(), &blinding) {
            return Err(EncDiscError::MigrationRejected);
        }
        rows.push(row);
        record_readers.push(ReaderMigration {
            accessor: reader.enrolled.account.clone(),
            acknowledged: false,
            at_gate: reader.version >= version_gate,
        });
    }
    let migration = ProtocolMigration {
        object: object.to_string(),
        from_version,
        to_version,
        rewrapped: wraps,
        readers: record_readers,
        version_gate,
    };
    Ok(PreparedMigration::Encrypted(EncryptedMigration {
        migration,
        readers,
        item_blob,
        author,
        rows,
        plaintext: plaintext.to_vec(),
        soul_ham_state,
        epoch,
    }))
}

/// Verify receipts, then admit. A bad signature does not drop plaintext.
///
/// `grants` is the verifier's merged plaintext ACL, not a list the
/// presenter extends. The caller must be the owner who prepared it.
/// `soul_ham_state` and `soul_body` are the soul as it stands now.
/// Either one differing from the prepared snapshot aborts. The owner
/// prepares again from the current item. Receipts are not applied to
/// a stale soul.
pub fn accept_migration(
    owner_secret: &AccountSeaSecret,
    prepared: &EncryptedMigration,
    proposed: &ProtocolMigration,
    receipts: &[WrapReceipt],
    grants: &[MigrationGrant],
    now: u64,
    soul_ham_state: u64,
    soul_body: &[u8],
    epoch_view: &MigrationEpoch<'_>,
) -> Result<MigrationOutcome, EncDiscError> {
    if owner_secret.account().is_empty() {
        return Err(EncDiscError::MigrationRejected);
    }
    if proposed.object != prepared.migration.object
        || proposed.from_version != prepared.migration.from_version
        || proposed.to_version != prepared.migration.to_version
        || proposed.version_gate != prepared.migration.version_gate
        || !same_wraps(&proposed.rewrapped, &prepared.migration.rewrapped)
        || proposed.readers.len() != prepared.migration.readers.len()
    {
        return Err(EncDiscError::MigrationRejected);
    }
    for prepared_reader in &prepared.migration.readers {
        let Some(proposed_reader) = proposed
            .readers
            .iter()
            .find(|reader| reader.accessor == prepared_reader.accessor)
        else {
            return Err(EncDiscError::MigrationRejected);
        };
        if proposed_reader.at_gate != prepared_reader.at_gate {
            return Err(EncDiscError::MigrationRejected);
        }
    }
    verify_item(owner_secret, prepared)?;
    safe_int(soul_ham_state)?;
    if soul_ham_state != prepared.soul_ham_state || soul_body != prepared.plaintext.as_slice() {
        return Err(EncDiscError::MigrationRejected);
    }
    require_open_revision(
        epoch_view,
        &prepared.migration.object,
        prepared.epoch,
        &prepared_revision(prepared)?,
        now,
    )?;
    let versions = reader_versions(&prepared.readers)?;
    let payloads = open_rows(owner_secret, prepared)?;
    verify_receipts(prepared, proposed, receipts)?;
    apply_protocol_migration(&MigrationAdmissionInput {
        migration: proposed,
        owner: owner_secret.account(),
        caller: owner_secret.account(),
        now,
        storage: GrantStorage::PrivateRow,
        grants,
        payloads: &payloads,
        receipts,
        reader_versions: &versions,
        soul_ham_state,
    })
}

/// Sign the length-prefixed receipt. Not a grant.
pub fn sign_wrap_receipt(
    reader: &AccountSeaSecret,
    object: &str,
    to_version: u64,
    revision_id: &str,
    entry_id: &str,
) -> Result<String, EncDiscError> {
    let message =
        canonical::wrap_receipt_bytes(object, reader.account(), to_version, revision_id, entry_id)
            .map_err(|_| EncDiscError::MigrationRejected)?;
    sea::sign_sea(reader.local_priv(), &message).map_err(|_| EncDiscError::MigrationRejected)
}

/// Open a migrated item body. Holding the DEK does not grant.
///
/// The owner signature over the item-auth tuple is checked before the
/// body is returned. A reader who knows the DEK cannot substitute a
/// body. `object` is the item this caller fetched.
pub fn open_migrated_item(
    blob: &[u8],
    dek: &ItemDek,
    owner_pub: &str,
    object: &str,
) -> Result<Vec<u8>, EncDiscError> {
    if object.is_empty() || owner_pub.is_empty() || sea::parse_sea_point(owner_pub).is_err() {
        return Err(EncDiscError::MigrationRejected);
    }
    let opened = open_item_fields(blob, dek)?;
    let digest = canonical::plaintext_digest(&opened.plaintext);
    if digest != opened.plaintext_digest {
        return Err(EncDiscError::MigrationRejected);
    }
    let fields = ItemAuthFields {
        object: object.to_string(),
        epoch: opened.epoch,
        version: opened.version,
        plaintext_digest: digest,
        revision_id: opened.revision_id,
    };
    crate::account::verify_item_auth(owner_pub, &fields, &opened.item_auth)
        .map_err(|_| EncDiscError::MigrationRejected)?;
    Ok(opened.plaintext)
}

fn require_open_revision(
    epoch_view: &MigrationEpoch<'_>,
    object: &str,
    epoch: u64,
    revision_id: &str,
    now: u64,
) -> Result<(), EncDiscError> {
    if epoch_view.view.object != object {
        return Err(EncDiscError::MigrationRejected);
    }
    let Some(read_key) =
        epoch_read_key(epoch_view.view, epoch_view.winning, epoch_view.current, now)
    else {
        return Err(EncDiscError::MigrationRejected);
    };
    let open = match write_disposition(
        epoch_view.view,
        epoch_view.winning,
        epoch_view.settled,
        epoch_view.current,
        now,
    ) {
        WriteDisposition::Settled { revision_id, epoch }
        | WriteDisposition::Winner { revision_id, epoch } => (epoch, revision_id),
        WriteDisposition::Buffer => return Err(EncDiscError::MigrationRejected),
    };
    if read_key.epoch != open.0
        || read_key.revision_id != open.1
        || read_key.epoch != epoch
        || read_key.revision_id != revision_id
    {
        return Err(EncDiscError::MigrationRejected);
    }
    Ok(())
}

fn skip_public(
    input: &MigrationAdmissionInput<'_>,
    current: &[MigrationGrant],
) -> Result<MigrationOutcome, EncDiscError> {
    if !input.migration.readers.is_empty()
        || !input.migration.rewrapped.is_empty()
        || !input.payloads.is_empty()
        || !input.receipts.is_empty()
        || !input.reader_versions.is_empty()
    {
        return Err(EncDiscError::MigrationRejected);
    }
    Ok(MigrationOutcome {
        object: input.migration.object.clone(),
        plaintext_retained: names(current),
        plaintext_dropped: Vec::new(),
        soul_replaced: false,
        soul_ham_state: input.soul_ham_state,
        cancelled: Vec::new(),
        skipped_public: true,
        ciphertext_published: false,
    })
}

fn finish(
    input: &MigrationAdmissionInput<'_>,
    current: &[MigrationGrant],
) -> Result<MigrationOutcome, EncDiscError> {
    let mut dropped = Vec::new();
    let mut retained = Vec::new();
    for reader in &input.migration.readers {
        if reader.acknowledged {
            dropped.push(reader.accessor.clone());
        } else {
            retained.push(reader.accessor.clone());
        }
    }
    dropped.sort();
    retained.sort();
    if retained.is_empty() {
        let soul_ham_state = bump(input.soul_ham_state)?;
        let mut cancelled = Vec::with_capacity(current.len());
        for grant in current {
            cancelled.push(MigrationGrant {
                soul: grant.soul.clone(),
                owner: grant.owner.clone(),
                grant: MeshSeeGrant {
                    stated: GrantStated::Cancelled,
                    ..grant.grant.clone()
                },
                ham_state: bump(grant.ham_state)?,
            });
        }
        return Ok(MigrationOutcome {
            object: input.migration.object.clone(),
            plaintext_retained: retained,
            plaintext_dropped: dropped,
            soul_replaced: true,
            soul_ham_state,
            cancelled,
            skipped_public: false,
            ciphertext_published: true,
        });
    }
    Ok(MigrationOutcome {
        object: input.migration.object.clone(),
        plaintext_retained: retained,
        plaintext_dropped: dropped,
        soul_replaced: false,
        soul_ham_state: input.soul_ham_state,
        cancelled: Vec::new(),
        skipped_public: false,
        ciphertext_published: true,
    })
}

fn align_readers(
    input: &MigrationAdmissionInput<'_>,
    current: &[MigrationGrant],
) -> Result<Vec<ReaderVersion>, EncDiscError> {
    if input.migration.readers.len() != current.len()
        || input.reader_versions.len() != current.len()
    {
        return Err(EncDiscError::MigrationRejected);
    }
    let mut readers = input.migration.readers.clone();
    readers.sort_by(|left, right| left.accessor.cmp(&right.accessor));
    if readers
        .windows(2)
        .any(|pair| pair[0].accessor == pair[1].accessor)
    {
        return Err(EncDiscError::MigrationRejected);
    }
    let mut versions = input.reader_versions.to_vec();
    versions.sort_by(|left, right| left.accessor.cmp(&right.accessor));
    let mut epubs = Vec::new();
    for ((reader, version), grant) in readers.iter().zip(versions.iter()).zip(current.iter()) {
        if reader.accessor != grant.grant.accessor || version.accessor != grant.grant.accessor {
            return Err(EncDiscError::MigrationRejected);
        }
        safe_int(version.version)?;
        if version.epub.is_empty() || epubs.iter().any(|epub: &String| epub == &version.epub) {
            return Err(EncDiscError::MigrationRejected);
        }
        epubs.push(version.epub.clone());
        let at_gate = version.version >= input.migration.version_gate;
        if reader.at_gate != at_gate {
            return Err(EncDiscError::MigrationRejected);
        }
    }
    Ok(versions)
}

fn align_receipts(
    input: &MigrationAdmissionInput<'_>,
    current: &[MigrationGrant],
) -> Result<(), EncDiscError> {
    let mut seen = Vec::new();
    for receipt in input.receipts {
        if receipt.accessor.is_empty()
            || seen
                .iter()
                .any(|accessor: &String| accessor == &receipt.accessor)
            || !current
                .iter()
                .any(|grant| grant.grant.accessor == receipt.accessor)
        {
            return Err(EncDiscError::MigrationRejected);
        }
        if !is_signature(&receipt.signature) {
            return Err(EncDiscError::MigrationRejected);
        }
        seen.push(receipt.accessor.clone());
    }
    for reader in &input.migration.readers {
        let matched = input
            .receipts
            .iter()
            .filter(|receipt| receipt.accessor == reader.accessor)
            .count();
        let expected = if reader.acknowledged { 1 } else { 0 };
        if matched != expected {
            return Err(EncDiscError::MigrationRejected);
        }
    }
    Ok(())
}

fn align_payloads(
    input: &MigrationAdmissionInput<'_>,
    current: &[MigrationGrant],
) -> Result<Option<u64>, EncDiscError> {
    if input.payloads.len() != current.len() {
        return Err(EncDiscError::MigrationRejected);
    }
    if current.is_empty() {
        return Ok(None);
    }
    let mut epoch = None;
    let mut digest = None;
    for grant in current {
        let payload = input
            .payloads
            .iter()
            .find(|payload| payload.accessor == grant.grant.accessor)
            .ok_or(EncDiscError::MigrationRejected)?;
        safe_int(payload.from)?;
        safe_int(payload.until)?;
        safe_int(payload.epoch)?;
        safe_int(payload.grant_revision)?;
        if payload.object != grant.grant.object
            || payload.owner != input.owner
            || payload.accessor != grant.grant.accessor
            || payload.from != grant.grant.from
            || payload.until != grant.grant.until
            || payload.stated != GrantStated::Live
            || grant.grant.stated != GrantStated::Live
            || payload.grant_revision == 0
            || !is_digest(&payload.item_ciphertext_digest)
        {
            return Err(EncDiscError::MigrationRejected);
        }
        match epoch {
            None => epoch = Some(payload.epoch),
            Some(held) if held != payload.epoch => return Err(EncDiscError::MigrationRejected),
            Some(_) => {}
        }
        match digest {
            None => digest = Some(payload.item_ciphertext_digest.as_str()),
            Some(held) if held != payload.item_ciphertext_digest => {
                return Err(EncDiscError::MigrationRejected);
            }
            Some(_) => {}
        }
    }
    Ok(epoch)
}

fn align_wraps(
    input: &MigrationAdmissionInput<'_>,
    versions: &[ReaderVersion],
    epoch: Option<u64>,
) -> Result<(), EncDiscError> {
    if input.migration.rewrapped.len() != versions.len() {
        return Err(EncDiscError::MigrationRejected);
    }
    let mut revision = None;
    let mut seen = Vec::new();
    for version in versions {
        let wrap = input
            .migration
            .rewrapped
            .iter()
            .find(|wrap| wrap.target_id == version.epub)
            .ok_or(EncDiscError::MigrationRejected)?;
        if seen.iter().any(|epub: &String| epub == &wrap.target_id) {
            return Err(EncDiscError::MigrationRejected);
        }
        seen.push(wrap.target_id.clone());
        safe_int(wrap.epoch)?;
        if wrap.scope != WrapScope::ItemDek
            || wrap.target != WrapTarget::ReaderEpub
            || wrap.object.as_deref() != Some(input.migration.object.as_str())
            || wrap.group.as_deref().is_some_and(|group| !group.is_empty())
            || wrap.wrapped_key.is_empty()
            || !is_lower_hex(&wrap.wrapped_key)
            || canonical::require_revision_id(&wrap.revision_id).is_err()
        {
            return Err(EncDiscError::MigrationRejected);
        }
        if let Some(epoch) = epoch {
            if wrap.epoch != epoch {
                return Err(EncDiscError::MigrationRejected);
            }
        }
        match revision {
            None => revision = Some(wrap.revision_id.as_str()),
            Some(held) if held != wrap.revision_id => {
                return Err(EncDiscError::MigrationRejected);
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn grant_soul(owner: &str, object: &str, accessor: &str) -> Option<String> {
    let owner = sociacl_ids::parse_principal_id(owner).ok()?;
    let object = sociacl_ids::parse_object_id(object).ok()?;
    let accessor = sociacl_ids::parse_principal_id(accessor).ok()?;
    Some(sociacl_ids::grant_soul(&owner, &object, &accessor).to_string())
}

fn current_grants(
    grants: &[MigrationGrant],
    object: &str,
    owner: &str,
    now: u64,
) -> Result<Vec<MigrationGrant>, EncDiscError> {
    let mut current = Vec::new();
    let mut seen = Vec::new();
    for grant in grants {
        let Some(expected) = grant_soul(owner, object, &grant.grant.accessor) else {
            return Err(EncDiscError::MigrationRejected);
        };
        if grant.owner != owner || grant.grant.object != object || grant.soul != expected {
            return Err(EncDiscError::MigrationRejected);
        }
        safe_int(grant.ham_state)?;
        safe_int(grant.grant.from)?;
        safe_int(grant.grant.until)?;
        if seen
            .iter()
            .any(|accessor: &String| accessor == &grant.grant.accessor)
        {
            return Err(EncDiscError::MigrationRejected);
        }
        seen.push(grant.grant.accessor.clone());
        match grant.grant.stated {
            GrantStated::Cancelled => {
                if grant.ham_state == 0 {
                    return Err(EncDiscError::MigrationRejected);
                }
            }
            GrantStated::Live => {
                if grant.grant.from >= grant.grant.until {
                    return Err(EncDiscError::MigrationRejected);
                }
                // A window that has not ended is current, including one
                // whose `from` is still ahead of `now`. Dropping that
                // reader would leave a live plaintext grant and no wrap.
                if now < grant.grant.until {
                    current.push(grant.clone());
                }
            }
        }
    }
    current.sort_by(|left, right| left.grant.accessor.cmp(&right.grant.accessor));
    Ok(current)
}

fn align_enrolled(
    current: &[MigrationGrant],
    readers: &[MigrationReader],
) -> Result<Vec<MigrationReader>, EncDiscError> {
    if readers.len() != current.len() {
        return Err(EncDiscError::MigrationRejected);
    }
    let mut sorted = readers.to_vec();
    sorted.sort_by(|left, right| left.enrolled.account.cmp(&right.enrolled.account));
    let mut lanes = Vec::new();
    let mut epubs = Vec::new();
    for (reader, grant) in sorted.iter().zip(current.iter()) {
        let enrolled = &reader.enrolled;
        safe_int(reader.version)?;
        if enrolled.account != grant.grant.accessor
            || enrolled.account.is_empty()
            || enrolled.epub.is_empty()
            || enrolled.sea_pub.is_empty()
            || enrolled.identity_pub != enrolled.sea_pub
            || sea::parse_sea_point(&enrolled.epub).is_err()
            || sea::parse_sea_point(&enrolled.sea_pub).is_err()
        {
            return Err(EncDiscError::MigrationRejected);
        }
        let lane_bytes =
            decode_hex(&reader.lane_id).map_err(|_| EncDiscError::MigrationRejected)?;
        if lane_bytes.len() != 32
            || !lane_id_is_opaque(&enrolled.account, &reader.lane_id)
            || lanes.iter().any(|lane: &String| lane == &reader.lane_id)
            || epubs.iter().any(|epub: &String| epub == &enrolled.epub)
        {
            return Err(EncDiscError::MigrationRejected);
        }
        lanes.push(reader.lane_id.clone());
        epubs.push(enrolled.epub.clone());
    }
    Ok(sorted)
}

fn prior_for(
    accessor: &str,
    prior: &[(String, u64)],
    current: &[MigrationGrant],
) -> Result<u64, EncDiscError> {
    let mut found = None;
    for (name, revision) in prior {
        if !current.iter().any(|grant| grant.grant.accessor == *name) {
            return Err(EncDiscError::MigrationRejected);
        }
        if name != accessor {
            continue;
        }
        if found.is_some() {
            return Err(EncDiscError::MigrationRejected);
        }
        safe_int(*revision)?;
        found = Some(*revision);
    }
    Ok(found.unwrap_or(0))
}

fn verify_item(
    owner_secret: &AccountSeaSecret,
    prepared: &EncryptedMigration,
) -> Result<(), EncDiscError> {
    let dek_hex = prepared
        .author
        .open(&prepared.migration.object, &prepared_revision(prepared)?)
        .map_err(|_| EncDiscError::MigrationRejected)?;
    let dek_bytes =
        hexutil::decode_hex_array::<32>(&dek_hex).map_err(|_| EncDiscError::MigrationRejected)?;
    let dek = ItemDek::from_bytes(dek_bytes);
    let opened = open_item_fields(&prepared.item_blob, &dek)?;
    if opened.plaintext != prepared.plaintext
        || opened.version != prepared.migration.to_version
        || opened.epoch != prepared.epoch
        || opened.revision_id != prepared_revision(prepared)?
    {
        return Err(EncDiscError::MigrationRejected);
    }
    let digest = canonical::plaintext_digest(&opened.plaintext);
    if digest != opened.plaintext_digest {
        return Err(EncDiscError::MigrationRejected);
    }
    let fields = ItemAuthFields {
        object: prepared.migration.object.clone(),
        epoch: opened.epoch,
        version: opened.version,
        plaintext_digest: digest,
        revision_id: opened.revision_id,
    };
    crate::account::verify_item_auth(owner_secret.sea_pub(), &fields, &opened.item_auth)
        .map_err(|_| EncDiscError::MigrationRejected)?;
    Ok(())
}

fn open_rows(
    owner_secret: &AccountSeaSecret,
    prepared: &EncryptedMigration,
) -> Result<Vec<SignedGrantPayload>, EncDiscError> {
    let dek_hex = prepared
        .author
        .open(&prepared.migration.object, &prepared_revision(prepared)?)
        .map_err(|_| EncDiscError::MigrationRejected)?;
    let dek_bytes =
        hexutil::decode_hex_array::<32>(&dek_hex).map_err(|_| EncDiscError::MigrationRejected)?;
    let dek = ItemDek::from_bytes(dek_bytes);
    let digest = canonical::sha256_hex(&prepared.item_blob);
    let mut payloads = Vec::with_capacity(prepared.rows.len());
    if prepared.rows.len() != prepared.readers.len() {
        return Err(EncDiscError::MigrationRejected);
    }
    for (row, reader) in prepared.rows.iter().zip(prepared.readers.iter()) {
        if !grant::row_entry_matches(row).unwrap_or(false) || row.lane_id != reader.lane_id {
            return Err(EncDiscError::MigrationRejected);
        }
        let wrap = row.wrap.as_ref().ok_or(EncDiscError::MigrationRejected)?;
        let recorded = prepared
            .migration
            .rewrapped
            .iter()
            .find(|item| item.target_id == reader.enrolled.epub)
            .ok_or(EncDiscError::MigrationRejected)?;
        if wrap != recorded
            || wrap.target_id != reader.enrolled.epub
            || wrap.revision_id != prepared_revision(prepared)?
            || wrap.epoch != prepared.epoch
        {
            return Err(EncDiscError::MigrationRejected);
        }
        let opened = open_grant_ciphertext(&row.grant_ciphertext, &dek)?;
        let payload = grant::decode_grant_bytes(&opened.grant_bytes)
            .map_err(|_| EncDiscError::MigrationRejected)?;
        if payload.accessor != reader.enrolled.account
            || payload.owner != owner_secret.account()
            || payload.item_ciphertext_digest != digest
            || payload.epoch != prepared.epoch
        {
            return Err(EncDiscError::MigrationRejected);
        }
        let commitment = commit_grant(&opened.blinding, &payload)
            .map_err(|_| EncDiscError::MigrationRejected)?;
        if commitment.hash != row.commitment.hash {
            return Err(EncDiscError::MigrationRejected);
        }
        if grant::row_exposes_opening(row, owner_secret.sea_pub(), &opened.blinding) {
            return Err(EncDiscError::MigrationRejected);
        }
        let message = canonical::grant_payload_bytes(&payload.body())
            .map_err(|_| EncDiscError::MigrationRejected)?;
        sea::verify_sea(owner_secret.sea_pub(), &message, &opened.signature)
            .map_err(|_| EncDiscError::MigrationRejected)?;
        payloads.push(payload);
    }
    Ok(payloads)
}

fn same_wraps(left: &[WrappedKey], right: &[WrappedKey]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    right.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    left == right
}

fn verify_receipts(
    prepared: &EncryptedMigration,
    proposed: &ProtocolMigration,
    receipts: &[WrapReceipt],
) -> Result<(), EncDiscError> {
    for reader in &prepared.readers {
        let Some(proposed_reader) = proposed
            .readers
            .iter()
            .find(|item| item.accessor == reader.enrolled.account)
        else {
            return Err(EncDiscError::MigrationRejected);
        };
        let row = prepared
            .rows
            .iter()
            .find(|row| row.lane_id == reader.lane_id)
            .ok_or(EncDiscError::MigrationRejected)?;
        let matched: Vec<&WrapReceipt> = receipts
            .iter()
            .filter(|receipt| receipt.accessor == reader.enrolled.account)
            .collect();
        if proposed_reader.acknowledged {
            let receipt = matched
                .first()
                .copied()
                .ok_or(EncDiscError::MigrationRejected)?;
            if matched.len() != 1 {
                return Err(EncDiscError::MigrationRejected);
            }
            let message = canonical::wrap_receipt_bytes(
                &prepared.migration.object,
                &reader.enrolled.account,
                prepared.migration.to_version,
                &prepared_revision(prepared)?,
                &row.entry_id,
            )
            .map_err(|_| EncDiscError::MigrationRejected)?;
            sea::verify_sea(&reader.enrolled.sea_pub, &message, &receipt.signature)
                .map_err(|_| EncDiscError::MigrationRejected)?;
        } else if !matched.is_empty() {
            return Err(EncDiscError::MigrationRejected);
        }
    }
    Ok(())
}

fn reader_versions(readers: &[MigrationReader]) -> Result<Vec<ReaderVersion>, EncDiscError> {
    Ok(readers
        .iter()
        .map(|reader| ReaderVersion {
            accessor: reader.enrolled.account.clone(),
            version: reader.version,
            epub: reader.enrolled.epub.clone(),
        })
        .collect())
}

fn prepared_revision(prepared: &EncryptedMigration) -> Result<String, EncDiscError> {
    let revision = prepared.author.revision_id();
    canonical::require_revision_id(revision).map_err(|_| EncDiscError::MigrationRejected)?;
    Ok(revision.to_string())
}

struct OpenedItem {
    version: u64,
    epoch: u64,
    revision_id: String,
    item_auth: String,
    plaintext_digest: String,
    plaintext: Vec<u8>,
}

struct OpenedGrantCiphertext {
    blinding: String,
    signature: String,
    grant_bytes: String,
}

fn sign_item(
    owner: &AccountSeaSecret,
    object: &str,
    epoch: u64,
    version: u64,
    plaintext: &[u8],
    revision_id: &str,
) -> Result<String, EncDiscError> {
    let fields = ItemAuthFields {
        object: object.to_string(),
        epoch,
        version,
        plaintext_digest: canonical::plaintext_digest(plaintext),
        revision_id: revision_id.to_string(),
    };
    owner
        .sign_item_auth(&fields)
        .map_err(|_| EncDiscError::MigrationRejected)
}

fn seal_item(
    dek: &ItemDek,
    version: u64,
    epoch: u64,
    revision_id: &str,
    item_auth: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, EncDiscError> {
    let version_text =
        canonical::canonical_decimal(version).map_err(|_| EncDiscError::MigrationRejected)?;
    let epoch_text =
        canonical::canonical_decimal(epoch).map_err(|_| EncDiscError::MigrationRejected)?;
    let body = canonical::length_prefixed(&[
        DOMAIN_MIGRATED_ITEM,
        &version_text,
        &epoch_text,
        revision_id,
        item_auth,
        &encode_hex(plaintext),
    ])
    .map_err(|_| EncDiscError::MigrationRejected)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = encrypt(dek.as_bytes(), &nonce, &body)?;
    let mut blob = Vec::with_capacity(1 + 8 + 8 + 12 + ciphertext.len());
    blob.push(FORMAT_ITEM);
    blob.extend_from_slice(&version.to_be_bytes());
    blob.extend_from_slice(&epoch.to_be_bytes());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn seal_grant_ciphertext(
    dek: &ItemDek,
    blinding: &str,
    signature: &str,
    grant_bytes: &str,
) -> Result<Vec<u8>, EncDiscError> {
    let body =
        canonical::length_prefixed(&[DOMAIN_GRANT_CIPHERTEXT, blinding, signature, grant_bytes])
            .map_err(|_| EncDiscError::MigrationRejected)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = encrypt(dek.as_bytes(), &nonce, &body)?;
    let mut blob = Vec::with_capacity(1 + 12 + ciphertext.len());
    blob.push(FORMAT_ITEM);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn open_item_fields(blob: &[u8], dek: &ItemDek) -> Result<OpenedItem, EncDiscError> {
    if blob.len() < 1 + 8 + 8 + 12 + 16 || blob[0] != FORMAT_ITEM {
        return Err(EncDiscError::MigrationRejected);
    }
    let version = u64::from_be_bytes(
        blob[1..9]
            .try_into()
            .map_err(|_| EncDiscError::MigrationRejected)?,
    );
    let epoch = u64::from_be_bytes(
        blob[9..17]
            .try_into()
            .map_err(|_| EncDiscError::MigrationRejected)?,
    );
    let nonce: [u8; 12] = blob[17..29]
        .try_into()
        .map_err(|_| EncDiscError::MigrationRejected)?;
    let plain = decrypt(dek.as_bytes(), &nonce, &blob[29..])?;
    let fields =
        canonical::decode_length_prefixed(&plain).map_err(|_| EncDiscError::MigrationRejected)?;
    if fields.len() != 6 || fields[0] != DOMAIN_MIGRATED_ITEM {
        return Err(EncDiscError::MigrationRejected);
    }
    let inner_version = canonical::parse_canonical_decimal(&fields[1])
        .map_err(|_| EncDiscError::MigrationRejected)?;
    let inner_epoch = canonical::parse_canonical_decimal(&fields[2])
        .map_err(|_| EncDiscError::MigrationRejected)?;
    if inner_version != version || inner_epoch != epoch {
        return Err(EncDiscError::MigrationRejected);
    }
    canonical::require_revision_id(&fields[3]).map_err(|_| EncDiscError::MigrationRejected)?;
    let plaintext = decode_hex(&fields[5]).map_err(|_| EncDiscError::MigrationRejected)?;
    let plaintext_digest = canonical::plaintext_digest(&plaintext);
    Ok(OpenedItem {
        version,
        epoch,
        revision_id: fields[3].clone(),
        item_auth: fields[4].clone(),
        plaintext_digest,
        plaintext,
    })
}

fn open_grant_ciphertext(
    hex_blob: &str,
    dek: &ItemDek,
) -> Result<OpenedGrantCiphertext, EncDiscError> {
    let blob = decode_hex(hex_blob).map_err(|_| EncDiscError::MigrationRejected)?;
    if blob.len() < 1 + 12 + 16 || blob[0] != FORMAT_ITEM {
        return Err(EncDiscError::MigrationRejected);
    }
    let nonce: [u8; 12] = blob[1..13]
        .try_into()
        .map_err(|_| EncDiscError::MigrationRejected)?;
    let plain = decrypt(dek.as_bytes(), &nonce, &blob[13..])?;
    let fields =
        canonical::decode_length_prefixed(&plain).map_err(|_| EncDiscError::MigrationRejected)?;
    if fields.len() != 4 || fields[0] != DOMAIN_GRANT_CIPHERTEXT {
        return Err(EncDiscError::MigrationRejected);
    }
    Ok(OpenedGrantCiphertext {
        blinding: fields[1].clone(),
        signature: fields[2].clone(),
        grant_bytes: fields[3].clone(),
    })
}

fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::MigrationRejected)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| EncDiscError::MigrationRejected)
}

fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, EncDiscError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EncDiscError::MigrationRejected)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| EncDiscError::MigrationRejected)
}

fn input_object(input: &MigrationAdmissionInput<'_>) -> Result<String, EncDiscError> {
    if let Some(grant) = input.grants.first() {
        if input
            .grants
            .iter()
            .any(|edge| edge.grant.object != grant.grant.object)
        {
            return Err(EncDiscError::MigrationRejected);
        }
        if grant.grant.object != input.migration.object {
            return Err(EncDiscError::MigrationRejected);
        }
    }
    Ok(input.migration.object.clone())
}

fn names(grants: &[MigrationGrant]) -> Vec<String> {
    let mut names: Vec<String> = grants
        .iter()
        .map(|grant| grant.grant.accessor.clone())
        .collect();
    names.sort();
    names
}

fn bump(ham_state: u64) -> Result<u64, EncDiscError> {
    let next = ham_state
        .checked_add(1)
        .ok_or(EncDiscError::MigrationRejected)?;
    safe_int(next)?;
    Ok(next)
}

fn safe_int(value: u64) -> Result<(), EncDiscError> {
    canonical::canonical_decimal(value)
        .map(|_| ())
        .map_err(|_| EncDiscError::MigrationRejected)
}

fn is_signature(value: &str) -> bool {
    value.len() == 128 && is_lower_hex(value)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && is_lower_hex(value)
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn an_invalid_principal_is_not_admitted_as_an_empty_soul() {
        let migration = ProtocolMigration {
            object: "doc".to_string(),
            from_version: 1,
            to_version: 2,
            rewrapped: Vec::new(),
            readers: Vec::new(),
            version_gate: 2,
        };
        for accessor in ["0xbob/x", "x~1get('s3rch')", "../meta", "..."] {
            for soul in ["", &format!("s3rch/acl/0xalice/doc/{accessor}")] {
                let grant = MigrationGrant {
                    soul: soul.to_string(),
                    owner: "0xalice".to_string(),
                    grant: MeshSeeGrant {
                        object: "doc".to_string(),
                        accessor: accessor.to_string(),
                        from: 0,
                        until: 80,
                        stated: GrantStated::Live,
                    },
                    ham_state: 1,
                };
                let err = apply_protocol_migration(&MigrationAdmissionInput {
                    migration: &migration,
                    owner: "0xalice",
                    caller: "0xalice",
                    now: 10,
                    storage: GrantStorage::PublicPlain,
                    grants: std::slice::from_ref(&grant),
                    payloads: &[],
                    receipts: &[],
                    reader_versions: &[],
                    soul_ham_state: 1,
                });
                assert!(err.is_err(), "{accessor} {soul}");
            }
        }
    }

    #[test]
    fn a_reader_holding_the_dek_cannot_forge_the_body() {
        let owner = AccountSeaSecret::generate("0xalice").unwrap();
        let reader = AccountSeaSecret::generate("0xbob").unwrap();
        let dek = ItemDek::generate();
        let revision = "11".repeat(32);
        let signature = sign_item(&owner, "item-1", 1, 2, b"body", &revision).unwrap();
        let real = seal_item(&dek, 2, 1, &revision, &signature, b"body").unwrap();
        assert_eq!(
            open_migrated_item(&real, &dek, owner.sea_pub(), "item-1").unwrap(),
            b"body"
        );
        let forged_sig = sign_item(&reader, "item-1", 1, 2, b"forged", &revision).unwrap();
        let forged = seal_item(&dek, 2, 1, &revision, &forged_sig, b"forged").unwrap();
        assert!(open_migrated_item(&forged, &dek, owner.sea_pub(), "item-1").is_err());
        let relabeled = seal_item(&dek, 2, 1, &revision, &signature, b"forged").unwrap();
        assert!(open_migrated_item(&relabeled, &dek, owner.sea_pub(), "item-1").is_err());
        assert!(open_migrated_item(&real, &dek, owner.sea_pub(), "item-2").is_err());
        assert!(open_migrated_item(&real, &dek, reader.sea_pub(), "item-1").is_err());
    }
}
