//! Encrypted-discovery consume checks.
//!
//! Ciphertext lives at `s3rch/items/<itemId>/r/<rev>`. The grant names
//! the manifest soul `s3rch/items/<itemId>/m/<rev>`. A status signer
//! other than the current account SEA pub needs `StatusAuthorityBinding`.
//! A group-inbox `ssig` is that sender's current SEA pub. Those
//! signatures fail closed unless the provider or wallet account-key
//! log links. The signed head carries `issuedAt` and `maxAgeMs`. A
//! verifier with no anchor still refuses a head outside that max-age.
//! A hop, a status statement, and a chat node do not mint.
//!
//! s3r.ch copies `docs/s3rch-check.d.ts` and reimplements this module.
//! It does not import this crate.

use crate::canonical::{canonical_decimal, length_prefixed, sha256_hex};
use crate::error::EncDiscError;
use crate::limits::KEYRING_HISTORY_MAX;
use crate::sea::verify_sea;

/// Steps from a head at `KEYRING_HISTORY_MAX` down through seq 0.
const ACCOUNT_KEY_WALK_LIMIT: usize = KEYRING_HISTORY_MAX + 1;

/// Ceiling for a provider or wallet account-key head, in milliseconds.
///
/// Five minutes covers an answer from the provider or the wallet and
/// ordinary clock skew. A longer window would keep a retired key current
/// for a verifier that has not stored an anchor. The signed `maxAgeMs`
/// and the verifier's `policyMaxAgeMs` can be shorter. Neither can raise
/// this ceiling.
pub const ACCOUNT_KEY_HEAD_MAX_AGE_MS: u64 = 300_000;

pub const DOMAIN_ENV_DIGEST: &str = "s3rch-env-digest-v1";
pub const DOMAIN_REVISION_MANIFEST: &str = "s3rch-revision-manifest-v1";
pub const DOMAIN_GRANT_MANIFEST: &str = "s3rch-grant-manifest-v1";
pub const DOMAIN_STATUS_AUTHORITY: &str = "s3rch-status-authority-v1";
pub const DOMAIN_GROUP_INBOX_BODY: &str = "s3rch-group-inbox-body-v1";
pub const DOMAIN_GROUP_INBOX_SSIG: &str = "s3rch-group-inbox-ssig-v1";
pub const DOMAIN_ACCOUNT_KEY_LOG: &str = "s3rch-account-key-log-v1";
pub const DOMAIN_ACCOUNT_KEY_HEAD: &str = "s3rch-account-key-head-v1";

const PREV_NONE: &str = "none";

/// Accept, or a stable refusal reason shared with the TypeScript contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumeDecision {
    Accept,
    Refuse(&'static str),
}

/// Current SEA pub from the log head, or a refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CurrentKeyDecision {
    Accept { key_pub: String },
    Refuse(&'static str),
}

/// Product revision manifest. `status_auth_pub` is omitted when absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionManifest {
    pub item_id: String,
    pub e: u64,
    pub rev: String,
    pub parent: String,
    pub key_id: String,
    pub env_digest: String,
    pub status_auth_pub: Option<String>,
}

/// Current-account designation of the status authority. Not an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusAuthorityBinding {
    pub account: String,
    pub account_pub: String,
    pub status_auth_pub: String,
    pub seq: u64,
}

/// Group-inbox sender authentication. Signed by the sender's current SEA pub.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInboxWriteSig {
    pub tag: String,
    pub entry_id: String,
    pub sender_pub: String,
    pub body_hash: String,
}

/// Append-only account-key log entry. `key_pub` is the SEA pub for that seq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountKeyLogEntry {
    pub account: String,
    pub key_pub: String,
    pub seq: u64,
    pub prev: String,
}

/// Provider or wallet head. The SEA key does not sign these bytes.
///
/// `issued_at` and `max_age_ms` are inside the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountKeyLogHead {
    pub account: String,
    pub seq: u64,
    pub entry_hash: String,
    pub issued_at: u64,
    pub max_age_ms: u64,
}

/// An entry already accepted on an earlier check.
///
/// The hash is recomputed from `entry`. A hash supplied beside the entry
/// is not stored. A later entry may stop here only when it names the same
/// account and its seq is this seq plus one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountKeyAnchor {
    pub entry: AccountKeyLogEntry,
}

fn path_segment(value: &str) -> Result<(), EncDiscError> {
    if value.is_empty()
        || value.len() > 256
        || value == "."
        || value == ".."
        || value.contains('/')
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(EncDiscError::BadEncoding);
    }
    Ok(())
}

fn digest_hex(value: &str) -> Result<(), EncDiscError> {
    if value.len() != 64 || crate::hexutil::decode_hex(value).is_err() {
        return Err(EncDiscError::BadRevision);
    }
    Ok(())
}

fn prefixed(fields: &[&str]) -> Result<Vec<u8>, EncDiscError> {
    length_prefixed(fields)
}

/// `s3rch/items/<itemId>/r/<rev>`. The first revision uses this path too.
pub fn item_revision_soul(item_id: &str, rev: &str) -> Result<String, EncDiscError> {
    path_segment(item_id)?;
    path_segment(rev)?;
    Ok(format!("s3rch/items/{item_id}/r/{rev}"))
}

/// `s3rch/items/<itemId>/m/<rev>`. Not a grant.
pub fn manifest_soul(item_id: &str, rev: &str) -> Result<String, EncDiscError> {
    path_segment(item_id)?;
    path_segment(rev)?;
    Ok(format!("s3rch/items/{item_id}/m/{rev}"))
}

/// Write-once locator soul. Not a ciphertext path and not a Check object.
pub fn item_root_soul(item_id: &str) -> Result<String, EncDiscError> {
    path_segment(item_id)?;
    Ok(format!("s3rch/items/{item_id}"))
}

/// `s3rch/ginbox/<tag>/<entryId>`.
pub fn group_inbox_soul(tag: &str, entry_id: &str) -> Result<String, EncDiscError> {
    path_segment(tag)?;
    path_segment(entry_id)?;
    Ok(format!("s3rch/ginbox/{tag}/{entry_id}"))
}

/// `H(itemId || e || rev || alg || iv || ct)`, length-prefixed.
pub fn env_digest(
    item_id: &str,
    e: u64,
    rev: &str,
    alg: &str,
    iv: &str,
    ct: &str,
) -> Result<String, EncDiscError> {
    path_segment(item_id)?;
    path_segment(rev)?;
    let epoch = canonical_decimal(e)?;
    Ok(sha256_hex(&prefixed(&[
        DOMAIN_ENV_DIGEST,
        item_id,
        &epoch,
        rev,
        alg,
        iv,
        ct,
    ])?))
}

pub fn revision_manifest_bytes(manifest: &RevisionManifest) -> Result<Vec<u8>, EncDiscError> {
    path_segment(&manifest.item_id)?;
    path_segment(&manifest.rev)?;
    digest_hex(&manifest.key_id)?;
    digest_hex(&manifest.env_digest)?;
    let epoch = canonical_decimal(manifest.e)?;
    let mut fields = vec![
        DOMAIN_REVISION_MANIFEST.to_string(),
        manifest.item_id.clone(),
        epoch,
        manifest.rev.clone(),
        manifest.parent.clone(),
        manifest.key_id.clone(),
        manifest.env_digest.clone(),
    ];
    push_status_auth(&mut fields, manifest.status_auth_pub.as_deref())?;
    let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
    prefixed(&refs)
}

/// Signed grant-tuple field. Outside `s3rch-grant-payload-v1`.
pub fn grant_manifest_bytes(
    item_id: &str,
    rev: &str,
    manifest: &str,
) -> Result<Vec<u8>, EncDiscError> {
    path_segment(item_id)?;
    path_segment(rev)?;
    Ok(prefixed(&[DOMAIN_GRANT_MANIFEST, item_id, rev, manifest])?)
}

pub fn status_authority_bytes(binding: &StatusAuthorityBinding) -> Result<Vec<u8>, EncDiscError> {
    if binding.account.is_empty()
        || binding.account_pub.is_empty()
        || binding.status_auth_pub.is_empty()
    {
        return Err(EncDiscError::BadEncoding);
    }
    let seq = canonical_decimal(binding.seq)?;
    prefixed(&[
        DOMAIN_STATUS_AUTHORITY,
        &binding.account,
        &binding.account_pub,
        &binding.status_auth_pub,
        &seq,
    ])
}

pub fn group_inbox_body_hash(eph: &str, ct: &str, iv: &str) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&prefixed(&[
        DOMAIN_GROUP_INBOX_BODY,
        eph,
        ct,
        iv,
    ])?))
}

pub fn group_inbox_sig_bytes(sig: &GroupInboxWriteSig) -> Result<Vec<u8>, EncDiscError> {
    path_segment(&sig.tag)?;
    path_segment(&sig.entry_id)?;
    digest_hex(&sig.body_hash)?;
    if sig.sender_pub.is_empty() {
        return Err(EncDiscError::BadEncoding);
    }
    prefixed(&[
        DOMAIN_GROUP_INBOX_SSIG,
        &sig.tag,
        &sig.entry_id,
        &sig.sender_pub,
        &sig.body_hash,
    ])
}

pub fn account_key_log_bytes(entry: &AccountKeyLogEntry) -> Result<Vec<u8>, EncDiscError> {
    if entry.account.is_empty() || entry.key_pub.is_empty() {
        return Err(EncDiscError::BadEncoding);
    }
    let seq = canonical_decimal(entry.seq)?;
    prefixed(&[
        DOMAIN_ACCOUNT_KEY_LOG,
        &entry.account,
        &entry.key_pub,
        &seq,
        &entry.prev,
    ])
}

pub fn account_key_entry_hash(entry: &AccountKeyLogEntry) -> Result<String, EncDiscError> {
    Ok(sha256_hex(&account_key_log_bytes(entry)?))
}

pub fn account_key_head_bytes(head: &AccountKeyLogHead) -> Result<Vec<u8>, EncDiscError> {
    if head.account.is_empty() {
        return Err(EncDiscError::BadEncoding);
    }
    digest_hex(&head.entry_hash)?;
    let seq = canonical_decimal(head.seq)?;
    let issued_at = canonical_decimal(head.issued_at)?;
    let max_age = canonical_decimal(head.max_age_ms)?;
    prefixed(&[
        DOMAIN_ACCOUNT_KEY_HEAD,
        &head.account,
        &seq,
        &head.entry_hash,
        &issued_at,
        &max_age,
    ])
}

/// The SEA key does not sign the log head.
pub fn account_key_head_signed_by_sea() -> bool {
    false
}

/// A hop, a status statement, a chat node, and these consume records do not mint.
pub fn consume_statement_mints(_kind: &str) -> bool {
    false
}

pub fn accept_item_locator(
    v: u64,
    enc: u64,
    first: &str,
    expected_first: &str,
    has_ciphertext: bool,
) -> ConsumeDecision {
    if has_ciphertext {
        return ConsumeDecision::Refuse("root-ciphertext");
    }
    if v != 2 || enc != 1 || path_segment(first).is_err() || first != expected_first {
        return ConsumeDecision::Refuse("bad-soul");
    }
    ConsumeDecision::Accept
}

pub fn accept_envelope(
    item_id: &str,
    e: u64,
    rev: &str,
    fetched_soul: &str,
    root_has_ciphertext: bool,
    alg: &str,
    iv: &str,
    ct: &str,
    claimed_env_digest: &str,
) -> ConsumeDecision {
    if root_has_ciphertext {
        return ConsumeDecision::Refuse("root-ciphertext");
    }
    let Ok(soul) = item_revision_soul(item_id, rev) else {
        return ConsumeDecision::Refuse("bad-path");
    };
    if fetched_soul != soul {
        return ConsumeDecision::Refuse("bad-soul");
    }
    let Ok(digest) = env_digest(item_id, e, rev, alg, iv, ct) else {
        return ConsumeDecision::Refuse("digest-mismatch");
    };
    if digest != claimed_env_digest {
        return ConsumeDecision::Refuse("digest-mismatch");
    }
    ConsumeDecision::Accept
}

pub fn accept_grant_manifest(
    manifest: Option<&str>,
    item_id: &str,
    rev: &str,
    author_lane_only: bool,
) -> ConsumeDecision {
    if author_lane_only {
        return ConsumeDecision::Refuse("author-lane");
    }
    let Some(manifest) = manifest.filter(|soul| !soul.is_empty()) else {
        return ConsumeDecision::Refuse("bad-soul");
    };
    let Ok(soul) = manifest_soul(item_id, rev) else {
        return ConsumeDecision::Refuse("bad-path");
    };
    if manifest != soul {
        return ConsumeDecision::Refuse("bad-soul");
    }
    ConsumeDecision::Accept
}

pub fn accept_revision_manifest(
    node_v: u64,
    manifest: &RevisionManifest,
    item_id: &str,
    rev: &str,
    envelope_digest: &str,
    carries_account_pub: bool,
) -> ConsumeDecision {
    if carries_account_pub {
        return ConsumeDecision::Refuse("bad-soul");
    }
    if node_v != 1 || manifest.item_id != item_id || manifest.rev != rev {
        return ConsumeDecision::Refuse("bad-soul");
    }
    if manifest.env_digest != envelope_digest {
        return ConsumeDecision::Refuse("digest-mismatch");
    }
    if revision_manifest_bytes(manifest).is_err() {
        return ConsumeDecision::Refuse("bad-path");
    }
    ConsumeDecision::Accept
}

/// `binding_signed_by_current` is the consumer's result.
///
/// This check does not verify the binding signature. The consumer must
/// verify that signature under the current account SEA pub before passing
/// true.
pub fn accept_status_signer(
    signing_pub: &str,
    current_account_pub: &str,
    binding: Option<&StatusAuthorityBinding>,
    manifest_status_auth_pub: Option<&str>,
    log_head_account: Option<&str>,
    log_head_seq: Option<u64>,
    binding_signed_by_current: bool,
    purpose: &str,
) -> ConsumeDecision {
    if signing_pub.is_empty() || current_account_pub.is_empty() {
        return ConsumeDecision::Refuse("authority-key");
    }
    if purpose != "status" {
        return if signing_pub == current_account_pub {
            ConsumeDecision::Accept
        } else {
            ConsumeDecision::Refuse("authority-key")
        };
    }
    if signing_pub == current_account_pub {
        return ConsumeDecision::Accept;
    }
    let Some(binding) = binding else {
        return ConsumeDecision::Refuse("missing-binding");
    };
    let Some(manifest_pub) = manifest_status_auth_pub.filter(|pub_key| !pub_key.is_empty()) else {
        return ConsumeDecision::Refuse("missing-binding");
    };
    let Some(head_account) = log_head_account.filter(|account| !account.is_empty()) else {
        return ConsumeDecision::Refuse("missing-binding");
    };
    let Some(head_seq) = log_head_seq else {
        return ConsumeDecision::Refuse("missing-binding");
    };
    if binding.account != head_account
        || binding.account_pub != current_account_pub
        || binding.status_auth_pub != signing_pub
        || manifest_pub != signing_pub
        || binding.seq != head_seq
        || !binding_signed_by_current
    {
        return ConsumeDecision::Refuse("authority-key");
    }
    ConsumeDecision::Accept
}

/// `member`, `signature_under_sender`, and `derived_from_group_key` are
/// the consumer's results.
///
/// This check does not verify the group-inbox signature, membership, or a
/// derivation from the group epoch key. The consumer must do those checks
/// before passing true.
pub fn accept_group_inbox_sender(
    sender_pub: &str,
    current_account_pub: &str,
    member: bool,
    signature_under_sender: bool,
    derived_from_group_key: bool,
) -> ConsumeDecision {
    if derived_from_group_key {
        return ConsumeDecision::Refuse("group-writer-key");
    }
    if !signature_under_sender {
        return ConsumeDecision::Refuse("authority-key");
    }
    if !member {
        return ConsumeDecision::Refuse("not-member");
    }
    if sender_pub.is_empty() || sender_pub != current_account_pub {
        return ConsumeDecision::Refuse("superseded");
    }
    ConsumeDecision::Accept
}

fn unique_index(
    entries: &[AccountKeyLogEntry],
    account: &str,
    seq: u64,
) -> Result<Option<usize>, ()> {
    let mut found = None;
    for (index, entry) in entries.iter().enumerate() {
        if entry.account == account && entry.seq == seq {
            if found.is_some() {
                return Err(());
            }
            found = Some(index);
        }
    }
    Ok(found)
}

fn push_status_auth(
    fields: &mut Vec<String>,
    status_auth_pub: Option<&str>,
) -> Result<(), EncDiscError> {
    if let Some(status_auth_pub) = status_auth_pub {
        if status_auth_pub.is_empty() {
            return Err(EncDiscError::BadEncoding);
        }
        fields.push(status_auth_pub.to_string());
    }
    Ok(())
}

fn anchor_links(
    entry: &AccountKeyLogEntry,
    entry_hash: &str,
    anchor: &AccountKeyLogEntry,
    anchor_hash: &str,
) -> bool {
    if entry.account != anchor.account {
        return false;
    }
    if entry_hash == anchor_hash && entry.seq == anchor.seq {
        return true;
    }
    match anchor.seq.checked_add(1) {
        Some(next) => entry.seq == next && entry.prev == anchor_hash,
        None => false,
    }
}

fn head_is_fresh(
    issued_at: u64,
    signed_max_age_ms: u64,
    now: u64,
    skew_allowance_ms: u64,
    policy_max_age_ms: u64,
) -> bool {
    let bound = signed_max_age_ms
        .min(policy_max_age_ms)
        .min(ACCOUNT_KEY_HEAD_MAX_AGE_MS);
    let latest = now.saturating_add(skew_allowance_ms);
    if issued_at > latest {
        return false;
    }
    if now >= issued_at {
        now - issued_at <= bound
    } else {
        true
    }
}

/// True when a hash-linked entry below `seq` uses the provider signing key.
///
/// A missing parent stops the scan. The anchor already accepted that prefix,
/// so an absent older entry is not a broken link. A duplicate seq refuses.
fn provider_key_below(
    entries: &[AccountKeyLogEntry],
    account: &str,
    mut seq: u64,
    prev: &str,
    provider_pub: &str,
) -> bool {
    let mut prev = prev.to_string();
    for _ in 0..ACCOUNT_KEY_WALK_LIMIT {
        if seq == 0 {
            return false;
        }
        let parent = match unique_index(entries, account, seq - 1) {
            Ok(Some(parent)) => parent,
            Ok(None) => return false,
            Err(()) => return true,
        };
        let parent_entry = &entries[parent];
        if parent_entry.account != account {
            return true;
        }
        let Ok(parent_hash) = account_key_entry_hash(parent_entry) else {
            return false;
        };
        if parent_hash != prev {
            return false;
        }
        if parent_entry.key_pub == provider_pub {
            return true;
        }
        seq = parent_entry.seq;
        prev = parent_entry.prev.clone();
    }
    false
}

fn head_signature_ok(provider_pub: &str, head: &AccountKeyLogHead, signature: &str) -> bool {
    if provider_pub.is_empty() || signature.is_empty() {
        return false;
    }
    let Ok(message) = account_key_head_bytes(head) else {
        return false;
    };
    verify_sea(provider_pub, &message, signature).is_ok()
}

pub fn accept_current_key(
    head: Option<&AccountKeyLogHead>,
    entries: &[AccountKeyLogEntry],
    anchor: Option<&AccountKeyAnchor>,
    provider_answered: bool,
    provider_pub: &str,
    head_signature: &str,
    expected_account: &str,
    statement_key_pub: &str,
    now: u64,
    skew_allowance_ms: u64,
    policy_max_age_ms: u64,
) -> CurrentKeyDecision {
    if !provider_answered {
        return CurrentKeyDecision::Refuse("no-answer");
    }
    let Some(head) = head else {
        return CurrentKeyDecision::Refuse("missing-head");
    };
    if !head_signature_ok(provider_pub, head, head_signature) {
        return CurrentKeyDecision::Refuse("head-mismatch");
    }
    if expected_account.is_empty()
        || head.account != expected_account
        || digest_hex(&head.entry_hash).is_err()
    {
        return CurrentKeyDecision::Refuse("head-mismatch");
    }
    let start = match unique_index(entries, expected_account, head.seq) {
        Ok(Some(index)) => index,
        Ok(None) => return CurrentKeyDecision::Refuse("unlinked"),
        Err(()) => return CurrentKeyDecision::Refuse("head-mismatch"),
    };
    let Ok(start_hash) = account_key_entry_hash(&entries[start]) else {
        return CurrentKeyDecision::Refuse("head-mismatch");
    };
    if start_hash != head.entry_hash || entries[start].key_pub.is_empty() {
        return CurrentKeyDecision::Refuse("head-mismatch");
    }
    if !head_is_fresh(
        head.issued_at,
        head.max_age_ms,
        now,
        skew_allowance_ms,
        policy_max_age_ms,
    ) {
        return CurrentKeyDecision::Refuse("stale");
    }
    let resolved_anchor = if let Some(anchor) = anchor {
        if anchor.entry.account != expected_account {
            return CurrentKeyDecision::Refuse("unlinked");
        }
        let hash = match account_key_entry_hash(&anchor.entry) {
            Ok(hash) => hash,
            Err(_) => return CurrentKeyDecision::Refuse("unlinked"),
        };
        if head.seq < anchor.entry.seq {
            return CurrentKeyDecision::Refuse("superseded");
        }
        Some((anchor, hash))
    } else {
        None
    };
    let mut index = start;
    let mut linked = false;
    let mut below: Option<(u64, String)> = None;
    for _ in 0..ACCOUNT_KEY_WALK_LIMIT {
        let entry = &entries[index];
        if entry.account != expected_account {
            return CurrentKeyDecision::Refuse("head-mismatch");
        }
        if entry.key_pub == provider_pub {
            return CurrentKeyDecision::Refuse("head-mismatch");
        }
        let Ok(entry_hash) = account_key_entry_hash(entry) else {
            return CurrentKeyDecision::Refuse("prev-mismatch");
        };
        if let Some((anchor, anchor_hash)) = resolved_anchor.as_ref() {
            if anchor_links(entry, &entry_hash, &anchor.entry, anchor_hash) {
                if anchor.entry.key_pub == provider_pub {
                    return CurrentKeyDecision::Refuse("head-mismatch");
                }
                linked = true;
                below = Some((anchor.entry.seq, anchor.entry.prev.clone()));
                break;
            }
            if entry.seq <= anchor.entry.seq {
                return CurrentKeyDecision::Refuse("unlinked");
            }
        }
        if entry.seq == 0 {
            if resolved_anchor.is_some() {
                return CurrentKeyDecision::Refuse("unlinked");
            }
            if entry.prev != PREV_NONE {
                return CurrentKeyDecision::Refuse("prev-mismatch");
            }
            linked = true;
            below = Some((entry.seq, entry.prev.clone()));
            break;
        }
        let parent = match unique_index(entries, expected_account, entry.seq - 1) {
            Ok(Some(parent)) => parent,
            Ok(None) => return CurrentKeyDecision::Refuse("unlinked"),
            Err(()) => return CurrentKeyDecision::Refuse("head-mismatch"),
        };
        let Ok(parent_hash) = account_key_entry_hash(&entries[parent]) else {
            return CurrentKeyDecision::Refuse("prev-mismatch");
        };
        if parent_hash != entry.prev {
            return CurrentKeyDecision::Refuse("prev-mismatch");
        }
        index = parent;
    }
    if !linked {
        return CurrentKeyDecision::Refuse("unlinked");
    }
    if let Some((seq, prev)) = below {
        if provider_key_below(entries, expected_account, seq, &prev, provider_pub) {
            return CurrentKeyDecision::Refuse("head-mismatch");
        }
    }
    if statement_key_pub != entries[start].key_pub {
        return CurrentKeyDecision::Refuse("superseded");
    }
    CurrentKeyDecision::Accept {
        key_pub: entries[start].key_pub.clone(),
    }
}
