//! One inbox lane, content-addressed entries, and verifier admission.
//!
//! An append is not a grant. An opened wrap is not a grant. A forbidden
//! name fails closed. The accepting relay learns the writer. A replica
//! of the row does not.

use sociacl_encdisc::GenesisAccount;
use sociacl_encdisc::{
    filter_inbox_append, inbox_body_of, inbox_entry_bytes, inbox_entry_id, inbox_pow_bytes,
    inbox_pow_digest, inbox_pow_sha256, inbox_stamp_bytes, inbox_stamp_sha256, lane_id_is_opaque,
    lanes_per_device, leading_zero_bits, length_prefixed, open_reader_wrap,
    replicated_row_admitted, scan_daily_shard, seal_blinded_row, shard_close_watermark_implemented,
    shard_scan_uses_device_cursor, sign_sea, signature_covers_claimed_id,
    stored_row_reveals_writer, verify_inbox_envelope, wrap_item_dek_to_readers,
    writer_append_bytes, writer_append_sha256, writer_channel_bytes, writer_channel_sha256,
    writer_from_stored_row, AccountSeaSecret, AdmissionChallenge, AdmissionEvidence,
    AuthenticatedWriterChannel, BlindedGrantRow, DailyShardScan, EncDiscError, EnrolledSeaPub,
    GrantCommitment, InboxAdmission, InboxAppendResult, InboxEnvelope, InboxLane, InboxWriteFilter,
    InboxWriteHook, InboxWritePolicy, ItemDek, NamedSet, ReaderInboxes, RecipientInbox,
    SenderQuota, VerifierAdmissionState, WrappedKey, WriterAppendAuth, WriterAppendProof,
    DOMAIN_INBOX_POW, DOMAIN_INBOX_STAMP, DOMAIN_WRITER_APPEND, INBOX_ENTRY_MAX_BYTES,
};

const FIXTURE: &str = include_str!("../../../vectors/encrypted-discovery/sea-fixture.json");
const VECTOR: &str = include_str!("../../../vectors/encrypted-discovery/inbox.json");

const HASH_A: &str = "ae91fbe4909bbb7764797dcc6c8bca4ded3cedd03d9e97d78be9182758bb6ab9";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn alice() -> AccountSeaSecret {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    GenesisAccount::import(
        fixture["laneId"].as_str().unwrap(),
        fixture["signing"]["pub"].as_str().unwrap(),
        fixture["signing"]["priv"].as_str().unwrap(),
        fixture["encryption"]["epub"].as_str().unwrap(),
        fixture["encryption"]["epriv"].as_str().unwrap(),
    )
    .map(GenesisAccount::into_secret)
    .unwrap()
}

fn row(
    lane: &str,
    ciphertext: &str,
    commitment: &str,
    wrap: Option<WrappedKey>,
) -> BlindedGrantRow {
    seal_blinded_row(
        lane,
        ciphertext,
        GrantCommitment {
            hash: commitment.to_string(),
        },
        wrap,
    )
    .unwrap()
}

fn dummy_wrap(blob: &str) -> WrappedKey {
    WrappedKey {
        scope: sociacl_encdisc::WrapScope::ItemDek,
        epoch: 3,
        target: sociacl_encdisc::WrapTarget::ReaderEpub,
        target_id: "reader-epub".to_string(),
        object: Some("chat_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111".to_string()),
        group: None,
        revision_id: "ab".repeat(32),
        wrapped_key: blob.to_string(),
    }
}

fn challenge(nonce: &str, difficulty: u32) -> AdmissionChallenge {
    AdmissionChallenge {
        nonce: nonce.to_string(),
        difficulty,
        expires_at: 1_000,
    }
}

fn quota(sender: &str, remaining: u64) -> SenderQuota {
    SenderQuota {
        sender: sender.to_string(),
        remaining,
    }
}

fn pow(nonce: &str, solution: &str) -> InboxAdmission {
    InboxAdmission {
        evidence: Some(AdmissionEvidence::ProofOfWork {
            nonce: nonce.to_string(),
            solution: solution.to_string(),
        }),
    }
}

fn stamp(issuer: &str, signature: &str) -> InboxAdmission {
    InboxAdmission {
        evidence: Some(AdmissionEvidence::Stamp {
            issuer: issuer.to_string(),
            signature: signature.to_string(),
        }),
    }
}

fn channel(secret: &AccountSeaSecret) -> WriterAppendAuth {
    WriterAppendAuth::Channel(secret.writer_channel().unwrap())
}

fn signed(secret: &AccountSeaSecret, entry_id: &str) -> WriterAppendAuth {
    WriterAppendAuth::Signature(secret.writer_append_proof(entry_id).unwrap())
}

fn fingerprint(state: &VerifierAdmissionState) -> String {
    format!("{state:?}")
}

fn assert_unchanged(before: &VerifierAdmissionState, result: &InboxAppendResult) {
    assert!(!result.decision.allow_append);
    assert!(result.learned_writer().is_none());
    assert!(!result.grants_see());
    assert_eq!(fingerprint(&result.state), fingerprint(before));
}

struct Desk {
    reader: AccountSeaSecret,
    bob: AccountSeaSecret,
    carol: AccountSeaSecret,
    entry: BlindedGrantRow,
}

fn desk() -> Desk {
    let reader = alice();
    let bob = GenesisAccount::generate().unwrap().into_secret();
    let carol = GenesisAccount::generate().unwrap().into_secret();
    let entry = row(&reader.inbox().lane_id, "ct-1", HASH_A, None);
    Desk {
        reader,
        bob,
        carol,
        entry,
    }
}

fn enroll(desk: &Desk) -> Vec<EnrolledSeaPub> {
    vec![
        EnrolledSeaPub::from_account(&desk.reader),
        EnrolledSeaPub::from_account(&desk.bob),
        EnrolledSeaPub::from_account(&desk.carol),
    ]
}

fn open_state(first: u64, lane: u64) -> VerifierAdmissionState {
    VerifierAdmissionState {
        challenges: vec![challenge("nonce-a", 0), challenge("nonce-b", 0)],
        stamp_issuers: vec![alice().sea_pub().to_string()],
        first_contact_remaining: first,
        lane_remaining: lane,
        ..VerifierAdmissionState::default()
    }
}

#[test]
fn one_lane_per_reader_and_not_per_device() {
    let secret = alice();
    let phone = secret.enroll("phone").unwrap();
    let laptop = secret.enroll("laptop").unwrap();
    assert_eq!(phone.inbox(), laptop.inbox());
    assert_ne!(phone.inbox().lane_id, phone.inbox().accessor);
    assert!(!lanes_per_device());
    let mut lanes = ReaderInboxes::default();
    lanes.admit(&phone.inbox()).unwrap();
    lanes.admit(&laptop.inbox()).unwrap();
    assert_eq!(lanes.len(), 1);
    assert_eq!(
        lanes.lane_for(secret.account()),
        Some(phone.inbox().lane_id.as_str())
    );

    let mut second = phone.inbox();
    second.lane_id = "22".repeat(32);
    assert_eq!(
        lanes.admit(&second).unwrap_err(),
        EncDiscError::InboxRejected
    );

    let bob = GenesisAccount::generate().unwrap().into_secret();
    let shared = RecipientInbox {
        accessor: bob.account().to_string(),
        lane_id: phone.inbox().lane_id.clone(),
    };
    assert_eq!(
        lanes.admit(&shared).unwrap_err(),
        EncDiscError::InboxRejected
    );
    assert!(!lane_id_is_opaque("0xalice", "0xalice"));
    assert!(!lane_id_is_opaque(
        "0xalice",
        "s3rch/acl/0xalice/chat_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111/0xbob"
    ));
    assert!(lane_id_is_opaque("0xalice", &phone.inbox().lane_id));
    assert!(!lane_id_is_opaque("0xalice", "x"));
    assert!(!lane_id_is_opaque("0xalice", &"ab".repeat(31)));
    assert!(!lane_id_is_opaque("0xalice", &"AB".repeat(32)));
    assert!(!lane_id_is_opaque(
        "0xalice",
        &format!("{}g", "ab".repeat(31))
    ));
    assert_eq!(
        lanes
            .admit(&RecipientInbox {
                accessor: "0xcarol".to_string(),
                lane_id: "x".to_string(),
            })
            .unwrap_err(),
        EncDiscError::BadLane
    );
    assert_eq!(InboxLane::open("x").unwrap_err(), EncDiscError::BadLane);
    assert_eq!(
        lanes
            .admit(&RecipientInbox {
                accessor: "itar".to_string(),
                lane_id: "33".repeat(32),
            })
            .unwrap_err(),
        EncDiscError::InboxRejected
    );
    assert!(AuthenticatedWriterChannel::open_with_possession(
        "saas",
        secret.sea_pub(),
        &"11".repeat(64)
    )
    .is_err());
    assert!(AuthenticatedWriterChannel::open_with_possession(
        "lightiff",
        secret.sea_pub(),
        &"11".repeat(64)
    )
    .is_err());
    assert!(AuthenticatedWriterChannel::open_with_possession(
        secret.account(),
        secret.sea_pub(),
        &"11".repeat(64)
    )
    .is_err());
    let names: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vectors/encrypted-discovery/forbidden-names.json"
    ))
    .unwrap();
    for name in names["exact"].as_array().unwrap() {
        let name = name.as_str().unwrap();
        assert!(
            AuthenticatedWriterChannel::open_with_possession(name, secret.sea_pub(), "00").is_err(),
            "{name}"
        );
    }
    for needle in names["contains"].as_array().unwrap() {
        let name = format!("zz{}zz", needle.as_str().unwrap());
        assert!(
            AuthenticatedWriterChannel::open_with_possession(&name, secret.sea_pub(), "00")
                .is_err(),
            "{name}"
        );
    }
    let minted = secret.writer_channel().unwrap();
    assert!(minted.has_transport_brand());
    assert_eq!(minted.writer(), secret.account());
    let possession = &names["possession"];
    assert_eq!(
        writer_channel_sha256(possession["writer"].as_str().unwrap()).unwrap(),
        possession["sha256"].as_str().unwrap()
    );
    assert_eq!(
        writer_channel_bytes(possession["writer"].as_str().unwrap())
            .unwrap()
            .len(),
        possession["encodedLen"].as_u64().unwrap() as usize
    );
    assert_eq!(
        secret.sign_writer_channel().unwrap(),
        possession["signature"].as_str().unwrap()
    );
    let from_vector = AuthenticatedWriterChannel::open_with_possession(
        possession["writer"].as_str().unwrap(),
        possession["writerPub"].as_str().unwrap(),
        possession["signature"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(from_vector.writer_pub(), secret.sea_pub());
}

#[test]
fn entries_are_the_hash_of_the_whole_body() {
    let lane = alice().inbox().lane_id;
    let other_lane = "44".repeat(32);
    let plain = row(&lane, "ct-1", HASH_A, None);
    let other_ct = row(&lane, "ct-2", HASH_A, None);
    let other_commit = row(&lane, "ct-1", HASH_B, None);
    let wrapped = row(&lane, "ct-1", HASH_A, Some(dummy_wrap("aa")));
    let other_lane_row = row(&other_lane, "ct-1", HASH_A, None);
    let ids = [
        plain.entry_id.as_str(),
        other_ct.entry_id.as_str(),
        other_commit.entry_id.as_str(),
        wrapped.entry_id.as_str(),
        other_lane_row.entry_id.as_str(),
    ];
    let mut unique = ids.to_vec();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ids.len());

    let mut store = InboxLane::open(&lane).unwrap();
    store.append(plain.clone()).unwrap();
    let mut swapped_id = plain.clone();
    swapped_id.grant_ciphertext = "ct-2".to_string();
    assert_eq!(
        store.append(swapped_id).unwrap_err(),
        EncDiscError::RowRejected
    );
    assert_eq!(store.get(&plain.entry_id).unwrap().grant_ciphertext, "ct-1");

    store.append(wrapped.clone()).unwrap();
    assert_ne!(wrapped.entry_id, plain.entry_id);
    assert_eq!(store.entries().len(), 2);
    assert!(!store.grants_see());
    assert_eq!(
        store.append(other_lane_row).unwrap_err(),
        EncDiscError::InboxRejected
    );
}

#[test]
fn default_policy_is_public_and_pow_spends_one_nonce() {
    assert_eq!(
        InboxWriteHook::default().policy,
        InboxWritePolicy::PublicFiltered
    );
    assert_eq!(InboxWritePolicy::default().as_str(), "public-filtered");
    let desk = desk();
    let enrolled = enroll(&desk);
    let mut state = open_state(3, 4);
    let result = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&signed(&desk.bob, &desk.entry.entry_id)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert!(result.decision.allow_append);
    assert_eq!(result.decision.filter, InboxWriteFilter::Ok);
    assert!(!result.grants_see());
    assert_eq!(result.learned_writer(), Some(desk.bob.account()));
    assert_eq!(result.state.lane_remaining, 3);
    assert_eq!(result.state.sender_quotas.len(), 1);
    assert_eq!(result.state.sender_quotas[0].sender, desk.bob.account());
    assert_eq!(result.state.sender_quotas[0].remaining, 2);
    assert_eq!(
        result.state.known_senders,
        vec![desk.bob.account().to_string()]
    );
    assert_eq!(result.state.admitted, vec![desk.entry.entry_id.clone()]);
    assert_eq!(result.state.spent, vec!["nonce-a".to_string()]);
    assert_eq!(result.state.challenges.len(), 1);
    assert_eq!(result.state.challenges[0].nonce, "nonce-b");
    assert!(!stored_row_reveals_writer(
        &desk.entry,
        desk.bob.account(),
        desk.bob.sea_pub()
    ));
    assert!(writer_from_stored_row(&desk.entry).is_none());

    state.challenges = result.state.challenges.clone();
    state.spent = result.state.spent.clone();
    state.known_senders = result.state.known_senders.clone();
    state.sender_quotas = result.state.sender_quotas.clone();
    state.admitted = result.state.admitted.clone();
    state.lane_remaining = result.state.lane_remaining;
    let other = row(&desk.reader.inbox().lane_id, "ct-2", HASH_A, None);
    let again = filter_inbox_append(
        &InboxWriteHook::default(),
        &other,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert_eq!(again.decision.filter, InboxWriteFilter::Replay);
    assert_unchanged(&state, &again);
    assert_eq!(again.state.challenges[0].nonce, "nonce-b");
}

#[test]
fn only_the_named_pow_nonce_is_spent() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = open_state(3, 4);
    let missed = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-missing", "0")),
    )
    .unwrap();
    assert_eq!(missed.decision.filter, InboxWriteFilter::StampMismatch);
    assert_unchanged(&state, &missed);

    let spent = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert!(spent.decision.allow_append);
    assert!(spent.state.spent.iter().any(|item| item == "nonce-a"));
    assert!(spent
        .state
        .challenges
        .iter()
        .any(|item| item.nonce == "nonce-b"));
    assert!(!spent
        .state
        .challenges
        .iter()
        .any(|item| item.nonce == "nonce-a"));

    let other = row(&desk.reader.inbox().lane_id, "ct-9", HASH_A, None);
    let bob_state = spent.state.clone();
    let carol = filter_inbox_append(
        &InboxWriteHook::default(),
        &other,
        &bob_state,
        10,
        &enrolled,
        Some(&channel(&desk.carol)),
        Some(&pow("nonce-b", "0")),
    )
    .unwrap();
    assert!(carol.decision.allow_append);
    assert_eq!(carol.learned_writer(), Some(desk.carol.account()));
    assert!(carol.state.spent.iter().any(|item| item == "nonce-b"));
    assert_eq!(carol.state.known_senders.len(), 2);
}

#[test]
fn fabricated_quota_and_difficulty_do_not_refill() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let claimed_remaining = 99u64;
    let claimed_difficulty = 1u32;
    let _ = (claimed_remaining, claimed_difficulty);
    let mut state = open_state(3, 4);
    state.known_senders = vec![desk.bob.account().to_string()];
    state.sender_quotas = vec![quota(desk.bob.account(), 0)];
    let refused = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        None,
    )
    .unwrap();
    assert_eq!(refused.decision.filter, InboxWriteFilter::SenderQuota);
    assert_unchanged(&state, &refused);

    let mut hard = open_state(3, 4);
    hard.challenges = vec![challenge("nonce-a", 16)];
    let weak = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &hard,
        10,
        &enrolled,
        Some(&signed(&desk.bob, &desk.entry.entry_id)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert_eq!(weak.decision.filter, InboxWriteFilter::StampMismatch);
    assert_unchanged(&hard, &weak);
    assert!(
        leading_zero_bits(&inbox_pow_digest("nonce-a", &desk.entry.entry_id, "0").unwrap()) < 16
    );
}

#[test]
fn omitted_admission_is_not_a_caller_flag() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = open_state(3, 4);
    let omitted = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        None,
    )
    .unwrap();
    assert_eq!(omitted.decision.filter, InboxWriteFilter::StampRequired);
    assert_unchanged(&state, &omitted);
    assert!(!state.known_senders.iter().any(|s| s == desk.bob.account()));
}

#[test]
fn sender_quota_does_not_move_another_sender_or_the_lane() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = VerifierAdmissionState {
        known_senders: vec![
            desk.bob.account().to_string(),
            desk.carol.account().to_string(),
        ],
        sender_quotas: vec![quota(desk.bob.account(), 0), quota(desk.carol.account(), 4)],
        lane_remaining: 6,
        ..VerifierAdmissionState::default()
    };
    let refused = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        None,
    )
    .unwrap();
    assert_eq!(refused.decision.filter, InboxWriteFilter::SenderQuota);
    assert_unchanged(&state, &refused);
    assert_eq!(refused.state.sender_quotas[1].remaining, 4);
    assert_eq!(refused.state.lane_remaining, 6);
}

#[test]
fn lane_capacity_is_shared_and_does_not_spend_the_sender() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = VerifierAdmissionState {
        known_senders: vec![desk.bob.account().to_string()],
        sender_quotas: vec![quota(desk.bob.account(), 5)],
        lane_remaining: 0,
        ..VerifierAdmissionState::default()
    };
    let refused = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        None,
    )
    .unwrap();
    assert_eq!(refused.decision.filter, InboxWriteFilter::ReaderCapacity);
    assert_unchanged(&state, &refused);
    assert_eq!(refused.state.sender_quotas[0].remaining, 5);
}

#[test]
fn writer_auth_runs_before_quotas_and_the_allowlist() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = VerifierAdmissionState {
        known_senders: vec![desk.bob.account().to_string()],
        sender_quotas: vec![quota(desk.bob.account(), 5)],
        lane_remaining: 5,
        ..VerifierAdmissionState::default()
    };
    let bare = filter_inbox_append(
        &InboxWriteHook {
            policy: InboxWritePolicy::NamedWriters,
            writers: vec![desk.carol.account().to_string()],
        },
        &desk.entry,
        &state,
        10,
        &enrolled,
        None,
        None,
    )
    .unwrap();
    assert_eq!(bare.decision.filter, InboxWriteFilter::WriterAuth);
    assert_unchanged(&state, &bare);

    let other = GenesisAccount::generate().unwrap().into_secret();
    let forged = WriterAppendProof {
        writer: desk.bob.account().to_string(),
        writer_pub: other.sea_pub().to_string(),
        signature: other.sign_writer_append(&desk.entry.entry_id).unwrap(),
    };
    let mismatch = filter_inbox_append(
        &InboxWriteHook {
            policy: InboxWritePolicy::NamedWriters,
            writers: vec![desk.carol.account().to_string()],
        },
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&WriterAppendAuth::Signature(forged)),
        None,
    )
    .unwrap();
    assert_eq!(mismatch.decision.filter, InboxWriteFilter::WriterAuth);
    assert_unchanged(&state, &mismatch);

    let bare_bytes = sign_sea(desk.bob.local_priv(), desk.entry.entry_id.as_bytes()).unwrap();
    let bare_proof = WriterAppendProof {
        writer: desk.bob.account().to_string(),
        writer_pub: desk.bob.sea_pub().to_string(),
        signature: bare_bytes,
    };
    let bare_sig = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&WriterAppendAuth::Signature(bare_proof)),
        None,
    )
    .unwrap();
    assert_eq!(bare_sig.decision.filter, InboxWriteFilter::WriterAuth);
    assert_unchanged(&state, &bare_sig);

    let itar = WriterAppendProof {
        writer: "itar".to_string(),
        writer_pub: desk.bob.sea_pub().to_string(),
        signature: desk.bob.sign_writer_append(&desk.entry.entry_id).unwrap(),
    };
    let forbidden = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&WriterAppendAuth::Signature(itar)),
        None,
    )
    .unwrap();
    assert_eq!(forbidden.decision.filter, InboxWriteFilter::WriterAuth);
    assert_unchanged(&state, &forbidden);
}

#[test]
fn accepting_relay_learns_the_writer_and_a_replica_does_not() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = open_state(1, 2);
    assert!(!replicated_row_admitted(&desk.entry, &state));
    let result = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert_eq!(result.learned_writer(), Some(desk.bob.account()));
    assert!(replicated_row_admitted(&desk.entry, &result.state));
    let mut swapped_body = desk.entry.clone();
    swapped_body.grant_ciphertext = "ct-other".to_string();
    assert!(!replicated_row_admitted(&swapped_body, &result.state));
    swapped_body = desk.entry.clone();
    swapped_body.commitment.hash = HASH_B.to_string();
    assert!(!replicated_row_admitted(&swapped_body, &result.state));
    swapped_body = desk.entry.clone();
    swapped_body.lane_id = "44".repeat(32);
    assert!(!replicated_row_admitted(&swapped_body, &result.state));
    swapped_body = desk.entry.clone();
    swapped_body.entry_id = "cd".repeat(32);
    assert!(!replicated_row_admitted(&swapped_body, &result.state));
    assert!(writer_from_stored_row(&desk.entry).is_none());
    assert!(!stored_row_reveals_writer(
        &desk.entry,
        desk.bob.account(),
        desk.bob.sea_pub()
    ));
    let rendered = format!("{:?}", desk.entry);
    assert!(!rendered.contains("writerPub"));
    assert!(!rendered.contains(desk.bob.sea_pub()));
    assert!(!result.grants_see());
}

#[test]
fn stamp_mismatch_replay_and_first_contact_quota() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = open_state(3, 4);
    let other = row(&desk.reader.inbox().lane_id, "ct-other", HASH_A, None);
    let wrong = desk.reader.sign_inbox_stamp(&other.entry_id).unwrap();
    let mismatched = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&signed(&desk.bob, &desk.entry.entry_id)),
        Some(&stamp(desk.reader.sea_pub(), &wrong)),
    )
    .unwrap();
    assert_eq!(mismatched.decision.filter, InboxWriteFilter::StampMismatch);
    assert_unchanged(&state, &mismatched);

    let untrusted = desk.carol.sign_inbox_stamp(&desk.entry.entry_id).unwrap();
    let foreign = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&signed(&desk.bob, &desk.entry.entry_id)),
        Some(&stamp(desk.carol.sea_pub(), &untrusted)),
    )
    .unwrap();
    assert_eq!(foreign.decision.filter, InboxWriteFilter::StampMismatch);
    assert_unchanged(&state, &foreign);

    let good = desk.reader.sign_inbox_stamp(&desk.entry.entry_id).unwrap();
    let accepted = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&signed(&desk.bob, &desk.entry.entry_id)),
        Some(&stamp(desk.reader.sea_pub(), &good)),
    )
    .unwrap();
    assert!(accepted.decision.allow_append);
    assert!(accepted.state.spent.iter().any(|item| item == &good));
    assert_eq!(accepted.state.sender_quotas[0].remaining, 2);
    assert_eq!(accepted.learned_writer(), Some(desk.bob.account()));

    let second_row = row(&desk.reader.inbox().lane_id, "ct-3", HASH_B, None);
    let replay = filter_inbox_append(
        &InboxWriteHook::default(),
        &second_row,
        &accepted.state,
        10,
        &enrolled,
        Some(&signed(&desk.bob, &second_row.entry_id)),
        Some(&stamp(desk.reader.sea_pub(), &good)),
    )
    .unwrap();
    assert_eq!(replay.decision.filter, InboxWriteFilter::Replay);
    assert_unchanged(&accepted.state, &replay);

    let mut blocked = open_state(0, 4);
    let no_quota = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &blocked,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&stamp(desk.reader.sea_pub(), &good)),
    )
    .unwrap();
    assert_eq!(no_quota.decision.filter, InboxWriteFilter::SenderQuota);
    assert_unchanged(&blocked, &no_quota);
    assert!(!no_quota
        .state
        .known_senders
        .iter()
        .any(|sender| sender == desk.bob.account()));
    blocked.first_contact_remaining = 3;
    blocked.lane_remaining = 0;
    let no_lane = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &blocked,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&stamp(desk.reader.sea_pub(), &good)),
    )
    .unwrap();
    assert_eq!(no_lane.decision.filter, InboxWriteFilter::ReaderCapacity);
    assert!(no_lane.state.sender_quotas.is_empty());
    assert!(no_lane.state.spent.is_empty());
}

#[test]
fn named_writers_is_the_allowlist_and_public_ignores_it() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = open_state(2, 3);
    let hook = InboxWriteHook {
        policy: InboxWritePolicy::NamedWriters,
        writers: vec![desk.carol.account().to_string()],
    };
    let unnamed = filter_inbox_append(
        &hook,
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert_eq!(unnamed.decision.filter, InboxWriteFilter::UnnamedWriter);
    assert_unchanged(&state, &unnamed);

    let listed = filter_inbox_append(
        &hook,
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.carol)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert!(listed.decision.allow_append);
    assert_eq!(listed.learned_writer(), Some(desk.carol.account()));

    let public = InboxWriteHook {
        policy: InboxWritePolicy::PublicFiltered,
        writers: vec![desk.carol.account().to_string()],
    };
    let still = filter_inbox_append(
        &public,
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-b", "0")),
    )
    .unwrap();
    assert!(still.decision.allow_append);
    assert_eq!(still.learned_writer(), Some(desk.bob.account()));
}

#[test]
fn envelope_recomputes_the_entry_id() {
    let desk = desk();
    let body = inbox_body_of(&desk.entry);
    let real = inbox_entry_id(&body).unwrap();
    let claimed = "ff".repeat(32);
    let claimed_sig = desk.bob.sign_writer_append(&claimed).unwrap();
    assert!(signature_covers_claimed_id(
        &claimed,
        desk.bob.sea_pub(),
        &claimed_sig
    ));
    let bad = InboxEnvelope {
        body: body.clone(),
        entry_id: claimed,
        writer_pub: desk.bob.sea_pub().to_string(),
        writer_signature: claimed_sig,
    };
    assert_eq!(
        verify_inbox_envelope(&bad, desk.bob.sea_pub()).unwrap_err(),
        EncDiscError::RowRejected
    );
    let good_sig = desk.bob.sign_writer_append(&real).unwrap();
    let good = InboxEnvelope {
        body,
        entry_id: real.clone(),
        writer_pub: desk.bob.sea_pub().to_string(),
        writer_signature: good_sig,
    };
    assert_eq!(
        verify_inbox_envelope(&good, desk.bob.sea_pub()).unwrap(),
        real
    );
    assert!(!replicated_row_admitted(
        &desk.entry,
        &VerifierAdmissionState::default()
    ));
}

#[test]
fn daily_shard_rescans_and_has_no_cursor_or_watermark() {
    assert!(!shard_scan_uses_device_cursor());
    assert!(!shard_close_watermark_implemented());
    let desk = desk();
    let lane = desk.reader.inbox().lane_id.clone();
    let first = desk.entry.clone();
    let second = row(&lane, "ct-2", HASH_A, None);
    let third = row(&lane, "ct-3", HASH_B, Some(dummy_wrap("bb")));
    let scan = DailyShardScan {
        lane_id: lane.clone(),
        day: "2026-10-16".to_string(),
        seen: vec![first.entry_id.clone()],
    };
    let found = scan_daily_shard(
        &scan,
        &[second.clone(), first.clone(), second.clone(), third.clone()],
    )
    .unwrap();
    assert_eq!(
        found
            .fresh
            .iter()
            .map(|row| row.entry_id.as_str())
            .collect::<Vec<_>>(),
        vec![second.entry_id.as_str(), third.entry_id.as_str()]
    );
    assert!(!found.grants_see());
    let late = row(&lane, "ct-late", HASH_A, None);
    let again = scan_daily_shard(
        &DailyShardScan {
            lane_id: lane.clone(),
            day: "2026-10-16".to_string(),
            seen: found.seen.clone(),
        },
        &[first, second, third, late.clone()],
    )
    .unwrap();
    assert_eq!(again.fresh.len(), 1);
    assert_eq!(again.fresh[0].entry_id, late.entry_id);

    assert!(scan_daily_shard(
        &DailyShardScan {
            lane_id: lane.clone(),
            day: "2026-02-31".to_string(),
            seen: Vec::new(),
        },
        &[],
    )
    .is_err());
    assert!(scan_daily_shard(
        &DailyShardScan {
            lane_id: lane,
            day: "2023-02-29".to_string(),
            seen: Vec::new(),
        },
        &[],
    )
    .is_err());
    let foreign = row(&"55".repeat(32), "ct-x", HASH_A, None);
    assert_eq!(
        scan_daily_shard(
            &DailyShardScan {
                lane_id: desk.reader.inbox().lane_id,
                day: "2024-02-29".to_string(),
                seen: Vec::new(),
            },
            &[foreign],
        )
        .unwrap_err(),
        EncDiscError::InboxRejected
    );
    let mut broken = row(&desk.reader.inbox().lane_id, "ct-1", HASH_A, None);
    broken.entry_id = "cd".repeat(32);
    assert_eq!(
        scan_daily_shard(
            &DailyShardScan {
                lane_id: desk.reader.inbox().lane_id.clone(),
                day: "2026-10-16".to_string(),
                seen: Vec::new(),
            },
            &[broken.clone()],
        )
        .unwrap_err(),
        EncDiscError::RowRejected
    );
    assert_eq!(
        filter_inbox_append(
            &InboxWriteHook::default(),
            &broken,
            &open_state(1, 1),
            10,
            &enroll(&desk),
            Some(&channel(&desk.bob)),
            Some(&pow("nonce-a", "0")),
        )
        .unwrap_err(),
        EncDiscError::RowRejected
    );
}

#[test]
fn oversized_rows_are_a_local_spam_drop() {
    let desk = desk();
    let huge = row(
        &desk.reader.inbox().lane_id,
        &"a".repeat(INBOX_ENTRY_MAX_BYTES + 8),
        HASH_A,
        None,
    );
    let mut unmatched = huge.clone();
    unmatched.entry_id = "cd".repeat(32);
    let state = open_state(3, 3);
    let dropped = filter_inbox_append(
        &InboxWriteHook::default(),
        &huge,
        &state,
        10,
        &enroll(&desk),
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert_eq!(dropped.decision.filter, InboxWriteFilter::Spam);
    assert_unchanged(&state, &dropped);
    let swapped = filter_inbox_append(
        &InboxWriteHook::default(),
        &unmatched,
        &state,
        10,
        &enroll(&desk),
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert_eq!(swapped.decision.filter, InboxWriteFilter::Spam);
    assert_unchanged(&state, &swapped);
}

#[test]
fn duplicate_entry_and_expired_challenge_do_not_spend() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = open_state(3, 4);
    let once = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    let duplicate = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &once.state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-b", "0")),
    )
    .unwrap();
    assert_eq!(duplicate.decision.filter, InboxWriteFilter::Replay);
    assert_unchanged(&once.state, &duplicate);
    assert!(duplicate
        .state
        .challenges
        .iter()
        .any(|item| item.nonce == "nonce-b"));

    let mut expired = open_state(3, 4);
    expired.challenges[0].expires_at = 10;
    let dead = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &expired,
        10,
        &enrolled,
        Some(&signed(&desk.bob, &desk.entry.entry_id)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert_eq!(dead.decision.filter, InboxWriteFilter::StampMismatch);
    assert_unchanged(&expired, &dead);
}

#[test]
fn known_sender_appends_without_evidence_and_a_bad_stamp_fails() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let state = VerifierAdmissionState {
        known_senders: vec![desk.bob.account().to_string()],
        sender_quotas: vec![quota(desk.bob.account(), 2)],
        lane_remaining: 2,
        stamp_issuers: vec![desk.reader.sea_pub().to_string()],
        ..VerifierAdmissionState::default()
    };
    let ok = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&signed(&desk.bob, &desk.entry.entry_id)),
        None,
    )
    .unwrap();
    assert!(ok.decision.allow_append);
    assert_eq!(ok.state.sender_quotas[0].remaining, 1);
    assert_eq!(ok.state.lane_remaining, 1);
    assert!(ok.state.spent.is_empty());
    assert_eq!(ok.learned_writer(), Some(desk.bob.account()));

    let junk = desk.carol.sign_inbox_stamp(&desk.entry.entry_id).unwrap();
    let bad = filter_inbox_append(
        &InboxWriteHook::default(),
        &row(&desk.reader.inbox().lane_id, "ct-4", HASH_A, None),
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&stamp(desk.carol.sea_pub(), &junk)),
    )
    .unwrap();
    assert_eq!(bad.decision.filter, InboxWriteFilter::StampMismatch);
    assert_unchanged(&state, &bad);
}

#[test]
fn append_and_opened_wrap_never_grant() {
    let desk = desk();
    let enrolled = enroll(&desk);
    let result = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &open_state(1, 1),
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        Some(&pow("nonce-a", "0")),
    )
    .unwrap();
    assert!(result.decision.allow_append);
    assert!(!result.grants_see());
    let dek = ItemDek::from_bytes([9u8; 32]);
    let wraps = wrap_item_dek_to_readers(
        &dek,
        1,
        "chat_p_6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5_11111111111111111111111111111111",
        &"ab".repeat(32),
        &[EnrolledSeaPub::from_account(&desk.reader)],
        &NamedSet::try_from_accessors([desk.reader.account()]).unwrap(),
    )
    .unwrap();
    let opened =
        open_reader_wrap(&wraps[0], desk.reader.local_epriv(), desk.reader.epub()).unwrap();
    assert!(!opened.grants_see());
    assert_eq!(opened.key_bytes(), dek.as_bytes());
}

#[test]
fn duplicate_quota_rows_fail_closed() {
    let desk = desk();
    let state = VerifierAdmissionState {
        known_senders: vec![desk.bob.account().to_string()],
        sender_quotas: vec![quota(desk.bob.account(), 1), quota(desk.bob.account(), 9)],
        lane_remaining: 2,
        ..VerifierAdmissionState::default()
    };
    assert_eq!(
        filter_inbox_append(
            &InboxWriteHook::default(),
            &desk.entry,
            &state,
            10,
            &enroll(&desk),
            Some(&channel(&desk.bob)),
            None,
        )
        .unwrap_err(),
        EncDiscError::InboxRejected
    );
}

#[test]
fn malformed_state_and_rows_fail_closed() {
    let desk = desk();
    let enrolled = enroll(&desk);
    assert!(InboxWritePolicy::parse("public-filtered").is_ok());
    assert!(InboxWritePolicy::parse("named-writers").is_ok());
    assert!(InboxWritePolicy::parse("public").is_err());
    assert!(InboxLane::open("").is_err());
    assert!(InboxLane::open("lightiff").is_err());

    let mut lanes = ReaderInboxes::default();
    assert_eq!(
        lanes
            .admit(&RecipientInbox {
                accessor: String::new(),
                lane_id: "66".repeat(32),
            })
            .unwrap_err(),
        EncDiscError::InboxRejected
    );

    let orphan = VerifierAdmissionState {
        sender_quotas: vec![quota(desk.bob.account(), 1)],
        lane_remaining: 1,
        ..VerifierAdmissionState::default()
    };
    assert_eq!(
        filter_inbox_append(
            &InboxWriteHook::default(),
            &desk.entry,
            &orphan,
            10,
            &enrolled,
            Some(&channel(&desk.bob)),
            None,
        )
        .unwrap_err(),
        EncDiscError::InboxRejected
    );
    let blank_nonce = VerifierAdmissionState {
        challenges: vec![challenge("", 0)],
        lane_remaining: 1,
        first_contact_remaining: 1,
        ..VerifierAdmissionState::default()
    };
    assert_eq!(
        filter_inbox_append(
            &InboxWriteHook::default(),
            &desk.entry,
            &blank_nonce,
            10,
            &enrolled,
            Some(&channel(&desk.bob)),
            Some(&pow("nonce-a", "0")),
        )
        .unwrap_err(),
        EncDiscError::InboxRejected
    );

    let mut broken = desk.entry.clone();
    broken.grant_ciphertext.clear();
    assert_eq!(
        filter_inbox_append(
            &InboxWriteHook::default(),
            &broken,
            &open_state(1, 1),
            10,
            &enrolled,
            Some(&channel(&desk.bob)),
            None,
        )
        .unwrap_err(),
        EncDiscError::RowRejected
    );
    broken = desk.entry.clone();
    broken.commitment.hash = "not-a-digest".to_string();
    assert_eq!(
        filter_inbox_append(
            &InboxWriteHook::default(),
            &broken,
            &open_state(1, 1),
            10,
            &enrolled,
            Some(&channel(&desk.bob)),
            None,
        )
        .unwrap_err(),
        EncDiscError::RowRejected
    );

    let wrong_message = writer_channel_bytes(desk.bob.account()).unwrap();
    let wrong_sig = sign_sea(desk.reader.local_priv(), &wrong_message).unwrap();
    assert!(AuthenticatedWriterChannel::open_with_possession(
        desk.bob.account(),
        desk.bob.sea_pub(),
        &wrong_sig,
    )
    .is_err());
    let wrong_pub = AuthenticatedWriterChannel::open_with_possession(
        desk.bob.account(),
        desk.reader.sea_pub(),
        &wrong_sig,
    )
    .unwrap();
    let state = VerifierAdmissionState {
        known_senders: vec![desk.bob.account().to_string()],
        lane_remaining: 2,
        ..VerifierAdmissionState::default()
    };
    let auth = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&WriterAppendAuth::Channel(wrong_pub)),
        None,
    )
    .unwrap();
    assert_eq!(auth.decision.filter, InboxWriteFilter::WriterAuth);
    assert_unchanged(&state, &auth);

    let missing_quota = filter_inbox_append(
        &InboxWriteHook::default(),
        &desk.entry,
        &state,
        10,
        &enrolled,
        Some(&channel(&desk.bob)),
        None,
    )
    .unwrap();
    assert_eq!(missing_quota.decision.filter, InboxWriteFilter::SenderQuota);

    let wrapped = row(
        &desk.reader.inbox().lane_id,
        "ct-1",
        HASH_A,
        Some(dummy_wrap("aa")),
    );
    assert!(!stored_row_reveals_writer(
        &wrapped,
        desk.bob.account(),
        desk.bob.sea_pub()
    ));

    let body = inbox_body_of(&desk.entry);
    let id = inbox_entry_id(&body).unwrap();
    let envelope = InboxEnvelope {
        body,
        entry_id: id,
        writer_pub: desk.carol.sea_pub().to_string(),
        writer_signature: desk.bob.sign_writer_append(&desk.entry.entry_id).unwrap(),
    };
    assert_eq!(
        verify_inbox_envelope(&envelope, desk.bob.sea_pub()).unwrap_err(),
        EncDiscError::PubMismatch
    );
    assert_eq!(
        scan_daily_shard(
            &DailyShardScan {
                lane_id: "itar".to_string(),
                day: "2026-10-16".to_string(),
                seen: Vec::new(),
            },
            &[],
        )
        .unwrap_err(),
        EncDiscError::InboxRejected
    );
    assert!(!signature_covers_claimed_id(
        "not-an-id",
        desk.bob.sea_pub(),
        "00"
    ));
}

#[test]
fn inbox_vectors_match_the_shared_fixture() {
    let document: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(
        document["maxEntryBytes"].as_u64().unwrap() as usize,
        INBOX_ENTRY_MAX_BYTES
    );
    assert_eq!(document["shardCloseWatermark"].as_bool(), Some(false));
    assert_eq!(document["perDeviceCursor"].as_bool(), Some(false));
    for body in document["bodies"].as_array().unwrap() {
        let wrap = body["wrap"].as_object().map(|wrap| WrappedKey {
            scope: sociacl_encdisc::WrapScope::ItemDek,
            epoch: wrap["epoch"].as_u64().unwrap(),
            target: sociacl_encdisc::WrapTarget::ReaderEpub,
            target_id: wrap["targetId"].as_str().unwrap().to_string(),
            object: wrap["object"].as_str().map(str::to_string),
            group: None,
            revision_id: wrap["revisionId"].as_str().unwrap().to_string(),
            wrapped_key: wrap["wrappedKey"].as_str().unwrap().to_string(),
        });
        let sealed = row(
            body["laneId"].as_str().unwrap(),
            body["grantCiphertext"].as_str().unwrap(),
            body["commitment"].as_str().unwrap(),
            wrap,
        );
        let bytes = inbox_entry_bytes(&inbox_body_of(&sealed)).unwrap();
        assert_eq!(sealed.entry_id, body["entryId"].as_str().unwrap());
        assert_eq!(bytes.len(), body["encodedLen"].as_u64().unwrap() as usize);
    }
    let ids: Vec<&str> = document["bodies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|body| body["entryId"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 4);
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        4
    );

    let entry_id = document["pow"]["entryId"].as_str().unwrap();
    let nonce = document["pow"]["nonce"].as_str().unwrap();
    let solution = document["pow"]["solution"].as_str().unwrap();
    let pow_bytes = inbox_pow_bytes(nonce, entry_id, solution).unwrap();
    assert_eq!(
        inbox_pow_sha256(nonce, entry_id, solution).unwrap(),
        document["pow"]["sha256"].as_str().unwrap()
    );
    assert_eq!(
        pow_bytes.len(),
        document["pow"]["encodedLen"].as_u64().unwrap() as usize
    );
    let digest = inbox_pow_digest(nonce, entry_id, solution).unwrap();
    assert!(leading_zero_bits(&digest) >= document["pow"]["difficulty"].as_u64().unwrap() as u32);
    let weak = document["pow"]["weakSolution"].as_str().unwrap();
    assert!(
        leading_zero_bits(&inbox_pow_digest(nonce, entry_id, weak).unwrap())
            < document["pow"]["difficulty"].as_u64().unwrap() as u32
    );

    let stamp_bytes = inbox_stamp_bytes(entry_id).unwrap();
    assert_eq!(
        inbox_stamp_sha256(entry_id).unwrap(),
        document["stamp"]["sha256"].as_str().unwrap()
    );
    assert_eq!(
        stamp_bytes.len(),
        document["stamp"]["encodedLen"].as_u64().unwrap() as usize
    );
    let writer_bytes = writer_append_bytes(entry_id).unwrap();
    assert_eq!(
        writer_append_sha256(entry_id).unwrap(),
        document["writerAppend"]["sha256"].as_str().unwrap()
    );
    assert_eq!(
        writer_bytes.len(),
        document["writerAppend"]["encodedLen"].as_u64().unwrap() as usize
    );
    let bare = sociacl_encdisc::sha256_hex(entry_id.as_bytes());
    assert_eq!(
        bare,
        document["writerAppend"]["bareSha256"].as_str().unwrap()
    );
    assert_ne!(bare, document["writerAppend"]["sha256"].as_str().unwrap());
    let concatenated = format!("{DOMAIN_WRITER_APPEND}{entry_id}");
    assert_eq!(
        sociacl_encdisc::sha256_hex(concatenated.as_bytes()),
        document["writerAppend"]["concatenatedSha256"]
            .as_str()
            .unwrap()
    );
    let pow_concat = format!("{DOMAIN_INBOX_POW}{nonce}{entry_id}{solution}");
    assert_ne!(
        sociacl_encdisc::sha256_hex(pow_concat.as_bytes()),
        document["pow"]["sha256"].as_str().unwrap()
    );
    let stamp_concat = format!("{DOMAIN_INBOX_STAMP}{entry_id}");
    assert_ne!(
        sociacl_encdisc::sha256_hex(stamp_concat.as_bytes()),
        document["stamp"]["sha256"].as_str().unwrap()
    );
    let _ = length_prefixed(&[DOMAIN_WRITER_APPEND, entry_id]).unwrap();

    let seen = document["shard"]["seen"].as_array().unwrap();
    let shard = document["shard"]["shard"].as_array().unwrap();
    let mut have: Vec<String> = seen
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect();
    let mut fresh = Vec::new();
    for id in shard {
        let id = id.as_str().unwrap();
        if have.iter().any(|seen| seen == id) {
            continue;
        }
        fresh.push(id.to_string());
        have.push(id.to_string());
    }
    let expected: Vec<&str> = document["shard"]["fresh"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect();
    assert_eq!(fresh, expected);
}
