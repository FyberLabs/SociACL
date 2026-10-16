//! Hidden authorship and presenter binding.
//!
//! A hop, a hint, or an opened wrap never sets `allowed`. A forbidden
//! hop fails closed. The visible row has no owner pub and no blinding.

use sociacl_encdisc::{
    binding_for, check_presented_grant, commit_grant, decode_grant_bytes, epoch_step_current,
    grant_commitment_hash, grant_payload_bytes, grant_payload_digest, open_commitment,
    open_reader_wrap, row_exposes_opening, seal_blinded_row, sha256_hex, sign_sea, verify_sea,
    AccountSeaSecret, AclScope, AclSnapshotBody, AclSnapshotEntry, AuthenticatedPresenterChannel,
    AuthorFastUnwrap, BlindedGrantRow, EnrolledSeaPub, EpochFinalization, EpochReplicaView,
    EpochStatusProof, GrantPresentation, GrantStated, GroupPredicate, HandoffHint, HopFactor,
    IdentitySeeGrant, ItemDek, LightZookie, MeshMembership, NamedSet, ObjectSetName,
    PresentedGrantInput, PresentedGroup, PresenterBinding, PresenterChallenge, SeeGraph,
    SignedGrantPayload, VerifierChallengeState, VerifierGrantRevision, VerifierGrantRevisionState,
    SETTLE_WINDOW_DEFAULT_MS,
};

const FIXTURE: &str = include_str!("../../../vectors/encrypted-discovery/sea-fixture.json");
const SNAPSHOT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ITEM: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
const OTHER_ITEM: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Obj {
    owner: String,
    version: u64,
    snapshot: String,
    grants: Vec<IdentitySeeGrant>,
    set: Option<ObjectSetName>,
    members: Vec<MeshMembership>,
}

struct MemGraph {
    objects: std::collections::BTreeMap<String, Obj>,
}

impl SeeGraph for MemGraph {
    fn has_object(&self, object: &str) -> bool {
        self.objects.contains_key(object)
    }

    fn owner_of(&self, object: &str) -> Option<&str> {
        self.objects.get(object).map(|obj| obj.owner.as_str())
    }

    fn see_grants(&self, object: &str) -> &[IdentitySeeGrant] {
        self.objects
            .get(object)
            .map(|obj| obj.grants.as_slice())
            .unwrap_or(&[])
    }

    fn object_version(&self, object: &str) -> Option<u64> {
        self.objects.get(object).map(|obj| obj.version)
    }

    fn snapshot_hash(&self, object: &str) -> Option<&str> {
        self.objects.get(object).map(|obj| obj.snapshot.as_str())
    }

    fn object_set(&self, object: &str) -> Option<ObjectSetName> {
        self.objects.get(object).and_then(|obj| obj.set.clone())
    }

    fn membership(
        &self,
        predicate: GroupPredicate,
        set_id: &str,
        accessor: &str,
    ) -> Option<MeshMembership> {
        self.objects.values().find_map(|obj| {
            obj.members
                .iter()
                .find(|edge| {
                    edge.predicate == predicate
                        && edge.set_id == set_id
                        && edge.accessor == accessor
                })
                .cloned()
        })
    }
}

struct World {
    alice: AccountSeaSecret,
    bob: AccountSeaSecret,
    carol: AccountSeaSecret,
    graph: MemGraph,
    revision: String,
    blinding: String,
}

fn secret_from(account: &str, signing: bool) -> AccountSeaSecret {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    if signing {
        return AccountSeaSecret::import_local(
            account,
            fixture["laneId"].as_str().unwrap(),
            fixture["signing"]["pub"].as_str().unwrap(),
            fixture["signing"]["priv"].as_str().unwrap(),
            fixture["encryption"]["epub"].as_str().unwrap(),
            fixture["encryption"]["epriv"].as_str().unwrap(),
        )
        .unwrap();
    }
    AccountSeaSecret::generate(account).unwrap()
}

fn world() -> World {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let alice = secret_from("0xalice", true);
    let bob = secret_from("0xbob", false);
    let carol = secret_from("0xcarol", false);
    let mut objects = std::collections::BTreeMap::new();
    objects.insert(
        "item-1".to_string(),
        Obj {
            owner: alice.account().to_string(),
            version: 7,
            snapshot: SNAPSHOT.to_string(),
            grants: Vec::new(),
            set: None,
            members: Vec::new(),
        },
    );
    World {
        alice,
        bob,
        carol,
        graph: MemGraph { objects },
        revision: fixture["revisionId"].as_str().unwrap().to_string(),
        blinding: "11".repeat(32),
    }
}

fn grant_of(world: &World, stated: GrantStated, revision: u64) -> SignedGrantPayload {
    SignedGrantPayload {
        object: "item-1".to_string(),
        accessor: world.bob.account().to_string(),
        from: 10,
        until: 40,
        stated,
        epoch: 2,
        owner: world.alice.account().to_string(),
        grant_revision: revision,
        item_ciphertext_digest: String::new(),
    }
}

fn view(world: &World) -> EpochReplicaView {
    EpochReplicaView {
        object: "item-1".to_string(),
        epoch: 9,
        previous_finalization_id: String::new(),
        seen: Vec::new(),
        winner_seen_at: 0,
        settle_window_ms: SETTLE_WINDOW_DEFAULT_MS,
        settled_revision_id: world.revision.clone(),
        settled_epoch: 2,
    }
}

fn status_for(
    world: &World,
    grant_revision: u64,
    stated: GrantStated,
    epoch: u64,
    revision_id: &str,
    signed_at: u64,
) -> EpochStatusProof {
    let mut proof = EpochStatusProof {
        object: "item-1".to_string(),
        epoch,
        revision_id: revision_id.to_string(),
        accessor: world.bob.account().to_string(),
        grant_revision,
        stated,
        signed_at,
        max_age_ms: 60_000,
        signature: String::new(),
        zookie: LightZookie {
            object: "item-1".to_string(),
            object_version: 7,
            snapshot_hash: SNAPSHOT.to_string(),
        },
    };
    proof.signature = world.alice.sign_epoch_status(&proof.body()).unwrap();
    proof
}

fn challenges(now: u64) -> VerifierChallengeState {
    VerifierChallengeState {
        outstanding: vec![
            PresenterChallenge {
                nonce: "nonce-1".to_string(),
                expires_at: now + 1_000,
                audience: "dest-a".to_string(),
            },
            PresenterChallenge {
                nonce: "nonce-2".to_string(),
                expires_at: now + 1_000,
                audience: "dest-a".to_string(),
            },
        ],
        spent: Vec::new(),
    }
}

struct Built {
    row: BlindedGrantRow,
    presentation: GrantPresentation,
    commitment: String,
}

fn build(world: &World, payload: &SignedGrantPayload, wrap: bool) -> Built {
    let commitment = commit_grant(&world.blinding, payload).unwrap();
    let hash = commitment.hash.clone();
    let wrap = if wrap {
        let readers = vec![EnrolledSeaPub::from_account(&world.bob)];
        let granted = NamedSet::try_from_accessors([world.bob.account()]).unwrap();
        Some(
            sociacl_encdisc::wrap_item_dek_to_readers(
                &ItemDek::from_bytes([7u8; 32]),
                payload.epoch,
                &payload.object,
                &world.revision,
                &readers,
                &granted,
            )
            .unwrap()
            .remove(0),
        )
    } else {
        None
    };
    let row = seal_blinded_row(
        world.alice.inbox().lane_id.as_str(),
        "ct-grant",
        commitment,
        wrap,
    )
    .unwrap();
    let presentation = world.alice.present_grant(payload, &world.blinding).unwrap();
    Built {
        row,
        presentation,
        commitment: hash,
    }
}

fn input(
    world: &World,
    built: Built,
    now: u64,
    binding: Option<PresenterBinding>,
    channel: Option<AuthenticatedPresenterChannel>,
    status: Option<EpochStatusProof>,
) -> PresentedGrantInput {
    PresentedGrantInput {
        row: built.row,
        presentation: built.presentation,
        accessor: world.bob.account().to_string(),
        now,
        skew_allowance_ms: 5_000,
        challenges: challenges(now),
        revisions: VerifierGrantRevisionState {
            current: Vec::new(),
        },
        epoch_view: view(world),
        policy_max_age_ms: 60_000,
        enrollment: vec![
            EnrolledSeaPub::from_account(&world.alice),
            EnrolledSeaPub::from_account(&world.bob),
            EnrolledSeaPub::from_account(&world.carol),
        ],
        snapshot: AclSnapshotBody {
            object_set: None,
            entries: Vec::new(),
        },
        current_acl: AclSnapshotBody {
            object_set: None,
            entries: Vec::new(),
        },
        binding,
        channel,
        status,
        group: None,
        fetched_item_digest: None,
        hint: None,
        hop: None,
    }
}

fn bound(world: &World, built: &Built, _now: u64) -> PresenterBinding {
    binding_for(&world.bob, "nonce-1", &built.commitment, "dest-a").unwrap()
}

fn decide(world: &World, now: u64) -> sociacl_encdisc::PresentedGrantDecision {
    let payload = grant_of(world, GrantStated::Live, 1);
    let built = build(world, &payload, false);
    let binding = bound(world, &built, now);
    let status = status_for(world, 1, GrantStated::Live, 2, &world.revision, now);
    check_presented_grant(
        world,
        input(world, built, now, Some(binding), None, Some(status)),
    )
}

impl SeeGraph for World {
    fn has_object(&self, object: &str) -> bool {
        self.graph.has_object(object)
    }
    fn owner_of(&self, object: &str) -> Option<&str> {
        self.graph.owner_of(object)
    }
    fn see_grants(&self, object: &str) -> &[IdentitySeeGrant] {
        self.graph.see_grants(object)
    }
    fn object_version(&self, object: &str) -> Option<u64> {
        self.graph.object_version(object)
    }
    fn snapshot_hash(&self, object: &str) -> Option<&str> {
        self.graph.snapshot_hash(object)
    }
    fn object_set(&self, object: &str) -> Option<ObjectSetName> {
        self.graph.object_set(object)
    }
    fn membership(
        &self,
        predicate: GroupPredicate,
        set_id: &str,
        accessor: &str,
    ) -> Option<MeshMembership> {
        self.graph.membership(predicate, set_id, accessor)
    }
}

fn assert_unchanged(decision: &sociacl_encdisc::PresentedGrantDecision, now: u64) {
    assert!(!decision.result.allowed);
    assert_eq!(decision.challenges.spent.len(), 0);
    assert_eq!(decision.challenges.outstanding.len(), 2);
    assert!(decision.revisions.current.is_empty());
    assert!(decision
        .challenges
        .outstanding
        .iter()
        .any(|c| c.nonce == "nonce-1" && c.expires_at == now + 1_000));
}

#[test]
fn commitment_opening_hides_the_owner_and_is_not_a_grant() {
    let world = world();
    let payload = grant_of(&world, GrantStated::Live, 4);
    let other = commit_grant(&"22".repeat(32), &payload).unwrap();
    let commitment = commit_grant(&world.blinding, &payload).unwrap();
    assert_ne!(commitment.hash, other.hash);
    let unsalted = sha256_hex(&grant_payload_bytes(&payload.body()).unwrap());
    assert_ne!(unsalted, commitment.hash);
    assert_eq!(
        commitment.hash,
        grant_commitment_hash(&world.blinding, &payload.body()).unwrap()
    );

    let built = build(&world, &payload, false);
    assert!(!row_exposes_opening(
        &built.row,
        world.alice.sea_pub(),
        &world.blinding
    ));
    let visible = format!("{:?}", built.row);
    assert!(!visible.contains(world.alice.sea_pub()));
    assert!(!visible.contains(&world.blinding));
    let opened = open_commitment(&built.row, &built.presentation).unwrap();
    assert_eq!(opened, payload);
    let mut swapped = built.presentation.clone();
    swapped.blinding = "22".repeat(32);
    assert!(open_commitment(&built.row, &swapped).is_err());

    let round = decode_grant_bytes(&built.presentation.grant_bytes).unwrap();
    assert_eq!(round.grant_revision, 4);
    assert_eq!(grant_payload_digest(&round.body()).unwrap().len(), 64);
}

#[test]
fn author_fast_unwrap_is_bound_to_the_revision() {
    let world = world();
    let dek = "ab".repeat(32);
    let local = AuthorFastUnwrap::store("item-1", 2, &world.revision, &dek).unwrap();
    assert_eq!(local.open("item-1", &world.revision).unwrap(), dek);
    let displaced = "cd".repeat(32);
    assert!(local.open("item-1", &displaced).is_err());
    assert_eq!(local.epoch(), 2);
    assert!(!local.grants_see());
    assert!(!local.scans_lane());
    assert!(!local.presents_commitment());
    let rendered = format!("{local:?}");
    assert!(!rendered.contains(&dek));
    assert!(rendered.contains("<redacted>"));
    assert!(AuthorFastUnwrap::store("item-1", 2, "short", &dek).is_err());
}

#[test]
fn presenter_nonce_allows_then_check_can_still_deny() {
    let world = world();
    let now = 20;
    let decision = decide(&world, now);
    assert!(decision.result.allowed);
    assert_eq!(decision.result.reason, "delegate");
    assert_eq!(decision.challenges.spent, vec!["nonce-1".to_string()]);
    assert_eq!(decision.challenges.outstanding.len(), 1);
    assert_eq!(decision.challenges.outstanding[0].nonce, "nonce-2");
    assert_eq!(decision.revisions.current.len(), 1);
    assert_eq!(decision.revisions.current[0].grant_revision, 1);
    assert_eq!(decision.revisions.current[0].stated, GrantStated::Live);
    assert!(!decision.revisions.current[0].payload_digest.is_empty());

    let again = {
        let payload = grant_of(&world, GrantStated::Live, 1);
        let built = build(&world, &payload, false);
        let binding = bound(&world, &built, now);
        let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
        let mut check = input(&world, built, now, Some(binding), None, Some(status));
        check.challenges = decision.challenges.clone();
        check.revisions = decision.revisions.clone();
        check_presented_grant(&world, check)
    };
    assert!(!again.result.allowed);
    assert_eq!(again.result.reason, "binding");
    assert_eq!(again.revisions, decision.revisions);
}

#[test]
fn proof_alone_and_a_bad_audience_do_not_spend() {
    let world = world();
    let now = 20;
    let payload = grant_of(&world, GrantStated::Live, 1);
    let built = build(&world, &payload, false);
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    let alone = check_presented_grant(
        &world,
        input(
            &world,
            build(&world, &payload, false),
            now,
            None,
            None,
            Some(status.clone()),
        ),
    );
    assert_eq!(alone.result.reason, "binding");
    assert_unchanged(&alone, now);

    let wrong = binding_for(&world.bob, "nonce-1", &built.commitment, "other-dest").unwrap();
    let audience = check_presented_grant(
        &world,
        input(&world, built, now, Some(wrong), None, Some(status)),
    );
    assert_eq!(audience.result.reason, "binding");
    assert_unchanged(&audience, now);
}

#[test]
fn presenter_binding_rejects_a_concatenated_string_and_a_different_key() {
    let world = world();
    let now = 20;
    let payload = grant_of(&world, GrantStated::Live, 1);
    let built = build(&world, &payload, false);
    let message =
        sociacl_encdisc::presenter_binding_bytes("nonce-1", &built.commitment, "dest-a").unwrap();
    assert!(verify_sea(
        world.bob.sea_pub(),
        &message,
        &bound(&world, &built, now).signature
    )
    .is_ok());
    let concatenated = format!(
        "s3rch-presenter-binding-v1nonce-1{}dest-a",
        built.commitment
    );
    let forged = PresenterBinding {
        nonce: "nonce-1".to_string(),
        signature: sign_sea(world.bob.local_priv(), concatenated.as_bytes()).unwrap(),
        reader_pub: world.bob.sea_pub().to_string(),
    };
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    let decision = check_presented_grant(
        &world,
        input(&world, built, now, Some(forged), None, Some(status.clone())),
    );
    assert_unchanged(&decision, now);

    let built = build(&world, &payload, false);
    let bad_key = PresenterBinding {
        nonce: "nonce-1".to_string(),
        signature: world
            .carol
            .sign_presenter_binding("nonce-1", &built.commitment, "dest-a")
            .unwrap(),
        reader_pub: world.carol.sea_pub().to_string(),
    };
    let decision = check_presented_grant(
        &world,
        input(&world, built, now, Some(bad_key), None, Some(status)),
    );
    assert_eq!(decision.result.reason, "enrollment");
    assert_unchanged(&decision, now);
}

#[test]
fn expired_challenge_fails_closed() {
    let world = world();
    let now = 20;
    let payload = grant_of(&world, GrantStated::Live, 1);
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    let mut check = input(&world, built, now, Some(binding), None, Some(status));
    check.challenges.outstanding[0].expires_at = now;
    let decision = check_presented_grant(&world, check);
    assert_eq!(decision.result.reason, "binding");
    assert!(decision.challenges.spent.is_empty());
}

#[test]
fn channel_must_match_the_accessor_and_the_enrolled_pub() {
    let world = world();
    let now = 20;
    let payload = grant_of(&world, GrantStated::Live, 1);
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    let channel =
        AuthenticatedPresenterChannel::open(world.bob.account(), world.bob.sea_pub()).unwrap();
    assert!(channel.has_transport_brand());
    let decision = check_presented_grant(
        &world,
        input(
            &world,
            build(&world, &payload, false),
            now,
            None,
            Some(channel),
            Some(status.clone()),
        ),
    );
    assert!(decision.result.allowed);
    assert!(decision.challenges.spent.is_empty());
    assert_eq!(decision.challenges.outstanding.len(), 2);

    let wrong_principal =
        AuthenticatedPresenterChannel::open(world.carol.account(), world.carol.sea_pub()).unwrap();
    let decision = check_presented_grant(
        &world,
        input(
            &world,
            build(&world, &payload, false),
            now,
            None,
            Some(wrong_principal),
            Some(status.clone()),
        ),
    );
    assert_eq!(decision.result.reason, "channel");
    assert_unchanged(&decision, now);

    let wrong_pub =
        AuthenticatedPresenterChannel::open(world.bob.account(), world.carol.sea_pub()).unwrap();
    let decision = check_presented_grant(
        &world,
        input(
            &world,
            build(&world, &payload, false),
            now,
            None,
            Some(wrong_pub),
            Some(status),
        ),
    );
    assert_eq!(decision.result.reason, "channel");
    assert_unchanged(&decision, now);
    assert!(AuthenticatedPresenterChannel::open("", world.bob.sea_pub()).is_err());
    assert!(AuthenticatedPresenterChannel::open(world.bob.account(), "not-a-key").is_err());
}

#[test]
fn a_bad_channel_does_not_spend_a_valid_nonce() {
    let world = world();
    let now = 20;
    let payload = grant_of(&world, GrantStated::Live, 1);
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    let channel =
        AuthenticatedPresenterChannel::open(world.carol.account(), world.carol.sea_pub()).unwrap();
    let decision = check_presented_grant(
        &world,
        input(
            &world,
            built,
            now,
            Some(binding),
            Some(channel),
            Some(status),
        ),
    );
    assert_eq!(decision.result.reason, "channel");
    assert_unchanged(&decision, now);
}

#[test]
fn binding_does_not_grant_when_check_denies() {
    let world = world();
    let now = 20;
    let payload = grant_of(&world, GrantStated::Cancelled, 1);
    let built = build(&world, &payload, true);
    let opened = open_reader_wrap(
        &built.row.wrap.clone().unwrap(),
        world.bob.local_epriv(),
        world.bob.epub(),
    )
    .unwrap();
    assert!(!opened.grants_see());
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Cancelled, 2, &world.revision, now);
    let mut check = input(&world, built, now, Some(binding), None, Some(status));
    check.hop = Some(HopFactor::Channel {
        name: "convention-badge".to_string(),
    });
    check.hint = Some(HandoffHint {
        principal: world.bob.account().to_string(),
        target: "item-1".to_string(),
        verb: Some("see".to_string()),
        context: None,
    });
    let decision = check_presented_grant(&world, check);
    assert!(!decision.result.allowed);
    assert_eq!(decision.result.reason, "cancelled");
    assert_eq!(decision.challenges.spent, vec!["nonce-1".to_string()]);
    assert_eq!(decision.revisions.current[0].stated, GrantStated::Cancelled);
}

#[test]
fn hop_and_wrap_do_not_mint_and_a_forbidden_hop_fails_closed() {
    let world = world();
    let now = 20;
    let live = decide(&world, now);
    assert!(live.result.allowed);
    let payload = grant_of(&world, GrantStated::Live, 1);
    let built = build(&world, &payload, true);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    let mut check = input(&world, built, now, Some(binding), None, Some(status));
    check.hop = Some(HopFactor::Channel {
        name: "enrolled-station".to_string(),
    });
    let with_hop = check_presented_grant(&world, check);
    assert!(with_hop.result.allowed);
    assert_eq!(with_hop.result.reason, live.result.reason);

    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    let mut check = input(&world, built, now, Some(binding), None, Some(status));
    check.hop = Some(HopFactor::Bytes(b"lightiff-token".to_vec()));
    let forbidden = check_presented_grant(&world, check);
    assert_eq!(forbidden.result.reason, "forbidden");
    assert_unchanged(&forbidden, now);

    for name in ["itar", "saas", "flash", "ping"] {
        let built = build(&world, &payload, false);
        let binding = bound(&world, &built, now);
        let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
        let mut check = input(&world, built, now, Some(binding), None, Some(status));
        check.hop = Some(HopFactor::Channel {
            name: name.to_string(),
        });
        let decision = check_presented_grant(&world, check);
        assert_eq!(decision.result.reason, "forbidden", "{name}");
        assert!(decision.challenges.spent.is_empty(), "{name}");
    }
}

#[test]
fn payload_mismatch_item_digest_owner_and_enrollment_fail_before_state_changes() {
    let world = world();
    let now = 20;
    let mut payload = grant_of(&world, GrantStated::Live, 1);
    payload.item_ciphertext_digest = ITEM.to_string();
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    let mut check = input(
        &world,
        built,
        now,
        Some(binding),
        None,
        Some(status.clone()),
    );
    check.presentation.grant_revision = 9;
    let mismatch = check_presented_grant(&world, check);
    assert_eq!(mismatch.result.reason, "payload");
    assert_unchanged(&mismatch, now);

    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let mut check = input(
        &world,
        built,
        now,
        Some(binding),
        None,
        Some(status.clone()),
    );
    check.fetched_item_digest = Some(OTHER_ITEM.to_string());
    let digest = check_presented_grant(&world, check);
    assert_eq!(digest.result.reason, "item-digest");
    assert_unchanged(&digest, now);

    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let mut check = input(
        &world,
        built,
        now,
        Some(binding),
        None,
        Some(status.clone()),
    );
    check.fetched_item_digest = Some(ITEM.to_string());
    assert_ne!(SNAPSHOT, ITEM);
    let ok = check_presented_grant(&world, check);
    assert!(ok.result.allowed);

    let payload = grant_of(&world, GrantStated::Live, 1);
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let check = input(
        &world,
        built,
        now,
        Some(binding),
        None,
        Some(status.clone()),
    );
    let owner = check_presented_grant(&OwnerSwap(&world), check);
    assert_eq!(owner.result.reason, "owner");
    assert_unchanged(&owner, now);

    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let mut check = input(&world, built, now, Some(binding), None, Some(status));
    check.presentation.sea_pub = world.bob.sea_pub().to_string();
    let enrolled = check_presented_grant(&world, check);
    assert_eq!(enrolled.result.reason, "enrollment");
    assert_unchanged(&enrolled, now);
}

struct OwnerSwap<'a>(&'a World);

impl SeeGraph for OwnerSwap<'_> {
    fn has_object(&self, object: &str) -> bool {
        self.0.graph.has_object(object)
    }
    fn owner_of(&self, object: &str) -> Option<&str> {
        let _ = object;
        Some(self.0.carol.account())
    }
    fn see_grants(&self, object: &str) -> &[IdentitySeeGrant] {
        self.0.graph.see_grants(object)
    }
    fn object_version(&self, object: &str) -> Option<u64> {
        self.0.graph.object_version(object)
    }
    fn snapshot_hash(&self, object: &str) -> Option<&str> {
        self.0.graph.snapshot_hash(object)
    }
}

#[test]
fn missing_owner_and_a_reader_signing_as_owner_fail_closed() {
    let world = world();
    let now = 20;
    let payload = grant_of(&world, GrantStated::Live, 1);
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    let check = input(&world, built, now, Some(binding), None, Some(status));
    let missing = check_presented_grant(&EmptyOwner(&world), check);
    assert_eq!(missing.result.reason, "owner");
    assert_unchanged(&missing, now);
}

struct EmptyOwner<'a>(&'a World);

impl SeeGraph for EmptyOwner<'_> {
    fn has_object(&self, object: &str) -> bool {
        self.0.has_object(object)
    }
    fn owner_of(&self, _object: &str) -> Option<&str> {
        None
    }
    fn see_grants(&self, object: &str) -> &[IdentitySeeGrant] {
        self.0.see_grants(object)
    }
    fn object_version(&self, object: &str) -> Option<u64> {
        self.0.object_version(object)
    }
    fn snapshot_hash(&self, object: &str) -> Option<&str> {
        self.0.snapshot_hash(object)
    }
}

#[test]
fn status_freshness_epoch_and_zookie_fail_before_a_nonce_is_spent() {
    let world = world();
    let now = 20_000;
    let payload = grant_of(&world, GrantStated::Live, 1);
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let mut stale = status_for(&world, 1, GrantStated::Live, 2, &world.revision, 0);
    stale.max_age_ms = 1_000_000;
    stale.signature = world.alice.sign_epoch_status(&stale.body()).unwrap();
    let mut check = input(&world, built, now, Some(binding), None, Some(stale));
    check.policy_max_age_ms = 1_000;
    let decision = check_presented_grant(&world, check);
    assert_eq!(decision.result.reason, "freshness");
    assert!(decision.challenges.spent.is_empty());

    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let future = status_for(
        &world,
        1,
        GrantStated::Live,
        2,
        &world.revision,
        now + 5_001,
    );
    let mut check = input(&world, built, now, Some(binding), None, Some(future));
    check.skew_allowance_ms = 5_000;
    let decision = check_presented_grant(&world, check);
    assert_eq!(decision.result.reason, "freshness");
    assert!(decision.challenges.spent.is_empty());

    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let pending = status_for(&world, 1, GrantStated::Live, 9, &"22".repeat(32), now);
    let decision = check_presented_grant(
        &world,
        input(&world, built, now, Some(binding), None, Some(pending)),
    );
    assert_eq!(decision.result.reason, "epoch");
    assert!(decision.challenges.spent.is_empty());
    assert!(decision.revisions.current.is_empty());

    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let mut zookie = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    zookie.zookie.snapshot_hash = OTHER_ITEM.to_string();
    zookie.signature = world.alice.sign_epoch_status(&zookie.body()).unwrap();
    let decision = check_presented_grant(
        &world,
        input(&world, built, now, Some(binding), None, Some(zookie)),
    );
    assert_eq!(decision.result.reason, "zookie");
    assert!(decision.challenges.spent.is_empty());

    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let mut other = status_for(&world, 1, GrantStated::Live, 2, &world.revision, now);
    other.object = "item-2".to_string();
    other.signature = world.alice.sign_epoch_status(&other.body()).unwrap();
    let decision = check_presented_grant(
        &world,
        input(&world, built, now, Some(binding), None, Some(other)),
    );
    assert_eq!(decision.result.reason, "status");
    assert!(decision.challenges.spent.is_empty());
}

#[test]
fn revision_order_tie_digest_and_empty_digest() {
    let world = world();
    let now = 20;
    let cancel = grant_of(&world, GrantStated::Cancelled, 4);
    let first = present_with(&world, &cancel, now, "nonce-1", &[]);
    assert!(!first.result.allowed);
    assert_eq!(first.revisions.current[0].stated, GrantStated::Cancelled);

    let mut live = grant_of(&world, GrantStated::Live, 4);
    live.until = 50;
    let second = present_with(&world, &live, now, "nonce-2", &first.revisions.current);
    assert_eq!(second.result.reason, "revision");
    assert_eq!(second.revisions.current[0].stated, GrantStated::Cancelled);

    let mut older = grant_of(&world, GrantStated::Live, 1);
    older.item_ciphertext_digest = String::new();
    let stale = present_with(&world, &older, now, "nonce-1", &first.revisions.current);
    assert_eq!(stale.result.reason, "revision");
    assert_eq!(stale.revisions.current[0].grant_revision, 4);

    let mut left = grant_of(&world, GrantStated::Live, 3);
    left.until = 80;
    let mut right = left.clone();
    right.until = 70;
    let left_digest = sociacl_encdisc::grant_digest(&left).unwrap();
    let right_digest = sociacl_encdisc::grant_digest(&right).unwrap();
    let (larger, smaller) = if left_digest > right_digest {
        (left, right)
    } else {
        (right, left)
    };
    let stored = present_with(&world, &larger, now, "nonce-1", &[]);
    assert!(stored.result.allowed);
    let larger_digest = stored.revisions.current[0].payload_digest.clone();
    let replaced = present_with(&world, &smaller, now, "nonce-2", &stored.revisions.current);
    assert!(replaced.result.allowed);
    assert!(replaced.revisions.current[0].payload_digest.as_str() < larger_digest.as_str());
    let rejected = present_with(&world, &larger, now, "nonce-1", &replaced.revisions.current);
    assert_eq!(rejected.result.reason, "revision");
    assert_eq!(
        rejected.revisions.current[0].payload_digest,
        replaced.revisions.current[0].payload_digest
    );

    let mut old_live = grant_of(&world, GrantStated::Live, 1);
    old_live.grant_revision = 1;
    let raised = present_proof(&world, &old_live, 5, GrantStated::Live, now, "nonce-1", &[]);
    assert_eq!(raised.result.reason, "revision");
    assert_eq!(raised.revisions.current[0].grant_revision, 5);
    assert!(raised.revisions.current[0].payload_digest.is_empty());
    let mut at_five = grant_of(&world, GrantStated::Live, 5);
    at_five.grant_revision = 5;
    let filled = present_proof(
        &world,
        &at_five,
        5,
        GrantStated::Live,
        now,
        "nonce-2",
        &raised.revisions.current,
    );
    assert!(filled.result.allowed);
    assert!(!filled.revisions.current[0].payload_digest.is_empty());
}

fn present_with(
    world: &World,
    payload: &SignedGrantPayload,
    now: u64,
    nonce: &str,
    current: &[VerifierGrantRevision],
) -> sociacl_encdisc::PresentedGrantDecision {
    present_proof(
        world,
        payload,
        payload.grant_revision,
        payload.stated,
        now,
        nonce,
        current,
    )
}

fn present_proof(
    world: &World,
    payload: &SignedGrantPayload,
    proof_revision: u64,
    proof_stated: GrantStated,
    now: u64,
    nonce: &str,
    current: &[VerifierGrantRevision],
) -> sociacl_encdisc::PresentedGrantDecision {
    let built = build(world, payload, false);
    let binding = binding_for(&world.bob, nonce, &built.commitment, "dest-a").unwrap();
    let status = status_for(
        world,
        proof_revision,
        proof_stated,
        payload.epoch,
        &world.revision,
        now,
    );
    let mut check = input(world, built, now, Some(binding), None, Some(status));
    check.revisions.current = current.to_vec();
    if payload.names_item() {
        check.fetched_item_digest = Some(payload.item_ciphertext_digest.clone());
    }
    check_presented_grant(world, check)
}

#[test]
fn a_higher_cancel_proof_updates_the_record_when_the_payload_is_older() {
    let world = world();
    let now = 20;
    let live = grant_of(&world, GrantStated::Live, 1);
    let first = present_with(&world, &live, now, "nonce-1", &[]);
    assert!(first.result.allowed);
    let older = grant_of(&world, GrantStated::Live, 1);
    let decision = present_proof(
        &world,
        &older,
        2,
        GrantStated::Cancelled,
        now,
        "nonce-2",
        &first.revisions.current,
    );
    assert_eq!(decision.result.reason, "revision");
    assert_eq!(decision.revisions.current[0].grant_revision, 2);
    assert_eq!(decision.revisions.current[0].stated, GrantStated::Cancelled);
    assert!(decision.revisions.current[0].payload_digest.is_empty());
    assert_eq!(decision.challenges.spent, vec!["nonce-2".to_string()]);
}

#[test]
fn windows_are_inclusive_at_from_and_exclusive_at_until() {
    let world = world();
    let mut payload = grant_of(&world, GrantStated::Live, 1);
    payload.from = 10;
    payload.until = 40;
    let at_from = present_with(&world, &payload, 10, "nonce-1", &[]);
    assert!(at_from.result.allowed, "{}", at_from.result.reason);
    let at_until = present_with(&world, &payload, 40, "nonce-1", &[]);
    assert_eq!(at_until.result.reason, "window");
    assert!(!at_until.result.allowed);
}

#[test]
fn plaintext_grants_do_not_decide_a_private_row() {
    let mut world = world();
    world
        .graph
        .objects
        .get_mut("item-1")
        .unwrap()
        .grants
        .push(IdentitySeeGrant {
            claim_id: "item-1".to_string(),
            accessor: world.bob.account().to_string(),
            from: 0,
            until: 1,
        });
    let live = grant_of(&world, GrantStated::Live, 1);
    let decision = present_with(&world, &live, 20, "nonce-1", &[]);
    assert!(decision.result.allowed);

    let cancel = grant_of(&world, GrantStated::Cancelled, 1);
    let decision = present_with(&world, &cancel, 20, "nonce-1", &[]);
    assert!(!decision.result.allowed);
}

#[test]
fn group_check_requires_the_argument_and_the_payload_window() {
    let mut world = world();
    let object = world.graph.objects.get_mut("item-1").unwrap();
    object.set = Some(ObjectSetName {
        object: "item-1".to_string(),
        predicate: GroupPredicate::SameGroup,
        set_id: "crew".to_string(),
        stated: GrantStated::Live,
        ham_state: 1,
    });
    object.members.push(MeshMembership {
        predicate: GroupPredicate::SameGroup,
        set_id: "crew".to_string(),
        accessor: world.bob.account().to_string(),
        stated: GrantStated::Live,
        ham_state: 2,
    });
    let payload = grant_of(&world, GrantStated::Live, 1);
    let missing = present_with(&world, &payload, 20, "nonce-1", &[]);
    assert_eq!(missing.result.reason, "group");
    assert!(missing.challenges.spent.is_empty());

    let allowed = present_group(&world, &payload, 20, GrantStated::Live);
    assert!(allowed.result.allowed);
    assert_eq!(allowed.result.reason, "same-group");

    let cancel = grant_of(&world, GrantStated::Cancelled, 2);
    let denied = present_group(&world, &cancel, 20, GrantStated::Cancelled);
    assert!(!denied.result.allowed);
    assert_eq!(denied.result.reason, "cancelled");
    assert_eq!(denied.revisions.current[0].stated, GrantStated::Cancelled);

    world.graph.objects.get_mut("item-1").unwrap().members[0].stated = GrantStated::Cancelled;
    let live = grant_of(&world, GrantStated::Live, 3);
    let edge = present_group(&world, &live, 20, GrantStated::Live);
    assert!(!edge.result.allowed);
    assert_eq!(edge.result.reason, "membership");
}

fn present_group(
    world: &World,
    payload: &SignedGrantPayload,
    now: u64,
    proof_stated: GrantStated,
) -> sociacl_encdisc::PresentedGrantDecision {
    let built = build(world, payload, false);
    let binding = bound(world, &built, now);
    let status = status_for(
        world,
        payload.grant_revision,
        proof_stated,
        payload.epoch,
        &world.revision,
        now,
    );
    let mut check = input(world, built, now, Some(binding), None, Some(status));
    check.group = Some(PresentedGroup {
        predicate: GroupPredicate::SameGroup,
        set_id: "crew".to_string(),
    });
    check_presented_grant(world, check)
}

#[test]
fn read_key_stays_settled_until_the_window_and_the_snapshot_agree() {
    let world = world();
    let now = SETTLE_WINDOW_DEFAULT_MS + 10;
    let win = "22".repeat(32);
    let settled = world.revision.clone();
    let fin = EpochFinalization::seal("item-1", 1, 3, &win, vec![win.clone()], "", "sig").unwrap();
    let mut pending = view(&world);
    pending.epoch = 3;
    pending.seen = vec![fin];
    pending.winner_seen_at = now;
    pending.settle_window_ms = SETTLE_WINDOW_DEFAULT_MS;
    pending.settled_epoch = 2;
    pending.settled_revision_id = settled.clone();
    assert!(!epoch_step_current(
        &pending,
        &empty_acl(),
        &empty_acl(),
        now
    ));
    let mut payload = grant_of(&world, GrantStated::Live, 1);
    payload.epoch = 3;
    payload.from = 0;
    payload.until = now + 1;
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 3, &win, now);
    let mut check = input(&world, built, now, Some(binding), None, Some(status));
    check.epoch_view = pending.clone();
    let decision = check_presented_grant(&world, check);
    assert_eq!(decision.result.reason, "epoch");
    assert!(decision.challenges.spent.is_empty());

    let mut payload = grant_of(&world, GrantStated::Live, 1);
    payload.epoch = 2;
    payload.from = 0;
    payload.until = now + 1;
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 2, &settled, now);
    let mut check = input(&world, built, now, Some(binding), None, Some(status));
    check.epoch_view = pending.clone();
    let decision = check_presented_grant(&world, check);
    assert!(decision.result.allowed, "{}", decision.result.reason);

    let mut ready = pending.clone();
    ready.winner_seen_at = 0;
    assert!(epoch_step_current(&ready, &empty_acl(), &empty_acl(), now));
    let mut payload = grant_of(&world, GrantStated::Live, 1);
    payload.epoch = 3;
    payload.from = 0;
    payload.until = now + 1;
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 3, &win, now);
    let mut check = input(&world, built, now, Some(binding), None, Some(status));
    check.epoch_view = ready.clone();
    let decision = check_presented_grant(&world, check);
    assert!(decision.result.allowed, "{}", decision.result.reason);

    let mut payload = grant_of(&world, GrantStated::Live, 1);
    payload.epoch = 2;
    payload.from = 0;
    payload.until = now + 1;
    let built = build(&world, &payload, false);
    let binding = bound(&world, &built, now);
    let status = status_for(&world, 1, GrantStated::Live, 2, &settled, now);
    let mut check = input(&world, built, now, Some(binding), None, Some(status));
    check.epoch_view = ready;
    let decision = check_presented_grant(&world, check);
    assert_eq!(decision.result.reason, "epoch");

    let mut expired = view(&world);
    expired.seen =
        vec![EpochFinalization::seal("item-1", 1, 9, &win, vec![win.clone()], "", "").unwrap()];
    expired.winner_seen_at = 0;
    expired.epoch = 9;
    let snapshot = AclSnapshotBody {
        object_set: None,
        entries: vec![AclSnapshotEntry {
            accessor: world.bob.account().to_string(),
            grant_revision: 1,
            stated: GrantStated::Live,
            from: 0,
            until: now,
            scope: AclScope::Direct,
            set_id: String::new(),
            ham_state: 0,
        }],
    };
    assert!(!epoch_step_current(&expired, &snapshot, &snapshot, now));
}

fn empty_acl() -> AclSnapshotBody {
    AclSnapshotBody {
        object_set: None,
        entries: Vec::new(),
    }
}

#[test]
fn meta_acl_and_url_fail_closed() {
    for object in ["s3rch/meta", "s3rch/acl/0xalice", "https://example.test/a"] {
        let mut world = world();
        let obj = world.graph.objects.remove("item-1").unwrap();
        world.graph.objects.insert(object.to_string(), obj);
        let mut payload = grant_of(&world, GrantStated::Live, 1);
        payload.object = object.to_string();
        let built = build(&world, &payload, false);
        let binding = bound(&world, &built, 20);
        let mut status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, 20);
        status.object = object.to_string();
        status.zookie.object = object.to_string();
        status.signature = world.alice.sign_epoch_status(&status.body()).unwrap();
        let mut view = view(&world);
        view.object = object.to_string();
        let mut check = input(&world, built, 20, Some(binding), None, Some(status));
        check.epoch_view = view;
        let decision = check_presented_grant(&world, check);
        assert!(!decision.result.allowed, "{object}");
        assert!(
            matches!(decision.result.reason.as_str(), "meta" | "acl" | "url-leaf"),
            "{} {}",
            object,
            decision.result.reason
        );
    }
}

#[test]
fn a_tampered_entry_id_fails_closed() {
    let world = world();
    let payload = grant_of(&world, GrantStated::Live, 1);
    let mut built = build(&world, &payload, false);
    built.row.entry_id = "00".repeat(32);
    let binding = bound(&world, &built, 20);
    let status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, 20);
    let decision = check_presented_grant(
        &world,
        input(&world, built, 20, Some(binding), None, Some(status)),
    );
    assert_eq!(decision.result.reason, "entry");
    assert!(decision.challenges.spent.is_empty());
}

#[test]
fn owner_path_uses_owner_when_the_accessor_is_the_owner() {
    let world = world();
    let mut payload = grant_of(&world, GrantStated::Live, 1);
    payload.accessor = world.alice.account().to_string();
    let built = build(&world, &payload, false);
    let binding = binding_for(&world.alice, "nonce-1", &built.commitment, "dest-a").unwrap();
    let mut status = status_for(&world, 1, GrantStated::Live, 2, &world.revision, 20);
    status.accessor = world.alice.account().to_string();
    status.signature = world.alice.sign_epoch_status(&status.body()).unwrap();
    let mut check = input(&world, built, 20, Some(binding), None, Some(status));
    check.accessor = world.alice.account().to_string();
    let decision = check_presented_grant(&world, check);
    assert!(decision.result.allowed, "{}", decision.result.reason);
    assert_eq!(decision.result.reason, "owner");
}
