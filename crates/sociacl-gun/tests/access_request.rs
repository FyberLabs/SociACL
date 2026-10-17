//! Shared access-request vectors. The TypeScript contract loads the same file.
//! A request is a hint. The helper writes owner rows. Hopcap stays 1.

use sociacl_core::{AttestationChannel, IssuerSecret, Timestamp};
use sociacl_gun::{
    accept_access_request, access_request_id, access_request_signing_bytes, factor_grants,
    grant_soul, post_grant_signing_bytes, sign_access_request, AccessRequest, GroupPredicate,
    GunAclEdge, GunError, HandoffHint, HopFactor, MembersAutoApprove, MeshSeeGrant, MeshSeeGraph,
    OwnerGrantRows, ACCESS_MESSAGE_MAX, ACCESS_REQUEST_DOMAIN, ACCESS_REQUEST_ID_DOMAIN,
    ACCESS_SCOPE_READ, ACCESS_SCOPE_READ_POST, ACCESS_STATUS_PENDING, ACCESS_STATUS_WITHDRAWN,
    MESH_REASON_DELEGATE, MESH_REASON_MISSING, MESH_REASON_POST,
};

const VECTORS: &str = include_str!("../../../vectors/mesh/access-request.json");

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    domain: String,
    id_domain: String,
    scopes: Vec<String>,
    statuses: Vec<String>,
    message_max: usize,
    factors: Vec<String>,
    signatures: Vec<SignatureCase>,
    ids: Vec<IdCase>,
    signing: Vec<SigningCase>,
    rejected: Vec<SigningCase>,
    approvals: Vec<ApprovalCase>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureCase {
    name: String,
    seed: String,
    requester: String,
    source: String,
    scope: String,
    message: String,
    status: String,
    public_key: String,
    signature: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdCase {
    name: String,
    requester: String,
    source: String,
    id: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigningCase {
    name: String,
    requester: String,
    source: String,
    scope: String,
    #[serde(default)]
    message: String,
    status: String,
    #[serde(default)]
    message_unit: Option<String>,
    #[serde(default)]
    message_repeat: Option<usize>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    hex: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalCase {
    name: String,
    mode: String,
    object: String,
    owner: String,
    #[serde(default)]
    caller: Option<String>,
    requester: String,
    source: String,
    scope: String,
    #[serde(default)]
    message: String,
    status: String,
    from: u64,
    until: u64,
    now: u64,
    expect: String,
    #[serde(default)]
    predicate: Option<String>,
    #[serde(default)]
    query_predicate: Option<String>,
    #[serde(default)]
    member: bool,
    #[serde(default)]
    cancelled: bool,
    #[serde(default)]
    set_id: Option<String>,
    #[serde(default)]
    repeat: bool,
    #[serde(default)]
    hint: bool,
    #[serde(default)]
    hop: bool,
    #[serde(default)]
    signature: Option<String>,
}

fn signer(name: &str) -> IssuerSecret {
    let mut bytes = [0u8; 32];
    for (i, b) in name.as_bytes().iter().enumerate() {
        bytes[i % 32] ^= b.wrapping_add((i as u8).wrapping_mul(17));
    }
    bytes[0] ^= name.len() as u8;
    bytes[31] |= 1;
    IssuerSecret::from_bytes(bytes)
}

fn fixture() -> Fixture {
    serde_json::from_str(VECTORS).expect("access-request vectors")
}

fn message_of(case: &SigningCase) -> String {
    match case.message_repeat {
        Some(count) => case.message_unit.clone().unwrap_or_default().repeat(count),
        None => case.message.clone(),
    }
}

fn request_of(
    requester: &str,
    source: &str,
    scope: &str,
    message: &str,
    status: &str,
) -> AccessRequest {
    AccessRequest {
        requester: requester.to_string(),
        source: source.to_string(),
        scope: scope.to_string(),
        message: message.to_string(),
        status: status.to_string(),
        signature: Vec::new(),
    }
}

fn request_from_signing(case: &SigningCase) -> AccessRequest {
    request_of(
        &case.requester,
        &case.source,
        &case.scope,
        &message_of(case),
        &case.status,
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn predicate(name: &str) -> GroupPredicate {
    match name {
        "same-group" => GroupPredicate::SameGroup,
        "named-circle" => GroupPredicate::NamedCircle,
        other => panic!("unknown predicate {other}"),
    }
}

fn reason_of(err: GunError) -> String {
    match err {
        GunError::AccessRequestField => "field".to_string(),
        GunError::AccessRequestWithdrawn => "withdrawn".to_string(),
        GunError::AccessRequestNotMember => "not-member".to_string(),
        GunError::AclOwnerOnly => "owner".to_string(),
        GunError::ObjectNotInGraph => "missing".to_string(),
        GunError::AccessRequestSignature => "signature".to_string(),
        GunError::SeeGrantCeiling => "see".to_string(),
        other => panic!("unexpected access-request error: {other}"),
    }
}

fn prepare(graph: &mut MeshSeeGraph, case: &ApprovalCase) {
    if case.object.is_empty() {
        return;
    }
    graph.put_object(&case.object, &case.owner);
    if case.mode != "members" {
        return;
    }
    let stored = case.predicate.as_deref().expect("members predicate");
    let set_id = case.set_id.as_deref().expect("members set id");
    let alice = signer("0xalice");
    let bob = signer("0xbob");
    graph.enroll_signer("0xalice", alice.verify_key()).unwrap();
    graph.enroll_signer("0xbob", bob.verify_key()).unwrap();
    graph
        .record_set_owner(&case.owner, predicate(stored), set_id)
        .unwrap();
    graph
        .name_object_set(&case.owner, &case.object, predicate(stored), set_id, &alice)
        .unwrap();
    if case.member {
        graph
            .state_membership("0xbob", predicate(stored), set_id, "0xbob", &bob)
            .unwrap();
        graph
            .state_membership(&case.owner, predicate(stored), set_id, "0xbob", &alice)
            .unwrap();
    }
    if case.cancelled {
        graph
            .cancel_membership(&case.owner, predicate(stored), set_id, "0xbob", &alice)
            .unwrap();
    }
}

fn attach_signature(graph: &mut MeshSeeGraph, case: &ApprovalCase, request: &mut AccessRequest) {
    let mode = case.signature.as_deref().unwrap_or("ok");
    if mode == "missing" {
        return;
    }
    let secret = signer("0xbob");
    if mode != "unenrolled" {
        graph
            .enroll_signer("0xbob", secret.verify_key())
            .expect("enroll requester");
    }
    let Ok(mut signature) = sign_access_request(&secret, request) else {
        return;
    };
    if mode == "bad" {
        signature[0] ^= 0xff;
    }
    request.signature = signature;
}

fn approve(graph: &mut MeshSeeGraph, case: &ApprovalCase) -> Result<OwnerGrantRows, String> {
    let mut request = request_of(
        &case.requester,
        &case.source,
        &case.scope,
        &case.message,
        &case.status,
    );
    attach_signature(graph, case, &mut request);
    let caller = case.caller.as_deref().unwrap_or(&case.owner);
    let members = if case.mode == "members" {
        let query = case
            .query_predicate
            .as_deref()
            .or(case.predicate.as_deref())
            .expect("query predicate");
        Some(MembersAutoApprove {
            predicate: predicate(query),
            now: Timestamp(case.now),
        })
    } else {
        None
    };
    graph
        .grant_approved_request(caller, &request, case.from, case.until, members)
        .map_err(reason_of)
}

fn assert_no_rows(graph: &MeshSeeGraph, case: &ApprovalCase) {
    assert!(
        graph.grant_edge(&case.object, &case.requester).is_none(),
        "{} wrote a see row",
        case.name
    );
    assert!(
        graph.post_edge(&case.object, &case.requester).is_none(),
        "{} wrote a post row",
        case.name
    );
}

fn assert_granted(graph: &MeshSeeGraph, case: &ApprovalCase, rows: &OwnerGrantRows, ham: u64) {
    let accessor = sociacl_gun::canonical_request_accessor(&case.requester).unwrap();
    assert_eq!(
        rows.request_id,
        access_request_id(&case.requester, &case.source).unwrap()
    );
    assert_eq!(rows.see.grant.object, case.object);
    assert_eq!(rows.see.grant.accessor, accessor);
    assert_eq!(rows.see.grant.stated, 1);
    assert_eq!(rows.see.ham_state, ham);
    assert_eq!(rows.see.owner, case.owner);
    assert_eq!(
        rows.see.soul.as_node_id().as_str(),
        grant_soul(&case.owner, &case.object, &accessor).as_str()
    );
    let see = graph.check_see(
        &case.source,
        &case.requester,
        Timestamp(case.now),
        None,
        None,
    );
    assert!(see.allowed, "{}", case.name);
    assert_eq!(see.reason, MESH_REASON_DELEGATE);
    assert!(!see.request_is_grant());
    let post = graph.check_post(
        &case.source,
        &case.requester,
        Timestamp(case.now),
        None,
        None,
    );
    if case.expect == "both" {
        let edge = rows.post.as_ref().expect("post row");
        assert_eq!(edge.grant.object, case.object);
        assert_eq!(edge.grant.accessor, accessor);
        assert_eq!(edge.ham_state, ham);
        assert_eq!(
            rows.post_signing_bytes.as_deref(),
            Some(post_grant_signing_bytes(&edge.grant, edge.ham_state).unwrap()).as_deref()
        );
        assert!(post.allowed, "{}", case.name);
        assert_eq!(post.reason, MESH_REASON_POST);
    } else {
        assert!(rows.post.is_none(), "{}", case.name);
        assert!(rows.post_signing_bytes.is_none(), "{}", case.name);
        assert!(!post.allowed, "{}", case.name);
        assert_eq!(post.reason, MESH_REASON_MISSING);
        assert!(graph.post_edge(&case.object, &accessor).is_none());
    }
    let by_source = graph
        .grant_edge(&case.source, &case.requester)
        .expect("source lookup");
    let by_object = graph
        .grant_edge(&case.object, &accessor)
        .expect("object lookup");
    assert_eq!(by_source.soul_key(), by_object.soul_key());
}

#[test]
fn vectors_name_the_request_encoding() {
    let fixture = fixture();
    assert_eq!(fixture.domain, ACCESS_REQUEST_DOMAIN);
    assert_eq!(fixture.id_domain, ACCESS_REQUEST_ID_DOMAIN);
    assert_eq!(
        fixture.scopes,
        vec![ACCESS_SCOPE_READ, ACCESS_SCOPE_READ_POST]
    );
    assert_eq!(
        fixture.statuses,
        vec![ACCESS_STATUS_PENDING, ACCESS_STATUS_WITHDRAWN]
    );
    assert_eq!(fixture.message_max, ACCESS_MESSAGE_MAX);
    assert_eq!(
        fixture.factors,
        vec!["hop", "hint", "wrap", "inbox", "request"]
    );
    for factor in &fixture.factors {
        assert!(!factor_grants(factor), "{factor}");
    }
}

#[test]
fn shared_ids_have_no_spelling_variant() {
    let fixture = fixture();
    for case in &fixture.ids {
        let id = access_request_id(&case.requester, &case.source).unwrap_or_else(|err| {
            panic!("{} id failed: {err}", case.name);
        });
        assert_eq!(id.len(), 64, "{}", case.name);
        assert_eq!(id, case.id, "{}", case.name);
    }
}

#[test]
fn shared_signing_bytes_match() {
    let fixture = fixture();
    for case in &fixture.signing {
        let request = request_from_signing(case);
        let bytes = access_request_signing_bytes(&request).unwrap_or_else(|err| {
            panic!("{} signing failed: {err}", case.name);
        });
        let accepted = accept_access_request(&request).unwrap();
        assert_eq!(accepted.signing_bytes, bytes, "{}", case.name);
        if let Some(id) = &case.id {
            assert_eq!(accepted.id, *id, "{}", case.name);
        }
        if let Some(expected) = &case.hex {
            assert_eq!(hex(&bytes), *expected, "{}", case.name);
        }
        assert!(accepted.id.len() == 64);
    }
}

#[test]
fn rejected_spellings_do_not_encode() {
    let fixture = fixture();
    for case in &fixture.rejected {
        let request = request_from_signing(case);
        let err = access_request_signing_bytes(&request).expect_err(&case.name);
        assert_eq!(reason_of(err), "field", "{}", case.name);
        assert!(accept_access_request(&request).is_err(), "{}", case.name);
    }
}

#[test]
fn owner_client_writes_rows_and_a_request_does_not() {
    let fixture = fixture();
    for case in &fixture.approvals {
        let mut graph = MeshSeeGraph::new();
        prepare(&mut graph, case);
        if case.expect == "accept" {
            let request = request_of(
                &case.requester,
                &case.source,
                &case.scope,
                &case.message,
                &case.status,
            );
            let accepted = accept_access_request(&request).unwrap();
            assert_eq!(accepted.id.len(), 64);
            let hint = case.hint.then(|| {
                HandoffHint::parse(&case.requester, &case.source, Some("see"), None).unwrap()
            });
            let hop = case.hop.then(|| HopFactor::Structured {
                channel: AttestationChannel::ConventionBadge,
                attestation_bytes: None,
                share_token: None,
            });
            let see = graph.check_see(
                &case.source,
                &case.requester,
                Timestamp(case.now),
                hint.as_ref(),
                hop.as_ref(),
            );
            assert!(!see.allowed, "{}", case.name);
            assert_eq!(see.reason, MESH_REASON_MISSING);
            assert!(!see.hint_is_grant());
            assert!(!see.hop_is_grant());
            assert!(!see.wrap_is_grant());
            assert!(!see.inbox_is_grant());
            assert!(!see.request_is_grant());
            assert_no_rows(&graph, case);
            continue;
        }
        let first = approve(&mut graph, case);
        match case.expect.as_str() {
            "see" | "both" => {
                let rows = first.unwrap_or_else(|err| panic!("{}: {err}", case.name));
                assert_granted(&graph, case, &rows, 1);
                if case.repeat {
                    let again = approve(&mut graph, case)
                        .unwrap_or_else(|err| panic!("{} repeat: {err}", case.name));
                    assert_granted(&graph, case, &again, 2);
                }
            }
            other => {
                let err = first.expect_err(&case.name);
                assert_eq!(err, other, "{}", case.name);
                assert_no_rows(&graph, case);
            }
        }
    }
}

#[test]
fn a_slash_id_does_not_share_a_request_with_the_flattened_item_soul() {
    let slash = access_request_id("0xbob", "a/b").unwrap();
    let flat = access_request_id("0xbob", "a_b").unwrap();
    let soul = access_request_id("0xbob", "s3rch/items/a_b").unwrap();
    assert_ne!(slash, flat);
    assert_ne!(flat, soul);
    assert_ne!(slash, soul);
    let bob = signer("0xbob");
    let mut graph = MeshSeeGraph::new();
    graph.put_object("a/b", "0xalice");
    graph.put_object("s3rch/items/a_b", "0xalice");
    graph.enroll_signer("0xbob", bob.verify_key()).unwrap();
    let mut request = request_of("0xbob", "a/b", "read", "", "pending");
    request.signature = sign_access_request(&bob, &request).unwrap();
    let mut swapped = request.clone();
    swapped.source = "s3rch/items/a_b".into();
    assert!(graph
        .grant_approved_request("0xalice", &swapped, 0, 80, None)
        .is_err());
    assert!(graph.grant_edge("a/b", "0xbob").is_none());
    assert!(graph.grant_edge("s3rch/items/a_b", "0xbob").is_none());
    graph
        .grant_approved_request("0xalice", &request, 0, 80, None)
        .unwrap();
    assert!(graph.grant_edge("a/b", "0xbob").is_some());
    assert!(graph.grant_edge("s3rch/items/a_b", "0xbob").is_none());
}

#[test]
fn user_soul_segments_and_non_http_uris_share_one_id() {
    let bob = access_request_id("bob", "room:alpha").unwrap();
    assert_eq!(
        access_request_id("s3rch/users/ bob ", "room:alpha").unwrap(),
        bob
    );
    assert_eq!(
        access_request_id("s3rch/users//bob", "room:alpha").unwrap(),
        bob
    );
    let ipfs = access_request_id("0xbob", "ipfs://cid").unwrap();
    assert_eq!(ipfs.len(), 64);
    assert_ne!(ipfs, access_request_id("0xbob", "room:alpha").unwrap());
    assert!(access_request_id("0xbob", "https://gi.rss3.io/decentralized/0xalice").is_err());
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn requester_signature_matches_the_enrolled_key() {
    let fixture = fixture();
    for case in &fixture.signatures {
        let seed = decode_hex(&case.seed);
        let secret = IssuerSecret::from_bytes(seed.as_slice().try_into().unwrap());
        assert_eq!(
            hex(&secret.verify_key().0),
            case.public_key,
            "{}",
            case.name
        );
        let mut request = request_of(
            &case.requester,
            &case.source,
            &case.scope,
            &case.message,
            &case.status,
        );
        let signed = sign_access_request(&secret, &request).unwrap();
        assert_eq!(hex(&signed), case.signature, "{}", case.name);
        request.signature = signed;
        let mut graph = MeshSeeGraph::new();
        graph.put_object(&case.source, "0xalice");
        graph
            .enroll_signer(&case.requester, secret.verify_key())
            .unwrap();
        let rows = graph
            .grant_approved_request("0xalice", &request, 0, 80, None)
            .unwrap();
        assert_eq!(rows.see.grant.stated, 1);
        request.signature[0] ^= 0xff;
        assert!(graph
            .grant_approved_request("0xalice", &request, 0, 80, None)
            .is_err());
        let mut unsigned = request_of(
            &case.requester,
            &case.source,
            &case.scope,
            &case.message,
            &case.status,
        );
        unsigned.signature.clear();
        let mut fresh = MeshSeeGraph::new();
        fresh.put_object(&case.source, "0xalice");
        fresh
            .enroll_signer(&case.requester, secret.verify_key())
            .unwrap();
        assert!(fresh
            .grant_approved_request("0xalice", &unsigned, 0, 80, None)
            .is_err());
        assert!(fresh.grant_edge(&case.source, &case.requester).is_none());
    }
}

#[test]
fn cancelled_see_at_ham_ceiling_does_not_grow_a_post() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    let bob = signer("0xbob");
    graph.enroll_signer("0xbob", bob.verify_key()).unwrap();
    graph.merge_edge(GunAclEdge::new(
        "0xalice",
        MeshSeeGrant {
            object: "room:alpha".into(),
            accessor: "0xbob".into(),
            from: Timestamp(0),
            until: Timestamp(80),
            stated: 0,
        },
        u64::MAX,
    ));
    let mut request = request_of("0xbob", "room:alpha", "read+post", "", "pending");
    request.signature = sign_access_request(&bob, &request).unwrap();
    let err = graph
        .grant_approved_request("0xalice", &request, 0, 80, None)
        .unwrap_err();
    assert_eq!(reason_of(err), "see");
    assert!(graph.post_edge("room:alpha", "0xbob").is_none());
    let see = graph.grant_edge("room:alpha", "0xbob").unwrap();
    assert_eq!(see.grant.stated, 0);
    assert_eq!(see.ham_state, u64::MAX);
}

#[test]
fn see_at_the_js_safe_ceiling_does_not_grow_a_post() {
    const JS_SAFE_INTEGER_MAX: u64 = (1 << 53) - 1;
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    let bob = signer("0xbob");
    graph.enroll_signer("0xbob", bob.verify_key()).unwrap();
    graph.merge_edge(GunAclEdge::new(
        "0xalice",
        MeshSeeGrant {
            object: "room:alpha".into(),
            accessor: "0xbob".into(),
            from: Timestamp(0),
            until: Timestamp(80),
            stated: 1,
        },
        JS_SAFE_INTEGER_MAX,
    ));
    let mut request = request_of("0xbob", "room:alpha", "read+post", "", "pending");
    request.signature = sign_access_request(&bob, &request).unwrap();
    let err = graph
        .grant_approved_request("0xalice", &request, 0, 80, None)
        .unwrap_err();
    assert_eq!(reason_of(err), "see");
    assert!(graph.post_edge("room:alpha", "0xbob").is_none());
    let see = graph.grant_edge("room:alpha", "0xbob").unwrap();
    assert_eq!(see.grant.stated, 1);
    assert_eq!(see.ham_state, JS_SAFE_INTEGER_MAX);
}

#[test]
fn encoded_item_soul_shares_the_raw_object_request_id() {
    let raw = access_request_id("0xbob", "room.alpha").unwrap();
    let soul = access_request_id("0xbob", "s3rch/items/room~1alpha").unwrap();
    assert_eq!(soul, raw);
    assert_ne!(
        sociacl_gun::acl_key(&sociacl_gun::acl_key("room.alpha")),
        sociacl_gun::acl_key("room.alpha")
    );
}

#[test]
fn dotted_principal_round_trips_through_enroll_and_approval() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room:alpha", "0xalice");
    let bob = signer("bob.name");
    graph.enroll_signer("bob.name", bob.verify_key()).unwrap();
    let canonical = sociacl_gun::canonical_request_accessor("bob.name").unwrap();
    assert_eq!(canonical, "bob.name");
    assert!(graph.enrolled_key(&canonical).is_some());
    let mut request = request_of("bob.name", "room:alpha", "read", "", "pending");
    assert_eq!(
        access_request_id(&canonical, &request.source).unwrap(),
        access_request_id(&request.requester, &request.source).unwrap()
    );
    request.signature = sign_access_request(&bob, &request).unwrap();
    let rows = graph
        .grant_approved_request("0xalice", &request, 0, 80, None)
        .unwrap();
    assert_eq!(rows.see.grant.accessor, "bob.name");
    assert!(
        graph
            .check_see("room:alpha", "bob.name", Timestamp(10), None, None)
            .allowed
    );
}

#[test]
fn folded_alias_at_the_js_safe_ceiling_does_not_grow_a_post() {
    const JS_SAFE_INTEGER_MAX: u64 = (1 << 53) - 1;
    let mut graph = MeshSeeGraph::new();
    graph.merge_edge(GunAclEdge::new(
        "0xalice",
        MeshSeeGrant::live("room", "0xbob", 0, 80),
        1,
    ));
    graph.merge_edge(GunAclEdge::new(
        "0xalice",
        MeshSeeGrant::live("s3rch/items/room", "0xbob", 0, 80),
        JS_SAFE_INTEGER_MAX,
    ));
    graph.put_object("room", "0xalice");
    let bob = signer("0xbob");
    graph.enroll_signer("0xbob", bob.verify_key()).unwrap();
    let mut request = request_of("0xbob", "room", "read+post", "", "pending");
    request.signature = sign_access_request(&bob, &request).unwrap();
    let err = graph
        .grant_approved_request("0xalice", &request, 0, 80, None)
        .unwrap_err();
    assert_eq!(reason_of(err), "see");
    assert!(graph.post_edge("room", "0xbob").is_none());
    let see = graph.grant_edge("room", "0xbob").unwrap();
    assert!(see.ham_state <= JS_SAFE_INTEGER_MAX);
}

#[test]
fn members_gate_uses_the_stored_object_id() {
    let mut graph = MeshSeeGraph::new();
    graph.put_object("room", "0xalice");
    let alice = signer("0xalice");
    let bob = signer("0xbob");
    graph.enroll_signer("0xalice", alice.verify_key()).unwrap();
    graph.enroll_signer("0xbob", bob.verify_key()).unwrap();
    graph
        .record_set_owner("0xalice", GroupPredicate::SameGroup, "0xalice/ops")
        .unwrap();
    graph
        .name_object_set(
            "0xalice",
            "room",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            &alice,
        )
        .unwrap();
    graph
        .state_membership(
            "0xbob",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &bob,
        )
        .unwrap();
    graph
        .state_membership(
            "0xalice",
            GroupPredicate::SameGroup,
            "0xalice/ops",
            "0xbob",
            &alice,
        )
        .unwrap();
    let mut request = request_of("0xbob", "s3rch/items/room", "read", "", "pending");
    request.signature = sign_access_request(&bob, &request).unwrap();
    let rows = graph
        .grant_approved_request(
            "0xalice",
            &request,
            0,
            80,
            Some(MembersAutoApprove {
                predicate: GroupPredicate::SameGroup,
                now: Timestamp(10),
            }),
        )
        .unwrap();
    assert_eq!(rows.see.grant.object, "room");
}
