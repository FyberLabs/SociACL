//! Forum acceptance vectors. Dest ACL is the grant. A hint is not.
//! Resolve does not elect. Chat is a tagged item.

use p256::elliptic_curve::sec1::ToSec1Point;
use serde_json::Value;
use sociacl_gun::{
    accept_hint, accept_hint_bytes, accept_need_transition, accept_offer_transition,
    forum_agent_soul, forum_alarm_soul, forum_chat_tag, forum_chat_tag_present, forum_chat_tags,
    forum_emergency_alarm, forum_need_soul, forum_offer_soul, forum_role_soul, forum_roles_match,
    forum_subtask_soul, forum_template_soul, forum_update_soul, from_gun_node,
    is_separate_chat_soul, split_tags, to_gun_node, FeedItem, FeedSource, ForumAgentState,
    ForumAgentStatus, ForumAlarm, ForumNeed, ForumNeedSeverity, ForumOffer, ForumRoleMembership,
    ForumRoleMode, ForumTemplate, GunError, GunFeedNode, HandoffHint, HopFactor, MeshSeeGraph,
};
use sociacl_ids::{
    history_state, mint_object_id_with, object_principal, object_record_bytes, parse_object_id,
    parse_principal_id, parse_soul, principal_from_sec1, see_grant_bytes, sign_with_keyring,
    ObjectId, ObjectRecord, PrincipalId, Reason, ResolutionContext, SeeGrant,
};
use std::collections::{BTreeMap, BTreeSet};

fn vector() -> Value {
    serde_json::from_str(include_str!("../../../vectors/mesh/forums.json")).unwrap()
}

fn see_file() -> Value {
    serde_json::from_str(include_str!("../../../vectors/mesh/v2/see.json")).unwrap()
}

fn see_case<'a>(file: &'a Value, name: &str) -> &'a Value {
    file["accept"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
}

struct Hold {
    graph: MeshSeeGraph,
    jwks: sociacl_ids::Jwks,
    policy: sociacl_ids::SiwePolicy,
    links: BTreeMap<String, Value>,
    pinned: BTreeSet<String>,
    now: u64,
    owner: PrincipalId,
    accessor: PrincipalId,
    object: ObjectId,
    live: Value,
    cancel: Value,
}

impl Hold {
    fn open() -> Self {
        let file = see_file();
        let doc = vector();
        let case = see_case(&file, doc["seeCase"].as_str().unwrap());
        let record = case["steps"][0]["record"].clone();
        let live = case["steps"][1]["row"].clone();
        let cancel = case["steps"][2]["row"].clone();
        let owner: PrincipalId = record["owner"].as_str().unwrap().parse().unwrap();
        let accessor: PrincipalId = live["accessor"].as_str().unwrap().parse().unwrap();
        let object: ObjectId = record["object"].as_str().unwrap().parse().unwrap();
        let raw = &file["context"];
        let mut hold = Self {
            graph: MeshSeeGraph::new(),
            jwks: serde_json::from_value(raw["jwks"].clone()).unwrap(),
            policy: serde_json::from_value(raw["policy"].clone()).unwrap(),
            links: BTreeMap::new(),
            pinned: BTreeSet::new(),
            now: raw["now"].as_u64().unwrap(),
            owner,
            accessor,
            object,
            live,
            cancel,
        };
        hold.put(&record);
        hold
    }

    fn with_ctx(&mut self, body: impl FnOnce(&mut MeshSeeGraph, &ResolutionContext<'_>)) {
        let owner = self.owner.clone();
        let accessor = self.accessor.clone();
        let history = |principal: &PrincipalId, at, until| {
            if principal != &owner && principal != &accessor {
                return Err(Reason::MissingHistory);
            }
            Ok(history_state(principal, &[], at, until))
        };
        let ctx = ResolutionContext {
            jwks: &self.jwks,
            links: &self.links,
            revocations: &[],
            now: self.now,
            policy: &self.policy,
            pinned_iss: &self.pinned,
            history: &history,
            genesis_epub_bindings: &[],
        };
        body(&mut self.graph, &ctx);
    }

    fn put(&mut self, record: &Value) {
        self.with_ctx(|graph, ctx| {
            let owner = record["owner"].as_str().unwrap().to_string();
            let resolver =
                move |principal: &PrincipalId| (principal.as_ref() == owner).then(Vec::new);
            assert_eq!(graph.put_object(record, &resolver, ctx), Ok(true));
        });
    }

    fn admit(&mut self, row: &Value) {
        let row = row.clone();
        self.with_ctx(|graph, ctx| {
            let resolver = |_principal: &PrincipalId| Some(Vec::new());
            graph.admit_row(&row, &resolver, ctx).expect("admit");
        });
    }
}

#[test]
fn forum_vector_names_the_cases() {
    let doc = vector();
    let cases: Vec<_> = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        cases,
        [
            "check-deny-without-dest-acl",
            "cancel-visible-on-next-check",
            "sgh1-hint-alone-fails-closed",
            "resolve-need-does-not-elect",
            "chat-via-tagged-items",
            "see-gated-offer",
            "owner-or-subject-accepts",
            "decline-or-ignore-stays-open",
            "owner-reopen-clears-accepted-offer",
            "freeze-body-and-severity",
            "hop-status-chat-hint-never-mint",
        ]
    );
    assert!(doc["identity"]
        .as_str()
        .unwrap()
        .contains("GunDB SEA pubkey"));
    assert!(doc["identity"]
        .as_str()
        .unwrap()
        .contains("linked credentials"));
    let rule = doc["offerRule"].as_str().unwrap();
    assert!(rule.contains("accepted_offer"));
    assert!(rule.contains("does not elect"));
    assert!(rule.contains("body and severity stay as posted"));
    assert!(rule.contains("helper must still pass Check see"));
    assert!(rule.contains("refuses withdrawal of the offer it names"));
    assert!(rule.contains("live offer stored when that helper posted it"));
}

#[test]
fn check_deny_without_dest_acl() {
    let hold = Hold::open();
    let hint = HandoffHint::parse(
        hold.owner.as_ref(),
        hold.object.as_ref(),
        Some("see"),
        Some("forum-status"),
    )
    .unwrap();
    let hint = accept_hint(hint);
    let seen = hold
        .graph
        .check_see(&hold.object, &hold.accessor, 10, Some(&hint), None);
    assert!(!seen.allowed);
    assert_ne!(seen.reason, "owner");
    assert!(
        hold.graph
            .check_see(&hold.object, &hold.owner, 10, Some(&hint), None)
            .allowed
    );
}

#[test]
fn cancel_visible_on_next_check() {
    let mut hold = Hold::open();
    hold.admit(&hold.live.clone());
    assert!(
        hold.graph
            .check_see(&hold.object, &hold.accessor, 10, None, None)
            .allowed
    );
    hold.admit(&hold.cancel.clone());
    let next = hold
        .graph
        .check_see(&hold.object, &hold.accessor, 10, None, None);
    assert!(!next.allowed);
    assert_eq!(next.reason, "delegate");
}

#[test]
fn sgh1_hint_alone_fails_closed() {
    let hold = Hold::open();
    let hint = HandoffHint::parse(
        hold.accessor.as_ref(),
        hold.object.as_ref(),
        Some("see"),
        Some("emergency"),
    )
    .unwrap();
    let bytes = hint.encode().unwrap();
    assert_eq!(&bytes[..4], b"SGH1");
    let doc = vector();
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, doc["hint"]["hex"].as_str().unwrap());
    assert_eq!(
        hint.principal.as_str(),
        doc["hint"]["fields"]["principal"].as_str().unwrap()
    );
    assert_eq!(
        hint.target.as_str(),
        doc["hint"]["fields"]["target"].as_str().unwrap()
    );
    assert_eq!(hint.verb.as_deref(), doc["hint"]["fields"]["verb"].as_str());
    assert_eq!(
        hint.context.as_deref(),
        doc["hint"]["fields"]["context"].as_str()
    );
    let decoded = accept_hint_bytes(&bytes).unwrap();
    assert_eq!(decoded, hint);
    let hop = HopFactor::Structured {
        channel: sociacl_core::AttestationChannel::ConventionBadge,
        attestation_bytes: None,
        share_token: None,
    };
    assert!(!hop.is_grant());
    let seen = hold
        .graph
        .check_see(&hold.object, &hold.accessor, 10, Some(&decoded), Some(&hop));
    assert!(!seen.allowed);
}

fn minted(kind: &str, owner: &PrincipalId, byte: u8) -> ObjectId {
    mint_object_id_with(kind, owner, |bytes| {
        bytes.fill(byte);
        Ok(())
    })
    .unwrap()
    .object_id()
    .clone()
}

fn need_from(row: &Value, stated: u8, ham_state: u64) -> ForumNeed {
    let severity = match row["severity"].as_str().unwrap() {
        "emergency" => ForumNeedSeverity::Emergency,
        "need" => ForumNeedSeverity::Need,
        other => panic!("unknown severity {other}"),
    };
    let id: ObjectId = row["needId"].as_str().unwrap().parse().unwrap();
    let accepted_offer = if stated == 0 {
        Some(minted("offer", &object_principal(&id).unwrap(), 0x44))
    } else {
        None
    };
    ForumNeed {
        id,
        forum_id: row["needForumId"].as_str().unwrap().parse().unwrap(),
        subject: row["subject"].as_str().unwrap().parse().unwrap(),
        severity,
        body: row["name"].as_str().unwrap_or("blocked").into(),
        stated,
        ham_state,
        ts: 11,
        accepted_offer,
        spec: None,
    }
}

fn alarm_from(row: &Value) -> ForumAlarm {
    ForumAlarm {
        forum_id: row["alarmForumId"].as_str().unwrap().parse().unwrap(),
        need: row["needId"].as_str().unwrap().parse().unwrap(),
        pinned: row["pinned"].as_u64().unwrap() as u8,
    }
}

#[test]
fn resolve_need_does_not_elect() {
    let mut hold = Hold::open();
    let doc = vector();
    let row = &doc["resolve"];
    let forum: ObjectId = row["forumId"].as_str().unwrap().parse().unwrap();
    let need_id: ObjectId = row["needId"].as_str().unwrap().parse().unwrap();
    let subject: PrincipalId = row["subject"].as_str().unwrap().parse().unwrap();
    let agent: PrincipalId = doc["seaPubkey"].as_str().unwrap().parse().unwrap();
    assert_ne!(subject, agent);
    assert_ne!(object_principal(&forum).unwrap(), subject);
    assert_eq!(object_principal(&need_id).unwrap(), agent);
    assert!(row["admittedOwner"].is_null());

    let open = need_from(
        row,
        row["open"]["stated"].as_u64().unwrap() as u8,
        row["open"]["hamState"].as_u64().unwrap(),
    );
    assert!(open.validate().is_ok());
    let soul = open.soul().unwrap().join();
    assert_eq!(soul, row["soul"].as_str().unwrap());
    assert_eq!(soul, doc["souls"]["need"].as_str().unwrap());
    assert!(parse_soul(&soul).is_err());

    let alarm = alarm_from(row);
    assert_eq!(
        alarm.pins_open_emergency(&open),
        row["pinsOpen"].as_bool().unwrap()
    );
    assert!(hold.graph.admitted_owner(&need_id).is_none());
    let owner_before = hold.graph.admitted_owner(&hold.object).unwrap().0.clone();

    hold.admit(&hold.live.clone());
    hold.admit(&hold.cancel.clone());
    assert_eq!(
        hold.graph.admitted_owner(&hold.object).unwrap().0.clone(),
        owner_before
    );
    assert_eq!(owner_before, hold.owner);

    let resolved = need_from(
        row,
        row["resolved"]["stated"].as_u64().unwrap() as u8,
        row["resolved"]["hamState"].as_u64().unwrap(),
    );
    assert_eq!(resolved.stated, 0);
    assert_eq!(resolved.ham_state, open.ham_state + 1);
    assert!(resolved.validate().is_ok());
    assert_eq!(resolved.soul().unwrap().join(), soul);
    assert_eq!(
        alarm.pins_open_emergency(&resolved),
        row["pinsResolved"].as_bool().unwrap()
    );
    assert_eq!(
        accept_need_transition(&hold.graph, &open, &resolved, None, &agent, 10),
        Err(GunError::ObjectNotInGraph)
    );
    assert!(alarm.pins_open_emergency(&open));
    assert!(forum_emergency_alarm(
        &[ForumAgentState::Idle],
        Some(&alarm),
        Some(&open)
    ));
    assert!(hold.graph.admitted_owner(&need_id).is_none());
    assert_eq!(
        hold.graph.admitted_owner(&hold.object).unwrap().0.clone(),
        owner_before
    );
    let accessor = hold
        .graph
        .check_see(&hold.object, &hold.accessor, 10, None, None);
    assert!(!accessor.allowed);
    assert_ne!(accessor.reason, "owner");
    assert!(
        hold.graph
            .check_see(&hold.object, &hold.owner, 10, None, None)
            .allowed
    );
}

fn sea_signer(byte: u8) -> (PrincipalId, [u8; 32]) {
    let mut scalar = [0u8; 32];
    scalar[31] = byte;
    let secret = p256::SecretKey::from_slice(&scalar).unwrap();
    let point = secret.public_key().to_sec1_point(false);
    let principal = principal_from_sec1(point.as_bytes()).unwrap();
    (principal, scalar)
}

fn signed_object(object: &ObjectId, owner: &PrincipalId, scalar: &[u8], issued_at: u64) -> Value {
    let unsigned = ObjectRecord {
        object: object.clone(),
        owner: owner.clone(),
        issued_at,
        sig: String::new(),
    };
    let sig = sign_with_keyring(scalar, &object_record_bytes(&unsigned), owner).unwrap();
    serde_json::json!({
        "object": object.as_ref(),
        "owner": owner.as_ref(),
        "issuedAt": issued_at,
        "sig": sig,
    })
}

fn signed_see(
    owner: &PrincipalId,
    scalar: &[u8],
    object: &ObjectId,
    accessor: &PrincipalId,
    stated: u8,
    ham_state: u64,
    issued_at: u64,
) -> Value {
    let unsigned = SeeGrant {
        owner: owner.clone(),
        object: object.clone(),
        accessor: accessor.clone(),
        stated,
        from: 0,
        until: 4_000_000_000,
        ham_state,
        issued_at,
        sig: String::new(),
        attest: None,
    };
    let sig = sign_with_keyring(scalar, &see_grant_bytes(&unsigned), owner).unwrap();
    serde_json::json!({
        "owner": owner.as_ref(),
        "object": object.as_ref(),
        "accessor": accessor.as_ref(),
        "stated": stated,
        "from": 0,
        "until": 4_000_000_000u64,
        "hamState": ham_state,
        "issuedAt": issued_at,
        "sig": sig,
    })
}

#[test]
fn need_transition_checks_the_need_dest_acl() {
    let (owner, owner_scalar) = sea_signer(1);
    let (delegate, _) = sea_signer(2);
    let (stranger, _) = sea_signer(3);
    let (subject, _) = sea_signer(4);
    let forum: ObjectId = vector()["forumId"].as_str().unwrap().parse().unwrap();
    let need_id = minted("need", &owner, 0x22);
    assert_eq!(object_principal(&need_id).unwrap(), owner);
    assert_ne!(owner, delegate);
    assert_ne!(subject, delegate);

    let open = ForumNeed {
        id: need_id.clone(),
        forum_id: forum.clone(),
        subject: subject.clone(),
        severity: ForumNeedSeverity::Emergency,
        body: "blocked".into(),
        stated: 1,
        ham_state: 1,
        ts: 11,
        accepted_offer: None,
        spec: None,
    };
    let alarm = ForumAlarm {
        forum_id: forum,
        need: need_id.clone(),
        pinned: 1,
    };
    let offer = live_offer(&open, &delegate, 0x51, "help", "");
    let attack = ForumNeed {
        stated: 0,
        ham_state: 9,
        accepted_offer: Some(offer.id.clone()),
        ..open.clone()
    };

    let file = see_file();
    let raw = &file["context"];
    let mut graph = MeshSeeGraph::new();
    let jwks = serde_json::from_value(raw["jwks"].clone()).unwrap();
    let policy = serde_json::from_value(raw["policy"].clone()).unwrap();
    let links = BTreeMap::new();
    let pinned = BTreeSet::new();
    let now = raw["now"].as_u64().unwrap();
    let issued_at = 1_700_000_000;
    let history = |principal: &PrincipalId, at, until| Ok(history_state(principal, &[], at, until));
    let ctx = ResolutionContext {
        jwks: &jwks,
        links: &links,
        revocations: &[],
        now,
        policy: &policy,
        pinned_iss: &pinned,
        history: &history,
        genesis_epub_bindings: &[],
    };
    let resolver = |_principal: &PrincipalId| Some(Vec::new());

    assert_eq!(
        accept_need_transition(&graph, &open, &attack, Some(&offer), &stranger, now),
        Err(GunError::ObjectNotInGraph)
    );
    assert!(alarm.pins_open_emergency(&open));

    let record = signed_object(&need_id, &owner, &owner_scalar, issued_at);
    assert_eq!(graph.put_object(&record, &resolver, &ctx), Ok(true));
    let admitted_at = graph.admitted_owner(&need_id).unwrap().1;
    let hint = HandoffHint::parse(
        stranger.as_ref(),
        need_id.as_ref(),
        Some("see"),
        Some("resolve"),
    )
    .unwrap();
    assert!(
        !graph
            .check_see(&need_id, &stranger, now, Some(&hint), None)
            .allowed
    );
    assert_eq!(
        accept_need_transition(&graph, &open, &attack, Some(&offer), &stranger, now),
        Err(GunError::ForumSoul)
    );
    assert!(alarm.pins_open_emergency(&open));
    assert!(forum_emergency_alarm(
        &[ForumAgentState::Idle],
        Some(&alarm),
        Some(&open)
    ));
    assert_eq!(graph.admitted_owner(&need_id).unwrap().0, &owner);
    assert_eq!(graph.admitted_owner(&need_id).unwrap().1, admitted_at);

    let same_ham = ForumNeed {
        stated: 0,
        ham_state: 1,
        accepted_offer: Some(offer.id.clone()),
        ..open.clone()
    };
    assert_eq!(
        accept_need_transition(&graph, &open, &same_ham, Some(&offer), &owner, now),
        Err(GunError::ForumSoul)
    );

    let grant = signed_see(&owner, &owner_scalar, &need_id, &delegate, 1, 4, issued_at);
    graph
        .admit_row(&grant, &resolver, &ctx)
        .expect("delegate grant");
    assert_eq!(
        accept_need_transition(&graph, &open, &attack, Some(&offer), &delegate, now),
        Err(GunError::ForumSoul)
    );
    let bumped = ForumNeed {
        ham_state: 2,
        ts: 12,
        ..open.clone()
    };
    let by_delegate = accept_need_transition(&graph, &open, &bumped, None, &delegate, now).unwrap();
    assert_eq!(by_delegate.stated, 1);
    assert!(by_delegate.accepted_offer.is_none());
    assert!(alarm.pins_open_emergency(&by_delegate));
    assert_eq!(graph.admitted_owner(&need_id).unwrap().0, &owner);
    assert_eq!(graph.admitted_owner(&need_id).unwrap().1, admitted_at);

    let bare = ForumNeed {
        stated: 0,
        ham_state: 3,
        ..open.clone()
    };
    assert!(bare.validate().is_err());
    assert_eq!(
        accept_need_transition(&graph, &open, &attack, None, &owner, now),
        Err(GunError::ForumSoul)
    );

    let cancel = signed_see(&owner, &owner_scalar, &need_id, &delegate, 0, 5, issued_at);
    graph
        .admit_row(&cancel, &resolver, &ctx)
        .expect("delegate cancel");
    let later = ForumNeed {
        ham_state: 4,
        ..open.clone()
    };
    assert_eq!(
        accept_need_transition(&graph, &open, &later, None, &delegate, now),
        Err(GunError::ForumSoul)
    );
    let by_owner = accept_need_transition(&graph, &open, &bumped, None, &owner, now).unwrap();
    assert_eq!(by_owner.stated, 1);
    assert_eq!(by_owner.soul().unwrap().join(), open.soul().unwrap().join());
    assert_eq!(graph.admitted_owner(&need_id).unwrap().0, &owner);
    assert_eq!(graph.admitted_owner(&need_id).unwrap().1, admitted_at);
}

fn live_offer(
    need: &ForumNeed,
    helper: &PrincipalId,
    nonce: u8,
    body: &str,
    artifacts: &str,
) -> ForumOffer {
    ForumOffer {
        id: minted("offer", helper, nonce),
        need: need.id.clone(),
        forum_id: need.forum_id.clone(),
        helper: helper.clone(),
        body: body.into(),
        artifacts: artifacts.into(),
        stated: 1,
    }
}

#[test]
fn alarm_pin_rows() {
    let doc = vector();
    for row in doc["alarm"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let need = need_from(row, row["stated"].as_u64().unwrap() as u8, 1);
        let alarm = alarm_from(row);
        assert_eq!(
            alarm.pins_open_emergency(&need),
            row["pins"].as_bool().unwrap(),
            "{name}"
        );
        let tiles: Vec<_> = row["tiles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tile| match tile.as_str().unwrap() {
                "idle" => ForumAgentState::Idle,
                "working" => ForumAgentState::Working,
                "needs" => ForumAgentState::Needs,
                "emergency" => ForumAgentState::Emergency,
                other => panic!("unknown tile {other}"),
            })
            .collect();
        assert_eq!(
            forum_emergency_alarm(&tiles, Some(&alarm), Some(&need)),
            row["alarm"].as_bool().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn role_mode_rows() {
    let doc = vector();
    for row in doc["roles"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let mode = ForumRoleMode::parse(row["mode"].as_str().unwrap()).unwrap();
        let rows: Vec<_> = row["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| ForumRoleMembership {
                role: item["role"].as_str().unwrap().into(),
                principal: item["principal"].as_str().unwrap().parse().unwrap(),
            })
            .collect();
        assert_eq!(
            forum_roles_match(mode, &rows),
            row["accept"].as_bool().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn chat_via_tagged_items() {
    let doc = vector();
    let forum: ObjectId = doc["forumId"].as_str().unwrap().parse().unwrap();
    let tag = forum_chat_tag(&forum).unwrap();
    assert_eq!(tag, doc["souls"]["chatTag"].as_str().unwrap());
    let chat = &doc["chat"];
    let extras: Vec<_> = chat["extra"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let tags = forum_chat_tags(&forum, extras).unwrap();
    assert_eq!(tags, chat["joined"].as_str().unwrap());
    let dupes: Vec<_> = chat["duplicateExtra"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        forum_chat_tags(&forum, dupes).unwrap(),
        chat["duplicateJoined"].as_str().unwrap()
    );
    for rejected in chat["reject"].as_array().unwrap() {
        assert!(
            forum_chat_tags(&forum, [rejected.as_str().unwrap()]).is_err(),
            "{}",
            rejected
        );
    }
    assert!(forum_chat_tag_present(&tags, &forum));
    assert!(is_separate_chat_soul("s3rch/chat"));
    assert!(is_separate_chat_soul(
        doc["refusedChatSouls"][1].as_str().unwrap()
    ));
    assert!(!is_separate_chat_soul(&format!(
        "{}/statement-1",
        doc["chatCollection"].as_str().unwrap()
    )));
    let item = FeedItem {
        id: "statement-1".into(),
        source: FeedSource::Rss3,
        kind: "activity".into(),
        author: doc["seaPubkey"].as_str().unwrap().into(),
        body: "need tokens @treasurer".into(),
        ts: 10,
        permalink: "https://s3r.ch/forums/statement-1".into(),
        tags: tags.split(',').map(str::to_string).collect(),
        provenance: "forum".into(),
    };
    let node = to_gun_node(&item);
    assert!(node
        .tags
        .split(',')
        .any(|tag| tag == forum_chat_tag(&forum).unwrap()));
    let round = from_gun_node(&node).unwrap();
    assert!(forum_chat_tag_present(&round.tags.join(","), &forum));
    let raw = GunFeedNode {
        id: "statement-2".into(),
        source: "forum-chat".into(),
        kind: "statement".into(),
        author: doc["seaPubkey"].as_str().unwrap().into(),
        body: "emergency".into(),
        ts: 11,
        permalink: String::new(),
        tags: tag.clone(),
        provenance: "forum".into(),
    };
    assert!(from_gun_node(&raw).is_none());
    assert!(forum_chat_tag_present(&raw.tags, &forum));
    assert!(forum_chat_tags(&forum, ["s3rch/chat/1"]).is_err());
    assert!(forum_chat_tags(&forum, ["Urgent"]).is_err());
    assert!(forum_chat_tags(&forum, ["chat"]).is_err());
    assert!(forum_chat_tags(&forum, ["report,chat"]).is_err());
    let joined = forum_chat_tags(&forum, ["report"]).unwrap();
    assert!(!split_tags(&joined).iter().any(|tag| tag == "chat"));
    assert!(forum_role_soul(
        &forum,
        "chat",
        &doc["seaPubkey"].as_str().unwrap().parse().unwrap()
    )
    .is_err());
    assert!(forum_role_soul(
        &forum,
        "offers",
        &doc["seaPubkey"].as_str().unwrap().parse().unwrap()
    )
    .is_err());
}

#[test]
fn forum_souls_use_the_sea_pubkey() {
    let doc = vector();
    let forum: ObjectId = parse_object_id(doc["forumId"].as_str().unwrap()).unwrap();
    let need: ObjectId = parse_object_id(doc["needId"].as_str().unwrap()).unwrap();
    let status: ObjectId = parse_object_id(doc["statusId"].as_str().unwrap()).unwrap();
    let agent: PrincipalId = parse_principal_id(doc["seaPubkey"].as_str().unwrap()).unwrap();
    let other: PrincipalId = parse_principal_id(doc["secondPubkey"].as_str().unwrap()).unwrap();
    assert!(parse_principal_id(doc["linkedWallet"].as_str().unwrap()).is_err());
    assert!(parse_principal_id("panopticon-oauth-subject").is_err());

    let souls = &doc["souls"];
    let agent_soul = forum_agent_soul(&forum, &agent).unwrap();
    assert_eq!(agent_soul.join(), souls["agent"].as_str().unwrap());
    assert_eq!(agent_soul.segments().last().unwrap(), agent.as_ref());
    assert!(!agent_soul.segments().last().unwrap().starts_with("0x"));
    assert_eq!(agent_soul.as_forum_agent().unwrap().1, agent);
    assert!(parse_soul(&agent_soul.join()).is_err());

    let need_soul = forum_need_soul(&forum, &need).unwrap();
    assert_eq!(need_soul.join(), souls["need"].as_str().unwrap());
    assert_eq!(need_soul.as_forum_need().unwrap().1, need);
    assert!(need_soul.as_forum_offer().is_none());

    let offer: ObjectId = parse_object_id(doc["offerId"].as_str().unwrap()).unwrap();
    let spec: ObjectId = parse_object_id(doc["specId"].as_str().unwrap()).unwrap();
    let offer_soul = forum_offer_soul(&forum, &need, &offer).unwrap();
    assert_eq!(offer_soul.join(), souls["offer"].as_str().unwrap());
    assert_eq!(
        offer_soul.as_forum_offer().unwrap(),
        (forum.clone(), need.clone(), offer.clone())
    );
    assert!(offer_soul.as_forum_need().is_none());
    assert!(parse_soul(&offer_soul.join()).is_err());
    assert!(!is_separate_chat_soul(&offer_soul.join()));
    let minted_offer = minted("offer", &agent, 0x05);
    assert_eq!(minted_offer, offer);
    assert_eq!(minted("spec", &agent, 0x06), spec);

    let alarm = forum_alarm_soul(&forum).unwrap();
    assert_eq!(alarm.join(), souls["alarm"].as_str().unwrap());
    assert_eq!(alarm.as_forum_alarm().unwrap(), forum);

    let template = forum_template_soul(&forum).unwrap();
    assert_eq!(template.join(), souls["template"].as_str().unwrap());
    assert_eq!(template.as_forum_template().unwrap(), forum);

    let role = forum_role_soul(&forum, "treasurer", &agent).unwrap();
    assert_eq!(role.join(), souls["role"].as_str().unwrap());
    assert_eq!(role.as_forum_role().unwrap().1, "treasurer");
    assert!(forum_role_soul(&forum, "Treasurer", &agent).is_err());
    assert!(forum_role_soul(&forum, "practice manager", &agent).is_err());

    let sub = forum_subtask_soul(&forum, &agent, &status).unwrap();
    assert_eq!(sub.join(), souls["subtask"].as_str().unwrap());
    assert!(!is_separate_chat_soul(&sub.join()));
    let update = forum_update_soul(&forum, &agent, &need).unwrap();
    assert_eq!(update.join(), souls["update"].as_str().unwrap());
    assert!(forum_subtask_soul(
        &forum,
        &agent,
        &"ext_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .parse()
            .unwrap()
    )
    .is_err());

    let minted = mint_object_id_with("forum", &agent, |bytes| {
        bytes.fill(0x01);
        Ok(())
    })
    .unwrap();
    assert_eq!(minted.as_ref(), forum.as_ref());

    assert!(forum_agent_soul(&need, &agent).is_err());
    assert!(forum_need_soul(&forum, &forum).is_err());

    let distinct = [
        ForumRoleMembership {
            role: "treasurer".into(),
            principal: agent.clone(),
        },
        ForumRoleMembership {
            role: "secretary".into(),
            principal: other.clone(),
        },
    ];
    assert!(forum_roles_match(
        ForumRoleMode::DistinctPrincipals,
        &distinct
    ));
    assert!(!forum_roles_match(ForumRoleMode::RoleLabels, &distinct));
    let labels = [
        ForumRoleMembership {
            role: "treasurer".into(),
            principal: agent.clone(),
        },
        ForumRoleMembership {
            role: "secretary".into(),
            principal: agent.clone(),
        },
    ];
    assert!(forum_roles_match(ForumRoleMode::RoleLabels, &labels));
    assert!(!forum_roles_match(
        ForumRoleMode::DistinctPrincipals,
        &labels
    ));
    assert_eq!(
        ForumRoleMode::parse("distinct-principals"),
        Some(ForumRoleMode::DistinctPrincipals)
    );
    assert_eq!(
        ForumRoleMode::parse("role-labels"),
        Some(ForumRoleMode::RoleLabels)
    );
    assert!(ForumRoleMode::parse(" distinct-principals").is_none());

    let status_node = ForumAgentStatus {
        id: status,
        forum_id: forum.clone(),
        agent: agent.clone(),
        task: "sitrep".into(),
        result: String::new(),
        needs: need.as_ref().into(),
        progress: 40,
        state: ForumAgentState::Emergency,
        last_prompt: "report".into(),
        last_update: 11,
        agent_type: "agent".into(),
        started: 1,
        tokens: 12,
        runtime: 30,
        hb: None,
        batt: None,
        link: Some(1),
        artifacts: String::new(),
    };
    assert_eq!(status_node.soul().unwrap().join(), agent_soul.join());
    assert_eq!(status_node.started, 1);
    assert_eq!(status_node.tokens, 12);
    assert_eq!(status_node.runtime, 30);

    let open = ForumNeed {
        id: need.clone(),
        forum_id: forum.clone(),
        subject: agent.clone(),
        severity: ForumNeedSeverity::Emergency,
        body: "blocked".into(),
        stated: 1,
        ham_state: 1,
        ts: 11,
        accepted_offer: None,
        spec: Some(spec),
    };
    assert!(open.validate().is_ok());
    let alarm = ForumAlarm {
        forum_id: forum.clone(),
        need: need.clone(),
        pinned: 1,
    };
    assert!(alarm.soul().is_ok());
    assert!(forum_emergency_alarm(
        &[ForumAgentState::Idle],
        Some(&alarm),
        Some(&open)
    ));
    assert!(forum_emergency_alarm(
        &[ForumAgentState::Emergency],
        None,
        None
    ));
    assert!(!forum_emergency_alarm(
        &[ForumAgentState::Working],
        None,
        None
    ));
    let mut resolved = open.clone();
    resolved.stated = 0;
    resolved.accepted_offer = Some(offer.clone());
    assert!(resolved.validate().is_ok());
    assert!(!forum_emergency_alarm(
        &[ForumAgentState::Idle],
        Some(&alarm),
        Some(&resolved)
    ));
    let template = ForumTemplate {
        forum_id: forum,
        mode: ForumRoleMode::RoleLabels,
    };
    assert!(template.validate().is_ok());
}

struct World {
    graph: MeshSeeGraph,
    jwks: sociacl_ids::Jwks,
    policy: sociacl_ids::SiwePolicy,
    links: BTreeMap<String, Value>,
    pinned: BTreeSet<String>,
    now: u64,
    issued_at: u64,
    owner: PrincipalId,
    owner_scalar: [u8; 32],
    subject: PrincipalId,
    helper: PrincipalId,
    other: PrincipalId,
    stranger: PrincipalId,
    forum: ObjectId,
    need_id: ObjectId,
    open: ForumNeed,
}

impl World {
    fn open() -> Self {
        let (owner, owner_scalar) = sea_signer(1);
        let (subject, _) = sea_signer(2);
        let (helper, _) = sea_signer(3);
        let (other, _) = sea_signer(4);
        let (stranger, _) = sea_signer(5);
        let forum: ObjectId = vector()["forumId"].as_str().unwrap().parse().unwrap();
        let need_id = minted("need", &owner, 0x22);
        let spec = minted("spec", &owner, 0x66);
        let file = see_file();
        let raw = &file["context"];
        let now = raw["now"].as_u64().unwrap();
        let issued_at = 1_700_000_000;
        let mut world = Self {
            graph: MeshSeeGraph::new(),
            jwks: serde_json::from_value(raw["jwks"].clone()).unwrap(),
            policy: serde_json::from_value(raw["policy"].clone()).unwrap(),
            links: BTreeMap::new(),
            pinned: BTreeSet::new(),
            now,
            issued_at,
            owner: owner.clone(),
            owner_scalar,
            subject: subject.clone(),
            helper,
            other,
            stranger,
            forum: forum.clone(),
            need_id: need_id.clone(),
            open: ForumNeed {
                id: need_id,
                forum_id: forum,
                subject,
                severity: ForumNeedSeverity::Emergency,
                body: "blocked".into(),
                stated: 1,
                ham_state: 1,
                ts: 11,
                accepted_offer: None,
                spec: Some(spec),
            },
        };
        let record = signed_object(
            &world.need_id,
            &world.owner,
            &world.owner_scalar,
            world.issued_at,
        );
        world.with_ctx(|graph, ctx| {
            let resolver = |_principal: &PrincipalId| Some(Vec::new());
            assert_eq!(graph.put_object(&record, &resolver, ctx), Ok(true));
        });
        world
    }

    fn with_ctx(&mut self, body: impl FnOnce(&mut MeshSeeGraph, &ResolutionContext<'_>)) {
        let history =
            |principal: &PrincipalId, at, until| Ok(history_state(principal, &[], at, until));
        let ctx = ResolutionContext {
            jwks: &self.jwks,
            links: &self.links,
            revocations: &[],
            now: self.now,
            policy: &self.policy,
            pinned_iss: &self.pinned,
            history: &history,
            genesis_epub_bindings: &[],
        };
        body(&mut self.graph, &ctx);
    }

    fn grant(&mut self, accessor: &PrincipalId, stated: u8, ham: u64) {
        let row = signed_see(
            &self.owner,
            &self.owner_scalar,
            &self.need_id,
            accessor,
            stated,
            ham,
            self.issued_at,
        );
        self.with_ctx(|graph, ctx| {
            let resolver = |_principal: &PrincipalId| Some(Vec::new());
            graph.admit_row(&row, &resolver, ctx).expect("grant");
        });
    }

    fn offer(&self, helper: &PrincipalId, nonce: u8, body: &str, artifacts: &str) -> ForumOffer {
        live_offer(&self.open, helper, nonce, body, artifacts)
    }

    fn alarm(&self) -> ForumAlarm {
        ForumAlarm {
            forum_id: self.forum.clone(),
            need: self.need_id.clone(),
            pinned: 1,
        }
    }
}

fn accepting(current: &ForumNeed, offer: &ForumOffer, ham: u64) -> ForumNeed {
    ForumNeed {
        stated: 0,
        ham_state: ham,
        ts: current.ts + 1,
        accepted_offer: Some(offer.id.clone()),
        ..current.clone()
    }
}

#[test]
fn accept_requires_the_helper_to_still_pass_see() {
    let mut world = World::open();
    let helper = world.helper.clone();
    let owner = world.owner.clone();
    let subject = world.subject.clone();
    let offer = world.offer(&helper, 0x51, "unposted", "");
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            None,
            &offer,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let take = accepting(&world.open, &offer, 2);
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &take,
            Some(&offer),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &take,
            Some(&offer),
            &subject,
            world.now
        ),
        Err(GunError::ForumSoul)
    );

    world.grant(&helper, 1, 4);
    let posted = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &offer,
        &helper,
        world.now,
    )
    .unwrap();
    world.grant(&helper, 0, 5);
    let take_posted = accepting(&world.open, &posted, 3);
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &take_posted,
            Some(&posted),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &take_posted,
            Some(&posted),
            &subject,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(world.open.stated, 1);
    assert!(world.open.accepted_offer.is_none());
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().0,
        &owner
    );
    assert!(world.graph.admitted_owner(&posted.id).is_none());
}

#[test]
fn accept_rejects_a_fabricated_offer() {
    let mut world = World::open();
    let helper = world.helper.clone();
    let owner = world.owner.clone();
    let subject = world.subject.clone();
    world.grant(&helper, 1, 4);
    assert!(
        world
            .graph
            .check_see(&world.need_id, &helper, world.now, None, None)
            .allowed
    );
    let fabricated = world.offer(&helper, 0x51, "never posted", "");
    let take = accepting(&world.open, &fabricated, 2);
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &take,
            Some(&fabricated),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &take,
            Some(&fabricated),
            &subject,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(world.open.stated, 1);
    assert!(world.open.accepted_offer.is_none());
    assert!(world.alarm().pins_open_emergency(&world.open));
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().0,
        &owner
    );

    let posted = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &fabricated,
        &helper,
        world.now,
    )
    .unwrap();
    let mut rewritten = posted.clone();
    rewritten.body = "not the posted body".into();
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &accepting(&world.open, &rewritten, 3),
            Some(&rewritten),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let accepted = accept_need_transition(
        &world.graph,
        &world.open,
        &accepting(&world.open, &posted, 4),
        Some(&posted),
        &owner,
        world.now,
    )
    .unwrap();
    assert_eq!(accepted.stated, 0);
    assert_eq!(accepted.accepted_offer.as_ref(), Some(&posted.id));
    assert!(world.graph.admitted_owner(&posted.id).is_none());
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().0,
        &owner
    );
}

fn case_named(name: &str) {
    let doc = vector();
    assert!(doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .any(|case| case.as_str() == Some(name)));
}

#[test]
fn see_gated_offer_post() {
    case_named("see-gated-offer");
    let mut world = World::open();
    let helper = world.helper.clone();
    let other = world.other.clone();
    let stranger = world.stranger.clone();
    let offer = world.offer(&helper, 0x51, "I can help", "");
    let mut bare = MeshSeeGraph::new();
    assert_eq!(
        accept_offer_transition(&mut bare, &world.open, None, &offer, &helper, world.now),
        Err(GunError::ObjectNotInGraph)
    );
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            None,
            &offer,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let hint = HandoffHint::parse(
        stranger.as_ref(),
        world.need_id.as_ref(),
        Some("see"),
        Some("offer"),
    )
    .unwrap();
    let hop = HopFactor::Structured {
        channel: sociacl_core::AttestationChannel::ConventionBadge,
        attestation_bytes: None,
        share_token: None,
    };
    assert!(!hop.is_grant());
    assert!(
        !world
            .graph
            .check_see(
                &world.need_id,
                &stranger,
                world.now,
                Some(&hint),
                Some(&hop)
            )
            .allowed
    );
    let stranger_offer = world.offer(&stranger, 0x59, "sighting", "");
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            None,
            &stranger_offer,
            &stranger,
            world.now
        ),
        Err(GunError::ForumSoul)
    );

    world.grant(&helper, 1, 4);
    let posted = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &offer,
        &helper,
        world.now,
    )
    .unwrap();
    assert_eq!(posted.stated, 1);
    assert_eq!(posted.helper, helper);
    assert_eq!(object_principal(&posted.id).unwrap(), helper);
    assert!(world.graph.admitted_owner(&posted.id).is_none());
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().0,
        &world.owner
    );
    let foreign = world.offer(&other, 0x52, "theirs", "");
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            None,
            &foreign,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            None,
            &foreign,
            &other,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let resolved = accepting(&world.open, &posted, 2);
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &resolved,
            None,
            &foreign,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let mut cancelled = posted.clone();
    cancelled.stated = 0;
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            None,
            &cancelled,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let mut rewritten = cancelled.clone();
    rewritten.body = "rewritten".into();
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            Some(&posted),
            &rewritten,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let status: ObjectId = vector()["statusId"].as_str().unwrap().parse().unwrap();
    let mut bad = world.offer(&helper, 0x54, "files", "epriv");
    assert!(bad.validate().is_err());
    bad.artifacts = format!("{status},{status}");
    assert!(bad.validate().is_err());
    let with_art = world.offer(&helper, 0x55, "files", status.as_ref());
    assert!(with_art.validate().is_ok());
    let mut mismatched = with_art.clone();
    mismatched.helper = other.clone();
    assert!(mismatched.validate().is_err());

    world.grant(&helper, 0, 5);
    let again = world.offer(&helper, 0x53, "again", "");
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            None,
            &again,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let withdrawn = accept_offer_transition(
        &mut world.graph,
        &world.open,
        Some(&posted),
        &cancelled,
        &helper,
        world.now,
    )
    .unwrap();
    assert_eq!(withdrawn.stated, 0);
    assert_eq!(withdrawn.body, posted.body);
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            Some(&withdrawn),
            &posted,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(world.open.stated, 1);
    assert!(world.open.accepted_offer.is_none());
    assert!(world.graph.admitted_owner(&posted.id).is_none());
}

#[test]
fn owner_or_subject_accepts_one_offer() {
    case_named("owner-or-subject-accepts");
    case_named("owner-reopen-clears-accepted-offer");
    let mut world = World::open();
    let helper = world.helper.clone();
    let other = world.other.clone();
    let subject = world.subject.clone();
    let owner = world.owner.clone();
    let admitted_at = world.graph.admitted_owner(&world.need_id).unwrap().1;
    world.grant(&helper, 1, 4);
    world.grant(&other, 1, 6);
    let offer_one = world.offer(&helper, 0x51, "one", "");
    let offer_two = world.offer(&other, 0x52, "two", "");
    let first = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &offer_one,
        &helper,
        world.now,
    )
    .unwrap();
    let second = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &offer_two,
        &other,
        world.now,
    )
    .unwrap();
    let take_first = accepting(&world.open, &first, 2);
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &take_first,
            Some(&first),
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert!(
        !world
            .graph
            .check_see(&world.need_id, &subject, world.now, None, None)
            .allowed
    );
    let accepted = accept_need_transition(
        &world.graph,
        &world.open,
        &take_first,
        Some(&first),
        &subject,
        world.now,
    )
    .unwrap();
    assert_eq!(accepted.stated, 0);
    assert_eq!(accepted.accepted_offer.as_ref(), Some(&first.id));
    assert_eq!(accepted.body, world.open.body);
    assert_eq!(accepted.severity, world.open.severity);
    assert_eq!(accepted.spec, world.open.spec);
    assert_eq!(object_principal(&first.id).unwrap(), helper);
    assert!(world.graph.admitted_owner(&first.id).is_none());
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().0,
        &owner
    );
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().1,
        admitted_at
    );
    assert!(!world.alarm().pins_open_emergency(&accepted));
    let mut pull = first.clone();
    pull.stated = 0;
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &accepted,
            Some(&first),
            &pull,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &accepted,
            Some(&first),
            &pull,
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &accepted,
            Some(&first),
            &pull,
            &subject,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(accepted.stated, 0);
    assert_eq!(accepted.accepted_offer.as_ref(), Some(&first.id));
    assert_eq!(first.stated, 1);
    assert_eq!(second.stated, 1);
    assert!(second.validate().is_ok());
    let late_offer = world.offer(&helper, 0x57, "late", "");
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &accepted,
            None,
            &late_offer,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );

    let reopened = ForumNeed {
        stated: 1,
        ham_state: 3,
        accepted_offer: None,
        ..accepted.clone()
    };
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &accepted,
            &reopened,
            None,
            &subject,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(
        accept_need_transition(&world.graph, &accepted, &reopened, None, &helper, world.now),
        Err(GunError::ForumSoul)
    );
    let mut kept = reopened.clone();
    kept.accepted_offer = Some(first.id.clone());
    assert!(kept.validate().is_err());
    let opened =
        accept_need_transition(&world.graph, &accepted, &reopened, None, &owner, world.now)
            .unwrap();
    assert_eq!(opened.stated, 1);
    assert!(opened.accepted_offer.is_none());
    assert_eq!(first.stated, 1);
    assert_eq!(second.stated, 1);
    assert!(world.alarm().pins_open_emergency(&opened));
    let take_second = accepting(&opened, &second, 4);
    let again = accept_need_transition(
        &world.graph,
        &opened,
        &take_second,
        Some(&second),
        &owner,
        world.now,
    )
    .unwrap();
    assert_eq!(again.accepted_offer.as_ref(), Some(&second.id));
    assert_eq!(object_principal(&second.id).unwrap(), other);
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().0,
        &owner
    );
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().1,
        admitted_at
    );
    let switched = accepting(&again, &first, 5);
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &again,
            &switched,
            Some(&first),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let mut withdrawn = first.clone();
    withdrawn.stated = 0;
    let withdrawn = accept_offer_transition(
        &mut world.graph,
        &again,
        Some(&first),
        &withdrawn,
        &helper,
        world.now,
    )
    .unwrap();
    assert_eq!(withdrawn.stated, 0);
    assert_eq!(again.accepted_offer.as_ref(), Some(&second.id));
    let open_again = ForumNeed {
        stated: 1,
        ham_state: 6,
        accepted_offer: None,
        ..again.clone()
    };
    let opened_again =
        accept_need_transition(&world.graph, &again, &open_again, None, &owner, world.now).unwrap();
    let take_dead = accepting(&opened_again, &withdrawn, 7);
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &opened_again,
            &take_dead,
            Some(&withdrawn),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let mut foreign = second.clone();
    foreign.need = minted("need", &owner, 0x99);
    foreign.id = minted("offer", &other, 0x98);
    assert!(foreign.validate().is_ok());
    let take_foreign = accepting(&opened_again, &foreign, 8);
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &opened_again,
            &take_foreign,
            Some(&foreign),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let after = world.offer(&helper, 0x57, "after reopen", "");
    let late = accept_offer_transition(
        &mut world.graph,
        &opened_again,
        None,
        &after,
        &helper,
        world.now,
    )
    .unwrap();
    assert_eq!(late.stated, 1);
    assert_eq!(second.stated, 1);
}

#[test]
fn decline_or_ignore_leaves_the_need_open() {
    case_named("decline-or-ignore-stays-open");
    let mut world = World::open();
    let helper = world.helper.clone();
    let other = world.other.clone();
    let subject = world.subject.clone();
    let owner = world.owner.clone();
    let stranger = world.stranger.clone();
    world.grant(&helper, 1, 4);
    world.grant(&other, 1, 6);
    let offer_one = world.offer(&helper, 0x51, "one", "");
    let offer_two = world.offer(&other, 0x52, "two", "");
    let first = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &offer_one,
        &helper,
        world.now,
    )
    .unwrap();
    let second = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &offer_two,
        &other,
        world.now,
    )
    .unwrap();
    assert_eq!(world.open.stated, 1);
    assert!(world.open.accepted_offer.is_none());
    assert!(world.alarm().pins_open_emergency(&world.open));
    let mut cancel_second = second.clone();
    cancel_second.stated = 0;
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            Some(&second),
            &cancel_second,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let mut bare = MeshSeeGraph::new();
    assert_eq!(
        accept_offer_transition(
            &mut bare,
            &world.open,
            Some(&second),
            &cancel_second,
            &subject,
            world.now
        ),
        Err(GunError::ObjectNotInGraph)
    );
    let declined = accept_offer_transition(
        &mut world.graph,
        &world.open,
        Some(&second),
        &cancel_second,
        &owner,
        world.now,
    )
    .unwrap();
    assert_eq!(declined.stated, 0);
    assert_eq!(world.open.stated, 1);
    assert!(world.open.accepted_offer.is_none());
    assert!(world.alarm().pins_open_emergency(&world.open));
    assert!(
        !world
            .graph
            .check_see(&world.need_id, &subject, world.now, None, None)
            .allowed
    );
    let mut cancel_first = first.clone();
    cancel_first.stated = 0;
    let declined_by_subject = accept_offer_transition(
        &mut world.graph,
        &world.open,
        Some(&first),
        &cancel_first,
        &subject,
        world.now,
    )
    .unwrap();
    assert_eq!(declined_by_subject.stated, 0);
    assert_eq!(world.open.stated, 1);
    let owner_offer = world.offer(&owner, 0x61, "owner offer", "");
    let ignored = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &owner_offer,
        &owner,
        world.now,
    )
    .unwrap();
    assert_eq!(ignored.stated, 1);
    assert_eq!(world.open.stated, 1);
    assert!(world.open.accepted_offer.is_none());
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            Some(&ignored),
            &ForumOffer {
                stated: 0,
                ..ignored.clone()
            },
            &stranger,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().0,
        &owner
    );
}

#[test]
fn body_and_severity_stay_as_posted() {
    case_named("freeze-body-and-severity");
    let mut world = World::open();
    let helper = world.helper.clone();
    let owner = world.owner.clone();
    let subject = world.subject.clone();
    world.grant(&helper, 1, 4);
    let posted_one = world.offer(&helper, 0x51, "one", "");
    let offer = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &posted_one,
        &helper,
        world.now,
    )
    .unwrap();
    let mut changed = accepting(&world.open, &offer, 2);
    changed.body = "rewritten".into();
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &changed,
            Some(&offer),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    changed = accepting(&world.open, &offer, 2);
    changed.severity = ForumNeedSeverity::Need;
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &changed,
            Some(&offer),
            &subject,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    changed = accepting(&world.open, &offer, 2);
    changed.spec = None;
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &changed,
            Some(&offer),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    changed = accepting(&world.open, &offer, 2);
    changed.subject = helper.clone();
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &changed,
            Some(&offer),
            &owner,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let mut ham_only = world.open.clone();
    ham_only.ham_state = 2;
    ham_only.body = "rewritten".into();
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &ham_only,
            None,
            &helper,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let accepted = accept_need_transition(
        &world.graph,
        &world.open,
        &accepting(&world.open, &offer, 2),
        Some(&offer),
        &owner,
        world.now,
    )
    .unwrap();
    assert_eq!(accepted.body, "blocked");
    assert_eq!(accepted.severity, ForumNeedSeverity::Emergency);
    assert_eq!(accepted.spec, world.open.spec);
    assert_eq!(accepted.subject, subject);
}

#[test]
fn hop_status_chat_and_hint_do_not_mint() {
    case_named("hop-status-chat-hint-never-mint");
    case_named("resolve-need-does-not-elect");
    let mut world = World::open();
    let stranger = world.stranger.clone();
    let owner = world.owner.clone();
    let helper = world.helper.clone();
    let admitted_at = world.graph.admitted_owner(&world.need_id).unwrap().1;
    let hint = HandoffHint::parse(
        stranger.as_ref(),
        world.need_id.as_ref(),
        Some("see"),
        Some("offer"),
    )
    .unwrap();
    let hop = HopFactor::Structured {
        channel: sociacl_core::AttestationChannel::ConventionBadge,
        attestation_bytes: None,
        share_token: None,
    };
    assert!(!hop.is_grant());
    assert!(
        !world
            .graph
            .check_see(
                &world.need_id,
                &stranger,
                world.now,
                Some(&hint),
                Some(&hop)
            )
            .allowed
    );
    let stranger_offer = world.offer(&stranger, 0x59, "board sighting", "");
    assert_eq!(
        accept_offer_transition(
            &mut world.graph,
            &world.open,
            None,
            &stranger_offer,
            &stranger,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    assert_eq!(
        accept_need_transition(
            &world.graph,
            &world.open,
            &accepting(&world.open, &stranger_offer, 2),
            Some(&stranger_offer),
            &stranger,
            world.now
        ),
        Err(GunError::ForumSoul)
    );
    let status = ForumAgentStatus {
        id: minted("status", &helper, 0x33),
        forum_id: world.forum.clone(),
        agent: helper.clone(),
        task: "sitrep".into(),
        result: "done".into(),
        needs: world.need_id.as_ref().into(),
        progress: 40,
        state: ForumAgentState::Working,
        last_prompt: "report".into(),
        last_update: 11,
        agent_type: "agent".into(),
        started: 1,
        tokens: 12,
        runtime: 30,
        hb: None,
        batt: None,
        link: None,
        artifacts: String::new(),
    };
    assert!(status.validate().is_ok());
    assert_eq!(status.tokens, 12);
    assert_ne!(
        status.soul().unwrap().join(),
        stranger_offer.soul().unwrap().join()
    );
    let tags = forum_chat_tags(&world.forum, ["report"]).unwrap();
    assert!(forum_chat_tag_present(&tags, &world.forum));
    assert!(is_separate_chat_soul("s3rch/chat"));
    assert!(!is_separate_chat_soul(
        &stranger_offer.soul().unwrap().join()
    ));
    world.grant(&helper, 1, 4);
    let help = world.offer(&helper, 0x51, "help", "");
    let posted = accept_offer_transition(
        &mut world.graph,
        &world.open,
        None,
        &help,
        &helper,
        world.now,
    )
    .unwrap();
    let accepted = accept_need_transition(
        &world.graph,
        &world.open,
        &accepting(&world.open, &posted, 2),
        Some(&posted),
        &owner,
        world.now,
    )
    .unwrap();
    assert_eq!(accepted.stated, 0);
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().0,
        &owner
    );
    assert_eq!(
        world.graph.admitted_owner(&world.need_id).unwrap().1,
        admitted_at
    );
    assert!(world.graph.admitted_owner(&posted.id).is_none());
    assert!(world.graph.admitted_owner(&stranger_offer.id).is_none());
    assert_eq!(object_principal(&posted.id).unwrap(), helper);
    assert_eq!(status.tokens, 12);
    assert!(
        !world
            .graph
            .check_see(
                &world.need_id,
                &stranger,
                world.now,
                Some(&hint),
                Some(&hop)
            )
            .allowed
    );
}

#[test]
fn group_offer_requires_live_destination_binding_at_post_and_accept() {
    let mut world = World::open();
    let helper = world.subject.clone(); // scalar 2: the shared group's member
    let owner = world.owner.clone();
    let offer = world.offer(&helper, 0x71, "group offer", "");
    let file: Value = serde_json::from_str(include_str!("../../../vectors/mesh/v2/group.json")).unwrap();
    let steps = &file["accept"][0]["steps"];
    for index in [1, 2] {
        world.with_ctx(|graph, ctx| {
            graph.admit_membership(&steps[index]["row"], &|_| Some(Vec::new()), ctx).unwrap();
        });
    }
    assert!(accept_offer_transition(&mut world.graph, &world.open, None, &offer, &helper, 10).is_err());
    let mut edge = steps[3]["row"].clone();
    edge["object"] = world.need_id.as_ref().into();
    for (stated, ham) in [(1, 1), (0, 2)] {
        edge["stated"] = stated.into();
        edge["hamState"] = ham.into();
        let bytes = sociacl_ids::length_prefixed(&[
            "sociacl-object-set-v2", owner.as_ref(), world.need_id.as_ref(),
            "same-group", edge["set"].as_str().unwrap(), &stated.to_string(),
            &ham.to_string(), &world.issued_at.to_string(), "0",
        ]).unwrap();
        edge["sig"] = sign_with_keyring(&world.owner_scalar, &bytes, &owner).unwrap().into();
        world.with_ctx(|graph, ctx| {
            graph.admit_object_set(&edge, &|_| Some(Vec::new()), ctx).unwrap();
        });
        if stated == 1 {
            assert!(!world.graph.check_see(&world.need_id, &helper, 10, None, None).allowed);
            assert!(accept_offer_transition(&mut world.graph, &world.open, None, &offer, &helper, 10).is_ok());
            assert!(accept_need_transition(&world.graph, &world.open,
                &accepting(&world.open, &offer, 2), Some(&offer), &owner, 10).is_ok());
        } else {
            assert!(accept_need_transition(&world.graph, &world.open,
                &accepting(&world.open, &offer, 2), Some(&offer), &owner, 10).is_err());
            let another = world.offer(&helper, 0x72, "after withdrawal", "");
            assert!(accept_offer_transition(&mut world.graph, &world.open, None, &another, &helper, 10).is_err());
        }
        assert!(world.graph.admitted_owner(&offer.id).is_none());
    }
}
