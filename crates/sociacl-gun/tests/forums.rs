//! Forum acceptance vectors. Dest ACL is the grant. A hint is not.
//! Resolve does not elect. Chat is a tagged item.

use serde_json::Value;
use sociacl_gun::{
    accept_hint, accept_hint_bytes, forum_agent_soul, forum_alarm_soul, forum_chat_tag,
    forum_chat_tag_present, forum_chat_tags, forum_emergency_alarm, forum_need_soul,
    forum_role_soul, forum_roles_match, forum_subtask_soul, forum_template_soul, forum_update_soul,
    from_gun_node, is_separate_chat_soul, to_gun_node, FeedItem, FeedSource, ForumAgentState,
    ForumAgentStatus, ForumAlarm, ForumNeed, ForumNeedSeverity, ForumRoleMembership, ForumRoleMode,
    ForumTemplate, GunFeedNode, HandoffHint, HopFactor, MeshSeeGraph,
};
use sociacl_ids::{
    history_state, mint_object_id_with, object_principal, parse_object_id, parse_principal_id,
    parse_soul, ObjectId, PrincipalId, Reason, ResolutionContext,
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
fn forum_vector_names_the_five_cases() {
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

fn need_from(row: &Value, stated: u8, ham_state: u64) -> ForumNeed {
    let severity = match row["severity"].as_str().unwrap() {
        "emergency" => ForumNeedSeverity::Emergency,
        "need" => ForumNeedSeverity::Need,
        other => panic!("unknown severity {other}"),
    };
    ForumNeed {
        id: row["needId"].as_str().unwrap().parse().unwrap(),
        forum_id: row["needForumId"].as_str().unwrap().parse().unwrap(),
        subject: row["subject"].as_str().unwrap().parse().unwrap(),
        severity,
        body: row["name"].as_str().unwrap_or("blocked").into(),
        stated,
        ham_state,
        ts: 11,
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
    assert!(forum_role_soul(
        &forum,
        "chat",
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
