use serde_json::Value;
use sociacl_core::AttestationChannel;
use sociacl_gun::{
    GroupPredicate, GroupSnapshotMember, GroupSnapshotObjectSet, HopFactor, MeshSeeGraph,
};
use sociacl_ids::{
    history_state, parse_object_id, parse_principal_id, parse_see_grant, verify_see_grant, Jwks,
    ObjectId, PrincipalId, Reason, ResolutionContext, SignedAtMode, SiwePolicy,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn reason_name(reason: Reason) -> String {
    serde_json::to_value(reason)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn mode_name(mode: SignedAtMode) -> String {
    serde_json::to_value(mode)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn object_of(v: &Value) -> ObjectId {
    parse_object_id(v.as_str().expect("object")).expect("object id")
}

fn parsed_object(v: &Value) -> Result<ObjectId, Reason> {
    parse_object_id(v.as_str().ok_or(Reason::NotString)?)
}

fn principal_of(v: &Value) -> PrincipalId {
    parse_principal_id(v.as_str().expect("principal")).expect("principal id")
}

fn history_unavailable(step: &Value) -> bool {
    step.get("history").and_then(Value::as_str) == Some("unavailable")
}

fn rotations_of(ctx: &Value, step: &Value) -> Option<Vec<Value>> {
    if history_unavailable(step) {
        return None;
    }
    let Some(name) = step.get("rotations").and_then(Value::as_str) else {
        return Some(Vec::new());
    };
    Some(
        ctx["rotationSets"][name]
            .as_array()
            .cloned()
            .unwrap_or_default(),
    )
}

fn scalar_of(n: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = u8::try_from(n).unwrap_or(0);
    bytes
}

fn patch_row(row: &Value, step: &Value) -> Value {
    let Some(patch) = step.get("patch").and_then(Value::as_object) else {
        return row.clone();
    };
    let mut copy = row.clone();
    let Some(map) = copy.as_object_mut() else {
        return copy;
    };
    for (key, value) in patch {
        if value.as_str() == Some("-0") {
            map.insert(key.clone(), serde_json::json!(-0.0));
        } else {
            map.insert(key.clone(), value.clone());
        }
    }
    copy
}

fn resolver_for(rotations: Option<Vec<Value>>) -> impl Fn(&PrincipalId) -> Option<Vec<Value>> {
    move |_: &PrincipalId| rotations.clone()
}

fn run_case(file: &Value, case: &Value) -> MeshSeeGraph {
    let ctx = &file["context"];
    let now = ctx["now"].as_u64().unwrap();
    let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
    let links: BTreeMap<String, Value> = ctx["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (pair[0].as_str().unwrap().to_string(), pair[1].clone()))
        .collect();
    let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
    let accounts: Vec<String> = ctx["authenticatedAccounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let pinned: std::collections::BTreeSet<String> = ctx["pinnedIss"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let file_revocations = ctx["revocations"].as_array().cloned().unwrap_or_default();
    let history = |principal: &PrincipalId, at, until| {
        if !accounts.iter().any(|account| account == principal.as_ref()) {
            return Err(Reason::MissingHistory);
        }
        Ok(history_state(principal, &[], at, until))
    };
    let mut graphs = [MeshSeeGraph::new(), MeshSeeGraph::new()];
    let mut last_see: Option<Vec<u8>> = None;
    let mut last_post: Option<Vec<u8>> = None;
    for step in case["steps"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let op = step["op"].as_str().unwrap();
        let on_side = step.get("on").and_then(Value::as_str) == Some("side");
        if op == "merge" {
            let into_side = step.get("into").and_then(Value::as_str) == Some("side");
            let step_revocations = step
                .get("revocations")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_else(|| file_revocations.clone());
            let step_now = step.get("now").and_then(Value::as_u64).unwrap_or(now);
            let rc = ResolutionContext {
                jwks: &jwks,
                links: &links,
                revocations: &step_revocations,
                now: step_now,
                policy: &policy,
                pinned_iss: &pinned,
                history: &history,
                genesis_epub_bindings: &[],
            };
            let rotations = rotations_of(ctx, step);
            let (head, tail) = graphs.split_at_mut(1);
            if into_side {
                tail[0].vector_merge_groups(&head[0], &resolver_for(rotations), &rc);
            } else {
                head[0].vector_merge_groups(&tail[0], &resolver_for(rotations), &rc);
            }
            continue;
        }
        let graph = &mut graphs[usize::from(on_side)];
        let step_revocations = step
            .get("revocations")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| file_revocations.clone());
        let step_now = step.get("now").and_then(Value::as_u64).unwrap_or(now);
        let rc = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &step_revocations,
            now: step_now,
            policy: &policy,
            pinned_iss: &pinned,
            history: &history,
            genesis_epub_bindings: &[],
        };
        match op {
            "edge" => {
                let value = step["value"].as_str().unwrap();
                let got = if step["kind"] == "object" {
                    parse_object_id(value).map(|_| ())
                } else {
                    parse_principal_id(value).map(|_| ())
                };
                let reason = got.expect_err(name);
                assert_eq!(
                    reason_name(reason),
                    step["reason"].as_str().unwrap(),
                    "{name}"
                );
            }
            "verify" => {
                let row = patch_row(step.get("row").unwrap_or(&Value::Null), step);
                let rotations = rotations_of(ctx, step);
                let got = match rotations.as_deref() {
                    None => match parse_see_grant(&row) {
                        Ok(_) => Err(Reason::MissingHistory),
                        Err(reason) => Err(reason),
                    },
                    Some(rotations) => verify_see_grant(&row, rotations, &rc),
                };
                if step["ok"] == true {
                    let row = got.unwrap_or_else(|reason| panic!("{name} {reason:?}"));
                    assert_eq!(
                        mode_name(row.mode),
                        step["mode"].as_str().unwrap(),
                        "{name}"
                    );
                } else {
                    let reason = got.expect_err(name);
                    assert_eq!(
                        reason_name(reason),
                        step["reason"].as_str().unwrap(),
                        "{name}"
                    );
                }
            }
            "put" => {
                let record = patch_row(step.get("record").unwrap_or(&Value::Null), step);
                let rotations = rotations_of(ctx, step);
                let got = graph.put_object(&record, &resolver_for(rotations), &rc);
                if step["ok"] == false {
                    assert_eq!(
                        reason_name(got.expect_err(name)),
                        step["reason"].as_str().unwrap(),
                        "{name}"
                    );
                } else {
                    let kept = got.unwrap_or_else(|err| panic!("{name} {err:?}"));
                    if step.get("kept").is_some() {
                        assert_eq!(kept, step["kept"] == true, "{name}");
                    }
                }
            }
            "admit" => {
                let row = patch_row(step.get("row").unwrap_or(&Value::Null), step);
                let rotations = rotations_of(ctx, step);
                let got = graph.admit_row(&row, &resolver_for(rotations), &rc);
                if step["ok"] == true {
                    let (row, kept) = got.unwrap_or_else(|reason| panic!("{name} {reason:?}"));
                    assert_eq!(kept, step["kept"] == true, "{name}");
                    if let Some(mode) = step.get("mode").and_then(Value::as_str) {
                        assert_eq!(mode_name(row.mode), mode, "{name}");
                    }
                    if let Some(stated) = step.get("stated").and_then(Value::as_u64) {
                        assert_eq!(u64::from(row.stated), stated, "{name}");
                    }
                    if let Some(ham) = step.get("hamState").and_then(Value::as_u64) {
                        assert_eq!(row.ham_state, ham, "{name}");
                    }
                    if let Some(attest) = step.get("attest") {
                        assert_eq!(row.attest, attest == true, "{name}");
                    }
                } else {
                    let reason = got.expect_err(name);
                    assert_eq!(
                        reason_name(reason),
                        step["reason"].as_str().unwrap(),
                        "{name}"
                    );
                }
            }
            "reverify" => {
                let rotations = rotations_of(ctx, step);
                let got = graph.reverify_principal(
                    &principal_of(&step["principal"]),
                    &resolver_for(rotations),
                    &rc,
                );
                if step["ok"] == false {
                    assert_eq!(
                        reason_name(got.expect_err(name)),
                        step["reason"].as_str().unwrap(),
                        "{name}"
                    );
                } else {
                    assert_eq!(
                        got.unwrap(),
                        step["dropped"].as_u64().unwrap() as usize,
                        "{name}"
                    );
                }
            }
            "owner" => {
                let Ok(object) = parsed_object(&step["object"]) else {
                    assert!(step["absent"] == true, "{name}");
                    continue;
                };
                let got = graph.admitted_owner(&object);
                if step["absent"] == true {
                    assert!(got.is_none(), "{name}");
                } else {
                    let (owner, issued) = got.expect(name);
                    assert_eq!(owner.as_ref(), step["owner"].as_str().unwrap(), "{name}");
                    if let Some(at) = step.get("issuedAt").and_then(Value::as_u64) {
                        assert_eq!(issued, at, "{name}");
                    }
                }
            }
            "view" => {
                let got = graph.admitted_view(
                    &object_of(&step["object"]),
                    &principal_of(&step["accessor"]),
                );
                if step["absent"] == true {
                    assert!(got.is_none(), "{name}");
                } else {
                    let row = got.expect(name);
                    assert_eq!(
                        u64::from(row.stated),
                        step["stated"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(row.ham_state, step["hamState"].as_u64().unwrap(), "{name}");
                    assert_eq!(
                        mode_name(row.mode),
                        step["mode"].as_str().unwrap(),
                        "{name}"
                    );
                    if let Some(issued) = step.get("issuedAt").and_then(Value::as_u64) {
                        assert_eq!(row.issued_at, issued, "{name}");
                    }
                    if let Some(from) = step.get("from").and_then(Value::as_u64) {
                        assert_eq!(row.from, from, "{name}");
                    }
                    if let Some(until) = step.get("until").and_then(Value::as_u64) {
                        assert_eq!(row.until, until, "{name}");
                    }
                    if let Some(attest) = step.get("attest") {
                        assert_eq!(row.attest, attest == true, "{name}");
                    }
                }
            }
            "check" => {
                let (allowed, reason) = match (
                    parsed_object(&step["object"]),
                    parse_principal_id(step["accessor"].as_str().unwrap_or("")),
                ) {
                    (Err(reason), _) | (_, Err(reason)) => (false, reason_name(reason)),
                    (Ok(object), Ok(accessor)) => {
                        let got = graph.check_see(
                            &object,
                            &accessor,
                            step["now"].as_u64().unwrap(),
                            None,
                            None,
                        );
                        (got.allowed, got.reason.to_string())
                    }
                };
                assert_eq!(allowed, step["allowed"] == true, "{name}");
                assert_eq!(reason, step["reason"].as_str().unwrap(), "{name}");
            }
            "admit-post" => {
                let row = patch_row(step.get("row").unwrap_or(&Value::Null), step);
                let rotations = rotations_of(ctx, step);
                let got = graph.admit_post(&row, &resolver_for(rotations), &rc);
                if step["ok"] == true {
                    let (row, kept) = got.unwrap_or_else(|reason| panic!("{name} {reason}"));
                    assert_eq!(kept, step["kept"] == true, "{name}");
                    if let Some(mode) = step.get("mode").and_then(Value::as_str) {
                        assert_eq!(mode_name(row.mode), mode, "{name}");
                    }
                    if let Some(stated) = step.get("stated").and_then(Value::as_u64) {
                        assert_eq!(u64::from(row.stated), stated, "{name}");
                    }
                    if let Some(ham) = step.get("hamState").and_then(Value::as_u64) {
                        assert_eq!(row.ham_state, ham, "{name}");
                    }
                } else {
                    let reason = got.expect_err(name);
                    assert_eq!(
                        reason_name(reason),
                        step["reason"].as_str().unwrap(),
                        "{name}"
                    );
                }
            }
            "view-post" => {
                let got = graph.admitted_post(
                    &object_of(&step["object"]),
                    &principal_of(&step["accessor"]),
                );
                if step["absent"] == true {
                    assert!(got.is_none(), "{name}");
                } else {
                    let row = got.expect(name);
                    assert_eq!(
                        u64::from(row.stated),
                        step["stated"].as_u64().unwrap(),
                        "{name}"
                    );
                    assert_eq!(row.ham_state, step["hamState"].as_u64().unwrap(), "{name}");
                    assert_eq!(
                        mode_name(row.mode),
                        step["mode"].as_str().unwrap(),
                        "{name}"
                    );
                    if let Some(from) = step.get("from").and_then(Value::as_u64) {
                        assert_eq!(row.from, from, "{name}");
                    }
                    if let Some(until) = step.get("until").and_then(Value::as_u64) {
                        assert_eq!(row.until, until, "{name}");
                    }
                }
            }
            "check-post" => {
                let got = graph.check_post(
                    &object_of(&step["object"]),
                    &principal_of(&step["accessor"]),
                    step["now"].as_u64().unwrap(),
                    None,
                    None,
                );
                assert_eq!(got.allowed, step["allowed"] == true, "{name}");
                assert_eq!(got.reason, step["reason"].as_str().unwrap(), "{name}");
            }
            "request-id" => {
                let got = match (
                    step.get("requester").and_then(Value::as_str),
                    step.get("object").and_then(Value::as_str),
                ) {
                    (Some(requester), Some(object)) => {
                        sociacl_ids::request_id(requester, object).map_err(reason_name)
                    }
                    _ => Err("not-string".to_string()),
                };
                if let Some(id) = step.get("id").and_then(Value::as_str) {
                    assert_eq!(got.expect(name), id, "{name}");
                } else {
                    assert_eq!(
                        got.expect_err(name),
                        step["reason"].as_str().unwrap(),
                        "{name}"
                    );
                }
            }
            "join" => {
                let rotations = rotations_of(ctx, step);
                let resolver = resolver_for(rotations);
                graph
                    .admit_membership(&step["member"], &resolver, &rc)
                    .unwrap_or_else(|reason| panic!("{name} member {reason}"));
                graph
                    .admit_membership(&step["set"], &resolver, &rc)
                    .unwrap_or_else(|reason| panic!("{name} set {reason}"));
                graph
                    .admit_object_set(&step["edge"], &resolver, &rc)
                    .unwrap_or_else(|reason| panic!("{name} edge {reason}"));
            }
            "admit-member" | "admit-object-set" | "admit-cancel" => {
                let rotations = rotations_of(ctx, step);
                let resolver = resolver_for(rotations);
                let got = match op {
                    "admit-member" => graph.admit_membership(&step["row"], &resolver, &rc),
                    "admit-object-set" => graph.admit_object_set(&step["row"], &resolver, &rc),
                    _ => graph.admit_group_cancel(&step["row"], &resolver, &rc),
                };
                if step["ok"] == true {
                    let kept = got.unwrap_or_else(|reason| panic!("{name} {reason}"));
                    if step.get("kept").is_some() {
                        assert_eq!(kept, step["kept"] == true, "{name}");
                    }
                } else {
                    assert_eq!(
                        reason_name(got.expect_err(name)),
                        step["reason"].as_str().unwrap(),
                        "{name}"
                    );
                }
            }
            "reverify-group" => {
                let rotations = rotations_of(ctx, step);
                let got = graph.reverify_group(
                    &principal_of(&step["principal"]),
                    &resolver_for(rotations),
                    &rc,
                );
                if step["ok"] == false {
                    assert_eq!(
                        reason_name(got.expect_err(name)),
                        step["reason"].as_str().unwrap(),
                        "{name}"
                    );
                } else {
                    let dropped = got.unwrap_or_else(|reason| panic!("{name} {reason}"));
                    if let Some(want) = step.get("dropped").and_then(Value::as_u64) {
                        assert_eq!(dropped as u64, want, "{name}");
                    }
                }
            }
            "check-group" => {
                let hop = step["hop"]
                    .as_bool()
                    .unwrap_or(false)
                    .then_some(HopFactor::Structured {
                        channel: AttestationChannel::ConventionBadge,
                        attestation_bytes: None,
                        share_token: None,
                    });
                let predicate = match step["predicate"].as_str().unwrap() {
                    "named-circle" => GroupPredicate::NamedCircle,
                    _ => GroupPredicate::SameGroup,
                };
                let got = graph.check_group_see(
                    predicate,
                    &object_of(&step["object"]),
                    &principal_of(&step["accessor"]),
                    step["now"].as_u64().unwrap(),
                    None,
                    hop.as_ref(),
                );
                assert_eq!(got.allowed, step["allowed"] == true, "{name}");
                assert_eq!(got.reason, step["reason"].as_str().unwrap(), "{name}");
                assert!(!got.hop_is_grant(), "{name}");
                assert_eq!(got.hop.is_some(), hop.is_some(), "{name}");
            }
            "check-presentation" => {
                let set = step
                    .get("set")
                    .filter(|value| !value.is_null())
                    .map(object_of);
                let payload = step
                    .get("payload")
                    .filter(|value| !value.is_null())
                    .map(|payload| sociacl_gun::DecodedGroupPayload {
                        stated: payload["stated"].as_u64().unwrap() as u8,
                        from: payload["from"].as_u64().unwrap(),
                        until: payload["until"].as_u64().unwrap(),
                    });
                let got = graph.check_group_presentation(
                    set.as_ref(),
                    &object_of(&step["object"]),
                    &principal_of(&step["accessor"]),
                    payload.as_ref(),
                    step["now"].as_u64().unwrap(),
                    None,
                    None,
                );
                assert_eq!(got.allowed, step["allowed"] == true, "{name}");
                assert_eq!(got.reason, step["reason"].as_str().unwrap(), "{name}");
                assert!(!got.hop_is_grant(), "{name}");
            }
            "snapshot" => {
                let members = step["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|member| GroupSnapshotMember {
                        accessor: member["accessor"].as_str().unwrap().to_string(),
                        predicate: match member["predicate"].as_str().unwrap() {
                            "named-circle" => GroupPredicate::NamedCircle,
                            _ => GroupPredicate::SameGroup,
                        },
                        set_id: member["setId"].as_str().unwrap().to_string(),
                        stated: member["stated"].as_u64().unwrap() as u8,
                        ham_state: member["hamState"].as_u64().unwrap(),
                    })
                    .collect::<Vec<_>>();
                let edge = step
                    .get("objectSet")
                    .filter(|value| !value.is_null())
                    .map(|edge| GroupSnapshotObjectSet {
                        predicate: match edge["predicate"].as_str().unwrap() {
                            "named-circle" => GroupPredicate::NamedCircle,
                            _ => GroupPredicate::SameGroup,
                        },
                        set_id: edge["setId"].as_str().unwrap().to_string(),
                        stated: edge["stated"].as_u64().unwrap() as u8,
                        ham_state: edge["hamState"].as_u64().unwrap(),
                    });
                assert_eq!(
                    graph.snapshot_understates_group(
                        &object_of(&step["object"]),
                        &members,
                        edge.as_ref()
                    ),
                    step["understates"] == true,
                    "{name}"
                );
            }
            "mutate-row" => {
                let _ = step["field"].as_str().expect(name);
            }
            "grant" => {
                let rotations = rotations_of(ctx, step);
                let scalar = scalar_of(step["signer"].as_u64().unwrap_or(1));
                let members = step
                    .get("members")
                    .filter(|value| !value.is_null())
                    .map(|members| {
                        let predicate = match members["predicate"].as_str().unwrap() {
                            "named-circle" => GroupPredicate::NamedCircle,
                            _ => GroupPredicate::SameGroup,
                        };
                        (predicate, members["now"].as_u64().unwrap())
                    });
                let from = step["window"]["from"].as_u64().unwrap_or(0);
                let until = step["window"]["until"].as_u64().unwrap_or(0);
                let calls = std::cell::Cell::new(0u64);
                let resolver = resolver_for(rotations);
                let counted = |principal: &PrincipalId| {
                    calls.set(calls.get() + 1);
                    resolver(principal)
                };
                let got = match sociacl_gun::request_owner(&step["owner"]) {
                    Ok(owner) => graph.grant_approved_request(
                        &owner,
                        &step["request"],
                        from,
                        until,
                        members,
                        &scalar,
                        &counted,
                        &rc,
                    ),
                    Err(reason) => Err(reason),
                };
                if let Some(expected) = step["resolverCalls"].as_u64() {
                    assert_eq!(calls.get(), expected, "{name}");
                }
                if step["granted"] == true {
                    let row = got.unwrap_or_else(|reason| panic!("{name} {reason}"));
                    if let Some(id) = step.get("requestId").and_then(Value::as_str) {
                        assert_eq!(row.request_id, id, "{name}");
                    }
                    if let Some(ham) = step.get("hamState").and_then(Value::as_u64) {
                        assert_eq!(row.see.ham_state, ham, "{name}");
                    }
                    if step["post"] == false {
                        assert!(row.post.is_none(), "{name}");
                    }
                    if step["post"] == true {
                        let post = row.post.as_ref().expect(name);
                        assert_eq!(post.ham_state, step["postHam"].as_u64().unwrap(), "{name}");
                    }
                    if step.get("unchanged") == Some(&Value::Bool(true)) {
                        assert!(row.unchanged, "{name}");
                        assert_eq!(row.see.bytes, last_see.clone().expect(name), "{name}");
                        assert_eq!(
                            row.post.as_ref().map(|post| post.bytes.clone()),
                            last_post,
                            "{name}"
                        );
                    } else {
                        assert!(!row.unchanged, "{name}");
                    }
                    if step.get("seeBytesSame") == Some(&Value::Bool(true)) {
                        assert_eq!(row.see.bytes, last_see.clone().expect(name), "{name}");
                    }
                    if step.get("bytesDiffer") == Some(&Value::Bool(true)) {
                        assert_ne!(row.see.bytes, last_see.clone().expect(name), "{name}");
                    }
                    last_see = Some(row.see.bytes.clone());
                    last_post = row.post.as_ref().map(|post| post.bytes.clone());
                } else {
                    assert_eq!(
                        reason_name(got.expect_err(name)),
                        step["reason"].as_str().unwrap(),
                        "{name}"
                    );
                }
            }
            "factor" => {
                assert_eq!(
                    sociacl_gun::factor_grants(step["kind"].as_str().unwrap()),
                    step["grants"] == true,
                    "{name}"
                );
            }
            other => panic!("{name} unknown {other}"),
        }
    }
    let [graph, _] = graphs;
    graph
}

#[test]
fn see_vectors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/mesh/v2");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    let mut names = Vec::new();
    for path in paths {
        let file: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let family = file["family"].as_str().unwrap();
        for side in ["accept", "reject"] {
            for case in file[side].as_array().unwrap() {
                let _ = run_case(&file, case);
                names.push(format!(
                    "{family}/{side}/{}",
                    case["name"].as_str().unwrap()
                ));
            }
        }
    }
    names.sort();
    assert_eq!(
        names.len(),
        names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    if let Ok(report) = std::env::var("MESH_VECTOR_REPORT") {
        fs::write(report, names.join("\n") + "\n").unwrap();
    }
}

fn xorshift(state: &mut u32) -> u32 {
    *state ^= state.wrapping_shl(13);
    *state ^= *state >> 17;
    *state ^= state.wrapping_shl(5);
    *state
}

fn mutate_id(value: &str, roll: u32, pick: u32) -> String {
    match roll % 5 {
        0 => {
            let mut chars: Vec<char> = value.chars().collect();
            let index = pick as usize % chars.len();
            let ch = chars[index];
            let flipped = if ch.is_ascii_lowercase() {
                ch.to_ascii_uppercase()
            } else if ch.is_ascii_uppercase() {
                ch.to_ascii_lowercase()
            } else {
                ch
            };
            if flipped != ch {
                chars[index] = flipped;
                return chars.into_iter().collect();
            }
            format!("{value}x")
        }
        1 => {
            if let Some(at) = value.find('_') {
                let mut copy = value.to_string();
                copy.replace_range(at..at + 1, ".");
                copy
            } else if let Some(at) = value.find('.') {
                let mut copy = value.to_string();
                copy.replace_range(at..at + 1, "_");
                copy
            } else {
                format!("{value}x")
            }
        }
        2 => format!("{value} "),
        3 => "room.alpha".to_string(),
        _ => format!("s3rch/items/{value}"),
    }
}

#[test]
fn see_edge_mutations_call_check_see() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/mesh/v2/see.json");
    let file: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let entry = file["accept"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "grant-on-chat_a-does-not-allow-chat_b")
        .unwrap();
    let case = serde_json::json!({
        "name": "property",
        "steps": [entry["steps"][0].clone(), entry["steps"][2].clone()]
    });
    let graph = run_case(&file, &case);
    let object = entry["steps"][2]["row"]["object"].as_str().unwrap();
    let accessor = entry["steps"][2]["row"]["accessor"].as_str().unwrap();
    let owner = entry["steps"][0]["record"]["owner"].as_str().unwrap();
    assert!(
        graph
            .check_see(
                &object_of(&Value::String(object.into())),
                &principal_of(&Value::String(accessor.into())),
                10,
                None,
                None,
            )
            .allowed
    );
    let bases = [object, accessor, owner];
    let mut state = 0x5502u32;
    for _ in 0..10_000 {
        let roll = xorshift(&mut state);
        let pick = xorshift(&mut state);
        let base = bases[xorshift(&mut state) as usize % bases.len()];
        let value = mutate_id(base, roll, pick);
        match parse_object_id(&value) {
            Ok(id) => {
                assert_eq!(id.as_ref(), value.as_str());
                let got = graph.check_see(
                    &id,
                    &principal_of(&Value::String(accessor.into())),
                    10,
                    None,
                    None,
                );
                assert_eq!(got.allowed, value == object);
            }
            Err(_) => {}
        }
        match parse_principal_id(&value) {
            Ok(id) => {
                assert_eq!(id.as_ref(), value.as_str());
                let got = graph.check_see(
                    &object_of(&Value::String(object.into())),
                    &id,
                    10,
                    None,
                    None,
                );
                assert_eq!(got.allowed, value == accessor || value == owner);
            }
            Err(_) => {}
        }
    }
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

/// Kept in lockstep with scripts/audit-forbidden-names.mjs and test_see.js.
fn imports_node_crypto(source: &str) -> bool {
    let bytes = source.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    let mut stmt: Option<&str> = None;
    let skip_space = |mut at: usize| {
        while at < n && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        at
    };
    let word_at = |at: usize, word: &str| {
        let end = at + word.len();
        end <= n
            && &bytes[at..end] == word.as_bytes()
            && (at == 0 || !is_ident(bytes[at - 1]))
            && (end == n || !is_ident(bytes[end]))
    };
    let nested_crypto = std::cell::Cell::new(false);
    fn read_string(
        source: &str,
        at: usize,
        nested_crypto: &std::cell::Cell<bool>,
    ) -> (Option<String>, usize) {
        let bytes = source.as_bytes();
        let n = bytes.len();
        let quote = bytes[at];
        let mut j = at + 1;
        let mut value = Vec::new();
        let mut interpolated = false;
        while j < n {
            let c = bytes[j];
            if c == b'\\' {
                if j + 1 < n {
                    value.push(bytes[j + 1]);
                }
                j += 2;
                continue;
            }
            if quote == b'`' && c == b'$' && j + 1 < n && bytes[j + 1] == b'{' {
                interpolated = true;
                let end = skip_balanced(source, j + 1, b'{', b'}', nested_crypto);
                let content_end = if bytes.get(end.wrapping_sub(1)) == Some(&b'}') {
                    end - 1
                } else {
                    end
                };
                if imports_node_crypto(&source[j + 2..content_end]) {
                    nested_crypto.set(true);
                }
                j = end;
                continue;
            }
            if c == quote {
                return (
                    if interpolated {
                        None
                    } else {
                        String::from_utf8(value).ok()
                    },
                    j + 1,
                );
            }
            value.push(c);
            j += 1;
        }
        (
            if interpolated {
                None
            } else {
                String::from_utf8(value).ok()
            },
            n,
        )
    }
    fn skip_balanced(
        source: &str,
        at: usize,
        open: u8,
        close: u8,
        nested_crypto: &std::cell::Cell<bool>,
    ) -> usize {
        let bytes = source.as_bytes();
        let n = bytes.len();
        let mut depth = 0;
        let mut j = at;
        while j < n {
            let c = bytes[j];
            if c == b'/' && j + 1 < n && bytes[j + 1] == b'/' {
                j += 2;
                while j < n && bytes[j] != b'\n' {
                    j += 1;
                }
                continue;
            }
            if c == b'/' && j + 1 < n && bytes[j + 1] == b'*' {
                j += 2;
                while j + 1 < n && !(bytes[j] == b'*' && bytes[j + 1] == b'/') {
                    j += 1;
                }
                j = (j + 2).min(n);
                continue;
            }
            if matches!(c, b'\'' | b'"' | b'`') {
                j = read_string(source, j, nested_crypto).1;
                continue;
            }
            if c == open {
                depth += 1;
            } else if c == close {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            j += 1;
        }
        n
    }
    let specifier_at = |at: usize| {
        if at >= n || !matches!(bytes[at], b'\'' | b'"' | b'`') {
            return false;
        }
        matches!(
            read_string(source, at, &nested_crypto).0.as_deref(),
            Some("crypto" | "node:crypto")
        )
    };
    while i < n {
        if !source.is_char_boundary(i) {
            i += 1;
            continue;
        }
        let c = bytes[i];
        if c == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            i += 2;
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && i + 1 < n && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(n);
            continue;
        }
        if matches!(c, b'\'' | b'"' | b'`') {
            i = read_string(source, i, &nested_crypto).1;
            continue;
        }
        if c == b';' {
            stmt = None;
            i += 1;
            continue;
        }
        if matches!(stmt, Some("import" | "export")) && word_at(i, "from") {
            if specifier_at(skip_space(i + 4)) {
                return true;
            }
            i += 4;
            continue;
        }
        if word_at(i, "import") {
            let j = skip_space(i + 6);
            if j < n && bytes[j] == b'(' {
                if specifier_at(skip_space(j + 1)) {
                    return true;
                }
                i = j + 1;
                continue;
            }
            if specifier_at(j) {
                return true;
            }
            stmt = Some("import");
            i += 6;
            continue;
        }
        if word_at(i, "export") {
            stmt = Some("export");
            i += 6;
            continue;
        }
        if word_at(i, "createRequire") {
            let mut j = skip_space(i + 13);
            if j < n && bytes[j] == b'(' {
                j = skip_space(skip_balanced(source, j, b'(', b')', &nested_crypto));
                if j < n && bytes[j] == b'(' && specifier_at(skip_space(j + 1)) {
                    return true;
                }
            }
            i += 13;
            continue;
        }
        if word_at(i, "getBuiltinModule") || word_at(i, "require") {
            let word = if word_at(i, "getBuiltinModule") {
                "getBuiltinModule"
            } else {
                "require"
            };
            let j = skip_space(i + word.len());
            if j < n && bytes[j] == b'(' && specifier_at(skip_space(j + 1)) {
                return true;
            }
            i += word.len();
            continue;
        }
        i += 1;
    }
    nested_crypto.get()
}

fn ident_present(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(at) = text[from..].find(name) {
        let start = from + at;
        let end = start + name.len();
        let before = start == 0 || {
            let c = bytes[start - 1];
            !c.is_ascii_alphanumeric() && c != b'_'
        };
        let after = end == bytes.len() || {
            let c = bytes[end];
            !c.is_ascii_alphanumeric() && c != b'_'
        };
        if before && after {
            return true;
        }
        from = start + 1;
    }
    false
}

fn glob_match(glob: &str, path: &str) -> bool {
    fn rec(glob: &[u8], path: &[u8]) -> bool {
        if glob.is_empty() {
            return path.is_empty();
        }
        if glob.starts_with(b"**") {
            let rest = if glob.len() > 2 && glob[2] == b'/' {
                &glob[3..]
            } else {
                &glob[2..]
            };
            if rec(rest, path) {
                return true;
            }
            for index in 0..path.len() {
                if rec(glob, &path[index + 1..]) {
                    return true;
                }
            }
            return false;
        }
        if glob[0] == b'*' {
            let mut index = 0;
            loop {
                if rec(&glob[1..], &path[index..]) {
                    return true;
                }
                if index >= path.len() || path[index] == b'/' {
                    return false;
                }
                index += 1;
            }
        }
        if path.is_empty() || glob[0] != path[0] {
            return false;
        }
        rec(&glob[1..], &path[1..])
    }
    rec(glob.as_bytes(), path.as_bytes())
}

fn source_file(name: &str) -> bool {
    [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".rs"]
        .iter()
        .any(|ext| name.ends_with(ext))
}

fn glob_match_source(glob: &str, path: &str) -> bool {
    if glob_match(glob, path) {
        return true;
    }
    for (from, to) in [
        (".js", ".mjs"),
        (".js", ".cjs"),
        (".ts", ".mts"),
        (".ts", ".cts"),
    ] {
        if glob.ends_with(&format!("*{from}")) && path.ends_with(to) {
            let rewritten = format!("{}{from}", &path[..path.len() - to.len()]);
            if glob_match(glob, &rewritten) {
                return true;
            }
        }
    }
    false
}

fn files_for_glob(root: &Path, glob: &str) -> Vec<PathBuf> {
    if !glob.contains('*') {
        let path = root.join(glob);
        assert!(path.is_file(), "{glob}");
        return vec![path];
    }
    let mut files = Vec::new();
    walk_glob(root, root, glob, &mut files);
    files
}

fn walk_glob(root: &Path, dir: &Path, glob: &str, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "node_modules" || name == "target" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            walk_glob(root, &path, glob, files);
        } else if source_file(&name) {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if glob_match_source(glob, &relative) {
                files.push(path);
            }
        }
    }
}

#[test]
fn signed_owner_reaches_group_until_history_drops_it() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/mesh/v2/see.json");
    let file: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let case = file["accept"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "grant-on-chat_a-does-not-allow-chat_b")
        .unwrap();
    let mut graph = run_case(&file, case);
    let object = object_of(&case["steps"][0]["record"]["object"]);
    let owner = principal_of(&case["steps"][0]["record"]["owner"]);
    assert!(graph.admitted_owner(&object).is_some());
    let before = graph.check_group_see(GroupPredicate::SameGroup, &object, &owner, 10, None, None);
    assert!(before.allowed);
    assert_eq!(before.reason, "owner");
    let ctx = &file["context"];
    let now = ctx["now"].as_u64().unwrap();
    let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
    let links: BTreeMap<String, Value> = BTreeMap::new();
    let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
    let pinned = std::collections::BTreeSet::new();
    let history = |principal: &PrincipalId, at, until| Ok(history_state(principal, &[], at, until));
    let rc = ResolutionContext {
        jwks: &jwks,
        links: &links,
        revocations: &[],
        now,
        policy: &policy,
        pinned_iss: &pinned,
        history: &history,
        genesis_epub_bindings: &[],
    };
    assert!(graph.reverify_principal(&owner, &|_| None, &rc).is_err());
    assert!(graph.admitted_owner(&object).is_none());
    let after = graph.check_group_see(GroupPredicate::SameGroup, &object, &owner, 10, None, None);
    assert!(!after.allowed);
    assert_eq!(after.reason, "missing");
}

#[test]
fn typescript_src_does_not_import_node_crypto() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vectors: Value = serde_json::from_str(
        &fs::read_to_string(root.join("vectors/mesh/crypto-import.json")).unwrap(),
    )
    .unwrap();
    for row in vectors["allowed"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        assert!(
            !imports_node_crypto(row["source"].as_str().unwrap()),
            "{name}"
        );
    }
    for row in vectors["banned"].as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        assert!(
            imports_node_crypto(row["source"].as_str().unwrap()),
            "{name}"
        );
    }
    let mut files = files_for_glob(&root, "typescript/src/**/*.js");
    files.extend(files_for_glob(&root, "typescript/src/**/*.ts"));
    assert!(!files.is_empty());
    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        assert!(!imports_node_crypto(&text), "{}", path.display());
    }
}

#[test]
fn see_forbidden_names_are_absent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let list: Value = serde_json::from_str(
        &fs::read_to_string(root.join("vectors/mesh/forbidden-names.json")).unwrap(),
    )
    .unwrap();
    let names = list["identifiers"].as_array().unwrap();
    let scopes = list["scopes"].as_array().unwrap();
    assert!(!scopes.is_empty());
    for glob in scopes {
        let glob = glob.as_str().unwrap();
        let files = files_for_glob(&root, glob);
        assert!(!files.is_empty(), "{glob}");
        for name in names {
            let name = name.as_str().unwrap();
            for path in &files {
                let text = fs::read_to_string(path).unwrap();
                assert!(!ident_present(&text, name), "{name} in {}", path.display());
            }
        }
    }
}
