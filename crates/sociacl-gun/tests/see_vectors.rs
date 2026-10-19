use serde_json::Value;
use sociacl_core::IssuerSecret;
use sociacl_gun::{GroupPredicate, GunError, MeshSeeGraph};
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
    let mut graph = MeshSeeGraph::new();
    for step in case["steps"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let op = step["op"].as_str().unwrap();
        let step_revocations = step
            .get("revocations")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| file_revocations.clone());
        let rc = ResolutionContext {
            jwks: &jwks,
            links: &links,
            revocations: &step_revocations,
            now,
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
                let got = graph.admitted_owner(&object_of(&step["object"]));
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
                let got = graph.check_see(
                    &object_of(&step["object"]),
                    &principal_of(&step["accessor"]),
                    step["now"].as_u64().unwrap(),
                    None,
                    None,
                );
                assert_eq!(got.allowed, step["allowed"] == true, "{name}");
                assert_eq!(got.reason, step["reason"].as_str().unwrap(), "{name}");
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
            other => panic!("{name} unknown {other}"),
        }
    }
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
        } else if name.ends_with(".js") || name.ends_with(".ts") || name.ends_with(".rs") {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if glob_match(glob, &relative) {
                files.push(path);
            }
        }
    }
}

fn not_missing(err: GunError) {
    assert_ne!(err, GunError::ObjectNotInGraph);
}

#[test]
fn signed_owner_reaches_post_and_group_until_history_drops_it() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/mesh/v2/see.json");
    let file: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let case = file["accept"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "grant-on-chat_a-does-not-allow-chat_b")
        .unwrap();
    let mut graph = run_case(&file, case);
    let object = case["steps"][0]["record"]["object"].as_str().unwrap();
    let owner = case["steps"][0]["record"]["owner"].as_str().unwrap();
    assert!(graph
        .admitted_owner(&object_of(&Value::String(object.into())))
        .is_some());
    let secret = IssuerSecret::generate();
    match graph.name_object_set(
        owner,
        object,
        GroupPredicate::SameGroup,
        "0xalice/ops",
        &secret,
    ) {
        Ok(()) => {}
        Err(err) => not_missing(err),
    }
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
    let principal = principal_of(&case["steps"][0]["record"]["owner"]);
    assert!(graph
        .reverify_principal(&principal, &|_| None, &rc)
        .is_err());
    assert!(graph
        .admitted_owner(&object_of(&Value::String(object.into())))
        .is_none());
    assert_eq!(
        graph
            .name_object_set(
                owner,
                object,
                GroupPredicate::SameGroup,
                "0xalice/ops",
                &secret
            )
            .unwrap_err(),
        GunError::ObjectNotInGraph
    );
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
