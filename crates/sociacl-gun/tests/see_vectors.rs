use serde_json::Value;
use sociacl_gun::MeshSeeGraph;
use sociacl_ids::{
    history_state, parse_object_id, parse_principal_id, verify_see_grant, Jwks, ObjectId,
    PrincipalId, Reason, ResolutionContext, SignedAtMode, SiwePolicy,
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

fn rotations_of(ctx: &Value, step: &Value) -> Vec<Value> {
    let Some(name) = step.get("rotations").and_then(Value::as_str) else {
        return Vec::new();
    };
    ctx["rotationSets"][name]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn run_case(file: &Value, case: &Value) {
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
    let empty = Vec::new();
    let history = |principal: &PrincipalId, at, until| {
        if !accounts.iter().any(|account| account == principal.as_ref()) {
            return Err(Reason::MissingHistory);
        }
        Ok(history_state(principal, &[], at, until))
    };
    let rc = ResolutionContext {
        jwks: &jwks,
        links: &links,
        revocations: &empty,
        now,
        policy: &policy,
        pinned_iss: &pinned,
        history: &history,
        genesis_epub_bindings: &empty,
    };
    let mut graph = MeshSeeGraph::new();
    for step in case["steps"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let op = step["op"].as_str().unwrap();
        match op {
            "edge" => {
                let value = step["value"].as_str().unwrap();
                let got = if step["kind"] == "object" {
                    parse_object_id(value).map(|_| ())
                } else {
                    parse_principal_id(value).map(|_| ())
                };
                let reason = got.expect_err(name);
                assert_eq!(reason_name(reason), step["reason"].as_str().unwrap(), "{name}");
            }
            "verify" => {
                let got = verify_see_grant(&step["row"], &rotations_of(ctx, step), &rc);
                if step["ok"] == true {
                    let row = got.unwrap_or_else(|reason| panic!("{name} {reason}"));
                    assert_eq!(mode_name(row.mode), step["mode"].as_str().unwrap(), "{name}");
                } else {
                    let reason = got.expect_err(name);
                    assert_eq!(reason_name(reason), step["reason"].as_str().unwrap(), "{name}");
                }
            }
            "put" => graph.put_object_id(&object_of(&step["object"]), &principal_of(&step["owner"])),
            "admit" => {
                let got = graph.admit_row(&step["row"], &rotations_of(ctx, step), &rc);
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
                    assert_eq!(reason_name(reason), step["reason"].as_str().unwrap(), "{name}");
                }
            }
            "reverify" => {
                let dropped = graph.reverify_principal(
                    &principal_of(&step["principal"]),
                    &rotations_of(ctx, step),
                    &rc,
                );
                assert_eq!(dropped, step["dropped"].as_u64().unwrap() as usize, "{name}");
            }
            "view" => {
                let got = graph.admitted_view(&object_of(&step["object"]), &principal_of(&step["accessor"]));
                if step["absent"] == true {
                    assert!(got.is_none(), "{name}");
                } else {
                    let row = got.expect(name);
                    assert_eq!(u64::from(row.stated), step["stated"].as_u64().unwrap(), "{name}");
                    assert_eq!(row.ham_state, step["hamState"].as_u64().unwrap(), "{name}");
                    assert_eq!(mode_name(row.mode), step["mode"].as_str().unwrap(), "{name}");
                    if let Some(issued) = step.get("issuedAt").and_then(Value::as_u64) {
                        assert_eq!(row.issued_at, issued, "{name}");
                    }
                }
            }
            "check" => {
                let got = graph.check_see_id(
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
}

#[test]
fn see_vectors() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/mesh/v2/see.json");
    let file: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let mut names = Vec::new();
    for side in ["accept", "reject"] {
        for case in file[side].as_array().unwrap() {
            run_case(&file, case);
            names.push(format!("see/{side}/{}", case["name"].as_str().unwrap()));
        }
    }
    names.sort();
    assert_eq!(names.len(), names.iter().collect::<std::collections::BTreeSet<_>>().len());
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

#[test]
fn see_edge_matches_parse_for_10k_strings() {
    let alphabet = "abcXYZ./_~:()'\\get0123456789- \u{0}";
    let chars: Vec<char> = alphabet.chars().collect();
    let mut state = 0x5502u32;
    for _ in 0..10_000 {
        let len = xorshift(&mut state) as usize % 24;
        let mut value = String::new();
        for _ in 0..len {
            let index = xorshift(&mut state) as usize % chars.len();
            value.push(chars[index]);
        }
        match parse_object_id(&value) {
            Ok(id) => assert_eq!(id.as_ref(), value.as_str()),
            Err(_) => {}
        }
        match parse_principal_id(&value) {
            Ok(id) => assert_eq!(id.as_ref(), value.as_str()),
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

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    let skip = ["migration.ts", "acl-migration.ts", "migration.rs", "acl_migration.rs"];
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if skip.contains(&name.as_ref()) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            walk(&path, files);
        } else if name.ends_with(".js") || name.ends_with(".ts") || name.ends_with(".rs") {
            files.push(path);
        }
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
    let mut files = Vec::new();
    for dir in [
        "typescript/src",
        "typescript/contract",
        "crates/sociacl-gun/src",
        "crates/sociacl-encdisc/src",
    ] {
        walk(&root.join(dir), &mut files);
    }
    for name in names {
        let name = name.as_str().unwrap();
        for path in &files {
            let text = fs::read_to_string(path).unwrap();
            assert!(!ident_present(&text, name), "{name} in {}", path.display());
        }
    }
}
