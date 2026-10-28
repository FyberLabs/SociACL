use serde::Deserialize;
use serde_json::{value::RawValue, Value};
use sociacl_ids::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
struct Family {
    v: u32,
    family: String,
    accept: Vec<Case>,
    reject: Vec<Case>,
    #[serde(default)]
    context: Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    input: Box<RawValue>,
    #[serde(default)]
    canonical: Value,
    reason: Option<Reason>,
    path_key: Option<String>,
    link_id: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}
fn string(v: &Value) -> Result<&str, Reason> {
    v.as_str().ok_or(Reason::NotString)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}
fn unhex_vec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn context(f: &Family, c: &Case) -> Value {
    let mut ctx = f.context.clone();
    if let Some(o) = ctx.as_object_mut() {
        for (k, v) in &c.extra {
            o.insert(k.clone(), v.clone());
        }
    }
    ctx
}
fn links(ctx: &Value) -> BTreeMap<String, Value> {
    ctx["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| (pair[0].as_str().unwrap().to_owned(), pair[1].clone()))
        .collect()
}
fn resolution<T>(r: Resolution<T>, c: &Case) -> Result<T, Reason> {
    if let Some(reasons) = c.extra.get("diagnosticReasons") {
        assert_eq!(
            serde_json::to_value(r.diagnostics.iter().map(|d| d.reason).collect::<Vec<_>>())
                .unwrap(),
            *reasons,
            "{} diagnostics",
            c.name
        );
    }
    r.result
}
fn run(f: &Family, c: &Case, v: &Value) -> Result<Value, Reason> {
    if f.family == "witness-policy" {
        let ctx = context(f, c);
        let result = verify_witness_policy_envelope(
            string(v)?,
            ctx["root"].as_str().unwrap(),
            ctx["audience"].as_str().unwrap(),
            ctx["now"].as_u64().unwrap(),
        )?;
        return Ok(serde_json::to_value(result).unwrap());
    }
    if f.family == "edges" {
        return match c.extra["operation"].as_str().unwrap() {
            "json" => parse_json_input(string(v)?),
            "principal-key" => Ok(parse_principal_key(string(v)?)?.to_string().into()),
            "path-key" => Ok(parse_path_key(string(v)?)?.to_string().into()),
            "sec1" => {
                let s = string(v)?;
                let bytes: Vec<u8> = (0..s.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                    .collect();
                Ok(principal_from_sec1(&bytes)?.to_string().into())
            }
            _ => panic!("unknown edge operation"),
        };
    }
    if f.family == "records" {
        let ctx = context(f, c);
        let now = ctx["now"].as_u64().unwrap();
        let key = parse_principal_id(ctx["currentKey"].as_str().unwrap()).unwrap();
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let ls = links(&ctx);
        let empty = vec![];
        let revs = ctx["revocations"].as_array().unwrap_or(&empty);
        let policy: SiwePolicy = serde_json::from_value(ctx["policy"].clone()).unwrap();
        let history = |p: &PrincipalId, at, until| {
            if let Some(e) = ctx["historyErrors"]
                .as_array()
                .and_then(|es| es.iter().find(|e| e[0] == p.as_ref()))
            {
                return Err(serde_json::from_value(e[1].clone()).unwrap());
            }
            if !ctx["authenticatedAccounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a.as_str() == Some(p.as_ref()))
            {
                return Err(Reason::MissingHistory);
            }
            let hs: Vec<Rotate> = ctx["histories"]
                .as_array()
                .and_then(|hs| hs.iter().find(|h| h[0] == p.as_ref()))
                .map(|h| {
                    h[1].as_array()
                        .unwrap()
                        .iter()
                        .map(|r| {
                            let IdentityRecord::Rotate(r) =
                                serde_json::from_value(r.clone()).unwrap()
                            else {
                                panic!("history")
                            };
                            r
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok(history_state(p, &hs, at, until))
        };
        // Rust's required reference cannot be omitted; represent that wire fixture before constructing context.
        if ctx["missingHistory"] == true {
            return Err(Reason::MissingHistory);
        }
        let pinned_iss = ctx["pinnedIss"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let empty_bindings = Vec::new();
        let bindings = ctx
            .get("genesisEpubBindings")
            .and_then(Value::as_array)
            .unwrap_or(&empty_bindings);
        let rc = ResolutionContext {
            jwks: &jwks,
            links: &ls,
            revocations: revs,
            now,
            policy: &policy,
            pinned_iss: &pinned_iss,
            history: &history,
            genesis_epub_bindings: bindings,
        };
        let key_state = if ctx["directState"].is_object() {
            KeyState {
                key: parse_principal_id(ctx["directState"]["key"].as_str().unwrap()).unwrap(),
                current_key: parse_principal_id(ctx["directState"]["currentKey"].as_str().unwrap())
                    .unwrap(),
                retained_links: Some(
                    serde_json::from_value(ctx["directState"]["retainedLinks"].clone()).unwrap(),
                ),
            }
        } else {
            KeyState {
                key: key.clone(),
                current_key: key.clone(),
                retained_links: None,
            }
        };
        let principal = match c.extra["operation"].as_str().unwrap() {
            "prepare-retained-links-now" => {
                let retained = prepare_retained_links_now(v.as_array().unwrap(), &rc)?;
                return Ok(serde_json::to_value(retained).unwrap());
            }
            "oidc-resolve-now" => {
                resolution(
                    resolve_oidc_link_now(&ctx["cred"], v.as_array().unwrap(), revs, &rc),
                    c,
                )?
                .principal
            }
            "verifying-link-map" => {
                let map = verifying_link_map(v.as_array().unwrap(), &rc)?;
                return Ok(serde_json::to_value(map.keys().cloned().collect::<Vec<_>>()).unwrap());
            }
            "wallet-link" => verify_wallet_link(v, &jwks, &policy, now, &key_state)?.principal,
            "oidc-link" => {
                verify_oidc_link(
                    v,
                    &jwks,
                    &ctx["pinnedIss"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s.as_str().unwrap().to_owned())
                        .collect::<BTreeSet<_>>(),
                    now,
                    &key_state,
                )?
                .principal
            }
            operation @ ("publish-check" | "draft-check") => {
                let siblings = v["siblings"].as_array().unwrap();
                let prior = v["prior"].as_array().unwrap();
                let genesis = parse_principal_id(ctx["genesis"].as_str().unwrap())?;
                let published = if operation == "draft-check" {
                    check_rotation_draft(&v["candidate"], siblings, &genesis, prior, &rc)?
                } else {
                    check_rotation_publish(&v["candidate"], siblings, &genesis, prior, &rc)?
                };
                if let Some(expected) = c.extra.get("retainedLinks") {
                    assert_eq!(
                        serde_json::to_value(&published.retained_links).unwrap(),
                        *expected,
                        "{} retainedLinks",
                        c.name
                    );
                }
                published.principal
            }
            "rotation-request" => verify_rotation_request(v, &key, &rc)?.principal,
            "genesis-epub-request" => {
                verify_genesis_epub_request(
                    v,
                    &parse_principal_id(ctx["genesis"].as_str().unwrap())?,
                    now,
                    &policy,
                )?
                .principal
            }
            "rotate" => {
                let rot = verify_rotate(v, &key, &rc)?;
                if let Some(expected) = c.extra.get("nextEpub") {
                    assert_eq!(
                        rot.next_epub.as_ref().map(AsRef::as_ref),
                        expected.as_str(),
                        "{} nextEpub",
                        c.name
                    );
                }
                rot.principal
            }
            "revoke-now" => verify_revoke_now(v, &key, now)?.principal,
            "revoke" => verify_revoke(v, &key, &jwks, now)?.principal,
            "resolve" => {
                let account = resolution(
                    resolve_current_key(
                        &parse_principal_id(ctx["genesis"].as_str().unwrap()).unwrap(),
                        v.as_array().unwrap(),
                        &rc,
                    ),
                    c,
                )?;
                let expected = c.extra.get("currentEpub").and_then(Value::as_str);
                assert_eq!(
                    account.current_epub.as_ref().map(AsRef::as_ref),
                    expected,
                    "{} currentEpub",
                    c.name
                );
                account.current_key
            }
            operation @ ("resolve-and-wallet" | "resolve-and-wallet-now") => {
                let genesis = parse_principal_id(ctx["genesis"].as_str().unwrap()).unwrap();
                let account = resolve_current_key(&genesis, v.as_array().unwrap(), &rc).result?;
                let resolved = |p: &PrincipalId, at, until| {
                    if p == &genesis {
                        Ok(history_state(p, &account.rotations, at, until))
                    } else {
                        history(p, at, until)
                    }
                };
                let resolve = if operation == "resolve-and-wallet-now" {
                    resolve_wallet_link_now
                } else {
                    resolve_wallet_link
                };
                resolve(
                    &parse_eip55(ctx["address"].as_str().unwrap()).unwrap(),
                    &ls.values().cloned().collect::<Vec<_>>(),
                    revs,
                    &ResolutionContext {
                        history: &resolved,
                        ..rc
                    },
                )
                .result?
                .principal
            }
            operation @ ("wallet-resolve" | "wallet-resolve-now") => {
                let resolve = if operation == "wallet-resolve-now" {
                    resolve_wallet_link_now
                } else {
                    resolve_wallet_link
                };
                resolution(
                    resolve(
                        &parse_eip55(ctx["address"].as_str().unwrap()).unwrap(),
                        v.as_array().unwrap(),
                        revs,
                        &rc,
                    ),
                    c,
                )?
                .principal
            }
            _ => panic!("unknown operation"),
        };
        return Ok(Value::String(principal.to_string()));
    }
    if f.family == "signed-at" {
        let ctx = context(f, c);
        let now = ctx["now"].as_u64().unwrap();
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let ls = links(&ctx);
        let empty = vec![];
        let revs = ctx["revocations"].as_array().unwrap_or(&empty);
        if let Some(raw) = ctx["policy"].get("clockSkewSeconds") {
            match raw {
                Value::Number(n) if n.as_u64().is_some() => {}
                _ => return Err(Reason::BadRecord),
            }
        }
        let policy: SiwePolicy =
            serde_json::from_value(ctx["policy"].clone()).map_err(|_| Reason::BadRecord)?;
        let history = |p: &PrincipalId, at, until| {
            if let Some(e) = ctx["historyErrors"]
                .as_array()
                .and_then(|es| es.iter().find(|e| e[0] == p.as_ref()))
            {
                return Err(serde_json::from_value(e[1].clone()).unwrap());
            }
            if !ctx["authenticatedAccounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a.as_str() == Some(p.as_ref()))
            {
                return Err(Reason::MissingHistory);
            }
            Ok(history_state(p, &[], at, until))
        };
        let pinned_iss = ctx["pinnedIss"]
            .as_array()
            .unwrap_or(&empty)
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        let bindings = ctx
            .get("genesisEpubBindings")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let rc = ResolutionContext {
            jwks: &jwks,
            links: &ls,
            revocations: revs,
            now,
            policy: &policy,
            pinned_iss: &pinned_iss,
            history: &history,
            genesis_epub_bindings: bindings,
        };
        let rotations = c
            .extra
            .get("rotations")
            .or_else(|| ctx.get("rotations"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let plain = |r: Result<Value, Reason>| r;
        return match c.extra["operation"].as_str().unwrap() {
            "verify-signed-at" => {
                let principal = parse_principal_id(v["principal"].as_str().unwrap())?;
                let bytes = unhex_vec(v["bytes"].as_str().unwrap());
                let Some(issued_at) = v["issuedAt"].as_u64() else {
                    return Err(Reason::BadRecord);
                };
                plain(
                    verify_signed_at(
                        &principal,
                        &rotations,
                        &rc,
                        &bytes,
                        v["sig"].as_str().unwrap(),
                        issued_at,
                    )
                    .map(|signed| serde_json::to_value(signed).unwrap()),
                )
            }
            "verify-acl-attest" => {
                let bytes = unhex_vec(v["bytes"].as_str().unwrap());
                plain(
                    verify_acl_attestation(
                        v["jws"].as_str().unwrap(),
                        &jwks,
                        v["issuedAt"].as_u64().unwrap(),
                        &bytes,
                    )
                    .map(|a| serde_json::to_value(a).unwrap()),
                )
            }
            "verify-key-signature" => {
                let key = parse_principal_id(v["key"].as_str().unwrap())?;
                plain(
                    verify_key_signature(
                        &key,
                        v["sig"].as_str().unwrap(),
                        &unhex_vec(v["bytes"].as_str().unwrap()),
                    )
                    .map(|_| Value::Bool(true)),
                )
            }
            "sign-with-keyring" => {
                use base64ct::{Base64UrlUnpadded, Encoding};
                let scalar = Base64UrlUnpadded::decode_vec(v["seaPriv"].as_str().unwrap())
                    .map_err(|_| Reason::BadKey)?;
                let expected = parse_principal_id(v["expectedKey"].as_str().unwrap())?;
                plain(
                    sign_with_keyring(&scalar, &unhex_vec(v["bytes"].as_str().unwrap()), &expected)
                        .map(Value::String),
                )
            }
            _ => panic!("unknown operation"),
        };
    }
    if f.family == "signing-bytes" {
        if c.extra.get("operation").and_then(Value::as_str) == Some("length-prefixed") {
            let items = v.as_array().ok_or(Reason::BadRecord)?;
            let mut fields = Vec::new();
            for item in items {
                fields.push(item.as_str().ok_or(Reason::NotString)?.to_owned());
            }
            let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
            return length_prefixed(&refs).map(|b| Value::String(hex(&b)));
        }
        let b = parse_signing_bytes(v)?;
        if let Some(id) = &c.link_id {
            use sha2::{Digest, Sha256};
            assert_eq!(&hex(&Sha256::digest(&b)), id);
        }
        return Ok(Value::String(hex(&b)));
    }
    if f.family == "soul" {
        if let Some(op) = c.extra.get("operation").and_then(Value::as_str) {
            let items = v.as_array().ok_or(Reason::BadRecord)?;
            return match op {
                "build-membership" => {
                    let owner = parse_principal_id(items[0].as_str().ok_or(Reason::NotString)?)?;
                    let predicate: MembershipPredicate =
                        items[1].as_str().ok_or(Reason::NotString)?.parse()?;
                    let set = parse_object_id(items[2].as_str().ok_or(Reason::NotString)?)?;
                    let member = parse_principal_id(items[3].as_str().ok_or(Reason::NotString)?)?;
                    Ok(Value::String(
                        membership_soul(&owner, predicate, &set, &member).to_string(),
                    ))
                }
                "build-objset" => {
                    let owner = parse_principal_id(items[0].as_str().ok_or(Reason::NotString)?)?;
                    let object = parse_object_id(items[1].as_str().ok_or(Reason::NotString)?)?;
                    let predicate: MembershipPredicate =
                        items[2].as_str().ok_or(Reason::NotString)?.parse()?;
                    let set = parse_object_id(items[3].as_str().ok_or(Reason::NotString)?)?;
                    Ok(Value::String(
                        object_set_soul(&owner, &object, predicate, &set).to_string(),
                    ))
                }
                _ => panic!("unknown soul operation"),
            };
        }
    }
    let operation = c.extra.get("operation").and_then(Value::as_str);
    if let ("object", Some(operation)) = (f.family.as_str(), operation) {
        let id = match operation {
            "claim" => derive_claim_id(string(v)?)?,
            "external" => derive_external_id(
                &parse_source_key(v["source"].as_str().unwrap())?,
                v["providerItemId"].as_str().unwrap(),
            )?,
            "object-principal" => {
                let id = parse_object_id(string(v)?)?;
                return Ok(object_principal(&id)?.to_string().into());
            }
            "mint" => mint_object_id_with(
                v["kind"].as_str().unwrap(),
                &parse_principal_id(v["creator"].as_str().unwrap()).unwrap(),
                |b| {
                    for (out, n) in b.iter_mut().zip(v["bytes"].as_array().unwrap()) {
                        *out = n.as_u64().unwrap() as u8;
                    }
                    Ok(())
                },
            )?
            .object_id()
            .clone(),
            _ => panic!("unknown object operation"),
        };
        if let Some(key) = &c.path_key {
            assert_eq!(object_key(&id).as_ref(), key);
        }
        return Ok(id.to_string().into());
    }
    macro_rules! parse {
        ($parser:ident, $formatter:ident) => {{
            let id = $parser(string(v)?)?;
            if let Some(k) = &c.path_key {
                assert_eq!($formatter(&id).as_ref(), k, "{} path key", c.name);
            }
            Value::String(id.to_string())
        }};
    }
    Ok(match f.family.as_str() {
        "principal" => parse!(parse_principal_id, format_principal_key),
        "wallet" => {
            if c.extra.get("parser").and_then(Value::as_str) == Some("wallet-input") {
                parse!(parse_wallet_input, format_wallet_key)
            } else {
                parse!(parse_eip55, format_wallet_key)
            }
        }
        "tenant" => parse_tenant_id(string(v)?)?.to_string().into(),
        "oidc" => {
            let id = parse_oidc_credential(v)?;
            if let Some(k) = &c.path_key {
                assert_eq!(format_oidc_key(&id).as_ref(), k);
            }
            serde_json::to_value(id).unwrap()
        }
        "object" => parse!(parse_object_id, object_key),
        "network" => parse!(parse_network_id, format_network_key),
        "source-key" => parse!(parse_source_key, format_source_path_key),
        "soul" => serde_json::to_value(parse_soul(string(v)?)?).unwrap(),
        _ => panic!("unknown family: {}", f.family),
    })
}
#[test]
fn every_shared_vector() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/ids");
    let mut paths: Vec<_> = fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|s| s == "json"))
        .collect();
    paths.sort();
    assert_eq!(paths.len(), 13);
    let mut names = BTreeSet::new();
    for path in paths {
        let f: Family = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(f.v, 1);
        for (disposition, cases) in [("accept", &f.accept), ("reject", &f.reject)] {
            for c in cases {
                let name = format!("{}/{}/{}", f.family, disposition, c.name);
                // Rust strings cannot represent an unpaired UTF-16 surrogate. Check it at the JSON edge.
                let input = parse_json_input(c.input.get());
                let actual = input.and_then(|v| run(&f, c, &v));
                let expected = if disposition == "accept" {
                    Ok(c.canonical.clone())
                } else {
                    Err(c.reason.unwrap())
                };
                assert_eq!(actual, expected, "{name}");
                assert!(names.insert(name));
            }
        }
    }
    if let Ok(path) = std::env::var("IDS_VECTOR_REPORT") {
        fs::write(
            path,
            names.into_iter().collect::<Vec<_>>().join("\n") + "\n",
        )
        .unwrap();
    }
}

fn lower_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
}

/// Unbound `<kind>_<32 lowercase hex>`. The minted form and `claim_` / `ext_`
/// plus 64 hex do not match: the kind must be 2–16 chars at an identifier boundary.
fn unbound_kind_hex(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let mut i = 0;
    while i + 33 <= b.len() {
        let tail = i + 33;
        let closed = tail == b.len() || {
            let c = b[tail];
            !lower_hex(c) && c != b'_'
        };
        if b[i] == b'_' && closed && (i + 1..tail).all(|j| lower_hex(b[j])) {
            let mut start = i;
            while start > 0 && (b[start - 1].is_ascii_lowercase() || b[start - 1].is_ascii_digit())
            {
                start -= 1;
            }
            let kind_len = i - start;
            let boundary = start == 0 || {
                let c = b[start - 1];
                !c.is_ascii_alphanumeric() && c != b'_'
            };
            if (2..=16).contains(&kind_len) && b[start].is_ascii_lowercase() && boundary {
                return Some(text[..i].chars().count());
            }
        }
        i += 1;
    }
    None
}

fn skip_source_dir(name: &str) -> bool {
    matches!(
        name,
        "node_modules" | "target" | ".git" | "vectors" | "tests" | "test"
    )
}

fn source_file(name: &str) -> bool {
    if name.starts_with("test_") || name.ends_with("_tests.rs") {
        return false;
    }
    name.ends_with(".js") || name.ends_with(".ts") || name.ends_with(".mjs") || name.ends_with(".rs")
}

fn walk_sources(dir: &Path, hits: &mut Vec<String>, seen: &mut usize) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if skip_source_dir(&name) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            walk_sources(&path, hits, seen);
        } else if source_file(&name) {
            *seen += 1;
            let text = fs::read_to_string(&path).unwrap();
            if let Some(at) = unbound_kind_hex(&text) {
                hits.push(format!("{}:{at}", path.display()));
            }
        }
    }
}

#[test]
fn non_test_sources_do_not_build_unbound_kind_hex() {
    assert!(unbound_kind_hex(&format!("chat_{}", "1".repeat(32))).is_some());
    assert!(unbound_kind_hex(&format!(
        "chat_p_{}_{}",
        "ab".repeat(64),
        "1".repeat(32)
    ))
    .is_none());
    assert!(unbound_kind_hex(&format!("claim_{}", "ab".repeat(32))).is_none());
    assert!(unbound_kind_hex(&format!("ext_{}", "cd".repeat(32))).is_none());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut hits = Vec::new();
    let mut seen = 0;
    walk_sources(&root, &mut hits, &mut seen);
    assert!(seen > 0);
    assert!(hits.is_empty(), "{hits:?}");
}
