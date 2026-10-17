use serde::Deserialize;
use serde_json::{value::RawValue, Value};
use sociacl_ids::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
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
        let rc = ResolutionContext {
            jwks: &jwks,
            links: &ls,
            revocations: revs,
            now,
            policy: &policy,
            pinned_iss: &pinned_iss,
            history: &history,
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
                // Reference caller step over fixture candidates; no attestation is issued here.
                let mut retained = Vec::new();
                for id in v.as_array().unwrap() {
                    let id = id.as_str().unwrap();
                    let raw = ls.get(id).unwrap();
                    let principal = parse_principal_id(raw["principal"].as_str().unwrap())?;
                    let issued_at = raw["issuedAt"].as_f64().unwrap() as u64;
                    let state = history(&principal, issued_at, now)?;
                    let proof = if raw["kind"] == "wallet" {
                        IdentityRecord::Wallet(verify_wallet_link(
                            raw, &jwks, &policy, issued_at, &state,
                        )?)
                    } else {
                        IdentityRecord::Oidc(verify_oidc_link(
                            raw,
                            &jwks,
                            &pinned_iss,
                            issued_at,
                            &state,
                        )?)
                    };
                    assert_eq!(link_id(&proof)?, id);
                    let revoked = revs.iter().any(|raw| {
                        verify_revoke_now(raw, &state.current_key, now).is_ok_and(|r| {
                            r.principal == principal && r.link_id == id && r.issued_at >= issued_at
                        })
                    });
                    if !revoked {
                        retained.push(id);
                    }
                }
                retained.sort();
                return Ok(serde_json::to_value(retained).unwrap());
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
            "rotate" => verify_rotate(v, &key, &rc)?.principal,
            "revoke-now" => verify_revoke_now(v, &key, now)?.principal,
            "revoke" => verify_revoke(v, &key, &jwks, now)?.principal,
            "resolve" => {
                resolution(
                    resolve_current_key(
                        &parse_principal_id(ctx["genesis"].as_str().unwrap()).unwrap(),
                        v.as_array().unwrap(),
                        &rc,
                    ),
                    c,
                )?
                .current_key
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
    if f.family == "signing-bytes" {
        let b = parse_signing_bytes(v)?;
        if let Some(id) = &c.link_id {
            use sha2::{Digest, Sha256};
            assert_eq!(&hex(&Sha256::digest(&b)), id);
        }
        return Ok(Value::String(hex(&b)));
    }
    let operation = c.extra.get("operation").and_then(Value::as_str);
    if let ("object", Some(operation)) = (f.family.as_str(), operation) {
        let id = match operation {
            "claim" => derive_claim_id(string(v)?)?,
            "external" => derive_external_id(
                &parse_source_key(v["source"].as_str().unwrap())?,
                v["providerItemId"].as_str().unwrap(),
            )?,
            "mint" => mint_object_id_with(v["kind"].as_str().unwrap(), |b| {
                for (out, n) in b.iter_mut().zip(v["bytes"].as_array().unwrap()) {
                    *out = n.as_u64().unwrap() as u8;
                }
                Ok(())
            })?
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
    assert_eq!(paths.len(), 11);
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
