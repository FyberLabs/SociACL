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
fn links(ctx: &Value) -> BTreeMap<String, WalletLink> {
    ctx["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            let v = &pair[1];
            let link: WalletLink = serde_json::from_value({
                let mut value = v.clone();
                value.as_object_mut().unwrap().remove("kind");
                value
            })
            .unwrap();
            (pair[0].as_str().unwrap().to_owned(), link)
        })
        .collect()
}
fn run(f: &Family, c: &Case, v: &Value) -> Result<Value, Reason> {
    if f.family == "records" {
        let ctx = context(f, c);
        let now = ctx["now"].as_u64().unwrap();
        let key = parse_principal_id(ctx["currentKey"].as_str().unwrap()).unwrap();
        let jwks: Jwks = serde_json::from_value(ctx["jwks"].clone()).unwrap();
        let ls = links(&ctx);
        let empty = vec![];
        let revs = ctx["revocations"].as_array().unwrap_or(&empty);
        let principal = match c.extra["operation"].as_str().unwrap() {
            "wallet-link" => verify_wallet_link_at_key(v, now, Some(&key))?.principal,
            "oidc-link" => {
                verify_oidc_link_at_key(
                    v,
                    &jwks,
                    &ctx["pinnedIss"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|s| s.as_str().unwrap().to_owned())
                        .collect::<BTreeSet<_>>(),
                    now,
                    Some(&key),
                )?
                .principal
            }
            "rotate" => verify_rotate(v, &key, &ls, &jwks, now)?.principal,
            "revoke" => verify_revoke(v, &key, now)?.principal,
            "resolve" => resolve_current_key(
                &parse_principal_id(ctx["genesis"].as_str().unwrap()).unwrap(),
                v.as_array().unwrap(),
                &ResolutionContext {
                    jwks: &jwks,
                    links: &ls,
                    revocations: revs,
                    now,
                },
            )?,
            "wallet-resolve" => {
                resolve_wallet_link(
                    &parse_eip55(ctx["address"].as_str().unwrap()).unwrap(),
                    v.as_array().unwrap(),
                    revs,
                    now,
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
    assert_eq!(paths.len(), 10);
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
