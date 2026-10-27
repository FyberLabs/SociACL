use crate::ids::{checksum, principal_bytes};
use crate::*;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const MAX_SAFE: u64 = 9_007_199_254_740_991;
/// Each resolution list, link map, and revocation list stops at this length.
/// Longer input is [`Reason::TooLong`] and is not truncated.
pub const MAX_RESOLUTION_INPUT: usize = 1024;

fn bounded(len: usize) -> Result<(), Reason> {
    if len > MAX_RESOLUTION_INPUT {
        Err(Reason::TooLong)
    } else {
        Ok(())
    }
}

fn siwe_proof_hash(siwe: &Siwe) -> String {
    hex(&Sha256::digest(lp(&[
        "sociacl-siwe-proof-v1",
        &siwe.message,
        &siwe.signature,
    ])))
}
macro_rules! rx {
    ($pattern:literal) => {{
        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new($pattern).expect("constant regex"))
    }};
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Siwe {
    pub message: String,
    pub signature: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletLink {
    pub v: u8,
    pub principal: PrincipalId,
    pub address: Eip55,
    #[serde(deserialize_with = "deserialize_integer")]
    pub issued_at: u64,
    pub nonce: String,
    pub key_sig: String,
    pub siwe: Siwe,
    pub attest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcLink {
    pub v: u8,
    pub principal: PrincipalId,
    pub cred: OidcCredential,
    #[serde(deserialize_with = "deserialize_integer")]
    pub issued_at: u64,
    pub nonce: String,
    pub key_sig: String,
    pub attest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Authorizer {
    #[serde(rename = "wallet")]
    Wallet { link: String, siwe: Siwe },
    #[serde(rename = "oidc-fresh-login")]
    OidcFreshLogin { link: String },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rotate {
    pub v: u8,
    pub principal: PrincipalId,
    #[serde(deserialize_with = "deserialize_integer")]
    pub seq: u64,
    pub prev_key: PrincipalId,
    pub next_key: PrincipalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_epub: Option<PrincipalId>,
    pub retained_links: Vec<String>,
    #[serde(deserialize_with = "deserialize_integer")]
    pub issued_at: u64,
    pub next_sig: String,
    pub authorizer: Authorizer,
    pub attest: String,
}
/// Genesis key signs the account's first epub. Panopticon attests it at signup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenesisEpub {
    pub v: u8,
    pub principal: PrincipalId,
    pub epub: PrincipalId,
    #[serde(deserialize_with = "deserialize_integer")]
    pub issued_at: u64,
    pub key_sig: String,
    pub attest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revoke {
    pub v: u8,
    pub principal: PrincipalId,
    pub link_id: String,
    #[serde(deserialize_with = "deserialize_integer")]
    pub issued_at: u64,
    pub key_sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attest: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum IdentityRecord {
    Wallet(WalletLink),
    Oidc(OidcLink),
    Rotate(Rotate),
    Revoke(Revoke),
    #[serde(rename = "genesis-epub")]
    GenesisEpub(GenesisEpub),
}
impl IdentityRecord {
    pub fn principal(&self) -> &PrincipalId {
        match self {
            Self::Wallet(r) => &r.principal,
            Self::Oidc(r) => &r.principal,
            Self::Rotate(r) => &r.principal,
            Self::Revoke(r) => &r.principal,
            Self::GenesisEpub(r) => &r.principal,
        }
    }
    pub fn issued_at(&self) -> u64 {
        match self {
            Self::Wallet(r) => r.issued_at,
            Self::Oidc(r) => r.issued_at,
            Self::Rotate(r) => r.issued_at,
            Self::Revoke(r) => r.issued_at,
            Self::GenesisEpub(r) => r.issued_at,
        }
    }
    pub fn value(&self) -> Value {
        serde_json::to_value(self).expect("record contains only serializable types")
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub kid: String,
    pub x: String,
    pub y: String,
    pub alg: Option<String>,
    pub r#use: Option<String>,
    pub key_ops: Option<Vec<String>>,
    /// Trusted issuance bounds in Unix seconds. Missing bounds fail verification.
    #[serde(default, rename = "notBefore", deserialize_with = "deserialize_key_time")]
    pub not_before: Option<u64>,
    #[serde(default, rename = "notAfter", deserialize_with = "deserialize_key_time")]
    pub not_after: Option<u64>,
}
// Keep invalid or absent metadata unusable, while accepting integral JSON
// numbers regardless of spelling, just like the TypeScript verifier.
fn deserialize_key_time<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    let value = Value::deserialize(d)?;
    Ok(number(&value).ok())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}
pub struct ResolutionContext<'a> {
    pub jwks: &'a Jwks,
    pub links: &'a BTreeMap<String, Value>,
    pub revocations: &'a [Value],
    pub now: u64,
    pub policy: &'a SiwePolicy,
    pub pinned_iss: &'a BTreeSet<String>,
    pub history: &'a HistoryResolver<'a>,
    /// Witnessed `genesis-epub` records. Gun `user.epub` is not this slice.
    pub genesis_epub_bindings: &'a [Value],
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwePolicy {
    pub allowed_domains: Vec<String>,
    pub allowed_uris: Vec<String>,
    pub allowed_chain_ids: Vec<String>,
    #[serde(default)]
    pub clock_skew_seconds: u64,
}
#[derive(Clone, Debug)]
pub struct KeyState {
    pub key: PrincipalId,
    pub current_key: PrincipalId,
    pub retained_links: Option<Vec<String>>,
}
pub type HistoryResolver<'a> = dyn Fn(&PrincipalId, u64, u64) -> Result<KeyState, Reason> + 'a;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Diagnostic {
    pub source: String,
    pub index: usize,
    pub reason: Reason,
}
#[derive(Clone, Debug)]
pub struct Resolution<T> {
    pub result: Result<T, Reason>,
    pub diagnostics: Vec<Diagnostic>,
}
#[derive(Clone, Debug)]
pub struct ResolvedAccount {
    pub current_key: PrincipalId,
    pub current_epub: Option<PrincipalId>,
    /// In-force witnessed genesis epub. None when none was attested, or the
    /// only one was issued at or after the first accepted rotation.
    pub binding_epub: Option<PrincipalId>,
    pub rotations: Vec<Rotate>,
}
fn diagnostic(ds: &mut Vec<Diagnostic>, source: &str, index: usize, reason: Reason) {
    if !ds
        .iter()
        .any(|d| d.source == source && d.index == index && d.reason == reason)
    {
        ds.push(Diagnostic {
            source: source.into(),
            index,
            reason,
        });
    }
}

fn field<'a>(v: &'a Value, key: &str, max: usize) -> Result<&'a str, Reason> {
    text(v[key].as_str().ok_or(Reason::NotString)?, max)
}
fn only(v: &Value, keys: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.keys().all(|k| keys.contains(&k.as_str())))
}
fn number(v: &Value) -> Result<u64, Reason> {
    let n = v.as_f64().ok_or(Reason::BadRecord)?;
    if n.is_finite() && !n.is_sign_negative() && n.fract() == 0.0 && n <= MAX_SAFE as f64 {
        Ok(n as u64)
    } else {
        Err(Reason::BadRecord)
    }
}

fn deserialize_integer<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    number(&Value::deserialize(d)?).map_err(serde::de::Error::custom)
}

fn siwe_data(v: &Value) -> Result<Siwe, Reason> {
    if !only(v, &["message", "signature"]) {
        return Err(Reason::BadRecord);
    }
    let message = v["message"].as_str().ok_or(Reason::NotString)?;
    let signature = v["signature"].as_str().ok_or(Reason::NotString)?;
    if message.encode_utf16().count() > 8192 {
        return Err(Reason::TooLong);
    }
    if !rx!(r"^0x[0-9a-fA-F]{130}$").is_match(signature) {
        return Err(Reason::UnsupportedWallet);
    }
    Ok(Siwe {
        message: message.into(),
        signature: signature.into(),
    })
}
fn record(v: &Value, unsigned: bool) -> Result<IdentityRecord, Reason> {
    if !v.is_object()
        || v["v"].as_f64() != Some(1.0)
        || ![
            Some("wallet"),
            Some("oidc"),
            Some("rotate"),
            Some("revoke"),
            Some("genesis-epub"),
        ]
        .contains(&v["kind"].as_str())
    {
        return Err(Reason::BadRecord);
    }
    let principal = parse_principal_id(v["principal"].as_str().ok_or(Reason::NotString)?)?;
    let issued_at = number(&v["issuedAt"])?;
    let sig = |key: &str| {
        if unsigned {
            Ok(String::new())
        } else {
            field(v, key, 128).map(str::to_owned)
        }
    };
    let attest = || {
        if unsigned {
            Ok(String::new())
        } else {
            field(v, "attest", 16384).map(str::to_owned)
        }
    };
    match v["kind"].as_str().ok_or(Reason::BadRecord)? {
        "genesis-epub" => {
            if !only(
                v,
                &[
                    "v",
                    "kind",
                    "principal",
                    "epub",
                    "issuedAt",
                    "keySig",
                    "attest",
                ],
            ) {
                return Err(Reason::BadRecord);
            }
            let epub = parse_principal_id(v["epub"].as_str().ok_or(Reason::NotString)?)?;
            if epub == principal {
                return Err(Reason::BadRecord);
            }
            Ok(IdentityRecord::GenesisEpub(GenesisEpub {
                v: 1,
                principal,
                epub,
                issued_at,
                key_sig: sig("keySig")?,
                attest: attest()?,
            }))
        }
        "wallet" | "oidc" => {
            let nonce = field(v, "nonce", 128)?.to_owned();
            if !rx!(r"^[A-Za-z0-9]{8,128}$").is_match(&nonce) {
                return Err(Reason::BadRecord);
            }
            let key_sig = sig("keySig")?;
            if v["kind"] == "wallet" {
                if !only(
                    v,
                    &[
                        "v",
                        "kind",
                        "principal",
                        "issuedAt",
                        "address",
                        "nonce",
                        "keySig",
                        "siwe",
                        "attest",
                    ],
                ) {
                    return Err(Reason::BadRecord);
                }
                let address = parse_eip55(v["address"].as_str().ok_or(Reason::NotString)?)?;
                let siwe = if unsigned {
                    Siwe {
                        message: String::new(),
                        signature: "0x".into(),
                    }
                } else {
                    siwe_data(&v["siwe"])?
                };
                Ok(IdentityRecord::Wallet(WalletLink {
                    v: 1,
                    principal,
                    address,
                    issued_at,
                    nonce,
                    key_sig,
                    siwe,
                    attest: attest()?,
                }))
            } else {
                if !only(
                    v,
                    &[
                        "v",
                        "kind",
                        "principal",
                        "issuedAt",
                        "cred",
                        "nonce",
                        "keySig",
                        "attest",
                    ],
                ) {
                    return Err(Reason::BadRecord);
                }
                let cred = parse_oidc_credential(&v["cred"])?;
                Ok(IdentityRecord::Oidc(OidcLink {
                    v: 1,
                    principal,
                    cred,
                    issued_at,
                    nonce,
                    key_sig,
                    attest: attest()?,
                }))
            }
        }
        "revoke" => {
            if !only(
                v,
                &[
                    "v",
                    "kind",
                    "principal",
                    "issuedAt",
                    "linkId",
                    "keySig",
                    "attest",
                ],
            ) {
                return Err(Reason::BadRecord);
            }
            let link_id = field(v, "linkId", 64)?.to_owned();
            if !is_hex(&link_id, 64) {
                return Err(Reason::BadRecord);
            }
            Ok(IdentityRecord::Revoke(Revoke {
                v: 1,
                principal,
                issued_at,
                link_id,
                key_sig: sig("keySig")?,
                attest: if unsigned || v.get("attest").is_none() {
                    None
                } else {
                    Some(attest()?)
                },
            }))
        }
        "rotate" => {
            let mut keys = vec![
                "v",
                "kind",
                "principal",
                "issuedAt",
                "seq",
                "prevKey",
                "nextKey",
                "retainedLinks",
                "nextSig",
                "authorizer",
                "attest",
            ];
            if v.get("nextEpub").is_some() {
                keys.push("nextEpub");
            }
            if !only(v, &keys) {
                return Err(Reason::BadRecord);
            }
            let seq = number(&v["seq"]).map_err(|_| Reason::BadSequence)?;
            if seq == 0 {
                return Err(Reason::BadSequence);
            }
            let retained_links = retained_ids(&v["retainedLinks"])?;
            let prev_key = parse_principal_id(v["prevKey"].as_str().ok_or(Reason::NotString)?)?;
            let next_key = parse_principal_id(v["nextKey"].as_str().ok_or(Reason::NotString)?)?;
            let next_epub = if v.get("nextEpub").is_some() {
                Some(parse_principal_id(
                    v["nextEpub"].as_str().ok_or(Reason::NotString)?,
                )?)
            } else {
                None
            };
            let next_sig = sig("nextSig")?;
            let att = attest()?;
            let a = &v["authorizer"];
            if !(a["kind"] == "wallet" && only(a, &["kind", "link", "siwe"])
                || a["kind"] == "oidc-fresh-login" && only(a, &["kind", "link"]))
            {
                return Err(Reason::BadRecord);
            }
            let link = field(a, "link", 64)?.to_owned();
            if !is_hex(&link, 64) {
                return Err(Reason::BadRecord);
            }
            let authorizer = if a["kind"] == "oidc-fresh-login" {
                Authorizer::OidcFreshLogin { link }
            } else {
                Authorizer::Wallet {
                    link,
                    siwe: if unsigned {
                        Siwe {
                            message: String::new(),
                            signature: "0x".into(),
                        }
                    } else {
                        siwe_data(&a["siwe"])?
                    },
                }
            };
            Ok(IdentityRecord::Rotate(Rotate {
                v: 1,
                principal,
                seq,
                prev_key,
                next_key,
                next_epub,
                retained_links,
                issued_at,
                next_sig,
                authorizer,
                attest: att,
            }))
        }
        _ => Err(Reason::BadRecord),
    }
}
/// Sorted unique 64-hex link ids, at most 1024. The same rule as a signed rotation.
fn retained_ids(v: &Value) -> Result<Vec<String>, Reason> {
    let retained_links: Vec<String> = v
        .as_array()
        .ok_or(Reason::BadRecord)?
        .iter()
        .map(|x| {
            x.as_str()
                .filter(|s| is_hex(s, 64))
                .map(str::to_owned)
                .ok_or(Reason::BadRecord)
        })
        .collect::<Result<_, _>>()?;
    if retained_links.len() > 1024 || retained_links.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Reason::BadRecord);
    }
    Ok(retained_links)
}
fn bytes(r: &IdentityRecord) -> Vec<u8> {
    let t = r.issued_at().to_string();
    match r {
        IdentityRecord::Wallet(r) => lp(&[
            "sociacl-link-wallet-v1",
            r.principal.as_ref(),
            r.address.as_ref(),
            &t,
            &r.nonce,
        ]),
        IdentityRecord::Oidc(r) => lp(&[
            "sociacl-link-oidc-v1",
            r.principal.as_ref(),
            r.cred.issuer(),
            r.cred.tenant().as_ref(),
            r.cred.subject(),
            &t,
            &r.nonce,
        ]),
        IdentityRecord::Rotate(r) => {
            let seq = r.seq.to_string();
            let count = r.retained_links.len().to_string();
            let (auth, link) = match &r.authorizer {
                Authorizer::Wallet { link, .. } => ("wallet", link),
                Authorizer::OidcFreshLogin { link } => ("oidc-fresh-login", link),
            };
            let domain = if r.next_epub.is_some() {
                "sociacl-rotate-v3"
            } else {
                "sociacl-rotate-v2"
            };
            let mut fields = vec![
                domain,
                r.principal.as_ref(),
                &seq,
                r.prev_key.as_ref(),
                r.next_key.as_ref(),
            ];
            if let Some(epub) = &r.next_epub {
                fields.push(epub.as_ref());
            }
            fields.push(&t);
            fields.push(auth);
            fields.push(link);
            fields.push(&count);
            fields.extend(r.retained_links.iter().map(String::as_str));
            lp(&fields)
        }
        IdentityRecord::Revoke(r) => {
            lp(&["sociacl-revoke-v1", r.principal.as_ref(), &r.link_id, &t])
        }
        IdentityRecord::GenesisEpub(r) => lp(&[
            "sociacl-genesis-epub-v1",
            r.principal.as_ref(),
            r.epub.as_ref(),
            &t,
        ]),
    }
}
pub fn signing_bytes(r: &IdentityRecord) -> Result<Vec<u8>, Reason> {
    let validated = record(&r.value(), true)?;
    Ok(bytes(&validated))
}
/// Parse an unsigned wire record at the edge before producing signing bytes.
pub fn parse_signing_bytes(v: &Value) -> Result<Vec<u8>, Reason> {
    Ok(bytes(&record(v, true)?))
}
pub fn link_id(r: &IdentityRecord) -> Result<String, Reason> {
    Ok(hex(&Sha256::digest(signing_bytes(r)?)))
}
fn key_verify(key: &PrincipalId, sig: &str, message: &[u8]) -> bool {
    let Ok(raw) = unb64(sig) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&raw) else {
        return false;
    };
    VerifyingKey::from_sec1_bytes(&principal_bytes(key))
        .is_ok_and(|key| key.verify(message, &signature).is_ok())
}
fn time(issued: u64, now: u64) -> Result<(), Reason> {
    if now > MAX_SAFE {
        Err(Reason::BadRecord)
    } else if issued > now {
        Err(Reason::FutureRecord)
    } else {
        Ok(())
    }
}
fn date(s: &str) -> Option<f64> {
    let c = rx!(
        r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.[0-9]+)?([Zz]|[+-]\d{2}:\d{2})$"
    )
    .captures(s)?;
    let y: i64 = c[1].parse().ok()?;
    let m: usize = c[2].parse().ok()?;
    let d: i64 = c[3].parse().ok()?;
    let h: i64 = c[4].parse().ok()?;
    let min: i64 = c[5].parse().ok()?;
    let sec: i64 = c[6].parse().ok()?;
    let days = [
        31,
        if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            29
        } else {
            28
        },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&m) || d < 1 || d > days[m - 1] || h > 23 || min > 59 || sec > 59 {
        return None;
    }
    // Gregorian civil date to days since 1970-01-01, including year 0000.
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = m as i64 + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let mut offset = 0;
    if c[8] != *"Z" && c[8] != *"z" {
        let hh: i64 = c[8][1..3].parse().ok()?;
        let mm: i64 = c[8][4..].parse().ok()?;
        if hh > 23 || mm > 59 {
            return None;
        }
        offset = (hh * 60 + mm) * 60 * if c[8].starts_with('+') { 1 } else { -1 };
    }
    Some(
        ((era * 146097 + doe - 719468) * 86400 + h * 3600 + min * 60 + sec - offset) as f64
            + c.get(7)
                .map_or(Some(0.0), |m| m.as_str().parse::<f64>().ok())?,
    )
}
fn uri(s: &str) -> bool {
    crate::uri::web_uri(s, false, true)
}
fn siwe_verify(
    proof: &Siwe,
    address: &Eip55,
    message: &[u8],
    issued: u64,
    now: u64,
    policy: &SiwePolicy,
    nonce: Option<&str>,
) -> Result<(), Reason> {
    let l: Vec<_> = proof.message.split('\n').collect();
    if l.len() < 10 || !rx!(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?[^\s/?#]+ wants you to sign in with your Ethereum account:$").is_match(l[0]) || l[1] != address.as_ref() || !l[2].is_empty() || l[3] != format!("SociACL link: {}", hex(&Sha256::digest(message))) || !l[4].is_empty() { return Err(Reason::BadSignature); }
    if !l[5].strip_prefix("URI: ").is_some_and(uri)
        || l[6] != "Version: 1"
        || !rx!(r"^Chain ID: [0-9]+$").is_match(l[7])
        || !rx!(r"^Nonce: [A-Za-z0-9]{8,128}$").is_match(l[8])
        || nonce.is_some_and(|n| l[8] != format!("Nonce: {n}"))
        || l[9].strip_prefix("Issued At: ").and_then(date) != Some(issued as f64)
    {
        return Err(Reason::BadSignature);
    }
    let domain = l[0]
        .strip_suffix(" wants you to sign in with your Ethereum account:")
        .ok_or(Reason::BadSignature)?;
    if !uri(&format!(
        "{}/",
        if domain.starts_with("https://") {
            domain.to_owned()
        } else {
            format!("https://{domain}")
        }
    )) {
        return Err(Reason::BadSignature);
    }
    if !policy.allowed_domains.iter().any(|s| s == domain)
        || !policy
            .allowed_uris
            .iter()
            .any(|s| Some(s.as_str()) == l[5].strip_prefix("URI: "))
        || !policy
            .allowed_chain_ids
            .iter()
            .any(|s| Some(s.as_str()) == l[7].strip_prefix("Chain ID: "))
    {
        return Err(Reason::BadSignature);
    }
    let mut at = 10;
    if let Some(s) = l.get(at).and_then(|s| s.strip_prefix("Expiration Time: ")) {
        let expiry = date(s).ok_or(Reason::BadSignature)?;
        at += 1;
        if expiry <= issued as f64 {
            return Err(Reason::BadSignature);
        }
        if now as f64 - policy.clock_skew_seconds as f64 >= expiry {
            return Err(Reason::Expired);
        }
    }
    if let Some(s) = l.get(at).and_then(|s| s.strip_prefix("Not Before: ")) {
        let start = date(s).ok_or(Reason::BadSignature)?;
        at += 1;
        if start > issued as f64 {
            return Err(Reason::BadSignature);
        }
    }
    if let Some(s) = l.get(at).and_then(|s| s.strip_prefix("Request ID: ")) {
        if !rx!(r"^(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9a-fA-F]{2})*$").is_match(s) {
            return Err(Reason::BadSignature);
        }
        at += 1;
    }
    if l.get(at) == Some(&"Resources:") {
        at += 1;
        while l
            .get(at)
            .is_some_and(|s| s.strip_prefix("- ").is_some_and(uri))
        {
            at += 1;
        }
    }
    if at != l.len() {
        return Err(Reason::BadSignature);
    }
    let sig = unhex(
        proof
            .signature
            .strip_prefix("0x")
            .ok_or(Reason::BadSignature)?,
    )
    .map_err(|_| Reason::BadSignature)?;
    if sig.len() != 65 {
        return Err(Reason::UnsupportedWallet);
    }
    let recovery = if sig[64] >= 27 { sig[64] - 27 } else { sig[64] };
    if recovery > 1 {
        return Err(Reason::BadSignature);
    }
    let mut id = k256::ecdsa::RecoveryId::from_byte(recovery).ok_or(Reason::BadSignature)?;
    let mut signature =
        k256::ecdsa::Signature::from_slice(&sig[..64]).map_err(|_| Reason::BadSignature)?;
    if signature.normalize_s() != signature {
        signature = signature.normalize_s();
        id = k256::ecdsa::RecoveryId::from_byte(recovery ^ 1).ok_or(Reason::BadSignature)?;
    }
    let mut preimage =
        format!("\x19Ethereum Signed Message:\n{}", proof.message.len()).into_bytes();
    preimage.extend(proof.message.as_bytes());
    let prehash = Keccak256::digest(preimage);
    let key = k256::ecdsa::VerifyingKey::recover_from_prehash(prehash.as_slice(), &signature, id)
        .map_err(|_| Reason::BadSignature)?;
    let hash = Keccak256::digest(&key.to_sec1_point(false).as_bytes()[1..]);
    if checksum(&format!("0x{}", hex(&hash[12..]))) != address.as_ref() {
        return Err(Reason::BadSignature);
    }
    Ok(())
}

// Reject duplicate JSON members before serde_json can collapse them.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate members")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(Unique(v)) = a.next_element()? {
                    out.push(v);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut out = Map::new();
                while let Some((k, Unique(v))) = a.next_entry::<String, Unique>()? {
                    if out.insert(k, v).is_some() {
                        return Err(serde::de::Error::custom("duplicate member"));
                    }
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
pub(crate) fn unique_json(s: &str) -> Result<Value, serde_json::Error> {
    fn depth(v: &Value, n: usize) -> bool {
        n <= 16
            && match v {
                Value::Array(a) => a.iter().all(|v| depth(v, n + 1)),
                Value::Object(o) => o.values().all(|v| depth(v, n + 1)),
                _ => true,
            }
    }
    let v = serde_json::from_str::<Unique>(s)?.0;
    if !depth(&v, 0) {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "JSON depth",
        ));
    }
    Ok(v)
}
fn attest_verify(jws: &str, jwks: &Jwks, now: u64, skew: u64) -> Result<Value, Reason> {
    let parts: Vec<_> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(Reason::BadAttestation);
    }
    let decode = |s| -> Result<Value, Reason> {
        let raw = unb64(s).map_err(|_| Reason::BadAttestation)?;
        unique_json(std::str::from_utf8(&raw).map_err(|_| Reason::BadAttestation)?)
            .map_err(|_| Reason::BadAttestation)
    };
    let h = decode(parts[0])?;
    let c = decode(parts[1])?;
    if !only(&h, &["alg", "kid", "typ"])
        || h["alg"] != "ES256"
        || h["kid"].as_str().is_none_or(str::is_empty)
        || (h.get("typ").is_some() && h["typ"] != "JWT")
        || !c.is_object()
    {
        return Err(Reason::BadAttestation);
    }
    let keys: Vec<_> = jwks
        .keys
        .iter()
        .filter(|k| Some(k.kid.as_str()) == h["kid"].as_str())
        .collect();
    if keys.len() != 1 {
        return Err(Reason::BadAttestation);
    }
    let k = keys[0];
    if k.kty != "EC"
        || k.crv != "P-256"
        || k.alg.as_ref().is_some_and(|s| s != "ES256")
        || k.r#use.as_ref().is_some_and(|s| s != "sig")
        || k.key_ops.as_ref().is_some_and(|ops| {
            !ops.iter().any(|s| s == "verify") || ops.iter().any(|s| s != "verify")
        })
    {
        return Err(Reason::BadAttestation);
    }
    let key =
        parse_principal_id(&format!("{}.{}", k.x, k.y)).map_err(|_| Reason::BadAttestation)?;
    if !key_verify(
        &key,
        parts[2],
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
    ) {
        return Err(Reason::BadAttestation);
    }
    let iat = number(&c["iat"]).map_err(|_| Reason::BadAttestation)?;
    let exp = number(&c["exp"]).map_err(|_| Reason::BadAttestation)?;
    if now > MAX_SAFE || exp <= iat || exp - iat > 900 {
        return Err(Reason::BadAttestation);
    }
    // Historical verification uses signed issuance, not the lookup clock.
    // Skew does not expand the trusted key's authorization window.
    let start = k.not_before.ok_or(Reason::BadAttestation)?;
    let end = k.not_after.ok_or(Reason::BadAttestation)?;
    if start >= end || end > MAX_SAFE || iat < start || iat >= end {
        return Err(Reason::BadAttestation);
    }
    if iat > now.saturating_add(skew) {
        return Err(Reason::FutureRecord);
    }
    if exp as i128 <= now as i128 - skew as i128 {
        return Err(Reason::Expired);
    }
    Ok(c)
}
fn proof_time(issued: u64, now: u64, skew: u64) -> Result<(), Reason> {
    if skew > 300 || now > MAX_SAFE {
        return Err(Reason::BadRecord);
    }
    if issued > now.saturating_add(skew) {
        return Err(Reason::FutureRecord);
    }
    Ok(())
}
/// Request mode only. Historical proofs stay an upper bound.
fn request_time(issued: u64, now: u64, skew: u64) -> Result<(), Reason> {
    proof_time(issued, now, skew)?;
    if (issued as i128) < now as i128 - skew as i128 {
        return Err(Reason::Expired);
    }
    Ok(())
}
/// Present-revocation horizon for an unattested request. Historical checks stay skew-free.
/// A sum past the safe-integer cap falls back to `now`, which is stricter.
/// Direct [`verify_revoke_now`] does not use this.
fn present_horizon(now: u64, skew: u64) -> u64 {
    if now > MAX_SAFE || skew > MAX_SAFE {
        return now;
    }
    let horizon = now.saturating_add(skew);
    if horizon > MAX_SAFE {
        now
    } else {
        horizon
    }
}
fn wallet_witness(
    w: &WalletLink,
    jwks: &Jwks,
    policy: &SiwePolicy,
    now: u64,
) -> Result<(), Reason> {
    proof_time(w.issued_at, now, policy.clock_skew_seconds)?;
    siwe_verify(
        &w.siwe,
        &w.address,
        &bytes(&IdentityRecord::Wallet(w.clone())),
        w.issued_at,
        now,
        policy,
        Some(&w.nonce),
    )?;
    let c = attest_verify(&w.attest, jwks, now, policy.clock_skew_seconds)?;
    if !only(&c, &["typ", "principal", "linkId", "iat", "exp"])
        || c["typ"] != "sociacl-wallet-attest-v1"
        || c["principal"] != w.principal.as_ref()
        || c["linkId"] != link_id(&IdentityRecord::Wallet(w.clone()))?
        || number(&c["iat"]).ok() != Some(w.issued_at)
    {
        return Err(Reason::BadAttestation);
    }
    Ok(())
}
fn oidc_witness(
    o: &OidcLink,
    jwks: &Jwks,
    pinned_iss: &BTreeSet<String>,
    now: u64,
    clock_skew_seconds: u64,
) -> Result<(), Reason> {
    proof_time(o.issued_at, now, clock_skew_seconds)?;
    if !pinned_iss.contains(o.cred.issuer()) {
        return Err(Reason::UntrustedIssuer);
    }
    let c = attest_verify(&o.attest, jwks, now, clock_skew_seconds)?;
    if !only(
        &c,
        &[
            "typ",
            "iss",
            "tenant",
            "sub",
            "principal",
            "iat",
            "exp",
            "nonce",
        ],
    ) || c["typ"] != "sociacl-oidc-attest-v1"
        || c["iss"] != o.cred.issuer()
        || c["tenant"] != o.cred.tenant().as_ref()
        || c["sub"] != o.cred.subject()
        || c["principal"] != o.principal.as_ref()
        || number(&c["iat"]).ok() != Some(o.issued_at)
        || c["nonce"] != o.nonce
    {
        return Err(Reason::BadAttestation);
    }
    Ok(())
}
fn retained_link(r: &IdentityRecord, state: &KeyState) -> Result<(), Reason> {
    if state
        .retained_links
        .as_ref()
        .is_some_and(|ids| !ids.contains(&hex(&Sha256::digest(bytes(r)))))
    {
        return Err(Reason::UnretainedLink);
    }
    Ok(())
}
pub fn verify_wallet_link(
    v: &Value,
    jwks: &Jwks,
    policy: &SiwePolicy,
    now: u64,
    key_state: &KeyState,
) -> Result<WalletLink, Reason> {
    let r = record(v, false)?;
    let IdentityRecord::Wallet(w) = &r else {
        return Err(Reason::BadRecord);
    };
    proof_time(w.issued_at, now, policy.clock_skew_seconds)?;
    if !key_verify(&key_state.key, &w.key_sig, &bytes(&r)) {
        return Err(Reason::BadSignature);
    }
    retained_link(&r, key_state)?;
    wallet_witness(w, jwks, policy, now)?;
    Ok(w.clone())
}
pub fn verify_oidc_link(
    v: &Value,
    jwks: &Jwks,
    pinned_iss: &BTreeSet<String>,
    now: u64,
    key_state: &KeyState,
) -> Result<OidcLink, Reason> {
    verify_oidc_link_with_skew(v, jwks, pinned_iss, now, key_state, 0)
}
pub fn verify_oidc_link_with_skew(
    v: &Value,
    jwks: &Jwks,
    pinned_iss: &BTreeSet<String>,
    now: u64,
    key_state: &KeyState,
    clock_skew_seconds: u64,
) -> Result<OidcLink, Reason> {
    let r = record(v, false)?;
    let IdentityRecord::Oidc(o) = &r else {
        return Err(Reason::BadRecord);
    };
    proof_time(o.issued_at, now, clock_skew_seconds)?;
    if !pinned_iss.contains(o.cred.issuer()) {
        return Err(Reason::UntrustedIssuer);
    }
    if !key_verify(&key_state.key, &o.key_sig, &bytes(&r)) {
        return Err(Reason::BadSignature);
    }
    retained_link(&r, key_state)?;
    oidc_witness(o, jwks, pinned_iss, now, clock_skew_seconds)?;
    Ok(o.clone())
}
/// Present-time authority only. The caller supplies the final authenticated current key.
/// This never certifies an issuance time or produces historical revocation evidence.
pub fn verify_revoke_now(v: &Value, current_key: &PrincipalId, now: u64) -> Result<Revoke, Reason> {
    let r = record(v, false)?;
    let IdentityRecord::Revoke(rev) = &r else {
        return Err(Reason::BadRecord);
    };
    time(rev.issued_at, now)?;
    if !key_verify(current_key, &rev.key_sig, &bytes(&r)) {
        return Err(Reason::BadSignature);
    }
    Ok(rev.clone())
}
/// Witness required, including when the signer is the current key.
pub fn verify_revoke(
    v: &Value,
    current_key: &PrincipalId,
    jwks: &Jwks,
    now: u64,
) -> Result<Revoke, Reason> {
    let rev = verify_revoke_now(v, current_key, now)?;
    let attestation = rev.attest.as_deref().ok_or(Reason::BadAttestation)?;
    let c = attest_verify(attestation, jwks, now, 0)?;
    if !only(&c, &["typ", "principal", "recordId", "iat", "exp"])
        || c["typ"] != "sociacl-revoke-attest-v1"
        || c["principal"] != rev.principal.as_ref()
        || c["recordId"] != hex(&Sha256::digest(bytes(&IdentityRecord::Revoke(rev.clone()))))
        || number(&c["iat"]).ok() != Some(rev.issued_at)
    {
        return Err(Reason::BadAttestation);
    }
    Ok(rev)
}
/// Use only with authenticated history complete through `until`.
pub fn history_state(genesis: &PrincipalId, history: &[Rotate], at: u64, until: u64) -> KeyState {
    let past: Vec<_> = history.iter().filter(|r| r.issued_at <= until).collect();
    let later: Vec<_> = past.iter().filter(|r| r.issued_at >= at).collect();
    KeyState {
        key: past
            .iter()
            .rev()
            .find(|r| r.issued_at < at)
            .map_or_else(|| genesis.clone(), |r| r.next_key.clone()),
        current_key: past
            .last()
            .map_or_else(|| genesis.clone(), |r| r.next_key.clone()),
        retained_links: later.first().map(|first| {
            first
                .retained_links
                .iter()
                .filter(|id| later.iter().all(|r| r.retained_links.contains(id)))
                .cloned()
                .collect()
        }),
    }
}
fn historical_link(
    r: &IdentityRecord,
    ctx: &ResolutionContext<'_>,
    until: u64,
) -> Result<IdentityRecord, Reason> {
    time(r.issued_at(), until)?;
    let sig = match r {
        IdentityRecord::Wallet(w) => {
            wallet_witness(w, ctx.jwks, ctx.policy, w.issued_at)?;
            &w.key_sig
        }
        IdentityRecord::Oidc(o) => {
            oidc_witness(o, ctx.jwks, ctx.pinned_iss, o.issued_at, 0)?;
            &o.key_sig
        }
        _ => return Err(Reason::BadRecord),
    };
    let h = (ctx.history)(r.principal(), r.issued_at(), until)?;
    if !key_verify(&h.key, sig, &bytes(r)) {
        return Err(Reason::BadSignature);
    }
    retained_link(r, &h)?;
    Ok(r.clone())
}
#[derive(Clone, Copy)]
enum RevocationMode {
    Witnessed,
    Present,
}
fn revoked_at(
    link: &IdentityRecord,
    revocations: &[Value],
    current_key: &PrincipalId,
    now: u64,
    jwks: &Jwks,
    diagnostics: &mut Vec<Diagnostic>,
    mode: RevocationMode,
) -> bool {
    let id = hex(&Sha256::digest(bytes(link)));
    let mut revoked = false;
    for (index, raw) in revocations.iter().enumerate() {
        let r = match record(raw, false) {
            Ok(IdentityRecord::Revoke(r)) => r,
            Ok(_) => {
                diagnostic(diagnostics, "revoke", index, Reason::BadRecord);
                continue;
            }
            Err(e) => {
                diagnostic(diagnostics, "revoke", index, e);
                continue;
            }
        };
        if let Err(e) = time(r.issued_at, now) {
            diagnostic(diagnostics, "revoke", index, e);
            continue;
        }
        if &r.principal != link.principal() || r.link_id != id || r.issued_at < link.issued_at() {
            continue;
        }
        let verified = match mode {
            RevocationMode::Witnessed => verify_revoke(raw, current_key, jwks, r.issued_at),
            RevocationMode::Present => verify_revoke_now(raw, current_key, now),
        };
        match verified {
            Ok(_) => revoked = true,
            Err(e) => diagnostic(diagnostics, "revoke", index, e),
        }
    }
    revoked
}
fn required_history_failure(reason: Reason) -> Reason {
    match reason {
        Reason::RotationFork | Reason::RotationConflict => reason,
        _ => Reason::MissingHistory,
    }
}
pub fn verify_rotate(
    v: &Value,
    current_key: &PrincipalId,
    ctx: &ResolutionContext<'_>,
) -> Result<Rotate, Reason> {
    bounded(ctx.links.len())?;
    bounded(ctx.revocations.len())?;
    bounded(ctx.genesis_epub_bindings.len())?;
    check_rotate(v, current_key, ctx, &mut Vec::new())
}
// A missing/malformed unsigned SIWE proof must not hide an authenticated transition.
// This placeholder always fails proof verification after the key signature and witness checks.
fn rotation_candidate(v: &Value) -> Result<IdentityRecord, Reason> {
    let parsed = record(v, false);
    if parsed.is_ok() || v["kind"] != "rotate" || v["authorizer"]["kind"] != "wallet" {
        return parsed;
    }
    let mut candidate = v.clone();
    candidate["authorizer"]["siwe"] =
        serde_json::json!({"message":"", "signature":format!("0x{}", "00".repeat(65))});
    record(&candidate, false).or(parsed)
}
fn reuses_epub(
    raw: &Rotate,
    genesis: &PrincipalId,
    history: &[Rotate],
    binding_epub: Option<&PrincipalId>,
) -> bool {
    if history
        .iter()
        .any(|h| h.next_epub.as_ref() == Some(&raw.next_key))
    {
        return true;
    }
    if binding_epub.is_some_and(|bound| bound == &raw.next_key) {
        return true;
    }
    let Some(epub) = &raw.next_epub else {
        return false;
    };
    epub == &raw.next_key
        || epub == genesis
        || binding_epub.is_some_and(|bound| epub == bound)
        || history.iter().any(|h| {
            &h.next_key == epub || &h.prev_key == epub || h.next_epub.as_ref() == Some(epub)
        })
}
fn verify_genesis_epub(
    raw: &Value,
    genesis: &PrincipalId,
    ctx: &ResolutionContext<'_>,
) -> Result<GenesisEpub, Reason> {
    let IdentityRecord::GenesisEpub(binding) = record(raw, false)? else {
        return Err(Reason::BadRecord);
    };
    if &binding.principal != genesis {
        return Err(Reason::BadRecord);
    }
    proof_time(binding.issued_at, ctx.now, ctx.policy.clock_skew_seconds)?;
    let signed = IdentityRecord::GenesisEpub(binding.clone());
    if !key_verify(&binding.principal, &binding.key_sig, &bytes(&signed)) {
        return Err(Reason::BadSignature);
    }
    // The witness is checked as of issuance, so a binding does not expire.
    let c = attest_verify(
        &binding.attest,
        ctx.jwks,
        binding.issued_at,
        ctx.policy.clock_skew_seconds,
    )?;
    if !only(&c, &["typ", "principal", "epub", "iat", "exp"])
        || c["typ"] != "sociacl-genesis-epub-attest-v1"
        || c["principal"] != binding.principal.as_ref()
        || c["epub"] != binding.epub.as_ref()
        || number(&c["iat"]).ok() != Some(binding.issued_at)
    {
        return Err(Reason::BadAttestation);
    }
    Ok(binding)
}
fn verified_bindings(
    genesis: &PrincipalId,
    ctx: &ResolutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<(usize, GenesisEpub)>, Reason> {
    let mut accepted: Vec<(usize, GenesisEpub, String)> = Vec::new();
    for (index, raw) in ctx.genesis_epub_bindings.iter().enumerate() {
        match verify_genesis_epub(raw, genesis, ctx) {
            Ok(binding) => {
                let id = link_id(&IdentityRecord::GenesisEpub(binding.clone()))?;
                if accepted.iter().any(|(_, _, seen)| seen == &id) {
                    continue;
                }
                accepted.push((index, binding, id));
            }
            Err(reason) => diagnostic(diagnostics, "genesis-epub", index, reason),
        }
    }
    Ok(accepted
        .into_iter()
        .map(|(index, binding, _)| (index, binding))
        .collect())
}
/// Authenticate the transition independently of its replaceable SIWE proof copy.
fn rotation_transition_claims_match(rot: &Rotate, c: &Value) -> bool {
    let (auth, link, siwe) = match &rot.authorizer {
        Authorizer::Wallet { link, siwe } => ("wallet", link.as_str(), Some(siwe)),
        Authorizer::OidcFreshLogin { link } => ("oidc-fresh-login", link.as_str(), None),
    };
    let epub = rot.next_epub.is_some();
    let wallet = epub && siwe.is_some();
    let mut attest_keys = vec![
        "typ",
        "principal",
        "nextKey",
        "seq",
        "iat",
        "exp",
        "auth",
        "linkId",
        "retainedLinks",
    ];
    if epub {
        attest_keys.push("nextEpub");
    }
    if wallet {
        attest_keys.push("siweHash");
    }
    let epub_matches = match &rot.next_epub {
        Some(epub) => c["nextEpub"] == epub.as_ref(),
        None => true,
    };
    let typ = if !epub {
        "sociacl-rotate-attest-v2"
    } else if wallet {
        "sociacl-rotate-attest-v4"
    } else {
        "sociacl-rotate-attest-v3"
    };
    let hash_ok = !wallet
        || c["siweHash"].as_str().is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    only(c, &attest_keys)
        && c["typ"] == typ
        && c["principal"] == rot.principal.as_ref()
        && c["nextKey"] == rot.next_key.as_ref()
        && epub_matches
        && number(&c["seq"]).ok() == Some(rot.seq)
        && number(&c["iat"]).ok() == Some(rot.issued_at)
        && c["auth"] == auth
        && c["linkId"] == link
        && c["retainedLinks"] == serde_json::json!(rot.retained_links)
        && hash_ok
}
/// Direct verification also binds the exact presented SIWE proof.
fn rotation_claims_match(rot: &Rotate, c: &Value) -> bool {
    rotation_transition_claims_match(rot, c)
        && match (&rot.next_epub, &rot.authorizer) {
            (Some(_), Authorizer::Wallet { siwe, .. }) => {
                c["siweHash"].as_str() == Some(siwe_proof_hash(siwe).as_str())
            }
            _ => true,
        }
}
/// A sibling counts only when its next-key signature and Panopticon attestation both verify.
fn authenticated_sibling(raw: &Value, ctx: &ResolutionContext<'_>) -> Option<Rotate> {
    let IdentityRecord::Rotate(row) = rotation_candidate(raw).ok()? else {
        return None;
    };
    let signed = IdentityRecord::Rotate(row.clone());
    if !key_verify(&row.next_key, &row.next_sig, &bytes(&signed)) {
        return None;
    }
    let c = attest_verify(
        &row.attest,
        ctx.jwks,
        row.issued_at,
        ctx.policy.clock_skew_seconds,
    )
    .ok()?;
    if !rotation_transition_claims_match(&row, &c) {
        return None;
    }
    Some(row)
}
fn draft_rotation(v: &Value) -> Result<Rotate, Reason> {
    if v["v"].as_f64() != Some(1.0) || v["kind"] != "rotate" {
        return Err(Reason::BadRecord);
    }
    if v.get("nextSig").is_some() || v.get("authorizer").is_some() || v.get("attest").is_some() {
        return Err(Reason::BadRecord);
    }
    if !only(
        v,
        &[
            "v",
            "kind",
            "principal",
            "seq",
            "prevKey",
            "nextKey",
            "nextEpub",
            "retainedLinks",
            "issuedAt",
        ],
    ) {
        return Err(Reason::BadRecord);
    }
    let principal = parse_principal_id(v["principal"].as_str().ok_or(Reason::NotString)?)?;
    let seq = number(&v["seq"])?;
    if seq == 0 {
        return Err(Reason::BadSequence);
    }
    let prev_key = parse_principal_id(v["prevKey"].as_str().ok_or(Reason::NotString)?)?;
    let next_key = parse_principal_id(v["nextKey"].as_str().ok_or(Reason::NotString)?)?;
    let next_epub = parse_principal_id(v["nextEpub"].as_str().ok_or(Reason::NotString)?)?;
    let retained_links = retained_ids(&v["retainedLinks"])?;
    let issued_at = if v.get("issuedAt").is_some() {
        number(&v["issuedAt"])?
    } else {
        0
    };
    Ok(Rotate {
        v: 1,
        principal,
        seq,
        prev_key,
        next_key,
        next_epub: Some(next_epub),
        retained_links,
        issued_at,
        next_sig: String::new(),
        authorizer: Authorizer::OidcFreshLogin {
            link: "0".repeat(64),
        },
        attest: String::new(),
    })
}
/// A draft has no signing-byte id. The same transition is the same keys, epub, and retained set.
fn same_draft(raw: &Rotate, other: &Rotate) -> bool {
    other.next_epub.is_some()
        && other.principal == raw.principal
        && other.seq == raw.seq
        && other.prev_key == raw.prev_key
        && other.next_key == raw.next_key
        && other.next_epub == raw.next_epub
        && other.retained_links == raw.retained_links
        && (raw.issued_at == 0 || other.issued_at == raw.issued_at)
}
struct LoadedChain {
    history: Vec<Rotate>,
    binding_epub: Option<PrincipalId>,
}
fn load_chain(
    genesis: &PrincipalId,
    prior_records: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<LoadedChain, Reason> {
    let account = resolve_current_key(genesis, prior_records, ctx).result?;
    Ok(LoadedChain {
        history: account.rotations,
        binding_epub: account.binding_epub,
    })
}
fn publish_tail(
    raw: Rotate,
    siblings: &[Value],
    genesis: &PrincipalId,
    history: &[Rotate],
    binding_epub: Option<&PrincipalId>,
    ctx: &ResolutionContext<'_>,
    draft: bool,
) -> Result<Rotate, Reason> {
    let current = history
        .last()
        .map(|row| row.next_key.clone())
        .unwrap_or_else(|| genesis.clone());
    let candidate_id = if draft {
        String::new()
    } else {
        link_id(&IdentityRecord::Rotate(raw.clone()))?
    };
    for sibling in siblings {
        let Some(other) = authenticated_sibling(sibling, ctx) else {
            continue;
        };
        if other.principal != raw.principal || other.seq != raw.seq || other.prev_key != current {
            continue;
        }
        if draft {
            if !same_draft(&raw, &other) {
                return Err(Reason::RotationFork);
            }
            continue;
        }
        if other.next_epub.is_none() || link_id(&IdentityRecord::Rotate(other))? != candidate_id {
            return Err(Reason::RotationFork);
        }
    }
    let seq = history.len() as u64 + 1;
    let last_time = history.last().map(|row| row.issued_at);
    let timed = !draft || raw.issued_at != 0;
    if raw.seq != seq
        || (timed && last_time.is_some_and(|time| raw.issued_at <= time))
        || raw.prev_key != current
        || &raw.next_key == genesis
        || history.iter().any(|row| row.next_key == raw.next_key)
        || reuses_epub(&raw, genesis, history, binding_epub)
    {
        return Err(Reason::BadSequence);
    }
    Ok(raw)
}
/// Structural draft the keyring builder checks before a signature exists.
/// Never an attestation gate: success does not authorize a witness signature.
/// Witnesses must use [`check_rotation_publish`] on the signed request.
///
/// An unsigned draft has no `nextSig`, `authorizer`, `attest`, or required
/// `issuedAt`. `retainedLinks` uses the signed-record rule. An identical
/// attested sibling of the same transition is a retry and is not a fork.
/// [`check_rotation_publish`] rejects this shape with `bad-record`. Only
/// `rotate_keyring` calls this.
pub fn check_rotation_draft(
    candidate: &Value,
    siblings: &[Value],
    genesis: &PrincipalId,
    prior_records: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<Rotate, Reason> {
    let chain = load_chain(genesis, prior_records, ctx)?;
    let raw = draft_rotation(candidate)?;
    if &raw.principal != genesis {
        return Err(Reason::BadRecord);
    }
    publish_tail(
        raw,
        siblings,
        genesis,
        &chain.history,
        chain.binding_epub.as_ref(),
        ctx,
        true,
    )
}
/// Client publish check and Panopticon attest check. Same rules.
///
/// Refuses a v2 record and an unsigned draft (`bad-record`). Draft validation
/// is [`check_rotation_draft`], and only the keyring builder calls it.
/// An authenticated sibling with a different signing-byte id at the same
/// (principal, seq) is `rotation-fork`. An identical attested sibling is a
/// retry and is not a fork. Junk and unattested siblings are skipped. Priors
/// are whatever [`resolve_current_key`] accepts.
/// A signed candidate with no attestation is checked by
/// [`verify_rotation_request`] (its local checks only). Freshness and present
/// revocation apply only to that unattested request. An attested candidate
/// uses the historical checks: `issuedAt` is an upper bound, and revocation
/// is the witnessed check at `issuedAt`. Chain sequence, sibling forks, and
/// epub reuse are applied here, after that call.
/// Panopticon MUST call this function before attesting. It attests at most
/// one genesis-epub binding per principal, only before the first rotation,
/// and that limit is global across instances and signing keys (panopticon#499).
/// Does not replace [`verify_rotate`]. Historical v2 records still verify there.
pub fn check_rotation_publish(
    candidate: &Value,
    siblings: &[Value],
    genesis: &PrincipalId,
    prior_records: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<Rotate, Reason> {
    let signed_request = candidate["kind"] == "rotate"
        && candidate.get("attest").is_none()
        && (candidate.get("nextSig").is_some() || candidate.get("authorizer").is_some());
    let parsed = rotation_candidate(candidate);
    if !signed_request && !matches!(&parsed, Ok(IdentityRecord::Rotate(_))) {
        return Err(Reason::BadRecord);
    }
    let chain = load_chain(genesis, prior_records, ctx)?;
    let current = chain
        .history
        .last()
        .map(|item| item.next_key.clone())
        .unwrap_or_else(|| genesis.clone());
    let raw = if signed_request {
        verify_rotation_request(candidate, &current, ctx)?
    } else {
        check_rotate(candidate, &current, ctx, &mut Vec::new())?
    };
    if raw.next_epub.is_none() || &raw.principal != genesis {
        return Err(Reason::BadRecord);
    }
    publish_tail(
        raw,
        siblings,
        genesis,
        &chain.history,
        chain.binding_epub.as_ref(),
        ctx,
        false,
    )
}
/// Local pre-attestation check for one v3 rotation request.
///
/// Covers: v3 (`nextEpub` required; v2 is `bad-record`); no `attest` field (a
/// present attestation is `bad-record` and is not returned); `|issuedAt-now|`
/// within `policy.clock_skew_seconds` (`future-record` or `expired`); `prevKey`
/// equal to the supplied current key and `nextKey` different from it;
/// `nextEpub` different from `nextKey` and `prevKey`; the next-key signature;
/// the authorizer (wallet SIWE, or OIDC with no active wallet); every authorizer
/// and retained link historically valid at `issuedAt`; witnessed revocation of
/// those links at `issuedAt` and at `now` (`rotation-conflict`); and an
/// unwitnessed current-key revoke of those links at `now` (`revoked-link`,
/// [`verify_revoke_now`]).
///
/// Freshness and present revocation apply only to this unattested request.
/// Present revocation honors `policy.clock_skew_seconds`: an offline revoke
/// issued at or before `now + skew` removes the link. A revoke dated further
/// ahead is ignored. The same horizon applies to the active-wallet check:
/// a wallet linked after `issuedAt` but at or before `now + skew` still makes
/// OIDC recovery `wallet-required`. Historical witnessed checks stay
/// skew-free, and [`verify_revoke_now`] itself stays skew-free.
///
/// Does not cover chain sequence, sibling forks, or epub reuse against history
/// or the genesis-epub binding. Panopticon MUST call [`check_rotation_publish`]
/// for those. This is the building block that function uses when the candidate
/// has no attestation (panopticon#499). [`verify_rotate`] still requires an
/// attestation and does not use this window.
pub fn verify_rotation_request(
    v: &Value,
    current_key: &PrincipalId,
    ctx: &ResolutionContext<'_>,
) -> Result<Rotate, Reason> {
    bounded(ctx.links.len())?;
    bounded(ctx.revocations.len())?;
    bounded(ctx.genesis_epub_bindings.len())?;
    if v["kind"] != "rotate" || v.get("attest").is_some() || v.get("nextEpub").is_none() {
        return Err(Reason::BadRecord);
    }
    let mut owned = v.clone();
    owned["attest"] = Value::String("request".into());
    let mut rot = check_rotate_record(
        &rotation_candidate(&owned)?,
        current_key,
        ctx,
        &mut Vec::new(),
        false,
    )?;
    if rot.next_epub.is_none() {
        return Err(Reason::BadRecord);
    }
    rot.attest.clear();
    Ok(rot)
}
/// Pre-attestation check for a genesis-epub binding.
///
/// Shape, epub canonical and distinct from the genesis pub, genesis-key
/// signature, and `|issued_at - now| <= policy.clock_skew_seconds`
/// (`future-record` or `expired`). A present `attest` is `bad-record`. Does
/// not check that no rotation exists; Panopticon does that, then attests
/// (panopticon#499).
pub fn verify_genesis_epub_request(
    v: &Value,
    genesis: &PrincipalId,
    now: u64,
    policy: &SiwePolicy,
) -> Result<GenesisEpub, Reason> {
    if v["kind"] != "genesis-epub" || v.get("attest").is_some() {
        return Err(Reason::BadRecord);
    }
    let mut owned = v.clone();
    owned["attest"] = Value::String("request".into());
    let IdentityRecord::GenesisEpub(mut binding) = record(&owned, false)? else {
        return Err(Reason::BadRecord);
    };
    if &binding.principal != genesis {
        return Err(Reason::BadRecord);
    }
    request_time(binding.issued_at, now, policy.clock_skew_seconds)?;
    let signed = IdentityRecord::GenesisEpub(binding.clone());
    if !key_verify(genesis, &binding.key_sig, &bytes(&signed)) {
        return Err(Reason::BadSignature);
    }
    binding.attest.clear();
    Ok(binding)
}
fn check_rotate(
    v: &Value,
    current_key: &PrincipalId,
    ctx: &ResolutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Rotate, Reason> {
    check_rotate_record(&rotation_candidate(v)?, current_key, ctx, diagnostics, true)
}
fn check_rotate_record(
    r: &IdentityRecord,
    current_key: &PrincipalId,
    ctx: &ResolutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
    require_attest: bool,
) -> Result<Rotate, Reason> {
    let IdentityRecord::Rotate(rot) = r else {
        return Err(Reason::BadRecord);
    };
    if require_attest {
        proof_time(rot.issued_at, ctx.now, ctx.policy.clock_skew_seconds)?;
    } else {
        request_time(rot.issued_at, ctx.now, ctx.policy.clock_skew_seconds)?;
    }
    if &rot.prev_key != current_key || &rot.next_key == current_key {
        return Err(Reason::BadSequence);
    }
    if rot
        .next_epub
        .as_ref()
        .is_some_and(|epub| epub == &rot.next_key || epub == &rot.prev_key)
    {
        return Err(Reason::BadSequence);
    }
    if !key_verify(&rot.next_key, &rot.next_sig, &bytes(r)) {
        return Err(Reason::BadSignature);
    }
    if require_attest {
        // Historical records verify as of issued_at. The upper bound against ctx.now is proof_time above.
        let c = attest_verify(
            &rot.attest,
            ctx.jwks,
            rot.issued_at,
            ctx.policy.clock_skew_seconds,
        )?;
        if !rotation_claims_match(rot, &c) {
            return Err(Reason::BadAttestation);
        }
    }
    let link = match &rot.authorizer {
        Authorizer::Wallet { link, .. } | Authorizer::OidcFreshLogin { link } => link,
    };
    let mut checked = BTreeMap::new();
    for id in std::iter::once(link).chain(rot.retained_links.iter()) {
        if checked.contains_key(id) {
            continue;
        }
        let raw = record(ctx.links.get(id).ok_or(Reason::MissingHistory)?, false)
            .map_err(required_history_failure)?;
        if !matches!(raw, IdentityRecord::Wallet(_) | IdentityRecord::Oidc(_))
            || raw.principal() != &rot.principal
            || hex(&Sha256::digest(bytes(&raw))) != *id
        {
            return Err(Reason::MissingHistory);
        }
        let v = historical_link(&raw, ctx, rot.issued_at).map_err(required_history_failure)?;
        if revoked_at(
            &v,
            ctx.revocations,
            current_key,
            rot.issued_at,
            ctx.jwks,
            diagnostics,
            RevocationMode::Witnessed,
        ) {
            return Err(Reason::RotationConflict);
        }
        if !require_attest
            && revoked_at(
                &v,
                ctx.revocations,
                current_key,
                ctx.now,
                ctx.jwks,
                diagnostics,
                RevocationMode::Witnessed,
            )
        {
            return Err(Reason::RotationConflict);
        }
        if !require_attest
            && revoked_at(
                &v,
                ctx.revocations,
                current_key,
                present_horizon(ctx.now, ctx.policy.clock_skew_seconds),
                ctx.jwks,
                diagnostics,
                RevocationMode::Present,
            )
        {
            return Err(Reason::RevokedLink);
        }
        checked.insert(id.clone(), v);
    }
    let authorizer = checked.get(link).ok_or(Reason::MissingHistory)?;
    if let Authorizer::Wallet { siwe, .. } = &rot.authorizer {
        let IdentityRecord::Wallet(w) = authorizer else {
            return Err(Reason::MissingHistory);
        };
        siwe_verify(
            siwe,
            &w.address,
            &bytes(r),
            rot.issued_at,
            if require_attest { rot.issued_at } else { ctx.now },
            ctx.policy,
            None,
        )
        .map_err(required_history_failure)?;
    } else {
        if !matches!(authorizer, IdentityRecord::Oidc(_)) {
            return Err(Reason::MissingHistory);
        }
        // OIDC recovery requires no active wallet. An unattested request also
        // counts a wallet linked after issued_at, up to now+skew.
        let mut wallet_absent = |until: u64| -> Result<(), Reason> {
            for (index, (id, raw)) in ctx.links.iter().enumerate() {
                let parsed = match record(raw, false) {
                    Ok(v) => v,
                    Err(e) => {
                        diagnostic(diagnostics, "link", index, e);
                        continue;
                    }
                };
                let IdentityRecord::Wallet(w) = &parsed else {
                    continue;
                };
                if w.principal != rot.principal {
                    continue;
                }
                if hex(&Sha256::digest(bytes(&parsed))) != *id {
                    diagnostic(diagnostics, "link", index, Reason::UnknownLink);
                    continue;
                }
                let v = match historical_link(&parsed, ctx, until) {
                    Ok(v) => v,
                    Err(e) => {
                        diagnostic(diagnostics, "link", index, e);
                        if matches!(
                            e,
                            Reason::MissingHistory
                                | Reason::RotationFork
                                | Reason::RotationConflict
                        ) {
                            return Err(e);
                        }
                        continue;
                    }
                };
                if !revoked_at(
                    &v,
                    ctx.revocations,
                    current_key,
                    until,
                    ctx.jwks,
                    diagnostics,
                    RevocationMode::Witnessed,
                ) {
                    return Err(Reason::WalletRequired);
                }
            }
            Ok(())
        };
        wallet_absent(rot.issued_at)?;
        if !require_attest {
            wallet_absent(present_horizon(ctx.now, ctx.policy.clock_skew_seconds))?;
        }
    }
    Ok(rot.clone())
}
/// Copies share signing-byte identity: any fully verified copy satisfies that rotation ID.
/// Unresolved authenticated evidence still fails closed.
pub fn resolve_current_key(
    genesis: &PrincipalId,
    rotations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Resolution<ResolvedAccount> {
    let mut diagnostics = Vec::new();
    let result = (|| {
        bounded(rotations.len())?;
        bounded(ctx.links.len())?;
        bounded(ctx.revocations.len())?;
        bounded(ctx.genesis_epub_bindings.len())?;
        if ctx.now > MAX_SAFE {
            return Err(Reason::MissingHistory);
        }
        let mut pending = verified_bindings(genesis, ctx, &mut diagnostics)?;
        // A binding issued at or after the first accepted rotation is not a fork.
        let mut binding: Option<(usize, GenesisEpub)> = None;
        let mut groups: BTreeMap<u64, Vec<(usize, Rotate)>> = BTreeMap::new();
        for (index, raw) in rotations.iter().enumerate() {
            let parsed = (|| {
                let IdentityRecord::Rotate(r) = rotation_candidate(raw)? else {
                    return Err(Reason::BadRecord);
                };
                if &r.principal != genesis {
                    return Err(Reason::BadRecord);
                }
                time(r.issued_at, ctx.now)?;
                Ok(r)
            })();
            match parsed {
                Ok(r) => groups.entry(r.seq).or_default().push((index, r)),
                Err(e) => diagnostic(&mut diagnostics, "rotation", index, e),
            }
        }
        let mut history: Vec<Rotate> = Vec::new();
        let mut current = genesis.clone();
        let mut current_epub = None;
        let mut seq = 1;
        for (n, group) in groups {
            let mut valid = BTreeMap::new();
            // Preserve first-seen failure order while deferring the verdict until all copies verify.
            let mut unresolved = Vec::new();
            for (index, raw) in group {
                let history_at = |p: &PrincipalId, at, until| {
                    if p == genesis {
                        Ok(history_state(genesis, &history, at, until))
                    } else {
                        (ctx.history)(p, at, until)
                    }
                };
                let candidate = ResolutionContext {
                    now: raw.issued_at,
                    history: &history_at,
                    ..*ctx
                };
                let verified = (|| {
                    let early: Vec<PrincipalId> = if history.is_empty() {
                        pending
                            .iter()
                            .filter(|(_, row)| row.issued_at < raw.issued_at)
                            .map(|(_, row)| row.epub.clone())
                            .collect()
                    } else {
                        binding
                            .as_ref()
                            .filter(|(_, row)| {
                                history
                                    .first()
                                    .is_some_and(|first| row.issued_at < first.issued_at)
                            })
                            .map(|(_, row)| vec![row.epub.clone()])
                            .unwrap_or_default()
                    };
                    let reused = reuses_epub(&raw, genesis, &history, None)
                        || early
                            .iter()
                            .any(|epub| reuses_epub(&raw, genesis, &history, Some(epub)));
                    if n != seq
                        || history.last().is_some_and(|r| raw.issued_at <= r.issued_at)
                        || &raw.next_key == genesis
                        || history.iter().any(|r| r.next_key == raw.next_key)
                        || reused
                    {
                        return Err(Reason::BadSequence);
                    }
                    let r = check_rotate(
                        &IdentityRecord::Rotate(raw.clone()).value(),
                        &current,
                        &candidate,
                        &mut diagnostics,
                    )
                    .map_err(|e| {
                        if e == Reason::WalletRequired {
                            Reason::RotationConflict
                        } else if e == Reason::BadAttestation
                            && authenticated_sibling(
                                &IdentityRecord::Rotate(raw.clone()).value(),
                                &candidate,
                            )
                            .is_some()
                        {
                            // Preserve a witnessed transition whose v4 SIWE copy is damaged.
                            Reason::MissingHistory
                        } else {
                            e
                        }
                    })?;
                    if let Authorizer::Wallet { link, .. } = &raw.authorizer {
                        let IdentityRecord::Wallet(own) =
                            record(ctx.links.get(link).ok_or(Reason::MissingHistory)?, false)
                                .map_err(required_history_failure)?
                        else {
                            return Err(Reason::MissingHistory);
                        };
                        let lookup = resolve_wallet_link(
                            &own.address,
                            &ctx.links.values().cloned().collect::<Vec<_>>(),
                            ctx.revocations,
                            &candidate,
                        );
                        for d in lookup.diagnostics {
                            diagnostic(&mut diagnostics, &d.source, d.index, d.reason);
                        }
                        let w = lookup.result.map_err(|e| match e {
                            Reason::MissingHistory
                            | Reason::RotationFork
                            | Reason::RotationConflict => e,
                            _ => Reason::RotationConflict,
                        })?;
                        if link_id(&IdentityRecord::Wallet(w))? != *link {
                            return Err(Reason::RotationConflict);
                        }
                    }
                    Ok(r)
                })();
                let id = link_id(&IdentityRecord::Rotate(raw))?;
                match verified {
                    Ok(r) => {
                        valid.insert(id, r);
                    }
                    Err(e) => {
                        diagnostic(&mut diagnostics, "rotation", index, e);
                        if matches!(
                            e,
                            Reason::MissingHistory
                                | Reason::RotationFork
                                | Reason::RotationConflict
                        ) {
                            unresolved.push((id, e));
                        }
                    }
                }
            }
            // A valid copy satisfies only its own ID; another authenticated ID cannot be dropped.
            for (id, reason) in unresolved {
                if !valid.contains_key(&id) {
                    return Err(reason);
                }
            }
            if valid.len() > 1 {
                return Err(Reason::RotationFork);
            }
            if let Some(r) = valid.into_values().next() {
                if history.is_empty() {
                    let mut early = Vec::new();
                    for (index, row) in pending.drain(..) {
                        if row.issued_at < r.issued_at {
                            early.push((index, row));
                        } else {
                            diagnostic(
                                &mut diagnostics,
                                "genesis-epub",
                                index,
                                Reason::BadSequence,
                            );
                        }
                    }
                    if early.len() > 1 {
                        diagnostic(
                            &mut diagnostics,
                            "genesis-epub",
                            early[1].0,
                            Reason::RotationFork,
                        );
                        return Err(Reason::RotationFork);
                    }
                    binding = early.into_iter().next();
                }
                current = r.next_key.clone();
                current_epub = r.next_epub.clone();
                history.push(r);
                seq += 1;
            }
        }
        if history.is_empty() && pending.len() > 1 {
            diagnostic(
                &mut diagnostics,
                "genesis-epub",
                pending[1].0,
                Reason::RotationFork,
            );
            return Err(Reason::RotationFork);
        }
        if history.is_empty() {
            binding = pending.into_iter().next();
        }
        let binding_epub = binding.map(|(_, row)| row.epub);
        if history.is_empty() {
            current_epub = binding_epub.clone();
        }
        Ok(ResolvedAccount {
            current_key: current,
            current_epub,
            binding_epub,
            rotations: history,
        })
    })();
    Resolution {
        result,
        diagnostics,
    }
}
pub fn resolve_wallet_link(
    address: &Eip55,
    links: &[Value],
    revocations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Resolution<WalletLink> {
    resolve_wallet(address, links, revocations, ctx, RevocationMode::Witnessed)
}
/// Present lookup using the final authenticated current key. Never use for as-of queries.
pub fn resolve_wallet_link_now(
    address: &Eip55,
    links: &[Value],
    revocations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Resolution<WalletLink> {
    resolve_wallet(address, links, revocations, ctx, RevocationMode::Present)
}
fn resolve_wallet(
    address: &Eip55,
    links: &[Value],
    revocations: &[Value],
    ctx: &ResolutionContext<'_>,
    mode: RevocationMode,
) -> Resolution<WalletLink> {
    let mut diagnostics = Vec::new();
    let result = (|| {
        bounded(links.len())?;
        bounded(revocations.len())?;
        bounded(ctx.links.len())?;
        if ctx.now > MAX_SAFE {
            return Err(Reason::MissingHistory);
        }
        let mut valid = BTreeMap::new();
        for (index, raw) in links.iter().enumerate() {
            let p = match record(raw, false) {
                Ok(p) => p,
                Err(e) => {
                    diagnostic(&mut diagnostics, "link", index, e);
                    continue;
                }
            };
            let IdentityRecord::Wallet(w) = &p else {
                continue;
            };
            if &w.address != address {
                continue;
            }
            match historical_link(&p, ctx, ctx.now) {
                Ok(IdentityRecord::Wallet(w)) => {
                    valid.insert(link_id(&IdentityRecord::Wallet(w.clone()))?, w);
                }
                Ok(_) => unreachable!("historical link preserves kind"),
                Err(e) => {
                    diagnostic(&mut diagnostics, "link", index, e);
                    if matches!(
                        e,
                        Reason::MissingHistory | Reason::RotationFork | Reason::RotationConflict
                    ) {
                        return Err(e);
                    }
                }
            }
        }
        let mut sorted: Vec<_> = valid.into_iter().collect();
        sorted.sort_by(|a, b| b.1.issued_at.cmp(&a.1.issued_at).then(a.0.cmp(&b.0)));
        let (_, newest) = sorted.first().ok_or(Reason::UnknownLink)?;
        if sorted
            .get(1)
            .is_some_and(|(_, w)| w.issued_at == newest.issued_at)
        {
            return Err(Reason::AmbiguousLink);
        }
        let h = (ctx.history)(&newest.principal, newest.issued_at, ctx.now)?;
        let revoked = revoked_at(
            &IdentityRecord::Wallet(newest.clone()),
            revocations,
            &h.current_key,
            ctx.now,
            ctx.jwks,
            &mut diagnostics,
            mode,
        );
        if revoked {
            Err(Reason::RevokedLink)
        } else {
            Ok(newest.clone())
        }
    })();
    Resolution {
        result,
        diagnostics,
    }
}
/// Present OIDC eligibility. Matches issuer, tenant, and subject.
pub fn resolve_oidc_link_now(
    cred: &Value,
    links: &[Value],
    revocations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Resolution<OidcLink> {
    let mut diagnostics = Vec::new();
    let cred = match parse_oidc_credential(cred) {
        Ok(cred) => cred,
        Err(reason) => {
            return Resolution {
                result: Err(reason),
                diagnostics,
            };
        }
    };
    let result = (|| {
        bounded(links.len())?;
        bounded(revocations.len())?;
        bounded(ctx.links.len())?;
        if ctx.now > MAX_SAFE {
            return Err(Reason::MissingHistory);
        }
        let mut valid = BTreeMap::new();
        for (index, raw) in links.iter().enumerate() {
            let p = match record(raw, false) {
                Ok(p) => p,
                Err(e) => {
                    diagnostic(&mut diagnostics, "link", index, e);
                    continue;
                }
            };
            let IdentityRecord::Oidc(link) = &p else {
                continue;
            };
            if link.cred != cred {
                continue;
            }
            match historical_link(&p, ctx, ctx.now) {
                Ok(IdentityRecord::Oidc(link)) => {
                    valid.insert(link_id(&IdentityRecord::Oidc(link.clone()))?, link);
                }
                Ok(_) => unreachable!("historical link preserves kind"),
                Err(e) => {
                    diagnostic(&mut diagnostics, "link", index, e);
                    if matches!(
                        e,
                        Reason::MissingHistory | Reason::RotationFork | Reason::RotationConflict
                    ) {
                        return Err(e);
                    }
                }
            }
        }
        let mut sorted: Vec<_> = valid.into_iter().collect();
        sorted.sort_by(|a, b| b.1.issued_at.cmp(&a.1.issued_at).then(a.0.cmp(&b.0)));
        let (_, newest) = sorted.first().ok_or(Reason::UnknownLink)?;
        if sorted
            .get(1)
            .is_some_and(|(_, link)| link.issued_at == newest.issued_at)
        {
            return Err(Reason::AmbiguousLink);
        }
        let h = (ctx.history)(&newest.principal, newest.issued_at, ctx.now)?;
        let revoked = revoked_at(
            &IdentityRecord::Oidc(newest.clone()),
            revocations,
            &h.current_key,
            ctx.now,
            ctx.jwks,
            &mut diagnostics,
            RevocationMode::Present,
        );
        if revoked {
            Err(Reason::RevokedLink)
        } else {
            Ok(newest.clone())
        }
    })();
    Resolution {
        result,
        diagnostics,
    }
}

/// Authenticate candidate link ids and drop those revoked under the final current key.
/// Does not issue an attestation. Missing history fails the call.
pub fn prepare_retained_links_now(
    candidates: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<Vec<String>, Reason> {
    bounded(candidates.len())?;
    bounded(ctx.revocations.len())?;
    bounded(ctx.links.len())?;
    if ctx.now > MAX_SAFE {
        return Err(Reason::MissingHistory);
    }
    let mut retained = Vec::new();
    for id_value in candidates {
        let id = id_value.as_str().ok_or(Reason::BadRecord)?;
        if retained.iter().any(|seen| seen == id) {
            continue;
        }
        let raw = ctx.links.get(id).ok_or(Reason::MissingHistory)?;
        let parsed = record(raw, false)?;
        let principal = parsed.principal().clone();
        let issued_at = parsed.issued_at();
        if issued_at > ctx.now {
            return Err(Reason::FutureRecord);
        }
        let state = (ctx.history)(&principal, issued_at, ctx.now)?;
        let proof = match &parsed {
            IdentityRecord::Wallet(_) => IdentityRecord::Wallet(verify_wallet_link(
                raw, ctx.jwks, ctx.policy, issued_at, &state,
            )?),
            IdentityRecord::Oidc(_) => IdentityRecord::Oidc(verify_oidc_link(
                raw,
                ctx.jwks,
                ctx.pinned_iss,
                issued_at,
                &state,
            )?),
            _ => return Err(Reason::BadRecord),
        };
        if link_id(&proof)? != id {
            return Err(Reason::MissingHistory);
        }
        let revoked = ctx.revocations.iter().any(|raw| {
            let Ok(IdentityRecord::Revoke(revoke)) = record(raw, false) else {
                return false;
            };
            if revoke.principal != principal || revoke.link_id != id || revoke.issued_at < issued_at
            {
                return false;
            }
            verify_revoke_now(raw, &state.current_key, ctx.now).is_ok()
        });
        if !revoked {
            retained.push(id.to_owned());
        }
    }
    retained.sort();
    Ok(retained)
}

/// Group untrusted link copies by signing-byte id and keep one that verifies.
/// A tampered sibling does not drop that id. An id whose copies all fail closed
/// on missing history still fails the call. Other failures omit the id.
pub fn verifying_link_map(
    copies: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<BTreeMap<String, Value>, Reason> {
    bounded(copies.len())?;
    bounded(ctx.links.len())?;
    if ctx.now > MAX_SAFE {
        return Err(Reason::MissingHistory);
    }
    let mut groups: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for raw in copies {
        let Ok(parsed) = record(raw, false) else {
            continue;
        };
        if !matches!(parsed, IdentityRecord::Wallet(_) | IdentityRecord::Oidc(_)) {
            continue;
        }
        groups
            .entry(hex(&Sha256::digest(bytes(&parsed))))
            .or_default()
            .push(raw);
    }
    let mut kept = BTreeMap::new();
    for (id, list) in groups {
        let mut fatal = None;
        let mut winner = None;
        for raw in list {
            let parsed = match record(raw, false) {
                Ok(parsed) => parsed,
                Err(_) => continue,
            };
            match historical_link(&parsed, ctx, ctx.now) {
                Ok(_) => {
                    winner = Some(raw.clone());
                    break;
                }
                Err(reason)
                    if fatal.is_none()
                        && matches!(
                            reason,
                            Reason::MissingHistory
                                | Reason::RotationFork
                                | Reason::RotationConflict
                        ) =>
                {
                    fatal = Some(reason);
                }
                Err(_) => {}
            }
        }
        if let Some(raw) = winner {
            kept.insert(id, raw);
        } else if let Some(reason) = fatal {
            return Err(reason);
        }
    }
    Ok(kept)
}

/// SEA P-256 ECDSA over SHA-256. Raw r||s, base64url. High-S and low-S both verify.
pub fn verify_key_signature(key: &PrincipalId, sig: &str, message: &[u8]) -> Result<(), Reason> {
    let sig = text(sig, 128)?;
    if key_verify(key, sig, message) {
        Ok(())
    } else {
        Err(Reason::BadSignature)
    }
}
/// Sign ids bytes with a 32-byte SEA scalar. `expected_key` is the resolver's current key.
/// The working copy of the scalar is [`Zeroizing`]. A bad scalar or a different public key is [`Reason::BadKey`].
/// The result is raw r||s, base64url, the encoding [`verify_key_signature`] accepts.
pub fn sign_with_keyring(
    scalar: &[u8],
    message: &[u8],
    expected_key: &PrincipalId,
) -> Result<String, Reason> {
    if scalar.len() != 32 {
        return Err(Reason::BadKey);
    }
    let mut held = Zeroizing::new([0u8; 32]);
    held.copy_from_slice(scalar);
    let signing = SigningKey::from_slice(held.as_ref()).map_err(|_| Reason::BadKey)?;
    let point = signing.verifying_key().to_sec1_point(false);
    let derived = principal_from_sec1(point.as_bytes()).map_err(|_| Reason::BadKey)?;
    if derived != *expected_key {
        return Err(Reason::BadKey);
    }
    let sig: Signature = signing.sign(message);
    Ok(b64(&sig.to_bytes()))
}
fn record_id_of(message: &[u8]) -> String {
    hex(&Sha256::digest(message))
}
/// `sociacl-acl-attest-v1`. Checked like [`attest_verify`] with `now = issued_at`.
/// Nothing in this package issues the claim.
pub fn verify_acl_attestation(
    jws: &str,
    jwks: &Jwks,
    issued_at: u64,
    message: &[u8],
) -> Result<AclAttestation, Reason> {
    if jws.len() > 16384 * 3 || jws.encode_utf16().count() > 16384 {
        return Err(Reason::TooLong);
    }
    let jws = text(jws, 16384)?;
    if issued_at > MAX_SAFE {
        return Err(Reason::BadAttestation);
    }
    let c = attest_verify(jws, jwks, issued_at, 0)?;
    if !only(&c, &["typ", "principal", "recordId", "iat", "exp"])
        || c["typ"] != "sociacl-acl-attest-v1"
        || number(&c["iat"]).ok() != Some(issued_at)
        || c["recordId"] != record_id_of(message)
    {
        return Err(Reason::BadAttestation);
    }
    let principal = parse_principal_id(c["principal"].as_str().ok_or(Reason::BadAttestation)?)
        .map_err(|_| Reason::BadAttestation)?;
    let exp = number(&c["exp"]).map_err(|_| Reason::BadAttestation)?;
    Ok(AclAttestation {
        typ: "sociacl-acl-attest-v1".to_owned(),
        principal,
        record_id: c["recordId"]
            .as_str()
            .ok_or(Reason::BadAttestation)?
            .to_owned(),
        iat: issued_at,
        exp,
    })
}
const SEE_DOMAIN: &str = "sociacl-see-grant-v2";
/// One parsed see grant. `stated` is `0` (cancel) or `1` (grant). The kind is this field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeeGrant {
    pub owner: PrincipalId,
    pub object: ObjectId,
    pub accessor: PrincipalId,
    pub stated: u8,
    pub from: u64,
    pub until: u64,
    pub ham_state: u64,
    pub issued_at: u64,
    pub sig: String,
    pub attest: Option<String>,
}
/// Signature check over a parsed see row. `bytes` are the v2 signing bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSee {
    pub key: PrincipalId,
    pub mode: SignedAtMode,
    pub grant: SeeGrant,
    pub bytes: Vec<u8>,
}
fn see_u64(v: Option<&Value>) -> Result<u64, Reason> {
    number(v.ok_or(Reason::BadRecord)?)
}
/// A missing or non-string id is `not-string`, in both see and post parsers.
fn grant_id(value: Option<&Value>) -> Result<&str, Reason> {
    match value {
        Some(Value::String(text)) => Ok(text),
        _ => Err(Reason::NotString),
    }
}
/// Signing bytes for one parsed see row. Domain and `stated` are inside the bytes.
pub fn see_grant_bytes(grant: &SeeGrant) -> Vec<u8> {
    lp(&[
        SEE_DOMAIN,
        grant.owner.as_ref(),
        grant.object.as_ref(),
        grant.accessor.as_ref(),
        &grant.stated.to_string(),
        &grant.from.to_string(),
        &grant.until.to_string(),
        &grant.ham_state.to_string(),
        &grant.issued_at.to_string(),
    ])
}
/// Snapshot a see row from already-parsed JSON. `kind` is not read.
pub fn parse_see_grant(row: &Value) -> Result<(SeeGrant, Vec<u8>), Reason> {
    let map = row.as_object().ok_or(Reason::BadRecord)?;
    if let Some(domain) = map.get("domain") {
        if domain.as_str() != Some(SEE_DOMAIN) {
            return Err(Reason::LegacyRow);
        }
    }
    if !map.contains_key("sig") {
        return Err(Reason::LegacyRow);
    }
    let owner = parse_principal_id(grant_id(map.get("owner"))?)?;
    let object = parse_object_id(grant_id(map.get("object"))?)?;
    let accessor = parse_principal_id(grant_id(map.get("accessor"))?)?;
    let stated = see_u64(map.get("stated"))?;
    if stated > 1 {
        return Err(Reason::BadRecord);
    }
    let from = see_u64(map.get("from"))?;
    let until = see_u64(map.get("until"))?;
    let ham_state = see_u64(map.get("hamState"))?;
    let issued_at = see_u64(map.get("issuedAt"))?;
    if until < from {
        return Err(Reason::BadRecord);
    }
    let sig = match map.get("sig") {
        Some(Value::String(s)) => text(s, 128)?.to_owned(),
        Some(_) => return Err(Reason::NotString),
        None => return Err(Reason::LegacyRow),
    };
    let attest = match map.get("attest") {
        None => None,
        Some(Value::String(s)) => Some(text(s, 16384)?.to_owned()),
        Some(_) => return Err(Reason::NotString),
    };
    let grant = SeeGrant {
        owner,
        object,
        accessor,
        stated: stated as u8,
        from,
        until,
        ham_state,
        issued_at,
        sig,
        attest,
    };
    let bytes = see_grant_bytes(&grant);
    Ok((grant, bytes))
}
fn see_witness(
    grant: &SeeGrant,
    bytes: &[u8],
    ctx: &ResolutionContext<'_>,
) -> Result<AclAttestation, Reason> {
    let Some(token) = grant.attest.as_deref() else {
        return Err(Reason::UnwitnessedRetiredKey);
    };
    let attest = verify_acl_attestation(token, ctx.jwks, grant.issued_at, bytes)?;
    if attest.principal != grant.owner {
        return Err(Reason::BadAttestation);
    }
    Ok(attest)
}
/// See-grant authority. A retired cancel is `stated == 0` on the parsed row.
/// There is no kind argument. A retired `stated == 1` row is refused even when witnessed.
pub fn verify_see_grant(
    row: &Value,
    rotations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<VerifiedSee, Reason> {
    let (grant, bytes) = parse_see_grant(row)?;
    let account = resolve_current_key(&grant.owner, rotations, ctx).result?;
    proof_time(grant.issued_at, ctx.now, ctx.policy.clock_skew_seconds)?;
    let state = history_state(&grant.owner, &account.rotations, grant.issued_at, ctx.now);
    if state.key == account.current_key {
        if !key_verify(&account.current_key, &grant.sig, &bytes) {
            return Err(Reason::BadSignature);
        }
        return Ok(VerifiedSee {
            key: account.current_key,
            mode: SignedAtMode::Present,
            grant,
            bytes,
        });
    }
    if grant.stated != 0 {
        if grant.attest.is_some() {
            see_witness(&grant, &bytes, ctx)?;
        }
        return Err(Reason::UnwitnessedRetiredKey);
    }
    see_witness(&grant, &bytes, ctx)?;
    if !key_verify(&state.key, &grant.sig, &bytes) {
        return Err(Reason::BadSignature);
    }
    Ok(VerifiedSee {
        key: state.key,
        mode: SignedAtMode::Witnessed,
        grant,
        bytes,
    })
}
/// Present authority under the resolved current key.
/// Arbitrary bytes stay fail-closed on a retired key. A see cancel is
/// [`verify_see_grant`]: the signed `stated` field is `0`.
/// Kind is not a parameter, and this function does not take an attestation.
/// A resolver failure is returned unchanged.
pub fn verify_signed_at(
    principal: &PrincipalId,
    rotations: &[Value],
    ctx: &ResolutionContext<'_>,
    message: &[u8],
    sig: &str,
    issued_at: u64,
) -> Result<SignedAt, Reason> {
    let account = resolve_current_key(principal, rotations, ctx).result?;
    if issued_at > MAX_SAFE {
        return Err(Reason::BadRecord);
    }
    proof_time(issued_at, ctx.now, ctx.policy.clock_skew_seconds)?;
    let state = history_state(principal, &account.rotations, issued_at, ctx.now);
    if state.key != account.current_key {
        return Err(Reason::UnwitnessedRetiredKey);
    }
    let Ok(sig) = text(sig, 128) else {
        return Err(Reason::BadSignature);
    };
    if !key_verify(&account.current_key, sig, message) {
        return Err(Reason::BadSignature);
    }
    Ok(SignedAt {
        key: account.current_key,
        mode: SignedAtMode::Present,
    })
}
/// Length-prefixed domain for [`request_id`].
pub const REQUEST_ID_DOMAIN: &str = "sociacl-request-id-v2";
/// Length-prefixed domain for an access request.
pub const REQUEST_DOMAIN: &str = "sociacl-access-request-v2";
const REQUEST_MESSAGE_MAX: usize = 280;
/// One parsed access request. The request id is the hash of the requester and object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    pub request_id: String,
    pub requester: PrincipalId,
    pub object: ObjectId,
    pub scope: String,
    pub status: String,
    pub message: String,
    pub issued_at: u64,
    pub sig: String,
}
/// Present-authority check over a parsed access request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAccessRequest {
    pub key: PrincipalId,
    pub mode: SignedAtMode,
    pub request: AccessRequest,
    pub bytes: Vec<u8>,
}
fn request_field<'a>(value: Option<&'a Value>) -> Result<&'a str, Reason> {
    match value {
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(Reason::NotString),
        None => Err(Reason::BadRecord),
    }
}
/// Missing and non-string are the same reason for scope, status, message, requester, and object.
fn request_text<'a>(value: Option<&'a Value>) -> Result<&'a str, Reason> {
    match value {
        Some(Value::String(text)) => Ok(text),
        _ => Err(Reason::NotString),
    }
}
fn request_message(value: &str) -> Result<&str, Reason> {
    if value.chars().count() > REQUEST_MESSAGE_MAX {
        return Err(Reason::TooLong);
    }
    Ok(value)
}
/// Signing bytes for a request id. Scope, message, and status are not inputs.
pub fn request_id_bytes(requester: &PrincipalId, object: &ObjectId) -> Vec<u8> {
    lp(&[REQUEST_ID_DOMAIN, requester.as_ref(), object.as_ref()])
}
/// Lowercase hex SHA-256 of [`request_id_bytes`]. A non-string never reaches this function.
pub fn request_id(requester: &str, object: &str) -> Result<String, Reason> {
    let who = parse_principal_id(requester)?;
    let id = parse_object_id(object)?;
    Ok(hex(&Sha256::digest(request_id_bytes(&who, &id))))
}
/// Signing bytes for one parsed access request.
pub fn access_request_bytes(request: &AccessRequest) -> Vec<u8> {
    lp(&[
        REQUEST_DOMAIN,
        &request.request_id,
        request.requester.as_ref(),
        request.object.as_ref(),
        &request.scope,
        &request.status,
        &request.message,
        &request.issued_at.to_string(),
    ])
}
/// Snapshot an access request. The request id is computed from the requester and object.
/// A wrong domain or a missing signature is [`Reason::LegacyRow`]. An empty message is allowed.
pub fn parse_access_request(row: &Value) -> Result<(AccessRequest, Vec<u8>), Reason> {
    let map = row.as_object().ok_or(Reason::BadRecord)?;
    if let Some(domain) = map.get("domain") {
        if domain.as_str() != Some(REQUEST_DOMAIN) {
            return Err(Reason::LegacyRow);
        }
    }
    if !map.contains_key("sig") {
        return Err(Reason::LegacyRow);
    }
    let requester = parse_principal_id(request_text(map.get("requester"))?)?;
    let object = parse_object_id(request_text(map.get("object"))?)?;
    let request_id = hex(&Sha256::digest(request_id_bytes(&requester, &object)));
    let stated_id = request_field(map.get("requestId"))?;
    if stated_id != request_id {
        return Err(Reason::BadRecord);
    }
    let scope = request_text(map.get("scope"))?;
    if scope != "read" && scope != "read+post" {
        return Err(Reason::BadRecord);
    }
    let status = request_text(map.get("status"))?;
    if status != "pending" && status != "withdrawn" {
        return Err(Reason::BadRecord);
    }
    let message = request_message(request_text(map.get("message"))?)?.to_string();
    let issued_at = see_u64(map.get("issuedAt"))?;
    let sig = text(request_field(map.get("sig"))?, 128)?.to_string();
    let request = AccessRequest {
        request_id,
        requester,
        object,
        scope: scope.to_string(),
        status: status.to_string(),
        message,
        issued_at,
        sig,
    };
    let bytes = access_request_bytes(&request);
    Ok((request, bytes))
}
/// Present authority for the requester. A retired key is refused. Kind is not a parameter.
pub fn verify_access_request(
    row: &Value,
    rotations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<VerifiedAccessRequest, Reason> {
    let (request, bytes) = parse_access_request(row)?;
    let signed = verify_signed_at(
        &request.requester,
        rotations,
        ctx,
        &bytes,
        &request.sig,
        request.issued_at,
    )?;
    Ok(VerifiedAccessRequest {
        key: signed.key,
        mode: signed.mode,
        request,
        bytes,
    })
}
const POST_DOMAIN: &str = "sociacl-post-grant-v2";
/// Signing bytes for one parsed post row. Domain and `stated` are inside the bytes.
pub fn post_grant_bytes(grant: &SeeGrant) -> Vec<u8> {
    lp(&[
        POST_DOMAIN,
        grant.owner.as_ref(),
        grant.object.as_ref(),
        grant.accessor.as_ref(),
        &grant.stated.to_string(),
        &grant.from.to_string(),
        &grant.until.to_string(),
        &grant.ham_state.to_string(),
        &grant.issued_at.to_string(),
    ])
}
/// Snapshot a post row. Same fields as a see row. `kind` is not read.
pub fn parse_post_grant(row: &Value) -> Result<(SeeGrant, Vec<u8>), Reason> {
    let map = row.as_object().ok_or(Reason::BadRecord)?;
    if let Some(domain) = map.get("domain") {
        if domain.as_str() != Some(POST_DOMAIN) {
            return Err(Reason::LegacyRow);
        }
    }
    if !map.contains_key("sig") {
        return Err(Reason::LegacyRow);
    }
    let owner = parse_principal_id(grant_id(map.get("owner"))?)?;
    let object = parse_object_id(grant_id(map.get("object"))?)?;
    let accessor = parse_principal_id(grant_id(map.get("accessor"))?)?;
    let stated = see_u64(map.get("stated"))?;
    if stated > 1 {
        return Err(Reason::BadRecord);
    }
    let from = see_u64(map.get("from"))?;
    let until = see_u64(map.get("until"))?;
    let ham_state = see_u64(map.get("hamState"))?;
    let issued_at = see_u64(map.get("issuedAt"))?;
    if until < from {
        return Err(Reason::BadRecord);
    }
    let sig = match map.get("sig") {
        Some(Value::String(s)) => text(s, 128)?.to_owned(),
        Some(_) => return Err(Reason::NotString),
        None => return Err(Reason::LegacyRow),
    };
    let attest = match map.get("attest") {
        None => None,
        Some(Value::String(s)) => Some(text(s, 16384)?.to_owned()),
        Some(_) => return Err(Reason::NotString),
    };
    let grant = SeeGrant {
        owner,
        object,
        accessor,
        stated: stated as u8,
        from,
        until,
        ham_state,
        issued_at,
        sig,
        attest,
    };
    let bytes = post_grant_bytes(&grant);
    Ok((grant, bytes))
}
/// Post-grant authority. A retired cancel is `stated == 0` on the parsed row.
/// A retired `stated == 1` row is refused even when witnessed.
pub fn verify_post_grant(
    row: &Value,
    rotations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<VerifiedSee, Reason> {
    let (grant, bytes) = parse_post_grant(row)?;
    let account = resolve_current_key(&grant.owner, rotations, ctx).result?;
    proof_time(grant.issued_at, ctx.now, ctx.policy.clock_skew_seconds)?;
    let state = history_state(&grant.owner, &account.rotations, grant.issued_at, ctx.now);
    if state.key == account.current_key {
        if !key_verify(&account.current_key, &grant.sig, &bytes) {
            return Err(Reason::BadSignature);
        }
        return Ok(VerifiedSee {
            key: account.current_key,
            mode: SignedAtMode::Present,
            grant,
            bytes,
        });
    }
    if grant.stated != 0 {
        if grant.attest.is_some() {
            see_witness(&grant, &bytes, ctx)?;
        }
        return Err(Reason::UnwitnessedRetiredKey);
    }
    see_witness(&grant, &bytes, ctx)?;
    if !key_verify(&state.key, &grant.sig, &bytes) {
        return Err(Reason::BadSignature);
    }
    Ok(VerifiedSee {
        key: state.key,
        mode: SignedAtMode::Witnessed,
        grant,
        bytes,
    })
}
const OBJECT_DOMAIN: &str = "sociacl-object-v2";
/// Signed object owner. The owner is this record, not a caller argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRecord {
    pub object: ObjectId,
    pub owner: PrincipalId,
    pub issued_at: u64,
    pub sig: String,
}
/// One parsed object record and the bytes the owner signed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedObject {
    pub key: PrincipalId,
    pub mode: SignedAtMode,
    pub record: ObjectRecord,
    pub bytes: Vec<u8>,
}
/// Signing bytes for an object-owner record. The domain is inside the bytes.
pub fn object_record_bytes(record: &ObjectRecord) -> Vec<u8> {
    lp(&[
        OBJECT_DOMAIN,
        record.object.as_ref(),
        record.owner.as_ref(),
        &record.issued_at.to_string(),
    ])
}
/// Snapshot an object-owner record. A missing signature is unsigned.
pub fn parse_object_record(row: &Value) -> Result<(ObjectRecord, Vec<u8>), Reason> {
    let map = row.as_object().ok_or(Reason::BadRecord)?;
    if let Some(domain) = map.get("domain") {
        if domain.as_str() != Some(OBJECT_DOMAIN) {
            return Err(Reason::BadRecord);
        }
    }
    let object = parse_object_id(
        map.get("object")
            .and_then(Value::as_str)
            .ok_or(Reason::BadRecord)?,
    )?;
    let owner = parse_principal_id(
        map.get("owner")
            .and_then(Value::as_str)
            .ok_or(Reason::BadRecord)?,
    )?;
    let issued_at = see_u64(map.get("issuedAt"))?;
    let creator = crate::object_principal(&object).map_err(|_| Reason::BadRecord)?;
    if creator != owner {
        return Err(Reason::BadRecord);
    }
    let sig = match map.get("sig") {
        Some(Value::String(s)) => text(s, 128)?.to_owned(),
        Some(_) => return Err(Reason::NotString),
        None => return Err(Reason::BadSignature),
    };
    let record = ObjectRecord {
        object,
        owner,
        issued_at,
        sig,
    };
    let bytes = object_record_bytes(&record);
    Ok((record, bytes))
}
/// The owner signs `sociacl-object-v2`. A retired key is refused.
pub fn verify_object_record(
    row: &Value,
    rotations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<VerifiedObject, Reason> {
    let (record, bytes) = parse_object_record(row)?;
    let signed = verify_signed_at(
        &record.owner,
        rotations,
        ctx,
        &bytes,
        &record.sig,
        record.issued_at,
    )?;
    Ok(VerifiedObject {
        key: signed.key,
        mode: signed.mode,
        record,
        bytes,
    })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignedAtMode {
    Present,
    /// Returned by [`verify_see_grant`] for a retired see cancel.
    /// Eligibility is `stated == 0` inside `sociacl-see-grant-v2`.
    /// `sociacl-cancel-v2` is the group-cancel domain, not this one.
    Witnessed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedAt {
    pub key: PrincipalId,
    pub mode: SignedAtMode,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AclAttestation {
    pub typ: String,
    pub principal: PrincipalId,
    pub record_id: String,
    pub iat: u64,
    pub exp: u64,
}

/// JSON wire boundary. Rust `str` cannot carry unpaired UTF-16 surrogates.
/// Duplicate object members are rejected before deserialization can fold them.
pub fn parse_json_input(s: &str) -> Result<Value, Reason> {
    unique_json(s).map_err(|e| {
        let message = e.to_string();
        if message.contains("surrogate") || message.contains("unexpected end of hex escape") {
            Reason::UnpairedSurrogate
        } else {
            Reason::BadRecord
        }
    })
}
