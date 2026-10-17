use crate::ids::{checksum, principal_bytes};
use crate::*;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::{BTreeMap, BTreeSet};

const MAX_SAFE: u64 = 9_007_199_254_740_991;
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
}
impl IdentityRecord {
    pub fn principal(&self) -> &PrincipalId {
        match self {
            Self::Wallet(r) => &r.principal,
            Self::Oidc(r) => &r.principal,
            Self::Rotate(r) => &r.principal,
            Self::Revoke(r) => &r.principal,
        }
    }
    pub fn issued_at(&self) -> u64 {
        match self {
            Self::Wallet(r) => r.issued_at,
            Self::Oidc(r) => r.issued_at,
            Self::Rotate(r) => r.issued_at,
            Self::Revoke(r) => r.issued_at,
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
        || ![Some("wallet"), Some("oidc"), Some("rotate"), Some("revoke")]
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
            let retained_links: Vec<String> = v["retainedLinks"]
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
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
        id = k256::ecdsa::RecoveryId::from_byte(recovery ^ 1).ok_or(Reason::BadSignature)?;
    }
    let mut preimage =
        format!("\x19Ethereum Signed Message:\n{}", proof.message.len()).into_bytes();
    preimage.extend(proof.message.as_bytes());
    let key = k256::ecdsa::VerifyingKey::recover_from_prehash(
        &Keccak256::digest(preimage),
        &signature,
        id,
    )
    .map_err(|_| Reason::BadSignature)?;
    let hash = Keccak256::digest(&key.to_encoded_point(false).as_bytes()[1..]);
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
#[deprecated(
    since = "0.6.0",
    note = "Use verify_wallet_link; this alias retains historical verification semantics"
)]
pub use verify_wallet_link as verify_wallet_link_at_key;
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
#[deprecated(
    since = "0.6.0",
    note = "Use verify_oidc_link; this alias retains historical verification semantics"
)]
pub use verify_oidc_link as verify_oidc_link_at_key;

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
fn check_rotate(
    v: &Value,
    current_key: &PrincipalId,
    ctx: &ResolutionContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Rotate, Reason> {
    let r = rotation_candidate(v)?;
    let IdentityRecord::Rotate(rot) = &r else {
        return Err(Reason::BadRecord);
    };
    proof_time(rot.issued_at, ctx.now, ctx.policy.clock_skew_seconds)?;
    if &rot.prev_key != current_key || &rot.next_key == current_key {
        return Err(Reason::BadSequence);
    }
    if !key_verify(&rot.next_key, &rot.next_sig, &bytes(&r)) {
        return Err(Reason::BadSignature);
    }
    let c = attest_verify(
        &rot.attest,
        ctx.jwks,
        ctx.now,
        ctx.policy.clock_skew_seconds,
    )?;
    let (auth, link) = match &rot.authorizer {
        Authorizer::Wallet { link, .. } => ("wallet", link),
        Authorizer::OidcFreshLogin { link } => ("oidc-fresh-login", link),
    };
    let v3 = rot.next_epub.is_some();
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
    if v3 {
        attest_keys.push("nextEpub");
    }
    let epub_matches = match &rot.next_epub {
        Some(epub) => c["nextEpub"] == epub.as_ref(),
        None => true,
    };
    if !only(&c, &attest_keys)
        || c["typ"] != if v3 { "sociacl-rotate-attest-v3" } else { "sociacl-rotate-attest-v2" }
        || c["principal"] != rot.principal.as_ref()
        || c["nextKey"] != rot.next_key.as_ref()
        || !epub_matches
        || number(&c["seq"]).ok() != Some(rot.seq)
        || number(&c["iat"]).ok() != Some(rot.issued_at)
        || c["auth"] != auth
        || c["linkId"] != *link
        || c["retainedLinks"] != serde_json::json!(rot.retained_links)
    {
        return Err(Reason::BadAttestation);
    }
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
            &bytes(&r),
            rot.issued_at,
            ctx.now,
            ctx.policy,
            None,
        )
        .map_err(required_history_failure)?;
    } else {
        if !matches!(authorizer, IdentityRecord::Oidc(_)) {
            return Err(Reason::MissingHistory);
        }
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
            let v = match historical_link(&parsed, ctx, rot.issued_at) {
                Ok(v) => v,
                Err(e) => {
                    diagnostic(diagnostics, "link", index, e);
                    if matches!(
                        e,
                        Reason::MissingHistory | Reason::RotationFork | Reason::RotationConflict
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
                rot.issued_at,
                ctx.jwks,
                diagnostics,
                RevocationMode::Witnessed,
            ) {
                return Err(Reason::WalletRequired);
            }
        }
    }
    Ok(rot.clone())
}
#[deprecated(
    since = "0.6.0",
    note = "Use verify_rotate; this alias retains historical verification semantics"
)]
pub use verify_rotate as verify_rotate_at_key;

/// Copies share signing-byte identity: any fully verified copy satisfies that rotation ID.
/// Unresolved authenticated evidence still fails closed.
pub fn resolve_current_key(
    genesis: &PrincipalId,
    rotations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Resolution<ResolvedAccount> {
    let mut diagnostics = Vec::new();
    let result = (|| {
        if ctx.now > MAX_SAFE {
            return Err(Reason::MissingHistory);
        }
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
                    if n != seq
                        || history.last().is_some_and(|r| raw.issued_at <= r.issued_at)
                        || &raw.next_key == genesis
                        || history.iter().any(|r| r.next_key == raw.next_key)
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
                current = r.next_key.clone();
                if r.next_epub.is_some() {
                    current_epub = r.next_epub.clone();
                }
                history.push(r);
                seq += 1;
            }
        }
        Ok(ResolvedAccount {
            current_key: current,
            current_epub,
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
#[deprecated(
    since = "0.6.0",
    note = "Use resolve_wallet_link; this alias retains historical verification semantics"
)]
pub use resolve_wallet_link as resolve_wallet_link_at_key;

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
