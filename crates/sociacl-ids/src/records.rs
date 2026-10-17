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
    OidcFreshLogin,
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
    pub links: &'a BTreeMap<String, WalletLink>,
    pub revocations: &'a [Value],
    pub now: u64,
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
                &["v", "kind", "principal", "issuedAt", "linkId", "keySig"],
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
            }))
        }
        "rotate" => {
            if !only(
                v,
                &[
                    "v",
                    "kind",
                    "principal",
                    "issuedAt",
                    "seq",
                    "prevKey",
                    "nextKey",
                    "nextSig",
                    "authorizer",
                    "attest",
                ],
            ) {
                return Err(Reason::BadRecord);
            }
            let seq = number(&v["seq"]).map_err(|_| Reason::BadSequence)?;
            if seq == 0 {
                return Err(Reason::BadSequence);
            }
            let prev_key = parse_principal_id(v["prevKey"].as_str().ok_or(Reason::NotString)?)?;
            let next_key = parse_principal_id(v["nextKey"].as_str().ok_or(Reason::NotString)?)?;
            let next_sig = sig("nextSig")?;
            let att = attest()?;
            let a = &v["authorizer"];
            let authorizer = if unsigned || (a["kind"] == "oidc-fresh-login" && only(a, &["kind"]))
            {
                Authorizer::OidcFreshLogin
            } else if a["kind"] == "wallet" && only(a, &["kind", "link", "siwe"]) {
                let link = field(a, "link", 64)?.to_owned();
                if !is_hex(&link, 64) {
                    return Err(Reason::BadRecord);
                }
                Authorizer::Wallet {
                    link,
                    siwe: siwe_data(&a["siwe"])?,
                }
            } else {
                return Err(Reason::BadRecord);
            };
            Ok(IdentityRecord::Rotate(Rotate {
                v: 1,
                principal,
                seq,
                prev_key,
                next_key,
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
        IdentityRecord::Rotate(r) => lp(&[
            "sociacl-rotate-v1",
            r.principal.as_ref(),
            &r.seq.to_string(),
            r.prev_key.as_ref(),
            r.next_key.as_ref(),
            &t,
        ]),
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
    if !rx!(r"^[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]+$").is_match(s)
        || s.contains(['<', '>', '"', '{', '}', '|', '\\', '^', '`'])
    {
        return false;
    }
    let b = s.as_bytes();
    if b.iter().enumerate().any(|(i, c)| {
        *c == b'%'
            && (i + 2 >= b.len() || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit())
    }) {
        return false;
    }
    url::Url::parse(s).is_ok()
}
fn siwe_verify(
    proof: &Siwe,
    address: &Eip55,
    message: &[u8],
    issued: u64,
    now: u64,
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
    let mut at = 10;
    if let Some(s) = l.get(at).and_then(|s| s.strip_prefix("Expiration Time: ")) {
        let expiry = date(s).ok_or(Reason::BadSignature)?;
        at += 1;
        if expiry <= issued as f64 {
            return Err(Reason::BadSignature);
        }
        if now as f64 >= expiry {
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
    serde_json::from_str::<Unique>(s).map(|u| u.0)
}
fn attest_verify(jws: &str, jwks: &Jwks, now: u64) -> Result<Value, Reason> {
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
    if now > MAX_SAFE || exp <= iat {
        return Err(Reason::BadAttestation);
    }
    if iat > now {
        return Err(Reason::FutureRecord);
    }
    if exp <= now {
        return Err(Reason::Expired);
    }
    Ok(c)
}
pub fn verify_wallet_link(v: &Value, now: u64) -> Result<WalletLink, Reason> {
    verify_wallet_link_at_key(v, now, None)
}
pub fn verify_wallet_link_at_key(
    v: &Value,
    now: u64,
    current_key: Option<&PrincipalId>,
) -> Result<WalletLink, Reason> {
    let r = record(v, false)?;
    let IdentityRecord::Wallet(w) = &r else {
        return Err(Reason::BadRecord);
    };
    time(w.issued_at, now)?;
    if !key_verify(current_key.unwrap_or(&w.principal), &w.key_sig, &bytes(&r)) {
        return Err(Reason::BadSignature);
    }
    siwe_verify(
        &w.siwe,
        &w.address,
        &bytes(&r),
        w.issued_at,
        now,
        Some(&w.nonce),
    )?;
    Ok(w.clone())
}
pub fn verify_oidc_link(
    v: &Value,
    jwks: &Jwks,
    pinned_iss: &BTreeSet<String>,
    now: u64,
) -> Result<OidcLink, Reason> {
    verify_oidc_link_at_key(v, jwks, pinned_iss, now, None)
}
pub fn verify_oidc_link_at_key(
    v: &Value,
    jwks: &Jwks,
    pinned_iss: &BTreeSet<String>,
    now: u64,
    current_key: Option<&PrincipalId>,
) -> Result<OidcLink, Reason> {
    let r = record(v, false)?;
    let IdentityRecord::Oidc(o) = &r else {
        return Err(Reason::BadRecord);
    };
    time(o.issued_at, now)?;
    if !pinned_iss.contains(o.cred.issuer()) {
        return Err(Reason::UntrustedIssuer);
    }
    if !key_verify(current_key.unwrap_or(&o.principal), &o.key_sig, &bytes(&r)) {
        return Err(Reason::BadSignature);
    }
    let c = attest_verify(&o.attest, jwks, now)?;
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
    Ok(o.clone())
}
pub fn verify_revoke(v: &Value, current_key: &PrincipalId, now: u64) -> Result<Revoke, Reason> {
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
pub fn verify_rotate(
    v: &Value,
    current_key: &PrincipalId,
    links: &BTreeMap<String, WalletLink>,
    jwks: &Jwks,
    now: u64,
) -> Result<Rotate, Reason> {
    verify_rotate_at_key(v, current_key, links, jwks, now, &|p, _| p.clone())
}
pub fn verify_rotate_at_key(
    v: &Value,
    current_key: &PrincipalId,
    links: &BTreeMap<String, WalletLink>,
    jwks: &Jwks,
    now: u64,
    key_at: &impl Fn(&PrincipalId, u64) -> PrincipalId,
) -> Result<Rotate, Reason> {
    let r = record(v, false)?;
    let IdentityRecord::Rotate(rot) = &r else {
        return Err(Reason::BadRecord);
    };
    time(rot.issued_at, now)?;
    if &rot.prev_key != current_key || &rot.next_key == current_key {
        return Err(Reason::BadSequence);
    }
    if !key_verify(&rot.next_key, &rot.next_sig, &bytes(&r)) {
        return Err(Reason::BadSignature);
    }
    let c = attest_verify(&rot.attest, jwks, now)?;
    let auth = match rot.authorizer {
        Authorizer::Wallet { .. } => "wallet",
        Authorizer::OidcFreshLogin => "oidc-fresh-login",
    };
    if !only(
        &c,
        &["typ", "principal", "nextKey", "seq", "iat", "exp", "auth"],
    ) || c["typ"] != "sociacl-rotate-attest-v1"
        || c["principal"] != rot.principal.as_ref()
        || c["nextKey"] != rot.next_key.as_ref()
        || number(&c["seq"]).ok() != Some(rot.seq)
        || number(&c["iat"]).ok() != Some(rot.issued_at)
        || c["auth"] != auth
    {
        return Err(Reason::BadAttestation);
    }
    if let Authorizer::Wallet { link, siwe } = &rot.authorizer {
        let raw = links.get(link).ok_or(Reason::UnknownLink)?;
        let w = verify_wallet_link_at_key(
            &IdentityRecord::Wallet(raw.clone()).value(),
            raw.issued_at,
            Some(&key_at(&raw.principal, raw.issued_at)),
        )?;
        if link_id(&IdentityRecord::Wallet(w.clone()))? != *link
            || w.principal != rot.principal
            || w.issued_at > rot.issued_at
        {
            return Err(Reason::UnknownLink);
        }
        siwe_verify(siwe, &w.address, &bytes(&r), rot.issued_at, now, None)?;
    }
    Ok(rot.clone())
}
pub fn resolve_current_key(
    genesis: &PrincipalId,
    rotations: &[Value],
    ctx: &ResolutionContext<'_>,
) -> Result<PrincipalId, Reason> {
    if ctx.now > MAX_SAFE {
        return Err(Reason::BadRecord);
    }
    let mut groups: BTreeMap<u64, Vec<Rotate>> = BTreeMap::new();
    for raw in rotations {
        let IdentityRecord::Rotate(r) = record(raw, false)? else {
            return Err(Reason::BadRecord);
        };
        if &r.principal != genesis {
            return Err(Reason::BadRecord);
        }
        time(r.issued_at, ctx.now)?;
        groups.entry(r.seq).or_default().push(r);
    }
    let mut history: Vec<Rotate> = Vec::new();
    let mut current = genesis.clone();
    let mut seq = 1;
    for (n, group) in groups {
        if n != seq {
            return Err(Reason::BadSequence);
        }
        let key_at = |p: &PrincipalId, at: u64| {
            if p == genesis {
                history
                    .iter()
                    .rev()
                    .find(|r| r.issued_at < at)
                    .map_or_else(|| genesis.clone(), |r| r.next_key.clone())
            } else {
                p.clone()
            }
        };
        let mut valid = BTreeMap::new();
        for raw in group {
            if history.last().is_some_and(|r| raw.issued_at <= r.issued_at) {
                return Err(Reason::BadSequence);
            }
            let mut links = ctx.links.clone();
            for rev in ctx.revocations {
                let IdentityRecord::Revoke(p) = record(rev, false)? else {
                    return Err(Reason::BadRecord);
                };
                if &p.principal != genesis {
                    return Err(Reason::BadRecord);
                }
                time(p.issued_at, ctx.now)?;
                if p.issued_at > raw.issued_at {
                    continue;
                }
                let r = verify_revoke(rev, &key_at(genesis, p.issued_at), p.issued_at)?;
                if links
                    .get(&r.link_id)
                    .is_some_and(|w| &w.principal == genesis && r.issued_at >= w.issued_at)
                {
                    links.remove(&r.link_id);
                }
            }
            if let Authorizer::Wallet { link, .. } = &raw.authorizer {
                if !links.contains_key(link) && ctx.links.contains_key(link) {
                    return Err(Reason::RevokedLink);
                }
                if let Some(own) = links.get(link) {
                    for other in links.values() {
                        if other.address != own.address || other.issued_at > raw.issued_at {
                            continue;
                        }
                        verify_wallet_link_at_key(
                            &IdentityRecord::Wallet(other.clone()).value(),
                            other.issued_at,
                            Some(&key_at(&other.principal, other.issued_at)),
                        )?;
                        if &other.principal != genesis && other.issued_at >= own.issued_at {
                            return Err(Reason::AmbiguousLink);
                        }
                    }
                }
            }
            let r = verify_rotate_at_key(
                &IdentityRecord::Rotate(raw.clone()).value(),
                &current,
                &links,
                ctx.jwks,
                raw.issued_at,
                &key_at,
            )?;
            valid.insert(link_id(&IdentityRecord::Rotate(r.clone()))?, r);
        }
        if valid.len() > 1 {
            return Err(Reason::RotationFork);
        }
        let r = valid.into_values().next().ok_or(Reason::BadSequence)?;
        current = r.next_key.clone();
        history.push(r);
        seq += 1;
    }
    Ok(current)
}
pub fn resolve_wallet_link(
    address: &Eip55,
    links: &[Value],
    revocations: &[Value],
    now: u64,
) -> Result<WalletLink, Reason> {
    resolve_wallet_link_at_key(address, links, revocations, now, &|p, _| p.clone())
}
pub fn resolve_wallet_link_at_key(
    address: &Eip55,
    links: &[Value],
    revocations: &[Value],
    now: u64,
    key_at: &impl Fn(&PrincipalId, u64) -> PrincipalId,
) -> Result<WalletLink, Reason> {
    let mut valid = Vec::new();
    for raw in links {
        let IdentityRecord::Wallet(p) = record(raw, false)? else {
            return Err(Reason::BadRecord);
        };
        time(p.issued_at, now)?;
        let r =
            verify_wallet_link_at_key(raw, p.issued_at, Some(&key_at(&p.principal, p.issued_at)))?;
        if &r.address == address {
            valid.push(r);
        }
    }
    valid.sort_by_key(|r| std::cmp::Reverse(r.issued_at));
    let newest = valid.first().ok_or(Reason::UnknownLink)?;
    if valid
        .iter()
        .any(|r| r.issued_at == newest.issued_at && r.principal != newest.principal)
    {
        return Err(Reason::AmbiguousLink);
    }
    let id = link_id(&IdentityRecord::Wallet(newest.clone()))?;
    for raw in revocations {
        let IdentityRecord::Revoke(p) = record(raw, false)? else {
            return Err(Reason::BadRecord);
        };
        time(p.issued_at, now)?;
        let r = verify_revoke(raw, &key_at(&p.principal, p.issued_at), p.issued_at)?;
        if r.principal == newest.principal && r.link_id == id && r.issued_at >= newest.issued_at {
            return Err(Reason::RevokedLink);
        }
    }
    Ok(newest.clone())
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
