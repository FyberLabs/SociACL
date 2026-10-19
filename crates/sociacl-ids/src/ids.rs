use crate::uri::{public_host, web_uri};
use crate::*;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

id_type!(PrincipalId, parse_principal_id);
id_type!(PrincipalKey, parse_principal_key);
id_type!(Eip55, parse_eip55);
id_type!(TenantId, parse_tenant_id);
id_type!(ObjectId, parse_object_id);
id_type!(NetworkId, parse_network_id);
id_type!(SourceKey, parse_source_key);
id_type!(PathKey, parse_path_key);
id_type!(Soul, parse_soul_value);

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct MintedObjectId(ObjectId);
impl MintedObjectId {
    pub fn object_id(&self) -> &ObjectId {
        &self.0
    }
}
impl AsRef<str> for MintedObjectId {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
impl fmt::Display for MintedObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
pub struct OidcCredential {
    iss: String,
    tenant: TenantId,
    sub: String,
    #[serde(skip)]
    canonical: String,
}
impl OidcCredential {
    pub fn issuer(&self) -> &str {
        &self.iss
    }
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    pub fn subject(&self) -> &str {
        &self.sub
    }
}
impl FromStr for OidcCredential {
    type Err = Reason;
    fn from_str(s: &str) -> Result<Self, Reason> {
        let v = crate::records::unique_json(s).map_err(|_| Reason::BadRecord)?;
        parse_oidc_credential(&v)
    }
}
impl TryFrom<&str> for OidcCredential {
    type Error = Reason;
    fn try_from(s: &str) -> Result<Self, Reason> {
        s.parse()
    }
}
impl fmt::Display for OidcCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}
impl AsRef<str> for OidcCredential {
    fn as_ref(&self) -> &str {
        &self.canonical
    }
}
impl<'de> Deserialize<'de> for OidcCredential {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        parse_oidc_credential(&serde_json::Value::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

pub fn parse_principal_id(s: &str) -> Result<PrincipalId, Reason> {
    text(s, 160)?;
    if s.encode_utf16().count() != 87 {
        return Err(Reason::BadLength);
    }
    let b = s.as_bytes();
    if b[43] != b'.'
        || b.iter()
            .enumerate()
            .any(|(i, c)| i != 43 && !(c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-'))
    {
        return Err(Reason::BadAlphabet);
    }
    let mut point = vec![4];
    point.extend(unb64(&s[..43])?);
    point.extend(unb64(&s[44..])?);
    p256::PublicKey::from_sec1_bytes(&point).map_err(|_| Reason::NotOnCurve)?;
    Ok(PrincipalId(s.into()))
}
pub(crate) fn principal_bytes(p: &PrincipalId) -> Vec<u8> {
    let mut b = vec![4];
    b.extend(unb64(&p.0[..43]).expect("validated principal"));
    b.extend(unb64(&p.0[44..]).expect("validated principal"));
    b
}
pub fn format_principal_key(p: &PrincipalId) -> PrincipalKey {
    PrincipalKey(format!("p_{}", hex(&principal_bytes(p)[1..])))
}
pub fn parse_principal_key(s: &str) -> Result<PrincipalKey, Reason> {
    text(s, 160)?;
    let raw = s.strip_prefix("p_").ok_or(Reason::BadAlphabet)?;
    if !is_hex(raw, 128) {
        return Err(Reason::BadAlphabet);
    }
    let bytes = unhex(raw)?;
    parse_principal_id(&format!("{}.{}", b64(&bytes[..32]), b64(&bytes[32..])))?;
    Ok(PrincipalKey(s.into()))
}
fn key_principal(s: &str) -> Result<PrincipalId, Reason> {
    let k = parse_principal_key(s)?;
    let b = unhex(&k.0[2..])?;
    parse_principal_id(&format!("{}.{}", b64(&b[..32]), b64(&b[32..])))
}
pub(crate) fn checksum(s: &str) -> String {
    let lower = s[2..].to_ascii_lowercase();
    let hash = hex(&Keccak256::digest(lower.as_bytes()));
    format!(
        "0x{}",
        lower
            .bytes()
            .zip(hash.bytes())
            .map(|(c, h)| if h >= b'8' {
                (c as char).to_ascii_uppercase()
            } else {
                c as char
            })
            .collect::<String>()
    )
}
pub fn parse_eip55(s: &str) -> Result<Eip55, Reason> {
    text(s, 160)?;
    if s.len() != 42 || !s.starts_with("0x") || !s.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
    {
        return Err(Reason::BadAlphabet);
    }
    if checksum(s) != s {
        return Err(Reason::BadChecksum);
    }
    Ok(Eip55(s.into()))
}
pub fn parse_wallet_input(s: &str) -> Result<Eip55, Reason> {
    text(s, 160)?;
    if s.len() != 42 || !s.starts_with("0x") || !s.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
    {
        return Err(Reason::BadAlphabet);
    }
    let b = &s[2..];
    if b == b.to_ascii_lowercase() || b == b.to_ascii_uppercase() {
        parse_eip55(&checksum(s))
    } else {
        parse_eip55(s)
    }
}
pub fn parse_tenant_id(s: &str) -> Result<TenantId, Reason> {
    text(s, 160)?;
    if s.len() != 36
        || !s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
    {
        return Err(Reason::BadAlphabet);
    }
    if s != s.to_ascii_lowercase() {
        return Err(Reason::NonCanonical);
    }
    Ok(TenantId(s.into()))
}
pub fn parse_oidc_credential(v: &serde_json::Value) -> Result<OidcCredential, Reason> {
    let o = v.as_object().ok_or(Reason::BadRecord)?;
    if o.keys()
        .any(|k| !["iss", "tenant", "sub"].contains(&k.as_str()))
    {
        return Err(Reason::BadRecord);
    }
    let iss = text(v["iss"].as_str().ok_or(Reason::NotString)?, 2048)?;
    let tenant = parse_tenant_id(v["tenant"].as_str().ok_or(Reason::NotString)?)?;
    let sub = text(v["sub"].as_str().ok_or(Reason::NotString)?, 255)?;
    if !iss.starts_with("https://")
        || iss.len() < 9
        || !iss.bytes().all(|c| (33..=126).contains(&c))
        || !sub.bytes().all(|c| (33..=126).contains(&c))
    {
        return Err(Reason::BadAlphabet);
    }
    let mut out = OidcCredential {
        iss: iss.into(),
        tenant,
        sub: sub.into(),
        canonical: String::new(),
    };
    out.canonical = serde_json::to_string(&out).map_err(|_| Reason::BadRecord)?;
    Ok(out)
}
fn valid_kind(s: &str) -> bool {
    (2..=16).contains(&s.len())
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}
fn bound_parts(s: &str) -> Option<(&str, &str, &str)> {
    let (kind, rest) = s.split_once('_')?;
    let (key, nonce) = rest.rsplit_once('_')?;
    Some((kind, key, nonce))
}
fn bound_shape(kind: &str, key: &str, nonce: &str) -> bool {
    valid_kind(&kind.to_ascii_lowercase())
        && key.len() == 130
        && key
            .get(..2)
            .is_some_and(|tag| tag.eq_ignore_ascii_case("p_"))
        && key[2..].bytes().all(|c| c.is_ascii_hexdigit())
        && nonce.len() == 32
        && nonce.bytes().all(|c| c.is_ascii_hexdigit())
}
pub fn parse_object_id(s: &str) -> Result<ObjectId, Reason> {
    text(s, 180)?;
    if let Some((kind, key, nonce)) = bound_parts(s) {
        if bound_shape(kind, key, nonce) {
            if s != s.to_ascii_lowercase() {
                return Err(Reason::NonCanonical);
            }
            if ["claim", "ext", "post", "member", "objset"].contains(&kind) {
                return Err(Reason::ReservedKind);
            }
            key_principal(key)?;
            return Ok(ObjectId(s.into()));
        }
    }
    if let Some((kind, raw)) = s.split_once('_') {
        if ["claim", "ext"].contains(&kind) && is_hex(raw, 64) {
            return Ok(ObjectId(s.into()));
        }
        if valid_kind(kind) && is_hex(raw, 32) {
            if ["claim", "ext", "post", "member", "objset"].contains(&kind) {
                return Err(Reason::ReservedKind);
            }
            return Ok(ObjectId(s.into()));
        }
        if valid_kind(&kind.to_ascii_lowercase())
            && (32..=64).contains(&raw.len())
            && raw.bytes().all(|c| c.is_ascii_hexdigit())
            && s != s.to_ascii_lowercase()
        {
            return Err(Reason::NonCanonical);
        }
    }
    Err(Reason::BadAlphabet)
}
pub fn parse_network_id(s: &str) -> Result<NetworkId, Reason> {
    text(s, 2048)?;
    if ["atproto", "farcaster", "nostr", "activitypub", "rss"].contains(&s) {
        return Ok(NetworkId(s.into()));
    }
    let rest = s
        .strip_prefix("s3rch:https://")
        .ok_or(Reason::UnknownNetwork)?;
    let (authority, key) = rest.split_once(";key=").ok_or(Reason::UnknownNetwork)?;
    let (host, port) = authority.split_once(':').ok_or(Reason::UnknownNetwork)?;
    if host.is_empty()
        || host.contains(['/', ':', ';'])
        || !is_hex(key, 64)
        || !(1..=5).contains(&port.len())
        || !port.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(Reason::UnknownNetwork);
    }
    if !public_host(host) {
        return Err(Reason::BadHost);
    }
    if !port
        .parse::<u16>()
        .is_ok_and(|n| n > 0 && n.to_string() == port)
    {
        return Err(Reason::BadPort);
    }
    Ok(NetworkId(s.into()))
}
pub(crate) fn pct(s: &str) -> String {
    s.bytes()
        .map(|c| {
            if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
                (c as char).to_string()
            } else {
                format!("%{c:02X}")
            }
        })
        .collect()
}
fn unpct(s: &str) -> Result<String, Reason> {
    let mut bytes = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                return Err(Reason::NonCanonical);
            }
            bytes.push(u8::from_str_radix(&s[i + 1..i + 3], 16).map_err(|_| Reason::NonCanonical)?);
            i += 3;
        } else {
            bytes.push(b[i]);
            i += 1;
        }
    }
    let out = String::from_utf8(bytes).map_err(|_| Reason::NonCanonical)?;
    if pct(&out) != s {
        return Err(Reason::NonCanonical);
    }
    Ok(out)
}
fn did_web(s: &str) -> bool {
    let parts: Vec<_> = s[8..].split(':').collect();
    let host = parts[0];
    let host = if let Some((h, port)) = host.split_once("%3A") {
        if port.len() > 5
            || !port.bytes().all(|c| c.is_ascii_digit())
            || !port
                .parse::<u16>()
                .is_ok_and(|n| n > 0 && n.to_string() == port && n != 443)
        {
            return false;
        }
        h
    } else {
        host
    };
    if !public_host(host) {
        return false;
    }
    parts[1..].iter().all(|p| {
        if p.is_empty() {
            return false;
        }
        let b = p.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i].is_ascii_alphanumeric() || b"-._~".contains(&b[i]) {
                i += 1;
            } else if b[i] == b'%'
                && i + 2 < b.len()
                && b[i + 1].is_ascii_hexdigit()
                && b[i + 2].is_ascii_hexdigit()
            {
                i += 3;
            } else {
                return false;
            }
        }
        true
    })
}
pub fn parse_source_key(s: &str) -> Result<SourceKey, Reason> {
    text(s, 8192)?;
    let rest = s.strip_prefix("sr1:").ok_or(Reason::BadTemplate)?;
    let parts: Vec<_> = rest.split('/').collect();
    if parts.len() != 4 {
        return Err(Reason::BadTemplate);
    }
    let mut decoded = Vec::new();
    for p in &parts[..3] {
        let d = unpct(p)?;
        text(&d, 2048)?;
        decoded.push(d);
    }
    let n = parse_network_id(&decoded[0])?;
    let owner = &decoded[1];
    if !["chat", "forum", "feed", "stream", "voice"].contains(&parts[3]) {
        return Err(Reason::BadAlphabet);
    }
    let valid = match n.as_ref() {
        n if n.starts_with("s3rch:") => {
            parse_principal_id(owner)?;
            true
        }
        "atproto" => {
            owner.strip_prefix("did:plc:").is_some_and(|x| {
                x.len() == 24
                    && x.bytes()
                        .all(|c| c.is_ascii_lowercase() || (b'2'..=b'7').contains(&c))
            }) || (owner.starts_with("did:web:") && did_web(owner))
        }
        "farcaster" => owner
            .parse::<u64>()
            .is_ok_and(|n| n > 0 && n.to_string() == *owner),
        "nostr" => is_hex(owner, 64),
        "activitypub" => web_uri(owner, false, true),
        "rss" => web_uri(owner, true, false),
        _ => false,
    };
    if !valid {
        return Err(Reason::BadAlphabet);
    }
    Ok(SourceKey(s.into()))
}
fn hash_key(tag: &str, domain: &str, fields: &[&str]) -> PathKey {
    let mut all = vec![domain];
    all.extend_from_slice(fields);
    PathKey(format!("{tag}{}", hex(&Sha256::digest(lp(&all)))))
}
pub fn format_wallet_key(w: &Eip55) -> PathKey {
    PathKey(format!("w_{}", w.0[2..].to_ascii_lowercase()))
}
pub fn format_oidc_key(c: &OidcCredential) -> PathKey {
    hash_key(
        "k_",
        "sociacl-oidc-v1",
        &[&c.iss, c.tenant.as_ref(), &c.sub],
    )
}
pub fn format_network_key(n: &NetworkId) -> PathKey {
    hash_key("n_", "sociacl-network-v1", &[n.as_ref()])
}
pub fn format_source_path_key(s: &SourceKey) -> PathKey {
    hash_key("s_", "sociacl-source-v1", &[s.as_ref()])
}
pub fn object_key(o: &ObjectId) -> PathKey {
    PathKey(o.0.clone())
}
/// Genesis principal embedded in a bound object id.
/// An id with no embedded principal is `bad-template`.
pub fn object_principal(object: &ObjectId) -> Result<PrincipalId, Reason> {
    let Some((kind, key, nonce)) = bound_parts(object.as_ref()) else {
        return Err(Reason::BadTemplate);
    };
    if !bound_shape(kind, key, nonce) || object.as_ref() != object.as_ref().to_ascii_lowercase() {
        return Err(Reason::BadTemplate);
    }
    key_principal(key)
}
pub fn parse_path_key(s: &str) -> Result<PathKey, Reason> {
    text(s, 180)?;
    if s.starts_with("p_") {
        parse_principal_key(s)?;
    } else if s.strip_prefix("w_").is_some_and(|r| is_hex(r, 40))
        || ["k_", "n_", "s_"]
            .iter()
            .any(|p| s.strip_prefix(p).is_some_and(|r| is_hex(r, 64)))
    {
    } else {
        parse_object_id(s)?;
    }
    Ok(PathKey(s.into()))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Collection {
    Items,
    Rooms,
    UsersLegacy,
}
impl Collection {
    fn name(self) -> &'static str {
        match self {
            Self::Items => "items",
            Self::Rooms => "rooms",
            Self::UsersLegacy => "users-legacy",
        }
    }
}
fn soul(parts: &[&str], count: usize) -> Soul {
    let s = parts.join("/");
    debug_assert_eq!(s.split('/').count(), count);
    Soul(s)
}
pub fn object_soul(c: Collection, o: &ObjectId) -> Soul {
    soul(&["s3rch", c.name(), o.as_ref()], 3)
}
pub fn user_soul(p: &PrincipalId) -> Soul {
    soul(&[&format!("~{p}")], 1)
}
pub fn acl_soul(p: &PrincipalId) -> Soul {
    soul(&["s3rch", "acl", format_principal_key(p).as_ref()], 3)
}
pub fn grant_soul(p: &PrincipalId, o: &ObjectId, a: &PrincipalId) -> Soul {
    soul(
        &[
            "s3rch",
            "acl",
            format_principal_key(p).as_ref(),
            o.as_ref(),
            format_principal_key(a).as_ref(),
        ],
        5,
    )
}
pub fn post_soul(p: &PrincipalId, o: &ObjectId, a: &PrincipalId) -> Soul {
    soul(
        &[
            "s3rch",
            "acl",
            format_principal_key(p).as_ref(),
            "post",
            o.as_ref(),
            format_principal_key(a).as_ref(),
        ],
        6,
    )
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipPredicate {
    SameGroup,
    NamedCircle,
}
impl MembershipPredicate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SameGroup => "same-group",
            Self::NamedCircle => "named-circle",
        }
    }
}
impl std::str::FromStr for MembershipPredicate {
    type Err = Reason;
    fn from_str(s: &str) -> Result<Self, Reason> {
        match s {
            "same-group" => Ok(Self::SameGroup),
            "named-circle" => Ok(Self::NamedCircle),
            _ => Err(Reason::BadTemplate),
        }
    }
}
pub fn membership_soul(
    owner: &PrincipalId,
    predicate: MembershipPredicate,
    set: &ObjectId,
    accessor: &PrincipalId,
) -> Soul {
    soul(
        &[
            "s3rch",
            "acl",
            format_principal_key(owner).as_ref(),
            "member",
            predicate.as_str(),
            set.as_ref(),
            format_principal_key(accessor).as_ref(),
        ],
        7,
    )
}
pub fn object_set_soul(
    owner: &PrincipalId,
    object: &ObjectId,
    predicate: MembershipPredicate,
    set: &ObjectId,
) -> Soul {
    soul(
        &[
            "s3rch",
            "acl",
            format_principal_key(owner).as_ref(),
            "objset",
            predicate.as_str(),
            set.as_ref(),
            object.as_ref(),
        ],
        7,
    )
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ParsedSoul {
    pub template: &'static str,
    pub ids: Vec<String>,
}
fn minted_set_id(s: &str) -> Result<ObjectId, Reason> {
    let id = parse_object_id(s)?;
    if !id.as_ref().starts_with("set_") {
        return Err(Reason::BadTemplate);
    }
    object_principal(&id)?;
    Ok(id)
}
pub fn parse_soul(s: &str) -> Result<ParsedSoul, Reason> {
    text(s, 522)?;
    if let Some(p) = s.strip_prefix('~') {
        return Ok(ParsedSoul {
            template: "user",
            ids: vec![parse_principal_id(p)?.to_string()],
        });
    }
    let p: Vec<_> = s.split('/').collect();
    match p.as_slice() {
        ["s3rch", c @ ("items" | "rooms" | "users-legacy"), o] => Ok(ParsedSoul {
            template: "object",
            ids: vec![c.to_string(), parse_object_id(o)?.to_string()],
        }),
        ["s3rch", "acl", a] => Ok(ParsedSoul {
            template: "acl",
            ids: vec![key_principal(a)?.to_string()],
        }),
        ["s3rch", "acl", a, "objset", predicate, set_id, o]
            if matches!(*predicate, "same-group" | "named-circle") =>
        {
            let owner = key_principal(a)?;
            let set = minted_set_id(set_id)?;
            let object = parse_object_id(o)?;
            let embedded = object_principal(&object)?;
            if embedded != owner {
                return Err(Reason::BadTemplate);
            }
            Ok(ParsedSoul {
                template: "objset",
                ids: vec![
                    owner.to_string(),
                    (*predicate).to_string(),
                    set.to_string(),
                    object.to_string(),
                ],
            })
        }
        ["s3rch", "acl", a, o, b] => Ok(ParsedSoul {
            template: "grant",
            ids: vec![
                key_principal(a)?.to_string(),
                parse_object_id(o)?.to_string(),
                key_principal(b)?.to_string(),
            ],
        }),
        ["s3rch", "acl", a, "post", o, b] => Ok(ParsedSoul {
            template: "post",
            ids: vec![
                key_principal(a)?.to_string(),
                parse_object_id(o)?.to_string(),
                key_principal(b)?.to_string(),
            ],
        }),
        ["s3rch", "acl", a, "member", predicate, set_id, b]
            if matches!(*predicate, "same-group" | "named-circle") =>
        {
            Ok(ParsedSoul {
                template: "membership",
                ids: vec![
                    key_principal(a)?.to_string(),
                    (*predicate).to_string(),
                    parse_object_id(set_id)?.to_string(),
                    key_principal(b)?.to_string(),
                ],
            })
        }
        _ => Err(Reason::BadTemplate),
    }
}
fn parse_soul_value(s: &str) -> Result<Soul, Reason> {
    parse_soul(s)?;
    Ok(Soul(s.into()))
}
pub fn mint_object_id(kind: &str, creator: &PrincipalId) -> Result<MintedObjectId, Reason> {
    mint_object_id_with(kind, creator, |bytes| {
        getrandom::getrandom(bytes).map_err(|_| Reason::RngFailure)
    })
}
pub fn mint_object_id_with(
    kind: &str,
    creator: &PrincipalId,
    rng: impl FnOnce(&mut [u8; 16]) -> Result<(), Reason>,
) -> Result<MintedObjectId, Reason> {
    text(kind, 16)?;
    if !valid_kind(kind) {
        return Err(Reason::BadAlphabet);
    }
    if ["claim", "ext", "post", "member", "objset"].contains(&kind) {
        return Err(Reason::ReservedKind);
    }
    let mut bytes = [0; 16];
    rng(&mut bytes)?;
    let key = format_principal_key(creator);
    Ok(MintedObjectId(ObjectId(format!(
        "{kind}_{}_{}",
        key.as_ref(),
        hex(&bytes)
    ))))
}
pub fn derive_claim_id(claim: &str) -> Result<ObjectId, Reason> {
    text(claim, 2048)?;
    Ok(ObjectId(hash_key("claim_", "sociacl-claim-v1", &[claim]).0))
}
pub fn derive_external_id(source: &SourceKey, item: &str) -> Result<ObjectId, Reason> {
    text(item, 2048)?;
    Ok(ObjectId(
        hash_key("ext_", "sociacl-ext-v1", &[source.as_ref(), item]).0,
    ))
}

/// Utility for fixed-key tests and callers importing a validated SEC1 point.
pub fn principal_from_sec1(bytes: &[u8]) -> Result<PrincipalId, Reason> {
    let key = p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| Reason::NotOnCurve)?;
    let raw = key.to_encoded_point(false);
    parse_principal_id(&format!(
        "{}.{}",
        b64(&raw.as_bytes()[1..33]),
        b64(&raw.as_bytes()[33..])
    ))
}
