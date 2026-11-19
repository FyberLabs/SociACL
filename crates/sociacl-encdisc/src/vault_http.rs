//! Native client for the signed s3r.ch ingress to Spanopticon vault storage.
use std::{io::{Read, Write}, process::{Command, Stdio}, time::{SystemTime, UNIX_EPOCH}};
use base64ct::{Base64, Encoding};
use serde_json::{json, Value};
use sociacl_ids::{parse_principal_id, sign_with_keyring, PrincipalId};
use zeroize::Zeroizing;
use rand::{rngs::OsRng, RngCore};
use std::{fs::{self, OpenOptions}, os::unix::fs::OpenOptionsExt, path::PathBuf};

struct PayloadFile(PathBuf);
impl Drop for PayloadFile {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}
use crate::{canonical, EncDiscError};

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON: usize = 12 * 1024 * 1024;
const DOMAIN: &str = "s3rch-vault-operation-v1";

fn reject<T>(_: T) -> EncDiscError { EncDiscError::VaultRejected }
fn transport<T>(_: T) -> EncDiscError { EncDiscError::VaultStorage }
fn now() -> Result<u64, EncDiscError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(reject)?.as_secs())
}

// Restrict inputs to canonical ASCII DNS origins. In particular, exclude URL
// credentials, alternate IP syntax, percent encoding and any endpoint path.
fn validate_origin(origin: &str) -> Result<(), EncDiscError> {
    let host = origin.strip_prefix("https://").ok_or(EncDiscError::VaultRejected)?;
    let (host, port) = host.split_once(':').map_or((host, None), |(h, p)| (h, Some(p)));
    if let Some(port) = port {
        let n = port.parse::<u16>().map_err(reject)?;
        if n == 0 || n == 443 || port != n.to_string() { return Err(EncDiscError::VaultRejected); }
    }
    if host.len() > 253 || !host.contains('.') ||
        !host.rsplit('.').next().is_some_and(|label| label.as_bytes().first().is_some_and(u8::is_ascii_lowercase)) ||
        !host.split('.').all(|label| !label.is_empty() && label.len() <= 63 &&
            !label.starts_with('-') && !label.ends_with('-') &&
            label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')) {
        return Err(EncDiscError::VaultRejected);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultHttpHead {
    pub bytes: Vec<u8>,
    pub revision: String,
}

/// The origin is trusted configuration. The session cookie and signing key are
/// supplied by the caller and are never included in curl arguments or diagnostics.
pub struct NativeVaultHttp {
    origin: String,
    owner: PrincipalId,
    vault: String,
    session_key: PrincipalId,
    cookie: Zeroizing<String>,
    scalar: Zeroizing<Vec<u8>>,
}

impl NativeVaultHttp {
    pub fn new(origin: &str, owner: &str, vault: &str, session_key: &str,
        cookie: Zeroizing<String>, scalar: Zeroizing<Vec<u8>>) -> Result<Self, EncDiscError> {
        validate_origin(origin)?;
        canonical::require_digest_hex(vault)?;
        if cookie.is_empty() || cookie.len() > 8192 ||
            !cookie.bytes().all(|b| matches!(b, 0x20..=0x7e) && b != b'"' && b != b'\\') ||
            !cookie.contains('=') || scalar.len() != 32 {
            return Err(EncDiscError::VaultRejected);
        }
        Ok(Self { origin: origin.into(), owner: parse_principal_id(owner).map_err(reject)?,
            vault: vault.into(), session_key: parse_principal_id(session_key).map_err(reject)?, cookie, scalar })
    }

    fn request(&self, action: &str, id: &str, bytes: Option<&[u8]>, expected: Option<&str>,
        issued: u64) -> Result<Value, EncDiscError> {
        canonical::require_digest_hex(id)?;
        if let Some(expected) = expected { canonical::require_digest_hex(expected)?; }
        if bytes.is_some_and(|bytes| bytes.is_empty() || bytes.len() > MAX_BYTES) {
            return Err(EncDiscError::VaultRejected);
        }
        let digest = bytes.map(canonical::sha256_hex);
        if action == "putObject" && digest.as_deref() != Some(id) { return Err(EncDiscError::VaultRejected); }
        let expires = issued.checked_add(60).ok_or(EncDiscError::VaultRejected)?;
        canonical::canonical_decimal(expires)?;
        let transcript = operation_bytes(&self.origin, self.owner.as_ref(), &self.vault, action,
            id, digest.as_deref(), expected, issued, expires)?;
        let sig = sign_with_keyring(&self.scalar, &transcript, &self.session_key).map_err(reject)?;
        Ok(json!({"op": {"v":1,"origin":self.origin,"owner":self.owner.as_ref(),"vaultId":self.vault,
            "action":action,"id":id,"digest":digest,"expected":expected,"issuedAt":issued,"expiresAt":expires},
            "sig":sig,"bytes":bytes.map(Base64::encode_string)}))
    }

    fn call(&self, action: &str, id: &str, bytes: Option<&[u8]>, expected: Option<&str>) -> Result<Value, EncDiscError> {
        let request = self.request(action, id, bytes, expected, now()?)?;
        let payload = serde_json::to_string(&request).map_err(reject)?;
        if payload.len() > MAX_JSON { return Err(EncDiscError::VaultRejected); }
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let path = std::env::temp_dir().join(format!("sociacl-vault-http-{}", crate::hexutil::encode_hex(&random)));
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).map_err(transport)?;
        let temporary = PayloadFile(path);
        file.write_all(payload.as_bytes()).map_err(transport)?;
        drop(file);
        let mut data_arg = std::ffi::OsString::from("@");
        data_arg.push(&temporary.0);
        let mut child = Command::new("curl").args([
            "--disable", "--config", "-", "--proto", "=https", "--proxy", "", "--silent",
            "--max-time", "120", "--connect-timeout", "15", "--max-filesize", "12582912",
            "--write-out", "\\n%{http_code}\\n%{content_type}",
        ]).arg("--data-binary").arg(data_arg).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(transport)?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let mut stdout = child.stdout.take().expect("piped stdout");
        // The config contains the cookie and travels through a pipe. The
        // request file contains signed metadata and ciphertext only.
        let config = Zeroizing::new(format!(
            "url = \"{}/api/vault\"\nheader = \"Origin: {}\"\nheader = \"Content-Type: application/json\"\nheader = \"Accept-Encoding: identity\"\nheader = \"Cookie: {}\"\n",
            self.origin, self.origin, self.cookie.as_str()));
        let mut result = Vec::new();
        let (sent, received) = std::thread::scope(|scope| {
            let writer = scope.spawn(move || stdin.write_all(config.as_bytes()));
            let received = stdout.by_ref().take((MAX_JSON + 1025) as u64).read_to_end(&mut result);
            if received.is_err() || result.len() >= MAX_JSON + 1025 { let _ = child.kill(); }
            drop(stdout);
            (writer.join(), received)
        });
        let status = child.wait().map_err(transport)?;
        sent.map_err(transport)?.map_err(transport)?;
        received.map_err(transport)?;
        if !status.success() { return Err(EncDiscError::VaultStorage); }
        let mut parts = result.rsplitn(3, |b| *b == b'\n');
        let content_type = parts.next().unwrap_or_default();
        let status = parts.next().unwrap_or_default();
        let body = parts.next().unwrap_or_default();
        if status != b"200" || content_type.split(|b| *b == b';').next() != Some(b"application/json".as_slice()) ||
            body.len() > MAX_JSON {
            return Err(EncDiscError::VaultStorage);
        }
        serde_json::from_slice(body).map_err(transport)
    }

    pub fn read(&self) -> Result<Option<VaultHttpHead>, EncDiscError> {
        let response = self.call("read", &self.vault, None, None)?;
        if response.is_null() { return Ok(None); }
        Ok(Some(VaultHttpHead { bytes: decode(&response["bytes"])?, revision: revision(&response)? }))
    }

    pub fn write(&self, bytes: &[u8], expected: Option<&str>) -> Result<String, EncDiscError> {
        revision(&self.call("write", &self.vault, Some(bytes), expected)?)
    }

    pub fn get_object(&self, id: &str) -> Result<Option<Vec<u8>>, EncDiscError> {
        let response = self.call("getObject", id, None, None)?;
        if response.is_null() { return Ok(None); }
        let bytes = decode(&response["bytes"])?;
        if canonical::sha256_hex(&bytes) != id { return Err(EncDiscError::VaultStorage); }
        Ok(Some(bytes))
    }

    pub fn put_object(&self, bytes: &[u8]) -> Result<String, EncDiscError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES { return Err(EncDiscError::VaultRejected); }
        let id = canonical::sha256_hex(bytes);
        let response = self.call("putObject", &id, Some(bytes), None)?;
        if response["ok"].as_bool() != Some(true) { return Err(EncDiscError::VaultStorage); }
        if self.get_object(&id)?.as_deref() != Some(bytes) { return Err(EncDiscError::VaultStorage); }
        Ok(id)
    }

    /// Accept the exact remote SAVFILE1 head into an enrolled native store.
    /// The independently retained floor and fresh identity context still decide
    /// admission. A browser JWE or a missing remote head fails closed.
    pub fn sync_native_head<'a, F>(
        &self,
        custody: &crate::NativeVaultCustody,
        expected: &crate::VaultSyncHeadFloor,
        password: &str,
        rotations: &[Value],
        current: F,
    ) -> Result<crate::VaultSyncHead, EncDiscError>
    where
        F: FnMut() -> Result<sociacl_ids::ResolutionContext<'a>, EncDiscError>,
    {
        let row = self.read()?.ok_or(EncDiscError::VaultStorage)?;
        let envelope = crate::LocalVaultEnvelope::from_bytes(row.bytes)?;
        // Bind the local store to this transport before it handles the bytes.
        if !custody.matches(self.owner.as_ref(), &self.vault) {
            return Err(EncDiscError::VaultRejected);
        }
        custody.advance(&envelope, expected, password, rotations, current)
    }

    /// Reconcile a lost write response by comparing the exact prepared bytes.
    /// A different live head must satisfy the original CAS, even on retry.
    pub fn publish(&self, bytes: &[u8], expected: Option<&str>) -> Result<String, EncDiscError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES { return Err(EncDiscError::VaultRejected); }
        if let Some(tag) = expected { canonical::require_digest_hex(tag)?; }
        if let Some(row) = self.read()? {
            if row.bytes == bytes { return Ok(row.revision); }
            if Some(row.revision.as_str()) != expected { return Err(EncDiscError::VaultStorage); }
        } else if expected.is_some() { return Err(EncDiscError::VaultStorage); }
        let write = self.write(bytes, expected);
        let checked = self.read()?.ok_or(EncDiscError::VaultStorage)?;
        if checked.bytes != bytes || write.is_ok_and(|revision| revision != checked.revision) {
            return Err(EncDiscError::VaultStorage);
        }
        Ok(checked.revision)
    }
}

fn operation_bytes(origin: &str, owner: &str, vault: &str, action: &str, id: &str,
    digest: Option<&str>, expected: Option<&str>, issued: u64, expires: u64) -> Result<Vec<u8>, EncDiscError> {
    serde_json::to_vec(&json!([DOMAIN, origin, owner, vault, action, id, digest, expected, issued, expires])).map_err(reject)
}
fn revision(body: &Value) -> Result<String, EncDiscError> {
    let tag = body["revision"].as_str().ok_or(EncDiscError::VaultStorage)?;
    canonical::require_digest_hex(tag).map_err(transport)?;
    Ok(tag.into())
}
fn decode(value: &Value) -> Result<Vec<u8>, EncDiscError> {
    let encoded = value.as_str().ok_or(EncDiscError::VaultStorage)?;
    if encoded.len() > MAX_BYTES.div_ceil(3) * 4 { return Err(EncDiscError::VaultStorage); }
    let bytes = Base64::decode_vec(encoded).map_err(transport)?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES || Base64::encode_string(&bytes) != encoded {
        return Err(EncDiscError::VaultStorage);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_write_matches_s3rch_operation_contract() {
        let fixture: Value = serde_json::from_str(include_str!("../../../vectors/vault/sync-head.json")).unwrap();
        let owner = fixture["head"]["owner"].as_str().unwrap();
        let vault = fixture["head"]["vaultId"].as_str().unwrap();
        let mut scalar = vec![0; 32];
        scalar[31] = 1;
        let client = NativeVaultHttp::new("https://test.s3r.ch", owner, vault, owner,
            Zeroizing::new("session=fixture".into()), Zeroizing::new(scalar)).unwrap();
        let envelope = client.request("write", vault, Some(b"abc"), None, 10).unwrap();
        let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let expected = format!(
            r#"["s3rch-vault-operation-v1","https://test.s3r.ch","{owner}","{vault}","write","{vault}","{digest}",null,10,70]"#);
        let scalar = client.scalar.as_slice();
        assert_eq!(envelope["bytes"], "YWJj");
        assert_eq!(envelope["op"]["digest"], digest);
        assert_eq!(envelope["op"]["expected"], Value::Null);
        assert_eq!(envelope["sig"], sign_with_keyring(scalar, expected.as_bytes(), &client.session_key).unwrap());
        assert!(client.request("putObject", vault, Some(b"abc"), None, 10).is_err());
    }

    #[test]
    fn origin_and_response_bounds_fail_closed() {
        for origin in ["http://test.s3r.ch", "https://test.s3r.ch:443", "https://test.s3r.ch/",
            "https://test.s3r.ch@elsewhere.test", "https://example.0xff", "https://test.s3r.ch\n"] {
            assert!(validate_origin(origin).is_err());
        }
        assert!(validate_origin("https://test.s3r.ch:8443").is_ok());
        for value in ["", "YQ", "YR==", "YQ==\n"] {
            assert!(decode(&json!(value)).is_err());
        }
        assert_eq!(decode(&json!("YQ==")).unwrap(), b"a");
    }
}
