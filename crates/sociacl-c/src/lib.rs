//! C FFI wrapping live Check and the Case C client path.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;
use std::sync::Mutex;

use sociacl_core::{
    Attestation, AttestationBinding, AttestationClaim, AttestationSig, CheckRequest, Client,
    EnrollmentKind, IssuerSecret, Plane, PredicateId, Relation, VerifyKey,
};

#[allow(non_camel_case_types)]
pub struct sociacl_plane {
    inner: Mutex<Plane>,
}

#[allow(non_camel_case_types)]
pub struct sociacl_client {
    inner: Mutex<Client>,
}

fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

fn write_reason(dst: *mut c_char, len: usize, text: &str) {
    if dst.is_null() || len == 0 {
        return;
    }
    let c = CString::new(text).unwrap_or_else(|_| CString::new("error").unwrap());
    let bytes = c.as_bytes_with_nul();
    let n = bytes.len().min(len);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, n);
        if n < len {
            *dst.add(n.saturating_sub(1)) = 0;
        } else {
            *dst.add(len - 1) = 0;
        }
    }
}

#[no_mangle]
pub extern "C" fn sociacl_plane_new() -> *mut sociacl_plane {
    Box::into_raw(Box::new(sociacl_plane {
        inner: Mutex::new(Plane::new()),
    }))
}

#[no_mangle]
pub extern "C" fn sociacl_plane_free(plane: *mut sociacl_plane) {
    if !plane.is_null() {
        unsafe {
            drop(Box::from_raw(plane));
        }
    }
}

fn with_plane<F>(plane: *mut sociacl_plane, f: F) -> c_int
where
    F: FnOnce(&mut Plane) -> c_int,
{
    let Some(p) = (unsafe { plane.as_mut() }) else {
        return -1;
    };
    let Ok(mut guard) = p.inner.lock() else {
        return -1;
    };
    f(&mut guard)
}

#[no_mangle]
pub extern "C" fn sociacl_add_person(plane: *mut sociacl_plane, id: *const c_char) -> c_int {
    let Some(id) = cstr(id) else {
        return -1;
    };
    with_plane(plane, |p| {
        p.add_person(id);
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_add_agent(plane: *mut sociacl_plane, id: *const c_char) -> c_int {
    let Some(id) = cstr(id) else {
        return -1;
    };
    with_plane(plane, |p| {
        p.add_agent(id);
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_add_device(plane: *mut sociacl_plane, id: *const c_char) -> c_int {
    let Some(id) = cstr(id) else {
        return -1;
    };
    with_plane(plane, |p| {
        p.add_device(id);
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_add_group(plane: *mut sociacl_plane, id: *const c_char) -> c_int {
    let Some(id) = cstr(id) else {
        return -1;
    };
    with_plane(plane, |p| {
        p.add_group(id);
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_add_circle(plane: *mut sociacl_plane, id: *const c_char) -> c_int {
    let Some(id) = cstr(id) else {
        return -1;
    };
    with_plane(plane, |p| {
        p.add_circle(id);
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_set_object_property(
    plane: *mut sociacl_plane,
    object: *const c_char,
    key: *const c_char,
    value: *const c_char,
) -> c_int {
    let (Some(object), Some(key), Some(value)) = (cstr(object), cstr(key), cstr(value)) else {
        return -1;
    };
    with_plane(plane, |p| {
        if p.set_object_property(object, key, value).is_err() {
            return -1;
        }
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_add_object(
    plane: *mut sociacl_plane,
    id: *const c_char,
    owner: *const c_char,
) -> c_int {
    let (Some(id), Some(owner)) = (cstr(id), cstr(owner)) else {
        return -1;
    };
    with_plane(plane, |p| {
        p.add_object(id, owner);
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_state_edge(
    plane: *mut sociacl_plane,
    speaker: *const c_char,
    from: *const c_char,
    to: *const c_char,
    relation: *const c_char,
) -> c_int {
    let (Some(speaker), Some(from), Some(to), Some(rel)) =
        (cstr(speaker), cstr(from), cstr(to), cstr(relation))
    else {
        return -1;
    };
    let Some(relation) = Relation::parse(rel) else {
        return -1;
    };
    with_plane(plane, |p| {
        p.state_edge(speaker, from, to, relation);
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_jointly_state(
    plane: *mut sociacl_plane,
    from: *const c_char,
    to: *const c_char,
    relation: *const c_char,
) -> c_int {
    let (Some(from), Some(to), Some(rel)) = (cstr(from), cstr(to), cstr(relation)) else {
        return -1;
    };
    let Some(relation) = Relation::parse(rel) else {
        return -1;
    };
    with_plane(plane, |p| {
        p.jointly_state(from, to, relation);
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_enroll(
    plane: *mut sociacl_plane,
    issuer: *const c_char,
    kind: *const c_char,
    pubkey: *const u8,
    pubkey_len: usize,
) -> c_int {
    let (Some(issuer), Some(kind)) = (cstr(issuer), cstr(kind)) else {
        return -1;
    };
    let Ok(kind) = EnrollmentKind::parse(kind) else {
        return -1;
    };
    if pubkey.is_null() || pubkey_len == 0 {
        return -1;
    }
    let bytes = unsafe { slice::from_raw_parts(pubkey, pubkey_len) };
    let Ok(public_key) = VerifyKey::from_slice(bytes) else {
        return -1;
    };
    with_plane(plane, |p| {
        if p.enroll(issuer, kind, public_key).is_err() {
            return -1;
        }
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_issuer_keygen(pk_out: *mut u8, sk_out: *mut u8) -> c_int {
    if pk_out.is_null() || sk_out.is_null() {
        return -1;
    }
    let secret = IssuerSecret::generate();
    let pk = secret.verify_key();
    unsafe {
        ptr::copy_nonoverlapping(pk.0.as_ptr(), pk_out, VerifyKey::LEN);
        ptr::copy_nonoverlapping(secret.as_bytes().as_ptr(), sk_out, IssuerSecret::LEN);
    }
    0
}

#[no_mangle]
pub extern "C" fn sociacl_sign_claim(
    plane: *mut sociacl_plane,
    sk: *const u8,
    sk_len: usize,
    issuer: *const c_char,
    subject: *const c_char,
    claim: *const c_char,
    object: *const c_char,
    sig_out: *mut u8,
    sig_len: usize,
) -> c_int {
    if sk.is_null() || sig_out.is_null() || sig_len < AttestationSig::LEN {
        return -1;
    }
    let (Some(issuer), Some(subject), Some(claim), Some(object)) =
        (cstr(issuer), cstr(subject), cstr(claim), cstr(object))
    else {
        return -1;
    };
    let Ok(claim) = AttestationClaim::parse(claim) else {
        return -1;
    };
    let sk_bytes = unsafe { slice::from_raw_parts(sk, sk_len) };
    let Ok(secret) = IssuerSecret::from_slice(sk_bytes) else {
        return -1;
    };
    with_plane(plane, |p| {
        let object_id = sociacl_core::NodeId::new(object);
        let Some(snap) = p.snapshot(&object_id) else {
            return -1;
        };
        let att = Attestation::new(
            issuer,
            subject,
            claim,
            p.now(),
            AttestationBinding::Snapshot {
                object: object_id,
                hash: snap.hash,
            },
        )
        .sign(&secret);
        unsafe {
            ptr::copy_nonoverlapping(att.signature.0.as_ptr(), sig_out, AttestationSig::LEN);
        }
        0
    })
}

#[no_mangle]
pub extern "C" fn sociacl_check(
    plane: *mut sociacl_plane,
    action: *const c_char,
    object: *const c_char,
    accessor: *const c_char,
    predicate: *const c_char,
    reason_out: *mut c_char,
    reason_len: usize,
) -> c_int {
    if cstr(action).is_none()
        || cstr(object).is_none()
        || cstr(accessor).is_none()
        || cstr(predicate).is_none()
    {
        write_reason(reason_out, reason_len, "invalid-argument");
        return -1;
    }
    sociacl_check_ex(
        plane,
        action,
        object,
        accessor,
        predicate,
        ptr::null(),
        ptr::null(),
        0,
        reason_out,
        reason_len,
    )
}

#[no_mangle]
pub extern "C" fn sociacl_check_ex(
    plane: *mut sociacl_plane,
    action: *const c_char,
    object: *const c_char,
    accessor: *const c_char,
    predicate: *const c_char,
    attestation: *const c_char,
    signature: *const u8,
    signature_len: usize,
    reason_out: *mut c_char,
    reason_len: usize,
) -> c_int {
    let (Some(action), Some(object), Some(accessor)) = (cstr(action), cstr(object), cstr(accessor))
    else {
        write_reason(reason_out, reason_len, "invalid-argument");
        return -1;
    };
    let predicate = cstr(predicate).map(PredicateId::new);
    let claim_s = cstr(attestation);
    with_plane(plane, |p| {
        let attestation = if let Some(claim_s) = claim_s {
            let claim = match AttestationClaim::parse(claim_s) {
                Ok(c) => c,
                Err(e) => {
                    write_reason(reason_out, reason_len, &e.to_string());
                    return -1;
                }
            };
            if signature.is_null() || signature_len == 0 {
                write_reason(
                    reason_out,
                    reason_len,
                    "attestation signature does not match the statement",
                );
                return -1;
            }
            let sig_bytes = unsafe { slice::from_raw_parts(signature, signature_len) };
            let signature = match AttestationSig::from_slice(sig_bytes) {
                Ok(s) => s,
                Err(e) => {
                    write_reason(reason_out, reason_len, &e.to_string());
                    return -1;
                }
            };
            let object_id = sociacl_core::NodeId::new(object);
            let Some(snap) = p.snapshot(&object_id) else {
                write_reason(reason_out, reason_len, "object not found");
                return -1;
            };
            let mut att = Attestation::new(
                accessor,
                accessor,
                claim,
                p.now(),
                AttestationBinding::Snapshot {
                    object: object_id,
                    hash: snap.hash,
                },
            );
            att.signature = signature;
            Some(att)
        } else {
            None
        };
        match p.check(CheckRequest {
            action: action.into(),
            object: object.into(),
            accessor: accessor.into(),
            predicate,
            zookie: None,
            attestation,
        }) {
            Ok(result) => {
                write_reason(reason_out, reason_len, result.reason.as_str());
                if result.allowed {
                    1
                } else {
                    0
                }
            }
            Err(e) => {
                write_reason(reason_out, reason_len, &e.to_string());
                -1
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn sociacl_export_bundle(
    plane: *mut sociacl_plane,
    holder: *const c_char,
    bytes_out: *mut u8,
    bytes_len: usize,
    written_out: *mut usize,
    reason_out: *mut c_char,
    reason_len: usize,
) -> c_int {
    let Some(holder) = cstr(holder) else {
        write_reason(reason_out, reason_len, "invalid-argument");
        return -1;
    };
    with_plane(plane, |p| match p.export_bundle_bytes(holder) {
        Ok(bytes) => {
            if !written_out.is_null() {
                unsafe {
                    *written_out = bytes.len();
                }
            }
            if bytes_out.is_null() {
                return 0;
            }
            if bytes_len < bytes.len() {
                write_reason(reason_out, reason_len, "buffer-too-small");
                return -1;
            }
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), bytes_out, bytes.len());
            }
            0
        }
        Err(e) => {
            write_reason(reason_out, reason_len, &e.to_string());
            -1
        }
    })
}

#[no_mangle]
pub extern "C" fn sociacl_export_bundle_file(
    plane: *mut sociacl_plane,
    holder: *const c_char,
    path: *const c_char,
    reason_out: *mut c_char,
    reason_len: usize,
) -> c_int {
    let (Some(holder), Some(path)) = (cstr(holder), cstr(path)) else {
        write_reason(reason_out, reason_len, "invalid-argument");
        return -1;
    };
    with_plane(plane, |p| match p.export_bundle_path(holder, path) {
        Ok(()) => 0,
        Err(e) => {
            write_reason(reason_out, reason_len, &e.to_string());
            -1
        }
    })
}

fn client_open_result(
    result: Result<Client, sociacl_core::VerbError>,
    reason_out: *mut c_char,
    reason_len: usize,
) -> *mut sociacl_client {
    match result {
        Ok(client) => Box::into_raw(Box::new(sociacl_client {
            inner: Mutex::new(client),
        })),
        Err(e) => {
            write_reason(reason_out, reason_len, &e.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn sociacl_client_open(
    bytes: *const u8,
    len: usize,
    reason_out: *mut c_char,
    reason_len: usize,
) -> *mut sociacl_client {
    if bytes.is_null() {
        write_reason(reason_out, reason_len, "invalid-argument");
        return ptr::null_mut();
    }
    let slice = unsafe { slice::from_raw_parts(bytes, len) };
    client_open_result(Client::from_bytes(slice), reason_out, reason_len)
}

#[no_mangle]
pub extern "C" fn sociacl_client_open_file(
    path: *const c_char,
    reason_out: *mut c_char,
    reason_len: usize,
) -> *mut sociacl_client {
    let Some(path) = cstr(path) else {
        write_reason(reason_out, reason_len, "invalid-argument");
        return ptr::null_mut();
    };
    client_open_result(Client::from_path(path), reason_out, reason_len)
}

#[no_mangle]
pub extern "C" fn sociacl_client_free(client: *mut sociacl_client) {
    if !client.is_null() {
        unsafe {
            drop(Box::from_raw(client));
        }
    }
}

fn with_client<F>(client: *mut sociacl_client, f: F) -> c_int
where
    F: FnOnce(&mut Client) -> c_int,
{
    let Some(c) = (unsafe { client.as_mut() }) else {
        return -1;
    };
    let Ok(mut guard) = c.inner.lock() else {
        return -1;
    };
    f(&mut guard)
}

#[no_mangle]
pub extern "C" fn sociacl_client_check(
    client: *mut sociacl_client,
    action: *const c_char,
    object: *const c_char,
    accessor: *const c_char,
    predicate: *const c_char,
    reason_out: *mut c_char,
    reason_len: usize,
) -> c_int {
    let (Some(action), Some(object), Some(accessor), Some(predicate)) =
        (cstr(action), cstr(object), cstr(accessor), cstr(predicate))
    else {
        write_reason(reason_out, reason_len, "invalid-argument");
        return -1;
    };
    with_client(client, |c| {
        match c.check(CheckRequest {
            action: action.into(),
            object: object.into(),
            accessor: accessor.into(),
            predicate: Some(PredicateId::new(predicate)),
            zookie: None,
            attestation: None,
        }) {
            Ok(result) => {
                write_reason(reason_out, reason_len, result.reason.as_str());
                if result.allowed {
                    1
                } else {
                    0
                }
            }
            Err(e) => {
                write_reason(reason_out, reason_len, &e.to_string());
                -1
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn sociacl_client_remint(
    client: *mut sociacl_client,
    object: *const c_char,
    principal: *const c_char,
    reason_out: *mut c_char,
    reason_len: usize,
) -> c_int {
    let (Some(object), Some(principal)) = (cstr(object), cstr(principal)) else {
        write_reason(reason_out, reason_len, "invalid-argument");
        return -1;
    };
    with_client(client, |c| match c.remint(object, principal) {
        Ok(_) => {
            write_reason(reason_out, reason_len, "remint");
            1
        }
        Err(e) => {
            write_reason(reason_out, reason_len, &e.to_string());
            -1
        }
    })
}

#[no_mangle]
pub extern "C" fn sociacl_client_elect(
    client: *mut sociacl_client,
    object: *const c_char,
    reason_out: *mut c_char,
    reason_len: usize,
) -> c_int {
    let Some(object) = cstr(object) else {
        write_reason(reason_out, reason_len, "invalid-argument");
        return -1;
    };
    with_client(client, |c| match c.elect(object) {
        Ok(_) => {
            write_reason(reason_out, reason_len, "elect-must-not-succeed");
            -1
        }
        Err(e) => {
            write_reason(reason_out, reason_len, &e.to_string());
            -1
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    #[test]
    fn ffi_check_group() {
        let plane = sociacl_plane_new();
        assert_eq!(sociacl_add_person(plane, c("alice").as_ptr()), 0);
        assert_eq!(sociacl_add_person(plane, c("bob").as_ptr()), 0);
        assert_eq!(sociacl_add_person(plane, c("carol").as_ptr()), 0);
        assert_eq!(sociacl_add_group(plane, c("ops").as_ptr()), 0);
        assert_eq!(
            sociacl_add_object(plane, c("doc").as_ptr(), c("alice").as_ptr()),
            0
        );
        assert_eq!(
            sociacl_set_object_property(
                plane,
                c("doc").as_ptr(),
                c("predicate").as_ptr(),
                c("same-group").as_ptr()
            ),
            0
        );
        assert_eq!(
            sociacl_set_object_property(
                plane,
                c("doc").as_ptr(),
                c("group").as_ptr(),
                c("ops").as_ptr()
            ),
            0
        );
        for (from, to, rel) in [
            ("alice", "ops", "member-of"),
            ("bob", "ops", "member-of"),
            ("doc", "ops", "object-group"),
        ] {
            assert_eq!(
                sociacl_jointly_state(plane, c(from).as_ptr(), c(to).as_ptr(), c(rel).as_ptr()),
                0
            );
        }
        let mut reason = [0i8; 64];
        let bob = sociacl_check(
            plane,
            c("read").as_ptr(),
            c("doc").as_ptr(),
            c("bob").as_ptr(),
            c("same-group").as_ptr(),
            reason.as_mut_ptr(),
            reason.len(),
        );
        assert_eq!(bob, 1);
        let carol = sociacl_check(
            plane,
            c("read").as_ptr(),
            c("doc").as_ptr(),
            c("carol").as_ptr(),
            c("same-group").as_ptr(),
            reason.as_mut_ptr(),
            reason.len(),
        );
        assert_eq!(carol, 0);
        sociacl_plane_free(plane);
    }

    #[test]
    fn ffi_signed_attestation_is_a_factor() {
        let plane = sociacl_plane_new();
        assert_eq!(sociacl_add_person(plane, c("alice").as_ptr()), 0);
        assert_eq!(sociacl_add_person(plane, c("bob").as_ptr()), 0);
        assert_eq!(
            sociacl_add_object(plane, c("doc").as_ptr(), c("alice").as_ptr()),
            0
        );
        let mut reason = [0i8; 128];
        let unsigned = sociacl_check_ex(
            plane,
            c("read").as_ptr(),
            c("doc").as_ptr(),
            c("bob").as_ptr(),
            c("owner").as_ptr(),
            c("identity-live").as_ptr(),
            ptr::null(),
            0,
            reason.as_mut_ptr(),
            reason.len(),
        );
        assert_eq!(unsigned, -1);

        let mut pk = [0u8; 32];
        let mut sk = [0u8; 32];
        assert_eq!(sociacl_issuer_keygen(pk.as_mut_ptr(), sk.as_mut_ptr()), 0);
        assert_eq!(
            sociacl_enroll(
                plane,
                c("bob").as_ptr(),
                c("principal").as_ptr(),
                ptr::null(),
                0
            ),
            -1
        );
        assert_eq!(
            sociacl_enroll(
                plane,
                c("bob").as_ptr(),
                c("principal").as_ptr(),
                pk.as_ptr(),
                pk.len()
            ),
            0
        );
        let mut sig = [0u8; 64];
        assert_eq!(
            sociacl_sign_claim(
                plane,
                sk.as_ptr(),
                sk.len(),
                c("bob").as_ptr(),
                c("bob").as_ptr(),
                c("identity-live").as_ptr(),
                c("doc").as_ptr(),
                sig.as_mut_ptr(),
                sig.len(),
            ),
            0
        );
        let allowed = sociacl_check_ex(
            plane,
            c("read").as_ptr(),
            c("doc").as_ptr(),
            c("bob").as_ptr(),
            c("owner").as_ptr(),
            c("identity-live").as_ptr(),
            sig.as_ptr(),
            sig.len(),
            reason.as_mut_ptr(),
            reason.len(),
        );
        assert_eq!(allowed, 0);
        sociacl_plane_free(plane);
    }

    #[test]
    fn ffi_client_check_remint_elect_closed() {
        let plane = sociacl_plane_new();
        assert_eq!(sociacl_add_person(plane, c("alice").as_ptr()), 0);
        assert_eq!(sociacl_add_person(plane, c("bob").as_ptr()), 0);
        assert_eq!(sociacl_add_person(plane, c("carol").as_ptr()), 0);
        assert_eq!(sociacl_add_group(plane, c("ops").as_ptr()), 0);
        assert_eq!(
            sociacl_add_object(plane, c("doc").as_ptr(), c("alice").as_ptr()),
            0
        );
        assert_eq!(
            sociacl_set_object_property(
                plane,
                c("doc").as_ptr(),
                c("predicate").as_ptr(),
                c("same-group").as_ptr()
            ),
            0
        );
        assert_eq!(
            sociacl_set_object_property(
                plane,
                c("doc").as_ptr(),
                c("group").as_ptr(),
                c("ops").as_ptr()
            ),
            0
        );
        for (from, to, rel) in [
            ("alice", "ops", "member-of"),
            ("bob", "ops", "member-of"),
            ("doc", "ops", "object-group"),
        ] {
            assert_eq!(
                sociacl_jointly_state(plane, c(from).as_ptr(), c(to).as_ptr(), c(rel).as_ptr()),
                0
            );
        }

        let mut reason = [0i8; 128];
        let live = sociacl_check(
            plane,
            c("read").as_ptr(),
            c("doc").as_ptr(),
            c("bob").as_ptr(),
            c("same-group").as_ptr(),
            reason.as_mut_ptr(),
            reason.len(),
        );
        assert_eq!(live, 1);

        let mut written = 0usize;
        assert_eq!(
            sociacl_export_bundle(
                plane,
                c("alice").as_ptr(),
                ptr::null_mut(),
                0,
                &mut written,
                reason.as_mut_ptr(),
                reason.len(),
            ),
            0
        );
        assert!(written > 0);
        let mut buf = vec![0u8; written];
        assert_eq!(
            sociacl_export_bundle(
                plane,
                c("alice").as_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &mut written,
                reason.as_mut_ptr(),
                reason.len(),
            ),
            0
        );

        let client = sociacl_client_open(buf.as_ptr(), written, reason.as_mut_ptr(), reason.len());
        assert!(!client.is_null());

        let alice = sociacl_client_check(
            client,
            c("read").as_ptr(),
            c("doc").as_ptr(),
            c("alice").as_ptr(),
            c("same-group").as_ptr(),
            reason.as_mut_ptr(),
            reason.len(),
        );
        assert_eq!(alice, 1);
        let carol = sociacl_client_check(
            client,
            c("read").as_ptr(),
            c("doc").as_ptr(),
            c("carol").as_ptr(),
            c("same-group").as_ptr(),
            reason.as_mut_ptr(),
            reason.len(),
        );
        assert_eq!(carol, 0);
        assert_eq!(
            sociacl_client_remint(
                client,
                c("doc").as_ptr(),
                c("bob").as_ptr(),
                reason.as_mut_ptr(),
                reason.len(),
            ),
            1
        );
        assert_eq!(
            sociacl_client_elect(client, c("doc").as_ptr(), reason.as_mut_ptr(), reason.len()),
            -1
        );
        let text = unsafe { CStr::from_ptr(reason.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        assert!(
            text.contains("refuses elect") || text.contains("silence"),
            "elect reason: {text}"
        );

        sociacl_client_free(client);
        sociacl_plane_free(plane);
    }
}
