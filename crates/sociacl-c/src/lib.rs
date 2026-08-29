//! C FFI wrapping SociACL Check only.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::Mutex;

use sociacl_core::{Attestation, CheckRequest, Plane, PredicateId, Relation};

#[allow(non_camel_case_types)]
pub struct sociacl_plane {
    inner: Mutex<Plane>,
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
    reason_out: *mut c_char,
    reason_len: usize,
) -> c_int {
    let (Some(action), Some(object), Some(accessor)) = (cstr(action), cstr(object), cstr(accessor))
    else {
        write_reason(reason_out, reason_len, "invalid-argument");
        return -1;
    };
    let predicate = cstr(predicate).map(PredicateId::new);
    let attestation = cstr(attestation).map(|statement| Attestation {
        principal: accessor.into(),
        statement: statement.to_string(),
        signed_at: sociacl_core::Timestamp(0),
    });
    with_plane(plane, |p| {
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
}
