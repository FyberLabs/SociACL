"""SociACL Python bindings. Live Check plus Case C Client via the C FFI."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Optional, Tuple

_REASON_LEN = 256


def _lib_candidates() -> list[Path]:
    here = Path(__file__).resolve()
    root = here.parents[2]
    names = (
        "libsociacl.so",
        "libsociacl.dylib",
        "sociacl.dll",
    )
    dirs = [
        root / "target" / "debug",
        root / "target" / "release",
        Path(os.environ["SOCIACL_LIB_DIR"]) if "SOCIACL_LIB_DIR" in os.environ else None,
    ]
    out: list[Path] = []
    for directory in dirs:
        if directory is None:
            continue
        for name in names:
            out.append(directory / name)
    return out


def _load_lib() -> ctypes.CDLL:
    last: Optional[OSError] = None
    for path in _lib_candidates():
        if not path.exists():
            continue
        try:
            return ctypes.CDLL(str(path))
        except OSError as exc:
            last = exc
    raise OSError(
        "libsociacl not found; run `cargo build -p sociacl-c`. "
        f"last error: {last}"
    )


_LIB = _load_lib()
_LIB.sociacl_plane_new.restype = ctypes.c_void_p
_LIB.sociacl_plane_free.argtypes = [ctypes.c_void_p]
_LIB.sociacl_add_person.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_LIB.sociacl_add_agent.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_LIB.sociacl_add_device.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_LIB.sociacl_add_group.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_LIB.sociacl_add_circle.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_LIB.sociacl_add_object.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
_LIB.sociacl_set_object_property.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_LIB.sociacl_state_edge.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_LIB.sociacl_jointly_state.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_LIB.sociacl_enroll.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
]
_LIB.sociacl_issuer_keygen.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte),
]
_LIB.sociacl_issuer_keygen.restype = ctypes.c_int
_LIB.sociacl_sign_claim.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
]
_LIB.sociacl_sign_claim.restype = ctypes.c_int
_LIB.sociacl_check.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_check.restype = ctypes.c_int
_LIB.sociacl_check_ex.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_check_ex.restype = ctypes.c_int
_LIB.sociacl_export_bundle.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_export_bundle.restype = ctypes.c_int
_LIB.sociacl_export_bundle_file.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_export_bundle_file.restype = ctypes.c_int
_LIB.sociacl_client_open.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_open.restype = ctypes.c_void_p
_LIB.sociacl_client_open_file.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_open_file.restype = ctypes.c_void_p
_LIB.sociacl_client_free.argtypes = [ctypes.c_void_p]
_LIB.sociacl_client_check.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_check.restype = ctypes.c_int
_LIB.sociacl_client_remint.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_remint.restype = ctypes.c_int
_LIB.sociacl_client_elect.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_elect.restype = ctypes.c_int


VERIFY_KEY_LEN = 32
ISSUER_SECRET_LEN = 32
SIGNATURE_LEN = 64


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def issuer_keygen() -> Tuple[bytes, bytes]:
    pk = (ctypes.c_ubyte * VERIFY_KEY_LEN)()
    sk = (ctypes.c_ubyte * ISSUER_SECRET_LEN)()
    if _LIB.sociacl_issuer_keygen(pk, sk) != 0:
        raise Error("issuer_keygen failed")
    return bytes(pk), bytes(sk)


class Error(Exception):
    pass


class CheckError(Error):
    pass


class Plane:
    def __init__(self) -> None:
        ptr = _LIB.sociacl_plane_new()
        if not ptr:
            raise CheckError("sociacl_plane_new failed")
        self._ptr = ptr

    def close(self) -> None:
        if getattr(self, "_ptr", None):
            _LIB.sociacl_plane_free(self._ptr)
            self._ptr = None

    def __del__(self) -> None:
        self.close()

    def add_person(self, id: str) -> None:
        if _LIB.sociacl_add_person(self._ptr, _b(id)) != 0:
            raise CheckError(f"add_person {id}")

    def add_agent(self, id: str) -> None:
        if _LIB.sociacl_add_agent(self._ptr, _b(id)) != 0:
            raise CheckError(f"add_agent {id}")

    def add_device(self, id: str) -> None:
        if _LIB.sociacl_add_device(self._ptr, _b(id)) != 0:
            raise CheckError(f"add_device {id}")

    def add_group(self, id: str) -> None:
        if _LIB.sociacl_add_group(self._ptr, _b(id)) != 0:
            raise CheckError(f"add_group {id}")

    def add_circle(self, id: str) -> None:
        if _LIB.sociacl_add_circle(self._ptr, _b(id)) != 0:
            raise CheckError(f"add_circle {id}")

    def add_object(self, id: str, owner: str) -> None:
        if _LIB.sociacl_add_object(self._ptr, _b(id), _b(owner)) != 0:
            raise CheckError(f"add_object {id}")

    def set_object_property(self, object: str, key: str, value: str) -> None:
        if _LIB.sociacl_set_object_property(self._ptr, _b(object), _b(key), _b(value)) != 0:
            raise CheckError(f"set_object_property {object} {key}")

    def state_edge(self, speaker: str, frm: str, to: str, relation: str) -> None:
        if _LIB.sociacl_state_edge(self._ptr, _b(speaker), _b(frm), _b(to), _b(relation)) != 0:
            raise CheckError(f"state_edge {relation}")

    def jointly_state(self, frm: str, to: str, relation: str) -> None:
        if _LIB.sociacl_jointly_state(self._ptr, _b(frm), _b(to), _b(relation)) != 0:
            raise CheckError(f"jointly_state {relation}")

    def enroll(self, issuer: str, kind: str, public_key: bytes) -> None:
        if not public_key:
            raise CheckError(f"enroll {issuer} {kind} requires a public key")
        pk = (ctypes.c_ubyte * len(public_key)).from_buffer_copy(public_key)
        if _LIB.sociacl_enroll(self._ptr, _b(issuer), _b(kind), pk, len(public_key)) != 0:
            raise CheckError(f"enroll {issuer} {kind}")

    def sign_claim(
        self, secret: bytes, issuer: str, subject: str, claim: str, object: str
    ) -> bytes:
        sk = (ctypes.c_ubyte * len(secret)).from_buffer_copy(secret)
        sig = (ctypes.c_ubyte * SIGNATURE_LEN)()
        rc = _LIB.sociacl_sign_claim(
            self._ptr,
            sk,
            len(secret),
            _b(issuer),
            _b(subject),
            _b(claim),
            _b(object),
            sig,
            SIGNATURE_LEN,
        )
        if rc != 0:
            raise Error("sign_claim failed")
        return bytes(sig)

    def check(
        self,
        action: str,
        object: str,
        accessor: str,
        predicate: Optional[str] = None,
        attestation: Optional[str] = None,
        signature: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        if predicate is None or attestation is not None:
            sig_ptr = None
            sig_len = 0
            if signature is not None:
                sig_buf = (ctypes.c_ubyte * len(signature)).from_buffer_copy(signature)
                sig_ptr = sig_buf
                sig_len = len(signature)
            rc = _LIB.sociacl_check_ex(
                self._ptr,
                _b(action),
                _b(object),
                _b(accessor),
                _b(predicate) if predicate is not None else None,
                _b(attestation) if attestation is not None else None,
                sig_ptr,
                sig_len,
                buf,
                _REASON_LEN,
            )
        else:
            rc = _LIB.sociacl_check(
                self._ptr,
                _b(action),
                _b(object),
                _b(accessor),
                _b(predicate),
                buf,
                _REASON_LEN,
            )
        reason = buf.value.decode("utf-8", errors="replace")
        if rc < 0:
            raise CheckError(reason or "check failed")
        return (rc == 1, reason)

    def export_bundle(self, holder: str) -> bytes:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        written = ctypes.c_size_t(0)
        rc = _LIB.sociacl_export_bundle(
            self._ptr,
            _b(holder),
            None,
            0,
            ctypes.byref(written),
            reason,
            _REASON_LEN,
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "export failed")
        buf = (ctypes.c_ubyte * written.value)()
        rc = _LIB.sociacl_export_bundle(
            self._ptr,
            _b(holder),
            buf,
            written.value,
            ctypes.byref(written),
            reason,
            _REASON_LEN,
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "export failed")
        return bytes(buf[: written.value])

    def export_bundle_file(self, holder: str, path: str) -> None:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        rc = _LIB.sociacl_export_bundle_file(
            self._ptr, _b(holder), _b(path), reason, _REASON_LEN
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "export failed")


class Client:
    def __init__(self, ptr: int) -> None:
        if not ptr:
            raise Error("sociacl_client_open failed")
        self._ptr = ptr

    @classmethod
    def from_bytes(cls, data: bytes) -> "Client":
        reason = ctypes.create_string_buffer(_REASON_LEN)
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        ptr = _LIB.sociacl_client_open(buf, len(data), reason, _REASON_LEN)
        if not ptr:
            raise Error(reason.value.decode("utf-8", errors="replace") or "open failed")
        return cls(ptr)

    @classmethod
    def from_path(cls, path: str) -> "Client":
        reason = ctypes.create_string_buffer(_REASON_LEN)
        ptr = _LIB.sociacl_client_open_file(_b(path), reason, _REASON_LEN)
        if not ptr:
            raise Error(reason.value.decode("utf-8", errors="replace") or "open failed")
        return cls(ptr)

    def close(self) -> None:
        if getattr(self, "_ptr", None):
            _LIB.sociacl_client_free(self._ptr)
            self._ptr = None

    def __del__(self) -> None:
        self.close()

    def check(
        self,
        action: str,
        object: str,
        accessor: str,
        predicate: str,
    ) -> Tuple[bool, str]:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        rc = _LIB.sociacl_client_check(
            self._ptr,
            _b(action),
            _b(object),
            _b(accessor),
            _b(predicate),
            buf,
            _REASON_LEN,
        )
        reason = buf.value.decode("utf-8", errors="replace")
        if rc < 0:
            raise CheckError(reason or "check failed")
        return (rc == 1, reason)

    def remint(self, object: str, principal: str) -> str:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        rc = _LIB.sociacl_client_remint(
            self._ptr, _b(object), _b(principal), buf, _REASON_LEN
        )
        reason = buf.value.decode("utf-8", errors="replace")
        if rc != 1:
            raise Error(reason or "remint failed")
        return reason

    def elect(self, object: str) -> None:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        _LIB.sociacl_client_elect(self._ptr, _b(object), buf, _REASON_LEN)
        reason = buf.value.decode("utf-8", errors="replace")
        raise Error(reason or "client path refuses elect")
