"""SociACL Python bindings. Live Check, Case C Client, Social Light hop, Gun hint."""

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
_LIB.sociacl_delegate.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_uint64,
]
_LIB.sociacl_delegate.restype = ctypes.c_int
_LIB.sociacl_undelegate.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_LIB.sociacl_undelegate.restype = ctypes.c_int
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
_LIB.sociacl_holder_keygen.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte),
]
_LIB.sociacl_holder_keygen.restype = ctypes.c_int
_LIB.sociacl_write_will.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_write_will.restype = ctypes.c_int
_LIB.sociacl_will.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_will.restype = ctypes.c_int
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
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_export_bundle_file.restype = ctypes.c_int
_LIB.sociacl_client_open.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_open.restype = ctypes.c_void_p
_LIB.sociacl_client_open_file.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
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
_LIB.sociacl_client_discover.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_discover.restype = ctypes.c_int
_LIB.sociacl_client_destroy.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_destroy.restype = ctypes.c_int
_LIB.sociacl_social_light_encode.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_social_light_encode.restype = ctypes.c_int
_LIB.sociacl_social_light_accept.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_social_light_accept.restype = ctypes.c_int
_LIB.sociacl_social_light_check.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_social_light_check.restype = ctypes.c_int
_LIB.sociacl_social_light_remint.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_social_light_remint.restype = ctypes.c_int
_LIB.sociacl_social_light_discover.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_social_light_discover.restype = ctypes.c_int
_LIB.sociacl_social_light_elect.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_social_light_elect.restype = ctypes.c_int
_LIB.sociacl_client_social_light_check.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_social_light_check.restype = ctypes.c_int
_LIB.sociacl_client_social_light_remint.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_social_light_remint.restype = ctypes.c_int
_LIB.sociacl_client_social_light_discover.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_social_light_discover.restype = ctypes.c_int
_LIB.sociacl_client_social_light_elect.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_client_social_light_elect.restype = ctypes.c_int
_LIB.sociacl_gun_hint_encode.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_gun_hint_encode.restype = ctypes.c_int
_LIB.sociacl_gun_hint_accept.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_gun_hint_accept.restype = ctypes.c_int
_LIB.sociacl_gun_check.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_gun_check.restype = ctypes.c_int
_LIB.sociacl_gun_remint.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_gun_remint.restype = ctypes.c_int
_LIB.sociacl_gun_cancel.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_LIB.sociacl_gun_cancel.restype = ctypes.c_int
_LIB.sociacl_gun_elect.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_gun_elect.restype = ctypes.c_int
_LIB.sociacl_gun_user_soul.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_gun_user_soul.restype = ctypes.c_int
_LIB.sociacl_gun_item_soul.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_gun_item_soul.restype = ctypes.c_int
_LIB.sociacl_gun_encode_key.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_gun_encode_key.restype = ctypes.c_int
_LIB.sociacl_gun_normalize_url.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_gun_normalize_url.restype = ctypes.c_int


VERIFY_KEY_LEN = 32
ISSUER_SECRET_LEN = 32
HOLDER_SECRET_LEN = 32
SIGNATURE_LEN = 64


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def issuer_keygen() -> Tuple[bytes, bytes]:
    pk = (ctypes.c_ubyte * VERIFY_KEY_LEN)()
    sk = (ctypes.c_ubyte * ISSUER_SECRET_LEN)()
    if _LIB.sociacl_issuer_keygen(pk, sk) != 0:
        raise Error("issuer_keygen failed")
    return bytes(pk), bytes(sk)


def holder_keygen() -> Tuple[bytes, bytes]:
    pk = (ctypes.c_ubyte * VERIFY_KEY_LEN)()
    sk = (ctypes.c_ubyte * HOLDER_SECRET_LEN)()
    if _LIB.sociacl_holder_keygen(pk, sk) != 0:
        raise Error("holder_keygen failed")
    return bytes(pk), bytes(sk)


def user_soul(wallet: str) -> str:
    buf = ctypes.create_string_buffer(_REASON_LEN)
    if _LIB.sociacl_gun_user_soul(_b(wallet), buf, _REASON_LEN) != 0:
        raise Error("user_soul failed")
    return buf.value.decode("utf-8", errors="replace")


def item_soul(id: str) -> str:
    buf = ctypes.create_string_buffer(_REASON_LEN)
    if _LIB.sociacl_gun_item_soul(_b(id), buf, _REASON_LEN) != 0:
        raise Error("item_soul failed")
    return buf.value.decode("utf-8", errors="replace")


def encode_key(id: str) -> str:
    buf = ctypes.create_string_buffer(_REASON_LEN)
    if _LIB.sociacl_gun_encode_key(_b(id), buf, _REASON_LEN) != 0:
        raise Error("encode_key failed")
    return buf.value.decode("utf-8", errors="replace")


def normalize_url(url: str) -> str:
    dst = ctypes.create_string_buffer(_REASON_LEN)
    reason = ctypes.create_string_buffer(_REASON_LEN)
    if _LIB.sociacl_gun_normalize_url(_b(url), dst, _REASON_LEN, reason, _REASON_LEN) != 0:
        raise Error(reason.value.decode("utf-8", errors="replace") or "invalid url")
    return dst.value.decode("utf-8", errors="replace")


def _secret_buf(secret: bytes):
    if not secret:
        raise Error("holder secret required to export or open a bundle")
    return (ctypes.c_ubyte * len(secret)).from_buffer_copy(secret)


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

    def delegate(
        self,
        owner: str,
        principal: str,
        object: str,
        actions: str,
        until: Optional[int] = None,
    ) -> None:
        tick = 0 if until is None else int(until)
        if (
            _LIB.sociacl_delegate(
                self._ptr, _b(owner), _b(principal), _b(object), _b(actions), tick
            )
            != 0
        ):
            raise CheckError(f"delegate {principal} {object}")

    def undelegate(self, owner: str, principal: str, object: str) -> None:
        if _LIB.sociacl_undelegate(self._ptr, _b(owner), _b(principal), _b(object)) != 0:
            raise CheckError(f"undelegate {principal} {object}")

    def write_will(self, src: str) -> None:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        if _LIB.sociacl_write_will(self._ptr, _b(src), reason, _REASON_LEN) != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "write_will failed")

    def will(self, object: str) -> str:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        written = ctypes.c_size_t(0)
        rc = _LIB.sociacl_will(
            self._ptr, _b(object), None, 0, ctypes.byref(written), reason, _REASON_LEN
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "will failed")
        buf = ctypes.create_string_buffer(written.value + 1)
        rc = _LIB.sociacl_will(
            self._ptr,
            _b(object),
            buf,
            written.value + 1,
            ctypes.byref(written),
            reason,
            _REASON_LEN,
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "will failed")
        return buf.value.decode("utf-8", errors="replace")

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

    def export_bundle(self, holder: str, secret: bytes) -> bytes:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        written = ctypes.c_size_t(0)
        sk = _secret_buf(secret)
        rc = _LIB.sociacl_export_bundle(
            self._ptr,
            _b(holder),
            sk,
            len(secret),
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
            sk,
            len(secret),
            buf,
            written.value,
            ctypes.byref(written),
            reason,
            _REASON_LEN,
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "export failed")
        return bytes(buf[: written.value])

    def encode_social_light(
        self,
        channel: str,
        secret: bytes,
        issuer: str,
        subject: str,
        claim: str,
        object: str,
        share_token: Optional[str] = None,
    ) -> bytes:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        written = ctypes.c_size_t(0)
        sk = (ctypes.c_ubyte * len(secret)).from_buffer_copy(secret)
        rc = _LIB.sociacl_social_light_encode(
            self._ptr,
            _b(channel),
            sk,
            len(secret),
            _b(issuer),
            _b(subject),
            _b(claim),
            _b(object),
            _b(share_token) if share_token is not None else None,
            None,
            0,
            ctypes.byref(written),
            reason,
            _REASON_LEN,
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "encode failed")
        buf = (ctypes.c_ubyte * written.value)()
        rc = _LIB.sociacl_social_light_encode(
            self._ptr,
            _b(channel),
            sk,
            len(secret),
            _b(issuer),
            _b(subject),
            _b(claim),
            _b(object),
            _b(share_token) if share_token is not None else None,
            buf,
            written.value,
            ctypes.byref(written),
            reason,
            _REASON_LEN,
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "encode failed")
        return bytes(buf[: written.value])

    def accept_social_light(self, frame: bytes) -> str:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        buf = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        rc = _LIB.sociacl_social_light_accept(
            self._ptr, buf, len(frame), reason, _REASON_LEN
        )
        text = reason.value.decode("utf-8", errors="replace")
        if rc != 0:
            raise Error(text or "accept failed")
        return text

    def check_social_light(
        self,
        action: str,
        object: str,
        accessor: str,
        frame: bytes,
        predicate: Optional[str] = None,
    ) -> Tuple[bool, str]:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        buf = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        rc = _LIB.sociacl_social_light_check(
            self._ptr,
            _b(action),
            _b(object),
            _b(accessor),
            _b(predicate) if predicate is not None else None,
            buf,
            len(frame),
            reason,
            _REASON_LEN,
        )
        text = reason.value.decode("utf-8", errors="replace")
        if rc < 0:
            raise CheckError(text or "check failed")
        return (rc == 1, text)

    def remint_social_light(self, object: str, principal: str, frame: bytes) -> str:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        buf = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        rc = _LIB.sociacl_social_light_remint(
            self._ptr, _b(object), _b(principal), buf, len(frame), reason, _REASON_LEN
        )
        text = reason.value.decode("utf-8", errors="replace")
        if rc != 1:
            raise Error(text or "remint failed")
        return text

    def discover_social_light(self, frame: bytes) -> str:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        buf = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        rc = _LIB.sociacl_social_light_discover(
            self._ptr, buf, len(frame), reason, _REASON_LEN
        )
        text = reason.value.decode("utf-8", errors="replace")
        if rc != 0:
            raise Error(text or "discover failed")
        return text

    def elect_social_light(self, object: str, frame: bytes) -> None:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        buf = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        _LIB.sociacl_social_light_elect(
            self._ptr, _b(object), buf, len(frame), reason, _REASON_LEN
        )
        text = reason.value.decode("utf-8", errors="replace")
        raise Error(text or "elect does not fire on an attestation")

    def encode_gun_hint(
        self,
        principal: str,
        target: str,
        verb: Optional[str] = None,
        context: Optional[str] = None,
    ) -> bytes:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        written = ctypes.c_size_t(0)
        rc = _LIB.sociacl_gun_hint_encode(
            _b(principal),
            _b(target),
            _b(verb) if verb is not None else None,
            _b(context) if context is not None else None,
            None,
            0,
            ctypes.byref(written),
            reason,
            _REASON_LEN,
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "encode failed")
        buf = (ctypes.c_ubyte * written.value)()
        rc = _LIB.sociacl_gun_hint_encode(
            _b(principal),
            _b(target),
            _b(verb) if verb is not None else None,
            _b(context) if context is not None else None,
            buf,
            written.value,
            ctypes.byref(written),
            reason,
            _REASON_LEN,
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "encode failed")
        return bytes(buf[: written.value])

    def accept_gun_hint(self, hint: bytes) -> str:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        buf = (ctypes.c_ubyte * len(hint)).from_buffer_copy(hint)
        rc = _LIB.sociacl_gun_hint_accept(buf, len(hint), reason, _REASON_LEN)
        text = reason.value.decode("utf-8", errors="replace")
        if rc != 0:
            raise Error(text or "accept failed")
        return text

    def check_gun(
        self,
        action: str,
        claim: str,
        accessor: str,
        hint: Optional[bytes] = None,
        hop: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        hint_ptr = None
        hint_len = 0
        if hint is not None:
            hint_buf = (ctypes.c_ubyte * len(hint)).from_buffer_copy(hint)
            hint_ptr = hint_buf
            hint_len = len(hint)
        hop_ptr = None
        hop_len = 0
        if hop is not None:
            hop_buf = (ctypes.c_ubyte * len(hop)).from_buffer_copy(hop)
            hop_ptr = hop_buf
            hop_len = len(hop)
        rc = _LIB.sociacl_gun_check(
            self._ptr,
            _b(action),
            _b(claim),
            _b(accessor),
            hint_ptr,
            hint_len,
            hop_ptr,
            hop_len,
            reason,
            _REASON_LEN,
        )
        text = reason.value.decode("utf-8", errors="replace")
        if rc < 0:
            raise CheckError(text or "check failed")
        return (rc == 1, text)

    def remint_gun(self, claim: str, principal: str) -> str:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        rc = _LIB.sociacl_gun_remint(
            self._ptr, _b(claim), _b(principal), reason, _REASON_LEN
        )
        text = reason.value.decode("utf-8", errors="replace")
        if rc != 1:
            raise Error(text or "remint failed")
        return text

    def cancel_gun(self, owner: str, principal: str, claim: str) -> None:
        if _LIB.sociacl_gun_cancel(self._ptr, _b(owner), _b(principal), _b(claim)) != 0:
            raise CheckError(f"cancel {principal} {claim}")

    def elect_gun(self, claim: str, hint: bytes) -> None:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        buf = (ctypes.c_ubyte * len(hint)).from_buffer_copy(hint)
        _LIB.sociacl_gun_elect(
            self._ptr, _b(claim), buf, len(hint), reason, _REASON_LEN
        )
        text = reason.value.decode("utf-8", errors="replace")
        raise Error(text or "elect does not fire on a handoff hint")

    def export_bundle_file(self, holder: str, path: str, secret: bytes) -> None:
        reason = ctypes.create_string_buffer(_REASON_LEN)
        sk = _secret_buf(secret)
        rc = _LIB.sociacl_export_bundle_file(
            self._ptr, _b(holder), _b(path), sk, len(secret), reason, _REASON_LEN
        )
        if rc != 0:
            raise Error(reason.value.decode("utf-8", errors="replace") or "export failed")


class Client:
    def __init__(self, ptr: int) -> None:
        if not ptr:
            raise Error("sociacl_client_open failed")
        self._ptr = ptr

    @classmethod
    def from_bytes(cls, data: bytes, secret: bytes) -> "Client":
        reason = ctypes.create_string_buffer(_REASON_LEN)
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        sk = _secret_buf(secret)
        ptr = _LIB.sociacl_client_open(buf, len(data), sk, len(secret), reason, _REASON_LEN)
        if not ptr:
            raise Error(reason.value.decode("utf-8", errors="replace") or "open failed")
        return cls(ptr)

    @classmethod
    def from_path(cls, path: str, secret: bytes) -> "Client":
        reason = ctypes.create_string_buffer(_REASON_LEN)
        sk = _secret_buf(secret)
        ptr = _LIB.sociacl_client_open_file(_b(path), sk, len(secret), reason, _REASON_LEN)
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

    def discover(self, object: str) -> str:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        rc = _LIB.sociacl_client_discover(self._ptr, _b(object), buf, _REASON_LEN)
        reason = buf.value.decode("utf-8", errors="replace")
        if rc != 0:
            raise Error(reason or "discover failed")
        return reason

    def check_social_light(
        self,
        action: str,
        object: str,
        accessor: str,
        frame: bytes,
        predicate: Optional[str] = None,
    ) -> Tuple[bool, str]:
        buf_reason = ctypes.create_string_buffer(_REASON_LEN)
        frame_buf = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        rc = _LIB.sociacl_client_social_light_check(
            self._ptr,
            _b(action),
            _b(object),
            _b(accessor),
            _b(predicate) if predicate is not None else None,
            frame_buf,
            len(frame),
            buf_reason,
            _REASON_LEN,
        )
        reason = buf_reason.value.decode("utf-8", errors="replace")
        if rc < 0:
            raise CheckError(reason or "check failed")
        return (rc == 1, reason)

    def remint_social_light(self, object: str, principal: str, frame: bytes) -> str:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        frame_buf = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        rc = _LIB.sociacl_client_social_light_remint(
            self._ptr,
            _b(object),
            _b(principal),
            frame_buf,
            len(frame),
            buf,
            _REASON_LEN,
        )
        reason = buf.value.decode("utf-8", errors="replace")
        if rc != 1:
            raise Error(reason or "remint failed")
        return reason

    def discover_social_light(self, frame: bytes) -> str:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        frame_buf = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        rc = _LIB.sociacl_client_social_light_discover(
            self._ptr, frame_buf, len(frame), buf, _REASON_LEN
        )
        reason = buf.value.decode("utf-8", errors="replace")
        if rc != 0:
            raise Error(reason or "discover failed")
        return reason

    def elect_social_light(self, object: str, frame: bytes) -> None:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        frame_buf = (ctypes.c_ubyte * len(frame)).from_buffer_copy(frame)
        _LIB.sociacl_client_social_light_elect(
            self._ptr, _b(object), frame_buf, len(frame), buf, _REASON_LEN
        )
        reason = buf.value.decode("utf-8", errors="replace")
        raise Error(reason or "elect does not fire on an attestation")

    def destroy(self, object: str) -> str:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        rc = _LIB.sociacl_client_destroy(self._ptr, _b(object), buf, _REASON_LEN)
        reason = buf.value.decode("utf-8", errors="replace")
        if rc != 1:
            raise Error(reason or "destroy failed")
        return reason
