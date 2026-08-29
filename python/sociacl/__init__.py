"""SociACL Python bindings. Check only, via the C FFI."""

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
    ctypes.c_char_p,
    ctypes.c_size_t,
]
_LIB.sociacl_check_ex.restype = ctypes.c_int


def _b(s: str) -> bytes:
    return s.encode("utf-8")


class CheckError(Exception):
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

    def check(
        self,
        action: str,
        object: str,
        accessor: str,
        predicate: Optional[str] = None,
        attestation: Optional[str] = None,
    ) -> Tuple[bool, str]:
        buf = ctypes.create_string_buffer(_REASON_LEN)
        if predicate is None or attestation is not None:
            rc = _LIB.sociacl_check_ex(
                self._ptr,
                _b(action),
                _b(object),
                _b(accessor),
                _b(predicate) if predicate is not None else None,
                _b(attestation) if attestation is not None else None,
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
