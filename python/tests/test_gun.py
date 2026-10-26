"""Gun adapter Python binding tests. Requires `cargo build -p sociacl-c`."""

import json
from pathlib import Path

from sociacl import Error, Plane, normalize_url

STRICT_ID = json.loads(
    (Path(__file__).resolve().parents[2] / "vectors" / "mesh" / "strict-id.json").read_text()
)


def test_url_leaf_is_not_a_node():
    assert normalize_url("https://Example.COM/item/1/#x") == "https://example.com/item/1"
    try:
        normalize_url("s3rch/users/0xalice")
        raise AssertionError("a soul is not a URL leaf")
    except Error:
        pass


def test_normalize_url_vectors():
    for row in STRICT_ID["urls"]:
        if row.get("dstLen") is not None:
            continue
        if row["ok"]:
            assert normalize_url(row["url"]) == row["normalized"], row["name"]
        else:
            try:
                normalize_url(row["url"])
            except Error as exc:
                assert str(exc) == row["reason"], row["name"]
            else:
                raise AssertionError(row["name"])


def test_gun_transport_has_no_unsigned_authority():
    from sociacl import _LIB

    for name in ("check_gun", "check_see_grant", "remint_gun", "cancel_gun", "elect_gun"):
        assert not hasattr(Plane, name), name
    for name in ("check", "check_see_grant", "remint", "cancel", "elect"):
        assert not hasattr(_LIB, "sociacl_gun_" + name), name
    plane = Plane()
    try:
        hint = plane.encode_gun_hint("untrusted-principal", "untrusted-target", verb="see")
        assert hint.startswith(b"SGH1")
        assert "untrusted-principal" in plane.accept_gun_hint(hint)
        try:
            plane.accept_gun_hint(b"bad")
        except Error:
            pass
        else:
            raise AssertionError("corrupt hint accepted")
    finally:
        plane.close()


if __name__ == "__main__":
    test_gun_transport_has_no_unsigned_authority()
    test_url_leaf_is_not_a_node()
    test_normalize_url_vectors()
    print("ok")
