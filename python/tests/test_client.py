"""Case C client Python binding tests. Requires `cargo build -p sociacl-c`."""

import tempfile
from pathlib import Path

from sociacl import Client, Error, Plane


def _group_plane() -> Plane:
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_person("carol")
    plane.add_group("ops")
    plane.add_object("doc", "alice")
    plane.set_object_property("doc", "predicate", "same-group")
    plane.set_object_property("doc", "group", "ops")
    plane.jointly_state("alice", "ops", "member-of")
    plane.jointly_state("bob", "ops", "member-of")
    plane.jointly_state("doc", "ops", "object-group")
    return plane


def test_client_check_remint_elect_from_bytes():
    plane = _group_plane()
    allowed, reason = plane.check("read", "doc", "bob", "same-group")
    assert allowed is True
    assert reason == "same-group"

    bundle = plane.export_bundle("alice")
    assert bundle.startswith(b"SACL")

    client = Client.from_bytes(bundle)
    allowed, reason = client.check("read", "doc", "alice", "same-group")
    assert allowed is True
    assert reason == "same-group"

    allowed, reason = client.check("read", "doc", "carol", "same-group")
    assert allowed is False
    assert reason == "same-group"

    assert client.remint("doc", "bob") == "remint"

    try:
        client.elect("doc")
        raise AssertionError("elect must fail closed")
    except Error as exc:
        text = str(exc)
        assert "elect" in text.lower() or "silence" in text.lower()

    allowed, reason = plane.check("read", "doc", "bob", "same-group")
    assert allowed is True
    client.close()
    plane.close()


def test_client_from_path_and_tampered_bytes():
    plane = _group_plane()
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "bundle.bin")
        plane.export_bundle_file("alice", path)
        client = Client.from_path(path)
        allowed, _ = client.check("read", "doc", "bob", "same-group")
        assert allowed is True
        client.close()

    tampered = bytearray(plane.export_bundle("alice"))
    tampered[len(tampered) // 2] ^= 0xFF
    try:
        Client.from_bytes(bytes(tampered))
        raise AssertionError("tampered bundle must be refused")
    except Error:
        pass
    plane.close()


if __name__ == "__main__":
    test_client_check_remint_elect_from_bytes()
    test_client_from_path_and_tampered_bytes()
    print("ok")
