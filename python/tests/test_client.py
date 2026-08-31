"""Case C client Python binding tests. Requires `cargo build -p sociacl-c`."""

import tempfile
from pathlib import Path

from sociacl import Client, Error, Plane, holder_keygen


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

    _, secret = holder_keygen()
    bundle = plane.export_bundle("alice", secret)
    assert bundle.startswith(b"SACL")

    client = Client.from_bytes(bundle, secret)
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
    _, secret = holder_keygen()
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "bundle.bin")
        plane.export_bundle_file("alice", path, secret)
        client = Client.from_path(path, secret)
        allowed, _ = client.check("read", "doc", "bob", "same-group")
        assert allowed is True
        client.close()

    tampered = bytearray(plane.export_bundle("alice", secret))
    tampered[len(tampered) // 2] ^= 0xFF
    try:
        Client.from_bytes(bytes(tampered), secret)
        raise AssertionError("tampered bundle must be refused")
    except Error:
        pass

    _, other = holder_keygen()
    bundle = plane.export_bundle("alice", secret)
    try:
        Client.from_bytes(bundle, other)
        raise AssertionError("wrong holder secret must be refused")
    except Error:
        pass
    plane.close()


def test_will_discover_destroy():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_object("doc", "alice")
    plane.write_will(
        "will desk for object doc\nwritten-by alice\ndiscover heir bob\n"
    )
    src = plane.will("doc")
    assert "discover heir bob" in src

    _, secret = holder_keygen()
    client = Client.from_bytes(plane.export_bundle("alice", secret), secret)
    assert client.discover("doc") == "heir bob"
    try:
        client.destroy("doc")
        raise AssertionError("heir will must not destroy")
    except Error:
        pass
    try:
        client.elect("doc")
        raise AssertionError("elect must fail closed")
    except Error:
        pass
    allowed, _ = client.check("read", "doc", "alice", "owner")
    assert allowed is True
    client.close()
    plane.close()

    plane = Plane()
    plane.add_person("alice")
    plane.add_object("doc", "alice")
    plane.write_will(
        "will hush for object doc\nwritten-by alice\ndestroy if-no-heir keys\n"
    )
    _, secret = holder_keygen()
    client = Client.from_bytes(plane.export_bundle("alice", secret), secret)
    assert client.discover("doc") == "stay-secret"
    assert client.destroy("doc") == "destroy"
    try:
        client.elect("doc")
        raise AssertionError("elect must fail closed after destroy")
    except Error:
        pass
    client.close()
    plane.close()


def test_client_precut_delegate_remint_elect_closed():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_object("doc", "alice")
    plane.set_object_property("doc", "predicate", "delegate")
    plane.delegate("alice", "bob", "doc", "execute")

    _, secret = holder_keygen()
    client = Client.from_bytes(plane.export_bundle("bob", secret), secret)
    allowed, reason = client.check("execute", "doc", "bob", "delegate")
    assert allowed is True
    assert reason == "delegate"
    allowed, reason = client.check("read", "doc", "bob", "delegate")
    assert allowed is False
    assert client.remint("doc", "bob") == "remint"
    try:
        client.elect("doc")
        raise AssertionError("elect from a delegate grant must fail closed")
    except Error as exc:
        text = str(exc)
        assert "elect" in text.lower() or "silence" in text.lower()
    client.close()
    plane.close()


if __name__ == "__main__":
    test_client_check_remint_elect_from_bytes()
    test_client_from_path_and_tampered_bytes()
    test_will_discover_destroy()
    test_client_precut_delegate_remint_elect_closed()
    print("ok")
