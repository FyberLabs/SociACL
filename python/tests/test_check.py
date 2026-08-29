"""Check-only Python binding tests. Requires `cargo build -p sociacl-c`."""

from sociacl import CheckError, Plane


def test_three_node_posix_check():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_person("carol")
    plane.add_group("ops")
    plane.add_object("doc", "alice")
    plane.set_object_property("doc", "predicate", "posix-mode")
    plane.set_object_property("doc", "group", "ops")
    plane.set_object_property("doc", "mode", "0640")
    plane.jointly_state("bob", "ops", "member-of")

    allowed, reason = plane.check("read", "doc", "bob", "posix-mode")
    assert allowed is True
    assert reason == "posix-mode"

    allowed, reason = plane.check("read", "doc", "carol", "posix-mode")
    assert allowed is False
    assert reason == "posix-mode"

    allowed, reason = plane.check("read", "doc", "alice", "posix-mode")
    assert allowed is True
    assert reason == "posix-mode"
    plane.close()


def test_simple_check_and_attestation():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_object("doc", "alice")

    allowed, reason = plane.check("read", "doc", "alice", "owner")
    assert allowed is True
    assert reason == "owner"

    try:
        plane.check("read", "doc", "bob", "owner", attestation="identity-live")
        raise AssertionError("unenrolled attestation must fail closed")
    except CheckError:
        pass

    plane.enroll("bob", "principal")
    allowed, reason = plane.check(
        "read", "doc", "bob", "owner", attestation="identity-live"
    )
    assert allowed is False
    assert reason == "owner"
    plane.close()


if __name__ == "__main__":
    test_three_node_posix_check()
    test_simple_check_and_attestation()
    print("ok")
