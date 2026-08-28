"""Check-only Python binding tests. Requires `cargo build -p sociacl-c`."""

from sociacl import Plane


def test_three_node_group_check():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_person("carol")
    plane.add_group("ops")
    plane.add_object("doc", "alice")
    plane.jointly_state("alice", "ops", "member-of")
    plane.jointly_state("bob", "ops", "member-of")
    plane.jointly_state("doc", "ops", "object-group")

    allowed, reason = plane.check("read", "doc", "bob", "same-group")
    assert allowed is True
    assert reason == "same-group"

    allowed, reason = plane.check("read", "doc", "carol", "same-group")
    assert allowed is False
    assert reason == "same-group"

    allowed, reason = plane.check("read", "doc", "alice", "owner")
    assert allowed is True
    assert reason == "owner"
    plane.close()


if __name__ == "__main__":
    test_three_node_group_check()
    print("ok")
