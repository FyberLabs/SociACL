"""Network membership Python binding tests. Requires `cargo build -p sociacl-c`."""

from sociacl import Error, Plane


def _mesh() -> Plane:
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_person("mallory")
    plane.add_network("panopticon")
    plane.add_object("panopticon", "alice")
    plane.set_object_property("panopticon", "predicate", "same-network")
    plane.admit_member("alice", "panopticon")
    plane.admit_member("bob", "panopticon")
    return plane


def test_same_network_membership():
    plane = _mesh()
    allowed, reason = plane.check("read", "panopticon", "bob", "same-network")
    assert allowed is True
    assert reason == "same-network"
    assert plane.is_member("bob", "panopticon") is True
    allowed, reason = plane.check("read", "panopticon", "mallory", "same-network")
    assert allowed is False
    assert plane.is_member("mallory", "panopticon") is False
    plane.close()


def test_owner_censure_drops_member():
    plane = _mesh()
    record = plane.censure("alice", "panopticon", "bob", "active-sabotage")
    assert "bob" in record
    assert "active-sabotage" in record
    allowed, _ = plane.check("read", "panopticon", "bob", "same-network")
    assert allowed is False
    assert plane.audit("panopticon")
    plane.close()


def test_member_cannot_censure_another():
    plane = _mesh()
    try:
        plane.censure("bob", "panopticon", "alice", "policy-violation")
        raise AssertionError("member must not censure another")
    except Error:
        pass
    assert plane.is_member("alice", "panopticon") is True
    plane.close()


def test_self_leave():
    plane = _mesh()
    plane.censure("bob", "panopticon", "bob", "self-leave")
    assert plane.is_member("bob", "panopticon") is False
    plane.close()


def test_one_sided_join_is_not_a_grant():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_network("mesh")
    plane.add_object("mesh", "alice")
    plane.set_object_property("mesh", "predicate", "same-network")
    plane.state_edge("bob", "bob", "mesh", "in-network")
    assert plane.is_member("bob", "mesh") is False
    allowed, _ = plane.check("read", "mesh", "bob", "same-network")
    assert allowed is False
    plane.close()


def test_owner_cannot_record_self_leave_for_another():
    plane = _mesh()
    try:
        plane.censure("alice", "panopticon", "bob", "self-leave")
        raise AssertionError("owner must not record self-leave for another")
    except Error:
        pass
    assert plane.is_member("bob", "panopticon") is True
    plane.close()


if __name__ == "__main__":
    test_same_network_membership()
    test_owner_censure_drops_member()
    test_member_cannot_censure_another()
    test_self_leave()
    test_one_sided_join_is_not_a_grant()
    test_owner_cannot_record_self_leave_for_another()
    print("ok")
