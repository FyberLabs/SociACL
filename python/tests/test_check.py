"""Check-only Python binding tests. Requires `cargo build -p sociacl-c`."""

from sociacl import CheckError, Plane, issuer_keygen


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

    pk, sk = issuer_keygen()
    try:
        plane.check("read", "doc", "bob", "owner", attestation="identity-live")
        raise AssertionError("unsigned attestation must fail closed")
    except CheckError:
        pass

    try:
        plane.enroll("bob", "principal", b"")
        raise AssertionError("enroll without a key must fail closed")
    except CheckError:
        pass

    try:
        sig = plane.sign_claim(sk, "bob", "bob", "identity-live", "doc")
        plane.check(
            "read", "doc", "bob", "owner", attestation="identity-live", signature=sig
        )
        raise AssertionError("unenrolled attestation must fail closed")
    except CheckError:
        pass

    plane.enroll("bob", "principal", pk)
    sig = plane.sign_claim(sk, "bob", "bob", "identity-live", "doc")
    allowed, reason = plane.check(
        "read", "doc", "bob", "owner", attestation="identity-live", signature=sig
    )
    assert allowed is False
    assert reason == "owner"
    plane.close()


def test_attestation_does_not_mint_delegate():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_object("doc", "alice")
    plane.set_object_property("doc", "predicate", "delegate")
    pk, sk = issuer_keygen()
    plane.enroll("bob", "principal", pk)
    sig = plane.sign_claim(sk, "bob", "bob", "identity-live", "doc")
    allowed, reason = plane.check(
        "read", "doc", "bob", "delegate", attestation="identity-live", signature=sig
    )
    assert allowed is False
    assert reason == "delegate"
    allowed, reason = plane.check("read", "doc", "bob", "delegate")
    assert allowed is False
    plane.close()


def test_delegate_view_execute_without_view_cancel():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_object("doc", "alice")
    plane.set_object_property("doc", "predicate", "delegate")

    plane.delegate("alice", "bob", "doc", "read")
    allowed, reason = plane.check("read", "doc", "bob", "delegate")
    assert allowed is True
    assert reason == "delegate"
    allowed, reason = plane.check("execute", "doc", "bob", "delegate")
    assert allowed is False
    assert reason == "delegate"

    plane.undelegate("alice", "bob", "doc")
    allowed, reason = plane.check("read", "doc", "bob", "delegate")
    assert allowed is False

    plane.delegate("alice", "bob", "doc", "execute")
    allowed, reason = plane.check("execute", "doc", "bob", "delegate")
    assert allowed is True
    allowed, reason = plane.check("read", "doc", "bob", "delegate")
    assert allowed is False
    plane.close()


if __name__ == "__main__":
    test_three_node_posix_check()
    test_simple_check_and_attestation()
    test_attestation_does_not_mint_delegate()
    test_delegate_view_execute_without_view_cancel()
    print("ok")
