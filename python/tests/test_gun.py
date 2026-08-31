"""Gun adapter Python binding tests. Requires `cargo build -p sociacl-c`."""

from sociacl import Error, Plane, normalize_url, user_soul


def test_hint_is_not_a_grant_dest_check_is():
    plane = Plane()
    alice = user_soul("0xalice")
    bob = user_soul("0xbob")
    assert alice == "s3rch/users/0xalice"
    plane.add_person(alice)
    plane.add_person(bob)
    plane.add_object("claim-1", alice)
    plane.set_object_property("claim-1", "predicate", "delegate")

    hint = plane.encode_gun_hint(bob, "claim-1", verb="see")
    assert hint.startswith(b"SGH1")
    assert "0xbob" in plane.accept_gun_hint(hint) or "s3rch/users/0xbob" in plane.accept_gun_hint(
        hint
    )

    allowed, reason = plane.check_gun("see", "claim-1", bob, hint=hint)
    assert allowed is False
    assert reason == "delegate"

    plane.delegate(alice, bob, "claim-1", "read")
    allowed, reason = plane.check_gun("see", "claim-1", bob, hint=hint)
    assert allowed is True
    assert reason == "delegate"

    try:
        plane.elect_gun("claim-1", hint)
        raise AssertionError("elect from a hint must fail")
    except Error as exc:
        assert "hint" in str(exc).lower() or "elect" in str(exc).lower()

    plane.cancel_gun(alice, bob, "claim-1")
    allowed, _ = plane.check_gun("see", "claim-1", bob)
    assert allowed is False

    plane.delegate(alice, bob, "claim-1", "x")
    allowed, _ = plane.check_gun("execute", "claim-1", bob)
    assert allowed is True
    allowed, _ = plane.check_gun("see", "claim-1", bob)
    assert allowed is False
    plane.close()


def test_url_leaf_is_not_a_node():
    assert normalize_url("https://Example.COM/item/1/#x") == "https://example.com/item/1"
    try:
        normalize_url("s3rch/users/0xalice")
        raise AssertionError("a soul is not a URL leaf")
    except Error:
        pass
