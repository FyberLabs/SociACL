"""Gun adapter Python binding tests. Requires `cargo build -p sociacl-c`."""

from sociacl import Error, Plane, encode_key, item_soul, normalize_url, user_soul


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


def test_feed_item_checks_the_same_as_a_claim():
    assert encode_key("rss3:act/1#x") == "rss3:act/1_x"
    object_id = item_soul("rss3:act/1#x")
    assert object_id == "s3rch/items/rss3:act/1_x"
    plane = Plane()
    alice = user_soul("0xalice")
    bob = user_soul("0xbob")
    plane.add_person(alice)
    plane.add_person(bob)
    plane.add_object(object_id, alice)
    plane.set_object_property(object_id, "predicate", "delegate")
    hint = plane.encode_gun_hint(
        bob, object_id, verb="see", context="https://gi.rss3.io/decentralized/0xalice"
    )
    allowed, _ = plane.check_gun("see", object_id, bob, hint=hint)
    assert allowed is False
    plane.delegate(alice, bob, object_id, "read")
    allowed, reason = plane.check_gun("see", object_id, bob, hint=hint)
    assert allowed is True
    assert reason == "delegate"
    allowed, _ = plane.check_see_grant(object_id, bob, 40, 80, object_id, bob)
    assert allowed is False, "from window denies at now=0"
    allowed, _ = plane.check_see_grant(object_id, bob, 0, 80, object_id, bob)
    assert allowed is True
    plane.close()
