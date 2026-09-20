"""Live-plane verb Python binding tests. Requires `cargo build -p sociacl-c`.

These are the same laws as Rust: keep-operating refuses Elect, the Elect
clock is a wait (not a fire), and a live canceler can stop a pending
ceremony before commit.
"""

from sociacl import Error, Plane

HEIR_WILL = (
    "will heir-doc for object doc\n"
    "written-by alice\n"
    "cancelable-by executor\n"
    "discover heir bob\n"
)


def test_remint_discover_destroy():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_person("executor")
    plane.add_group("ops")
    plane.add_object("doc", "alice")
    plane.set_object_property("doc", "predicate", "same-group")
    plane.set_object_property("doc", "group", "ops")
    plane.jointly_state("bob", "ops", "member-of")
    plane.jointly_state("doc", "ops", "object-group")

    assert plane.remint("doc", "bob") == "remint"

    plane.write_will(
        "will secret for object doc\nwritten-by alice\ndestroy if-no-heir keys\n"
    )
    assert plane.discover("doc") == "stay-secret"
    try:
        plane.elect("doc")
        raise AssertionError("stay-secret elect must fail")
    except Error:
        pass
    assert plane.destroy("doc") == "destroy"
    plane.close()


def test_elect_refuses_while_keep_operating():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_person("executor")
    plane.add_object("doc", "alice")
    plane.write_will(
        "will heir-doc for object doc\nwritten-by alice\ncancelable-by executor\n"
        "discover heir bob\n"
    )
    try:
        plane.elect("doc")
        raise AssertionError("live owner must refuse elect")
    except Error as exc:
        assert "keep-operating" in str(exc).lower() or "suffice" in str(exc).lower()
    plane.close()


def test_elect_is_pending_until_commit_after_wait():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_person("executor")
    plane.add_object("doc", "alice")
    plane.write_will(HEIR_WILL)
    plane.set_authn("alice", "gone")

    assert plane.elect("doc") == "pending bob"
    allowed, _ = plane.check("read", "doc", "bob", "owner")
    assert allowed is False
    try:
        plane.commit_elect("doc")
        raise AssertionError("commit before the Elect wait must fail")
    except Error as exc:
        assert "wait" in str(exc).lower() or "elapsed" in str(exc).lower()

    plane.set_now(plane.now() + 10)
    assert plane.commit_elect("doc") == "installed bob"
    allowed, reason = plane.check("read", "doc", "bob", "owner")
    assert allowed is True
    assert reason == "owner"
    plane.close()


def test_live_canceler_stops_pending_elect():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_person("executor")
    plane.add_object("doc", "alice")
    plane.write_will(HEIR_WILL)
    plane.set_authn("alice", "gone")
    plane.elect("doc")
    assert plane.cancel_will("doc", "executor") == "canceled"
    plane.set_now(plane.now() + 10)
    try:
        plane.commit_elect("doc")
        raise AssertionError("canceled will must not install")
    except Error:
        pass
    allowed, _ = plane.check("read", "doc", "alice", "owner")
    assert allowed is True
    plane.close()


def test_privilege_up_waits_unstate_is_immediate():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_group("ops")
    plane.add_object("doc", "alice")
    plane.set_object_property("doc", "predicate", "same-group")
    plane.set_object_property("doc", "group", "ops")
    plane.state_edge("bob", "bob", "ops", "member-of")
    allowed, _ = plane.check("read", "doc", "bob", "same-group")
    assert allowed is False
    plane.state_edge("ops", "bob", "ops", "member-of")
    allowed, _ = plane.check("read", "doc", "bob", "same-group")
    assert allowed is False
    plane.set_now(plane.now() + 1)
    allowed, _ = plane.check("read", "doc", "bob", "same-group")
    assert allowed is True
    plane.unstate_edge("bob", "bob", "ops", "member-of")
    allowed, _ = plane.check("read", "doc", "bob", "same-group")
    assert allowed is False
    plane.close()


if __name__ == "__main__":
    test_remint_discover_destroy()
    test_elect_refuses_while_keep_operating()
    test_elect_is_pending_until_commit_after_wait()
    test_live_canceler_stops_pending_elect()
    test_privilege_up_waits_unstate_is_immediate()
    print("ok")
