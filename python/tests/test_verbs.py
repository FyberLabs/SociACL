"""Live-plane verb Python binding tests. Requires `cargo build -p sociacl-c`."""

from sociacl import Error, Plane


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


if __name__ == "__main__":
    test_remint_discover_destroy()
    test_elect_refuses_while_keep_operating()
    print("ok")
