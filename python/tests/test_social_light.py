"""Social Light hop-frame Python binding tests. Requires `cargo build -p sociacl-c`."""

from sociacl import Client, Error, Plane, holder_keygen, issuer_keygen


def test_badge_discover_does_not_elect():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_object("doc", "alice")
    pk, sk = issuer_keygen()
    plane.enroll("alice", "principal", pk)

    frame = plane.encode_social_light(
        "convention-badge",
        sk,
        "alice",
        "bob",
        "identity-live",
        "doc",
        share_token="booth-12",
    )
    assert frame.startswith(b"SLHP")
    assert plane.accept_social_light(frame) == "convention-badge"
    assert plane.discover_social_light(frame) == "living-person bob share booth-12"
    try:
        plane.elect_social_light("doc", frame)
        raise AssertionError("elect from a flash must fail")
    except Error as exc:
        assert "elect" in str(exc).lower() or "attestation" in str(exc).lower()
    plane.close()


def test_station_remint_and_check():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_device("station-hall")
    plane.add_object("doc", "alice")
    pk, sk = issuer_keygen()
    plane.enroll("station-hall", "station", pk)

    remint = plane.encode_social_light(
        "enrolled-station",
        sk,
        "station-hall",
        "alice",
        "station-liveness",
        "doc",
    )
    assert plane.remint_social_light("doc", "alice", remint) == "remint"
    try:
        plane.remint_social_light("doc", "bob", remint)
        raise AssertionError("remint must not name a new principal")
    except Error:
        pass

    factor = plane.encode_social_light(
        "enrolled-station",
        sk,
        "station-hall",
        "alice",
        "identity-live",
        "doc",
    )
    allowed, reason = plane.check_social_light("read", "doc", "alice", factor, "owner")
    assert allowed is True
    assert reason == "owner"
    plane.close()


def test_forbidden_channel_fails():
    plane = Plane()
    plane.add_person("alice")
    plane.add_object("doc", "alice")
    pk, sk = issuer_keygen()
    plane.enroll("alice", "principal", pk)
    try:
        plane.encode_social_light(
            "lightiff", sk, "alice", "alice", "identity-live", "doc"
        )
        raise AssertionError("LightIFF channel must fail closed")
    except Error:
        pass
    try:
        plane.encode_social_light(
            "convention-badge", sk, "alice", "alice", "flash", "doc"
        )
        raise AssertionError("flash claim must fail closed")
    except Error:
        pass
    plane.close()


def test_client_still_consumes_a_precut_badge():
    plane = Plane()
    plane.add_person("alice")
    plane.add_person("bob")
    plane.add_object("doc", "alice")
    pk, sk = issuer_keygen()
    plane.enroll("alice", "principal", pk)
    frame = plane.encode_social_light(
        "convention-badge",
        sk,
        "alice",
        "bob",
        "identity-live",
        "doc",
        share_token="opt-in",
    )
    factor = plane.encode_social_light(
        "convention-badge",
        sk,
        "alice",
        "alice",
        "identity-live",
        "doc",
    )
    _, secret = holder_keygen()
    client = Client.from_bytes(plane.export_bundle("alice", secret), secret)
    assert client.discover_social_light(frame) == "living-person bob share opt-in"
    allowed, reason = client.check_social_light(
        "read", "doc", "alice", factor, "owner"
    )
    assert allowed is True
    assert reason == "owner"
    try:
        client.elect_social_light("doc", frame)
        raise AssertionError("elect from a flash must fail on the client")
    except Error:
        pass
    client.close()
    plane.close()


if __name__ == "__main__":
    test_badge_discover_does_not_elect()
    test_station_remint_and_check()
    test_forbidden_channel_fails()
    test_client_still_consumes_a_precut_badge()
    print("ok")
