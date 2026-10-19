#!/usr/bin/env python3
"""Write canonical-id vectors with hashlib, independent of the Rust and TS code.

Integers are ASCII decimal with no sign and no leading zeros. Zero is "0".
Each field is a uint32 little-endian byte length followed by UTF-8 bytes.
An empty field is four zero bytes. The id is SHA-256, lowercase hex.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent

SIGN_PRIV = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
SIGN_PUB = "YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y.eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk"
SIGN_PRIV_SEA = "ya-p2EW6dRZrXCFXZ7HWk05Qw9s26JsSe4piKxIPZyE"
EPRIV = "6EXhKuFCyTddo7uvYddNjXON5iKEMV7v8bCol7XOHt8"
EPUB = "EMvdmXTv89JPyMx5n3blU3L_D70U-6JoVaVzTvSzgYg.B_b0CP3o9X3I7tWrxA_F1VhXpjeMuIJCtQWnOh7LN5c"
# Parser-produced ids. Inbox and wrap rows stay on s3rch/items/post until PR 6.
OBJECT = "chat_" + "11" * 16
ALICE = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
BOB = "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg.B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E"
ADA = "4lNKNTLQj7ugLd5lnuYr0AMf4tt4VZbvUJMCRGsDCFI.4PFXWkxjPMcZ3-5f2oYtdk78lsPzDuAFXELCPxhO2MY"

# RFC 6979 A.2.5 signs "sample". s in that appendix is high. Low-s is n - s.
SAMPLE_SIG_HIGH_S = (
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
)
SAMPLE_SIG_LOW_S = (
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
    "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9"
)


def length_prefixed(fields: list[str]) -> bytes:
    out = bytearray()
    for field in fields:
        raw = field.encode("utf-8")
        if len(raw) > 0xFFFFFFFF:
            raise ValueError("field is too long")
        out += struct.pack("<I", len(raw))
        out += raw
    return bytes(out)


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def case_fields(name: str, fields: list[str]) -> dict:
    raw = length_prefixed(fields)
    return {
        "name": name,
        "kind": "fields",
        "fields": fields,
        "encodedLen": len(raw),
        "sha256": sha256_hex(raw),
    }


def decimal(n: int) -> str:
    if not isinstance(n, int) or isinstance(n, bool) or n < 0:
        raise ValueError(n)
    return str(n)


def opt(value: str | None) -> str:
    return "" if value is None else value


def inbox_fields(body: dict) -> list[str]:
    wrap = body["wrap"]
    if wrap is None:
        tail = [""] * 8
        flag = "0"
    else:
        flag = "1"
        # A missing object or group is the same empty field as "".
        tail = [
            wrap["scope"],
            decimal(wrap["epoch"]),
            wrap["target"],
            wrap["targetId"],
            opt(wrap["object"]) if "object" in wrap else "",
            opt(wrap["group"]) if "group" in wrap else "",
            wrap["revisionId"],
            wrap["wrappedKey"],
        ]
    return [
        "s3rch-inbox-entry-v1",
        body["laneId"],
        body["grantCiphertext"],
        body["commitment"]["hash"],
        flag,
        *tail,
    ]


def epoch_fields(body: dict) -> list[str]:
    return [
        "s3rch-epoch-revision-v1",
        body["object"],
        decimal(body["epoch"]),
        decimal(body["previousEpoch"]),
        body["deviceId"],
        body["keyCommitment"],
        decimal(body["settleWindowMs"]),
        body["aclSnapshot"],
    ]


def item_fields(body: dict) -> list[str]:
    return [
        "s3rch-item-auth-v1",
        body["object"],
        decimal(body["epoch"]),
        decimal(body["version"]),
        body["plaintextDigest"],
        body["revisionId"],
    ]


def account_fields(body: dict) -> list[str]:
    return [
        "s3rch-account-binding-v1",
        body["account"],
        body["pub"],
        body["epub"],
    ]


def structured(name: str, kind: str, body: dict, fields: list[str]) -> dict:
    raw = length_prefixed(fields)
    return {
        "name": name,
        "kind": kind,
        "body": body,
        "encodedLen": len(raw),
        "sha256": sha256_hex(raw),
    }


def main() -> None:
    revision = sha256_hex(b"s3rch-fixture-revision-v1")
    acl = sha256_hex(b"s3rch-fixture-acl-v1")
    commitment = sha256_hex(b"s3rch-fixture-commitment-v1")
    lane = sha256_hex(b"s3rch-fixture-lane-v1")
    hello = sha256_hex(b"hello")
    assert hello == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    wrap_doc = json.loads((HERE / "wrap.json").read_text(encoding="utf-8"))
    if wrap_doc["epoch"] != 3 or wrap_doc["object"] != "s3rch/items/post":
        raise SystemExit("wrap.json does not match the inbox fixture")
    if wrap_doc["dekHex"] != "11" * 32 or wrap_doc["nonceHex"] != "22" * 12:
        raise SystemExit("wrap.json DEK or nonce changed")
    real_wrap = {
        "scope": "item-dek",
        "epoch": wrap_doc["epoch"],
        "target": "reader-epub",
        "targetId": EPUB,
        "object": wrap_doc["object"],
        "revisionId": revision,
        "wrappedKey": wrap_doc["wrappedKey"],
    }
    wrap = {
        "scope": "item-dek",
        "epoch": 3,
        "target": "reader-epub",
        "targetId": EPUB,
        "object": "s3rch/items/post",
        "revisionId": revision,
        "wrappedKey": "aa",
    }
    wrap_empty_group = dict(wrap, group="")
    wrap_changed = dict(wrap, wrappedKey="ab")

    inbox_base = {
        "laneId": "lane-a",
        "grantCiphertext": "ct-1",
        "commitment": {"hash": commitment},
    }
    inbox_wrap = dict(inbox_base, wrap=wrap)
    inbox_empty_group = dict(inbox_base, wrap=wrap_empty_group)
    inbox_changed = dict(inbox_base, wrap=wrap_changed)
    inbox_unicode = {
        "laneId": "lane-λ",
        "grantCiphertext": "ct-1",
        "commitment": {"hash": commitment},
        "wrap": None,
    }
    inbox_empty = {
        "laneId": "",
        "grantCiphertext": "",
        "commitment": {"hash": ""},
        "wrap": None,
    }
    inbox_absent = dict(inbox_base, wrap=None)

    epoch = {
        "object": OBJECT,
        "epoch": 1,
        "previousEpoch": 0,
        "deviceId": "device-1",
        "keyCommitment": "opaque-commitment",
        "settleWindowMs": 86400000,
        "aclSnapshot": acl,
    }
    safe_max = 9007199254740991
    epoch_max = {
        "object": OBJECT,
        "epoch": safe_max,
        "previousEpoch": safe_max,
        "deviceId": "device-1",
        "keyCommitment": "opaque-commitment",
        "settleWindowMs": safe_max,
        "aclSnapshot": acl,
    }
    epoch_zero = {
        "object": OBJECT,
        "epoch": 0,
        "previousEpoch": 0,
        "deviceId": "device-1",
        "keyCommitment": "opaque-commitment",
        "settleWindowMs": 0,
        "aclSnapshot": acl,
    }
    item = {
        "object": OBJECT,
        "epoch": 1,
        "version": 2,
        "plaintextDigest": hello,
        "revisionId": revision,
    }
    item_zero = {
        "object": OBJECT,
        "epoch": 0,
        "version": 0,
        "plaintextDigest": hello,
        "revisionId": revision,
    }
    account = {"account": "0xalice", "pub": SIGN_PUB, "epub": EPUB}

    rev = "ab" * 32
    cases = [
        case_fields("fields-empty", []),
        case_fields("fields-ab-c", ["ab", "c"]),
        case_fields("fields-a-bc", ["a", "bc"]),
        case_fields("fields-decimal-zero", ["0"]),
        case_fields("fields-decimal-ten", ["10"]),
        case_fields("fields-decimal-leading-zero", ["010"]),
        structured("inbox-no-wrap", "inboxEntryId", inbox_absent, inbox_fields(inbox_absent)),
        structured("inbox-empty", "inboxEntryId", inbox_empty, inbox_fields(inbox_empty)),
        structured("inbox-unicode-lane", "inboxEntryId", inbox_unicode, inbox_fields(inbox_unicode)),
        structured("inbox-with-wrap", "inboxEntryId", inbox_wrap, inbox_fields(inbox_wrap)),
        structured(
            "inbox-group-empty",
            "inboxEntryId",
            inbox_empty_group,
            inbox_fields(inbox_empty_group),
        ),
        structured(
            "inbox-wrap-byte",
            "inboxEntryId",
            inbox_changed,
            inbox_fields(inbox_changed),
        ),
        structured("epoch-default-window", "epochRevisionId", epoch, epoch_fields(epoch)),
        structured("epoch-zero", "epochRevisionId", epoch_zero, epoch_fields(epoch_zero)),
        structured("epoch-max-safe", "epochRevisionId", epoch_max, epoch_fields(epoch_max)),
        structured("item-auth-hello", "itemAuth", item, item_fields(item)),
        structured("item-auth-zero", "itemAuth", item_zero, item_fields(item_zero)),
        structured("account-binding", "accountBinding", account, account_fields(account)),
        structured(
            "inbox-real-wrap",
            "inboxEntryId",
            dict(inbox_base, wrap=real_wrap),
            inbox_fields(dict(inbox_base, wrap=real_wrap)),
        ),
        case_fields(
            "acl-snapshot-direct",
            [
                "s3rch-acl-snapshot-v1",
                "0",
                "",
                "",
                "",
                "",
                BOB,
                "4",
                "0",
                "10",
                "20",
                "direct",
                "",
                "0",
            ],
        ),
        case_fields(
            "acl-snapshot-group",
            [
                "s3rch-acl-snapshot-v1",
                "1",
                "same-group",
                "crew",
                "1",
                "3",
                ADA,
                "2",
                "1",
                "0",
                "99",
                "same-group",
                "crew",
                "5",
            ],
        ),
        case_fields(
            "epoch-finalization-body",
            [
                "s3rch-epoch-finalization-v1",
                OBJECT,
                "3",
                "2",
                rev,
                "",
                rev,
            ],
        ),
        case_fields("epoch-manifest-sig", ["s3rch-epoch-manifest-sig-v1", rev]),
        case_fields("epoch-finalization-sig", ["s3rch-epoch-finalization-sig-v1", rev]),
        case_fields(
            "group-epoch-config",
            ["s3rch-group-epoch-config-v1", ALICE, "crew", "named-circle", "7200000", "2"],
        ),
        case_fields(
            "group-epoch-config-tie",
            ["s3rch-group-epoch-config-v1", ALICE, "crew", "named-circle", "86400000", "2"],
        ),
        # U+E000 then U+10000 is bytewise UTF-8 order. UTF-16 sorts them the other way.
        case_fields(
            "acl-snapshot-utf8-order",
            [
                "s3rch-acl-snapshot-v1",
                "0",
                "",
                "",
                "",
                "",
                "\ue000",
                "1",
                "1",
                "0",
                "4000000000000",
                "direct",
                "",
                "0",
                "\U00010000",
                "2",
                "0",
                "0",
                "4000000000000",
                "direct",
                "",
                "0",
            ],
        ),
        case_fields(
            "wrap-receipt",
            [
                "s3rch-wrap-receipt-v1",
                OBJECT,
                BOB,
                "2",
                rev,
                "cd" * 32,
            ],
        ),
    ]

    # Absent group and empty group are one encoding.
    absent_fields = inbox_fields(inbox_wrap)
    empty_fields = inbox_fields(inbox_empty_group)
    if absent_fields != empty_fields:
        raise SystemExit("absent group and empty group diverged")
    by_name = {row["name"]: row["sha256"] for row in cases}
    if by_name["inbox-with-wrap"] != by_name["inbox-group-empty"]:
        raise SystemExit("group empty hash diverged")
    if by_name["inbox-with-wrap"] == by_name["inbox-wrap-byte"]:
        raise SystemExit("wrap byte did not change the id")
    if by_name["inbox-real-wrap"] == by_name["inbox-with-wrap"]:
        raise SystemExit("real wrap matched the stub wrap")
    if by_name["fields-ab-c"] == by_name["fields-a-bc"]:
        raise SystemExit("length prefix did not split fields")
    if by_name["fields-decimal-ten"] == by_name["fields-decimal-leading-zero"]:
        raise SystemExit("leading zero matched canonical decimal")
    if by_name["fields-empty"] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        raise SystemExit("empty sha256 is not the well-known value")

    document = {
        "encoding": "uint32-le-length-prefixed-utf8",
        "hash": "sha256-lowercase-hex",
        "safeInteger": {"maxInclusive": safe_max, "rejected": "9007199254740992"},
        "notes": [
            "An empty field is four zero bytes.",
            "Integers are ASCII decimal with no sign and no leading zeros. Zero is 0.",
            "A missing wrap.object or wrap.group encodes the same as an empty string.",
            "fields-empty is SHA-256 of the empty byte string.",
            "itemAuth and accountBinding hashes cover the signed bytes. They are not signatures.",
            "keyCommitment in these vectors is an opaque string. This slice does not define that commitment.",
            "epoch-max-safe uses 9007199254740991, the largest integer Number.isSafeInteger accepts. 9007199254740992 is rejected and has no id.",
            "inbox-real-wrap hashes the wrappedKey blob in wrap.json. The short aa and ab wraps are id cases only.",
            "acl-snapshot-utf8-order sorts accessors by UTF-8 bytes. U+E000 precedes U+10000.",
            "wrap-receipt is the length-prefixed reader receipt. It is not a signature.",
            "Epoch and migration id fixtures are parser-produced ObjectId and PrincipalId values. acl-snapshot-utf8-order keeps U+E000 and U+10000 because those scalars are not principals.",
        ],
        "cases": cases,
    }
    (HERE / "canonical.json").write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    fixture = {
        "label": "Public test keys for the encrypted-discovery vectors. Not a live account.",
        "laneId": lane,
        "signing": {
            "note": "RFC 6979 appendix A.2.5 P-256 SHA-256 key.",
            "scalarHex": SIGN_PRIV,
            "priv": SIGN_PRIV_SEA,
            "pub": SIGN_PUB,
            "sampleMessage": "sample",
            "sampleSignatureHighS": SAMPLE_SIG_HIGH_S,
            "sampleSignatureLowS": SAMPLE_SIG_LOW_S,
        },
        "encryption": {
            "note": "Scalar is SHA-256 of the UTF-8 string sociacl-encdisc-epub-fixture-v1.",
            "epriv": EPRIV,
            "epub": EPUB,
        },
        "revisionId": revision,
        "plaintextHello": hello,
    }
    (HERE / "sea-fixture.json").write_text(
        json.dumps(fixture, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {len(cases)} cases")


if __name__ == "__main__":
    main()
