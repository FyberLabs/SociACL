//! The TS consume contract is the artifact s3r.ch reimplements.
//! It stays light Check only.

use std::path::PathBuf;

fn contract_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/s3rch-check.d.ts")
}

fn doc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/s3rch-check.md")
}

fn read(path: PathBuf) -> String {
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {}: {e}", path.display()))
}

#[test]
fn consume_contract_covers_light_check() {
    let dts = read(contract_path());
    for needle in [
        "CHECK(see, object, accessor)",
        "GunFeedNode",
        "GunUserNode",
        "IdentitySeeGrant",
        "HandoffHint",
        "UrlLeaf",
        "encodeKey",
        "s3rch/items",
        "s3rch/users",
        "s3rch/meta",
        "checkSee",
        "checkSeeGrant",
        "acceptHint",
        "admitFeedNode",
        "cancelSee",
        "hopcap",
        "MeshSeeGrant",
        "GunAclEdge",
        "HopFactor",
        "acceptHop",
        "decodeHop",
        "grantSoul",
        "aclKey",
        "s3rch/acl",
        "hop?: HopFactor",
        "Hop missing does not fail",
        "Hop alone never allows",
        "HeldClaimPrefix",
        "ens:",
        "unstoppable:",
        "fc:",
        "lens:",
        "rss3:",
        "GunUserNode.indicators",
        "s3rch/users/<wallet>/claims/",
        "ens:name.eth",
        "unstoppable:name.crypto",
        "fc:name",
        "lens:name",
        "rss3:0x",
    ] {
        assert!(dts.contains(needle), "contract missing {needle}");
    }
}

#[test]
fn consume_contract_stays_off_the_other_plane() {
    let dts = read(contract_path());
    let lower = dts.to_ascii_lowercase();
    for banned in [
        "elect",
        "will",
        "remint",
        "discover",
        "destroy",
        "case c",
        "case_c",
        "napi",
        "wasm",
        "wasm-pack",
        "wasm-bindgen",
        "npm install",
        "sea",
        "encrypt",
        "checkexecute",
        "break_glass",
        "break-glass",
        "hop mint",
        "hop mints",
    ] {
        assert!(
            !lower.contains(banned),
            "consume contract must not mention {banned}"
        );
    }
}

#[test]
fn consume_contract_hop_never_mints() {
    let dts = read(contract_path());
    let lower = dts.to_ascii_lowercase();
    assert!(
        lower.contains("hop never mints a grant") || lower.contains("hop alone never allows"),
        "contract must say hop does not mint"
    );
    assert!(
        !lower.contains("hop mint") && !lower.contains("hop mints"),
        "contract must not claim hop mints"
    );
    assert!(
        !dts.contains("Elect") && !dts.contains("elect"),
        "consume contract does not export Elect"
    );
    assert!(
        !lower.contains("break_glass") && !lower.contains("wills"),
        "consume contract does not export wills / break_glass"
    );
}

#[test]
fn consume_contract_locks_held_claim_souls() {
    let dts = read(contract_path());
    let md = read(doc_path());
    for text in [&dts, &md] {
        assert!(
            text.contains("s3rch/users/<wallet>/claims/"),
            "must refuse a nested claims/ soul"
        );
        assert!(
            text.contains("ens:")
                && text.contains("unstoppable:")
                && text.contains("fc:")
                && text.contains("lens:")
                && text.contains("rss3:"),
            "must name locked claim-id prefixes"
        );
        assert!(
            text.contains("indicators"),
            "claim ids link from GunUserNode.indicators"
        );
    }
    assert!(
        !dts.contains("s3rch/users/") || dts.contains("Do not invent"),
        "users collection stays the wallet node"
    );
}

#[test]
fn consume_doc_says_browser_not_a_package() {
    let md = read(doc_path());
    let lower = md.to_ascii_lowercase();
    assert!(md.contains("s3rch-check.d.ts"));
    assert!(lower.contains("browser"));
    assert!(lower.contains("do not `npm install sociacl`") || lower.contains("do not npm install"));
    assert!(lower.contains("wasm later is optional"));
    assert!(
        lower.contains("later, on request"),
        "extra verbs wait for a later ask"
    );
    assert!(
        !lower.contains("wasm-pack") && !lower.contains("wasm-bindgen"),
        "lab-feed path does not add a compiled module toolchain"
    );
    for banned in [
        "remint",
        "discover",
        "elect",
        "destroy",
        "sea",
        "break_glass",
    ] {
        assert!(
            !lower.contains(banned),
            "consume doc must not name {banned}"
        );
    }
    assert!(
        md.contains("Mesh") && md.contains("s3rch/acl"),
        "consume doc must name the Mesh dest ACL"
    );
    assert!(
        lower.contains("hop missing does not fail"),
        "consume doc must say hop missing does not fail"
    );
    assert!(
        lower.contains("hop alone never allows"),
        "consume doc must say hop alone never allows"
    );
}
