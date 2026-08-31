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
        "CheckExecute",
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
        "case c",
        "case_c",
        "napi",
        "wasm",
        "wasm-pack",
        "wasm-bindgen",
        "npm install",
    ] {
        assert!(
            !lower.contains(banned),
            "consume contract must not mention {banned}"
        );
    }
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
        !lower.contains("wasm-pack") && !lower.contains("wasm-bindgen"),
        "lab-feed path does not add a compiled module toolchain"
    );
}
