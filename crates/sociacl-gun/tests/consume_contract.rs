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
        "s3rch/items",
        "s3rch/users",
        "s3rch/meta",
        "checkSee",
        "admitRow",
        "reverifyPrincipal",
        "sociacl-object-v2",
        "checkPost",
        "admitPost",
        "MeshPostGrant",
        "postSoul",
        "postGrantBytes",
        "`p_` plus 128 lowercase hex",
        "sociacl-post-grant-v2",
        "Throws when owner, object, or accessor is not an already-parsed id",
        "requestId",
        "accessRequestBytes",
        "parseAccessRequest",
        "verifyAccessRequest",
        "grantApprovedRequest",
        "sociacl-access-request-v2",
        "sociacl-request-id-v2",
        "read+post",
        "A present request never makes this a grant",
        "inbox delivery never grants",
        "acceptHint",
        "hopcap",
        "MeshSeeGrant",
        "GunAclEdge",
        "HopFactor",
        "acceptHop",
        "decodeHop",
        "grantSoul",
        "aclSoul",
        "s3rch/acl",
        "WrappedKey",
        "BlindedGrantRow",
        "MeshMembership",
        "checkGroupSee",
        "rotateOnRevoke",
        "same-group",
        "named-circle",
        "A wrap is not a grant",
        "epriv",
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

fn mentions_discover_verb(lower: &str) -> bool {
    lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|word| word == "discover" || word == "discovers" || word == "discovered")
}

#[test]
fn consume_contract_stays_off_the_other_plane() {
    let dts = read(contract_path());
    let lower = dts.to_ascii_lowercase();
    // SEA wraps and encrypted rows are named on the wrapped-key spec.
    // "discovery" is recipient-side scan, not the DISCOVER verb.
    for banned in [
        "elect",
        "will",
        "remint",
        "destroy",
        "case c",
        "case_c",
        "napi",
        "wasm",
        "wasm-pack",
        "wasm-bindgen",
        "npm install",
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
    assert!(
        !mentions_discover_verb(&lower),
        "consume contract must not name the DISCOVER verb"
    );
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
fn consume_contract_locks_forums() {
    let dts = read(contract_path());
    let md = read(doc_path());
    let gun = read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/gun.md"));
    for text in [&dts, &md, &gun] {
        assert!(text.contains("s3rch/forums/"), "missing forum souls");
        assert!(text.contains("/agents/"), "missing per-agent status soul");
        assert!(text.contains("started"), "missing per-agent started");
        assert!(text.contains("tokens"), "missing per-agent tokens");
        assert!(text.contains("runtime"), "missing per-agent runtime");
        assert!(
            text.contains("distinct-principals"),
            "missing distinct principals"
        );
        assert!(text.contains("role-labels"), "missing role labels");
        assert!(text.contains("forum:"), "missing forum chat tag");
        assert!(text.contains("s3rch/items"), "chat stays on items");
        assert!(text.contains("pinned"), "missing pinned emergency");
        assert!(text.contains("emergency"), "missing emergency");
        assert!(
            text.contains("GunDB SEA pubkey") || text.contains("GunDB SEA pubkey"),
            "identity is the SEA pubkey"
        );
        assert!(
            text.contains("linked credential"),
            "wallet and oauth stay linked"
        );
        assert!(
            text.contains("s3rch/chat"),
            "must name the refused chat soul"
        );
    }
    assert!(dts.contains("ForumAgentStatus"));
    assert!(dts.contains("ForumNeed"));
    assert!(dts.contains("ForumAlarm"));
    assert!(dts.contains("ForumRoleMode"));
    assert!(dts.contains("ForumChatItem"));
    assert!(dts.contains("forumAgentSoul"));
    assert!(dts.contains("forumChatTag"));
    assert!(md.contains("vectors/mesh/forums.json"));
    assert!(gun.contains("resolve-need-does-not-elect"));
    assert!(gun.contains("check-deny-without-dest-acl"));
    assert!(gun.contains("cancel-visible-on-next-check"));
    assert!(gun.contains("sgh1-hint-alone-fails-closed"));
    assert!(gun.contains("chat-via-tagged-items"));
    let lower_dts = dts.to_ascii_lowercase();
    let lower_md = md.to_ascii_lowercase();
    for text in [&lower_dts, &lower_md] {
        assert!(
            !text.contains("elect"),
            "consume contract must not name elect"
        );
        assert!(!text.contains("stripe"), "forums pilot has no payments");
    }
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
    for banned in ["remint", "elect", "destroy", "break_glass"] {
        assert!(
            !lower.contains(banned),
            "consume doc must not name {banned}"
        );
    }
    assert!(
        !mentions_discover_verb(&lower),
        "consume doc must not name the DISCOVER verb"
    );
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
    assert!(
        md.contains("encrypted-discovery.md"),
        "consume doc must point at the wrapped-key spec"
    );
    assert!(
        md.contains("checkPost") && md.contains("vectors/mesh/v2/post.json"),
        "consume doc must name the post grant and its vectors"
    );
    assert!(
        md.contains("grantApprovedRequest") && md.contains("vectors/mesh/v2/request.json"),
        "consume doc must name the access request and its vectors"
    );
    assert!(
        lower.contains("no hosted evaluator"),
        "consume doc must say there is no hosted evaluator"
    );
    assert!(
        lower.contains("inbox delivery never grants"),
        "consume doc must say an inbox delivery never grants"
    );
    assert!(
        lower.contains("a wrap is not a grant") || lower.contains("wrap of a dek"),
        "consume doc must say a wrap is not a grant"
    );
}

#[test]
fn encrypted_discovery_spec_stays_on_the_light_surface() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/encrypted-discovery.md");
    let doc = read(path);
    let lower = doc.to_ascii_lowercase();
    for needle in [
        "a wrap is not a grant",
        "sea",
        "epriv",
        "hamstate",
        "same-group",
        "named-circle",
        "hopcap",
        "row counts",
        "timing",
        "sizes",
        "future work",
        "private information retrieval",
        "zero-knowledge",
        "sociacl runs no index",
        "https://github.com/fyberlabs/s3r.ch/pull/108",
        "already unwrapped",
        "grantsoul",
        "stated: 0",
        "exactly one",
        "scanning a shared bucket is not allowed",
        "forward-only",
        "re-encrypt",
        "public-filtered",
        "enrollment",
        "in place",
        "group search tokens",
        "author fast unwrap",
    ] {
        assert!(lower.contains(needle), "spec missing {needle}");
    }
    assert!(
        !mentions_discover_verb(&lower),
        "spec must not name the DISCOVER verb"
    );
    for banned in [
        "lightiff",
        "itar",
        "saas",
        "hypermesh",
        "case c",
        "wills",
        "checkout",
    ] {
        assert!(!lower.contains(banned), "spec must not name {banned}");
    }
    assert!(!doc.contains("DISCOVER"), "spec must not name DISCOVER");
    assert!(!doc.contains("ELECT"), "spec must not name ELECT");
}
