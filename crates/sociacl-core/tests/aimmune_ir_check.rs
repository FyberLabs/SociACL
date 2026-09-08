//! The TS consume contract is the artifact AImmune / auto-defense
//! reimplements. It stays light Check + delegate only.

use std::path::PathBuf;

fn contract_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/aimmune-ir-check.d.ts")
}

fn doc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/aimmune-ir-check.md")
}

fn read(path: PathBuf) -> String {
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {}: {e}", path.display()))
}

#[test]
fn consume_contract_covers_ir_check() {
    let dts = read(contract_path());
    for needle in [
        "CHECK(action, object, accessor)",
        "SiteObjectId",
        "site:${string}:ir",
        "ActionMask",
        "DelegateGrant",
        "HandoffHint",
        "CheckResult",
        "AccessorId",
        "checkDelegate",
        "applyDelegate",
        "cancelDelegate",
        "undelegate",
        "remintCapability",
        "acceptHint",
        "hopcap",
        "see maps to",
        "annotate-only",
        "contain never calls Check",
    ] {
        assert!(dts.contains(needle), "contract missing {needle}");
    }
}

#[test]
fn consume_contract_does_not_export_off_plane_verbs() {
    let dts = read(contract_path());
    let lower = dts.to_ascii_lowercase();

    for banned_export in [
        "export function elect",
        "export type elect",
        "export function will",
        "export type will",
        "export function sea",
        "export type sea",
        "export function break_glass",
        "export type break_glass",
        "export type breakglass",
        "export type ownerconsole",
        "export type owner-console",
        "export type sitetoken",
        "export type site-token",
        "export type checkout",
    ] {
        assert!(
            !lower.contains(banned_export),
            "consume contract must not export {banned_export}"
        );
    }

    assert!(
        dts.contains("break_glass is a Brewnix owner gate, not a SociACL verb"),
        "break_glass must be documented as not a SociACL verb"
    );
    assert!(
        !dts.contains("site:${string}:host"),
        ":host stays later; not a SiteObjectId this cut"
    );
    assert!(
        !dts.contains("site:${string}:incident"),
        "do not invent per-incident ACL objects"
    );
}

#[test]
fn consume_doc_says_copy_not_a_package() {
    let md = read(doc_path());
    let lower = md.to_ascii_lowercase();
    assert!(md.contains("aimmune-ir-check.d.ts"));
    assert!(md.contains("s3rch-check.d.ts"));
    assert!(md.contains("sociacl-ir-binding-v0.md"));
    assert!(md.contains("PR #11") || md.contains("pull/11"));
    assert!(md.contains("PR #13") || md.contains("pull/13"));
    assert!(md.contains("verbs.md"));
    assert!(lower.contains("browser"));
    assert!(lower.contains("mockcheck"));
    assert!(lower.contains("do not `npm install sociacl`") || lower.contains("do not npm install"));
    assert!(lower.contains("wasm later is optional"));
    assert!(
        lower.contains("later, on request"),
        ":host waits for a later ask"
    );
    assert!(
        !lower.contains("wasm-pack") && !lower.contains("wasm-bindgen"),
        "IR light path does not add a compiled module toolchain"
    );
}
