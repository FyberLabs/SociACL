# Shared identity migration

The independently versioned `sociacl-ids` package, in TypeScript and Rust, is the account identity. The account is its genesis SEA P-256 key. Wallets and tenant-scoped OIDC credentials link to it. Object ids are fixed at creation. Names and labels are attributes. Canonical ids enter through one parser and compare directly after that.

Source: [package specification with review amendments](sociacl-ids-package-spec.md). Package API: [typescript/ids/README.md](../typescript/ids/README.md). Implementation: [SociACL #57](https://github.com/FyberLabs/SociACL/pull/57). The [0.6 normative amendment](identity-review-amendment.md) is the proof and URL contract where it supersedes the original. `ids` 0.10.0 is unreleased. This document does not publish it.

SociACL never launched. There is no persisted graph, no pre-v2 ACL row, and nothing to migrate. Owners mint fresh v2 rows. Old domains are `legacy-row` and never reach Check. There is no `migrateAclRows`. A rejected id is not preserved, not mapped, and not an owner. Do not infer ownership from a wallet, a Gun path, or an old spelling.

## Delivery status

| Stage | Implementation | Review/merge/release | Acceptance evidence |
| --- | --- | --- | --- |
| Canonical ids and keys in TS/Rust | Implemented | Merged in #57. Tag `ids-v0.10.0` is not published | Shared grammar, path, and soul vectors |
| Wallet/OIDC proofs, rotation and revocation | Implemented | Merged in #57. Tag not published | Fixed-key records and the history, revocation, and fork vectors |
| Present credential lookup and retained-link preparation | Implemented | [PR #84](https://github.com/FyberLabs/SociACL/pull/84) under review; covers #58 and #59 | Shared future/issuance-boundary, duplicate-copy, revocation, and input-limit vectors. Retention rejects future links before history lookup |
| Browser package and optional Zod entry point | Implemented | Merged in #57. Tag not published | Strict types, browser bundle, installed-tarball consumer |
| Shared-vector accounting and release workflow | Implemented | Tag not published | CI compares both execution manifests to the vectors |
| SociACL permission callers | Implemented | #55 PRs 1–6 merged. PR 7 dropped. This close-out is PR 8 | Branded `ObjectId` and `PrincipalId`. Alias, fold, and chain-accessor helpers deleted. Forbidden-names guard and the `typescript/src` `node:crypto` audit |
| PR #84 review hardening | Implemented | [PR #84](https://github.com/FyberLabs/SociACL/pull/84) awaits review and merge | Damaged v4 proof copies cannot restore retired keys; shared resolution and signed-at regressions. One parser-based crypto import audit replaces three hand-written scanners |
| Panopticon credential attestation | Planned | Separate work | Pinned ES256 attestations after a wallet proof or a fresh OIDC login |
| s3r.ch account enrollment and recovery | Planned | Separate product work. Not a SociACL graph migration | One genesis per account |
| s3r.ch objects, permissions and Views | Planned | Separate product work. Mint new ids there | Exact object grants on stored ids |
| Existing graph data transition | Nothing to migrate | Dropped with PR 7 | No inventory of rejected ids and no read-only preservation |

Permission callers are on stored ids. A passing ids suite is not the permission-caller suite. That suite is `vectors/mesh/v2/` plus the forbidden-names guard.

## Still open

These are not a data migration:

1. **Publish `ids-v0.10.0`.** [#60](https://github.com/FyberLabs/SociACL/issues/60) is the protected-`master` gate for that release. The tag name is `ids-v0.10.0`. After review, publish through the release workflow and record the asset URL and SHA-256. Consumers pin lockfile integrity.
2. **Panopticon proofs and key backups.** Wallet and revoke timestamp attestations, tenant-scoped OIDC link attestation, and v2 rotation attestation stay at those endpoints. Panopticon assigns the issuance timestamp and the retained set from authenticated history. Use `resolveWalletLinkNow` for present wallet login and `verifyRevokeNow` for OIDC revocations. Do not infer a persistent revocation from a claimed time.
3. **s3r.ch account identity.** First enrollment mints one genesis identity. Later devices enroll into it. Never synthesize a principal from a wallet.
4. **s3r.ch permission and object callers.** Use the package in that product's check, rooms, chat, forum, and Views. Mint native object ids at creation. Do not keep a legacy object read-only and do not join on a label or a handle.

SociACL follow-ups that this close-out does not take:

- [#77](https://github.com/FyberLabs/SociACL/issues/77): request pairs now validate privately and publish together, with reentrant cancels and owner removal aborting the pair. Rust self-requests reuse one history lookup and members timestamps share the JavaScript safe-integer limit. Shared vectors cover missing request fields, self-resolution counts, and the timestamp limit. The KDF rejection test counts calls rather than elapsed time; the feature-off adapter build rejects warnings. Test hooks live outside the package, and the package import boundary is documented. These changes are in [PR #85](https://github.com/FyberLabs/SociACL/pull/85), merged. The old public owner bind/unbind functions were already removed on master. Group-policy questions remain in #79.
- [#79](https://github.com/FyberLabs/SociACL/issues/79) group-predicate leftovers that are not the incoming-predicate vector, the cancel-only tombstone snapshot, or the Rust `mutate-row` note
- [#81](https://github.com/FyberLabs/SociACL/issues/81): implemented removal of the unsigned `sociacl/ir` runtime and Rust core-plane Gun adapter, including C/Python authority wrappers. Signed object admission remains the ownership boundary. Public API regressions cover unsigned/forged records, rejected overwrites, core/mesh separation, and removed exports. Review and merge pending; [replacement APIs](gun.md#signed-ownership-boundary).

## Clarifications

- A TypeScript intersection of two brands using the same unique-symbol key collapses to `never`. `MintedObjectId` therefore adds a second unique-symbol marker to `ObjectId`.
- The source plan's `Reason` union omits its own verification errors. Both languages expose the same additional proof, history, and RNG errors.
- Gun user souls contain `~` and the SEA public-key `.` separator. The forbidden path-character rule applies to derived path keys and slash-separated ACL and object templates, with the specified `~pub` template exempted.
- The current-key-at-issuance requirement needs explicit authenticated history. The APIs expose that context. Record signatures never select their own key. Sequences start at one without gaps. Duplicate copies of the same signed transition are idempotent. Rotations take effect after their timestamp, so a same-second revocation uses the preceding key and blocks recovery.
- Proof verification alone cannot establish global freshness, discover omitted revocations, fetch trusted JWKS, authorize enrollment, or consume a nonce. The storage and authentication callers supply those guarantees.
- Build and test tooling may import Node built-ins. `typescript/src` does not import `node:crypto`. The published browser runtime does not either.

References for protocol details: [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361), [EIP-55](https://eips.ethereum.org/EIPS/eip-55), [OIDC Core subject identifiers](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
