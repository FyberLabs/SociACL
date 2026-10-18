# Shared identity migration

The first delivery is the independently versioned `sociacl-ids` package in
TypeScript and Rust. The account identity is its genesis SEA P-256 key. Wallets
and tenant-scoped OIDC credentials link to it. Object ids are fixed at creation;
names and labels remain mutable attributes. Canonical ids enter through one
parser and compare directly thereafter.

Source: [package specification with review amendments](sociacl-ids-package-spec.md), design dated 2026-10-16. See the package
[API and verification contract](../typescript/ids/README.md). The implementation
is additive to SociACL `master@246e941`, rebased after
SociACL [#56](https://github.com/FyberLabs/SociACL/pull/56) merged. The separate
s3r.ch [#125](https://github.com/FyberLabs/s3r.ch/pull/125) was open when this work began.

Implementation PR: [SociACL #57](https://github.com/FyberLabs/SociACL/pull/57).
Grok/Codex findings are addressed in the 0.6 amendment in this PR. Local validation
is recorded in the PR; merge, release, and consumer migration remain pending.

## Delivery status

| Stage | Implementation | Review/merge/release | Acceptance evidence |
| --- | --- | --- | --- |
| Canonical ids and keys in TS/Rust | Implemented in this PR | Pending review | Shared grammar/path/soul vectors and generated tests |
| Wallet/OIDC proofs, rotation and revocation | Implemented in this PR | Pending review | Fixed-key records; invalid-index DoS, revoked-link resurrection, OIDC recovery authority, timestamp replay, witness equivocation, missing required evidence, forks, and current-key offline revocation versus witnessed history |
| Browser package and optional Zod entry point | Implemented in this PR | Pending review | Strict types, browser bundle, installed-tarball consumer |
| Shared-vector accounting and release workflow | Implemented in this PR | Pending review; tag not published | CI compares both execution manifests to all vectors; release gated on full suite |
| SociACL permission callers | Planned | Separate PR after package review | Branded core inputs; remove alias, fold and chain-accessor code |
| Panopticon credential attestation | Planned | Separate PR | Pinned ES256 attestations after wallet proof/fresh OIDC login; tenant binding |
| s3r.ch account enrollment and recovery | Planned | Separate PR after attestation contract | One genesis per account; multiple devices; rotation/revocation/fork behavior |
| s3r.ch objects, permissions and Views | Planned | Separate PR after account transition | Exact object grants, principal owners, canonical SourceKey, immutable ids |
| Existing graph data transition | Unspecified | Requires a migration design | No inferred ownership or silent rewrite of old graph keys |

The shared package defines and verifies identities. Existing permission paths
continue using their current implementation until the caller PRs are merged.
A passing package suite does not establish that the existing app's bypasses
have been removed.

## Reviewable follow-up PRs

1. **Publish the reviewed package.** Merge after Grok/Codex review and CI, then
   configure branch protection and required CI/review on `master`, then publish
   `ids-v0.9.0` through the release workflow. Record the immutable asset
   URL and SHA-256. Consumer PRs must pin lockfile integrity; no unresolvable
   release URL or vendored replacement validator belongs in a merged consumer.
2. **SociACL core boundaries.** Replace TS `gun`, `post`, `group`, `request` and
   contract migration encoding, plus Rust `soul`, `mesh`, `post`, `group`,
   `request`, `feed` and encrypted-discovery migration helpers. Change core
   signatures to newtypes/brands. Parse raw input once. Regression tests must
   cover Gun-chain spoofing, the fold triple, grant-soul collisions, cross-room
   suffix matches, and request snapshot mutation. Keep #56's immediate fixes
   while this broader migration is reviewed.
3. **Panopticon proofs and key backups.** Implement wallet and revoke timestamp attestations, tenant-scoped OIDC link
   attestation, and v2 rotation attestation binding the authorizing credential
   and retained-link commitment. Fresh
   login/proof, issuer pinning, nonce replay prevention and authorization belong
   at these endpoints. Store wrapped key backups privately. A signed-in user or
   a client-supplied principal is not sufficient authority to relink an account.
   Panopticon assigns the issuance timestamp and computes the retained set from
   authenticated history; it must not attest an arbitrary client-supplied date/set.
   OIDC recovery must prove fresh login to the enrolled issuer/tenant/subject
   and require no active wallet. Supply complete authenticated link, revocation
   and rotation snapshots to the package, with explicit request/work budgets.
   When constructing link maps, preserve a copy that verifies for each ID;
   keep alternatives until verification is possible and never overwrite it with
   an unverified proof copy. Shared vectors cover duplicate rotation proofs and
   pre-attestation retention filtering; the production adapter is still planned.
   Preserve trusted latest-state checkpoints: an index's assertion of completeness
   is not sufficient, and a verifier cannot detect an entirely omitted rotation.
   Use `resolveWalletLinkNow` for present wallet login/recovery eligibility and
   `verifyRevokeNow` with matched principal/target/time for OIDC revocations;
   Panopticon must perform this check before attesting any rotation or login.
   Clients and Panopticon must exclude every present-revoked link from the signed
   retained set, check the authorizer independently, and recheck on state changes.
   Keep rotation and as-of checks witness-only. Current-key offline revokes
   need no live Panopticon request but stop applying when their signer retires.
   Preserve removal through the retained set or a witnessed revoke consistent
   with the transition; do not infer persistent revocation from claimed times.
   Propagate `missing-history`, `rotation-conflict` and `rotation-fork` to login
   and recovery; none may fall back to genesis or a previous successful key.
   Review the independent upload-grant lookup by file name separately.
4. **s3r.ch account identity.** Migrate `identity/mesh`, `idb`, `mesh-link`,
   `link`, and `wrap` together: first enrollment mints one genesis identity,
   later devices enroll into it, and credential links live under `~genesis`.
   Session credentials remain lookup credentials. Never synthesize a principal
   from a wallet or make a per-device key the account identity. Test lost-device
   recovery, current-key verification, key forks and revoked wallet recovery.
5. **s3r.ch permission/object/Views callers.** Use the package in
   `identity/check`, `users`, `rooms`, `chat`, `forum`, and Views source refs,
   picker, access, backup and store. Mint native object ids at creation, derive
   external/held-claim ids, remove label/handle joins and alias comparisons,
   scope forum lookup to its channel, and set the configured network identity.
   Bind backup AAD/manifests to the genesis principal. Preserve legacy objects
   read-only until the graph transition is explicitly designed and tested.

## Clarifications made while implementing the source plan

- A TypeScript intersection of two brands using the same unique-symbol key
  collapses to `never`. `MintedObjectId` therefore adds a second unique-symbol
  marker to `ObjectId`.
- The source plan's `Reason` union omits its own verification errors. Both
  languages expose the same additional proof/history/RNG errors.
- Gun user souls contain `~` and the SEA public-key `.` separator. The forbidden
  path-character rule applies to derived path keys and slash-separated ACL and
  object templates, with the specified `~pub` template exempted.
- The current-key-at-issuance requirement needs explicit authenticated history.
  The APIs expose that context; record signatures never select their own key.
  Sequences start at one without gaps. Duplicate copies of the same signed
  transition are idempotent. Rotations take effect after their timestamp, so a
  same-second revocation uses the preceding key and blocks recovery.
- Proof verification alone cannot establish global freshness, discover omitted
  revocations, fetch trusted JWKS, authorize enrollment, or consume a nonce.
  The later storage/authentication callers must supply those guarantees.
- Build/test tooling imports Node built-ins; the published browser runtime does
  not. The packed consumer example stays within `typescript/ids/` so the first
  PR leaves existing caller surfaces untouched.

References for protocol details: [EIP-4361](https://eips.ethereum.org/EIPS/eip-4361),
[EIP-55](https://eips.ethereum.org/EIPS/eip-55),
[OIDC Core subject identifiers](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).

## Review amendment and legacy audit

The [0.6 normative amendment](identity-review-amendment.md) supersedes the original
proof/URL contract where stated. Wallet/revoke timestamp witnesses, v2 rotation
credential binding, witnessed pre-rotation revocations, current-key offline
present revocation, OIDC-only recovery,
mandatory historical context, diagnostics, exact SIWE policy and deterministic
URL validation are implemented in #57; no production signer/consumer uses them yet.

Source audit of s3r.ch `lib/rooms.ts` and `lib/chat.ts`: default entropy is eight
lowercase hex digits and current second timestamps fit the legacy grammar.
`encodeKeySafe` only removes `. # $ [ ]`; caller-provided entropy can still contain
uppercase letters, slash, percent, Unicode or more than 64 characters. Supplied
negative or 13-digit timestamps also fall outside the grammar. These historical
values must not be silently repaired or widened into authorization identifiers.
Before the consumer migration, inventory actual persisted IDs with
`node typescript/ids/scripts/audit-legacy.mjs < exported-ids.jsonl` (one JSON string
or object with an `id` per line). Preserve rejected records read-only and design
an explicit mapping with ownership evidence. No persisted production graph was
available for this source audit, so actual prevalence remains unmeasured.
