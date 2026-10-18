# Changelog

## Encrypted discovery — unreleased

- Add a passphrase recovery copy of the account keyring
  (`sociacl-recovery-copy-v1`). Argon2id is pinned to RFC 9106's second
  recommended option (`m=64` MiB, `t=3`, `p=4`, version `0x13`, 32-byte
  output) as both the floor and the ceiling. Salt is 16 through 64 bytes.
  Open refuses a header outside that constant before the KDF. Refs #64.
- Associated data binds the domain, the `PrincipalId`, the keyring version,
  the KDF parameters, and the salt. A wrong passphrase and tampering share
  `recovery-rejected`. A decrypted copy of another version is
  `recovery-stale`.
- `rotateAndReseal` / `rotate_and_reseal` writes a new copy for the new
  version. The store keeps ciphertext only.
- Deliver the keyring to a device through the account-key wrap. The device
  inherits the one keypair and does not mint an identity.
- Refuse a serialized keyring over 256 KiB before seal and before decrypt,
  and apply that length check to the recovery envelope before decrypt. The
  cap is a fixed byte limit. It is not a count of prior lanes.
- The TypeScript KDF is hash-wasm, a single-threaded WASM build. `p=4` runs
  its lanes one after another, including in a browser. Mobile uses the same
  64 MiB Argon2id parameters.
- Normalize a passphrase string to Unicode NFC, then UTF-8, against Unicode
  16.0.0. Code points unassigned in that version are `recovery-params`
  before NFC. Whitespace is one explicit set in both languages and includes
  U+0085. Empty and whitespace-only passphrases are `recovery-params`.
- A recovery `put` refuses a lower `rotationSeq` (`store-rejected`). An
  equal sequence replaces that row. A higher sequence is stored as pending
  and does not replace the current copy until `commitRecoveryCopy` /
  `commit_recovery_copy` sees the rotation in the trusted chain. Adapters
  replace a row atomically and only forward.
- Key the wrap store by principal and wrap id, so a second device delivery
  keeps the first. **Breaking for adapter authors:** `KeyWrapStore.get` /
  `get_wrap` now takes a wrap id, and `list` / `list_wraps` was added.
  A principal holds at most 64 wrap rows. A wrap id stays in the class that
  first stored it (`genesis` or `delivery`); a delivery cannot replace the
  genesis backup's wrap id.
- Verify a delivery signature before parsing the plaintext. `recovery-stale`
  is returned only when that signature also verifies under the key that was
  valid at the older sequence. Codec failures on the delivery path are
  `wrap-rejected`. Delivery uses `sociacl-keyring-delivery-v1` and
  `sociacl-keyring-delivery-sig-v1`.
- The recovery plaintext cap does not grow with the salt. `RECOVERY_ENVELOPE_MAX`
  is 262205. The pre-parse ceiling `RECOVERY_ABSOLUTE_MAX` is 262269.

## sociacl-ids 0.8.0 — unreleased

This version is still untagged, so the witnessed genesis-epub binding lands
here rather than in a later version. It replaces the unwitnessed
`ResolutionContext.genesisEpub` input. Gun `user.epub` is never read.

- Add a `genesis-epub` record. The genesis key signs domain
  `sociacl-genesis-epub-v1` over principal, epub, and issuedAt. Panopticon
  attests it with typ `sociacl-genesis-epub-attest-v1`, and `iat` must equal
  `issuedAt`. No wallet or Keycloak proof is required. The epub must be a
  canonical on-curve SEA point and must not equal the genesis pub. Panopticon
  attests at most one binding per principal, and only at signup
  (panopticon#499). Two validly attested bindings freeze the account with
  `rotation-fork`.
- With no accepted rotation, `currentEpub` is the witnessed binding's epub, or
  null when there is none. A binding issued at or after the first accepted
  rotation is skipped with `bad-sequence`. Once a rotation is accepted, that
  binding epub joins the reuse set inside `resolveCurrentKey`.
- `checkRotationPublish` authenticates the candidate before Panopticon
  attests it. A signed candidate with no attestation is checked by
  `verifyRotationRequest` / `verify_rotation_request`, then this function
  applies chain sequence, sibling forks, and epub reuse. Panopticon must
  call `checkRotationPublish`; the request helper does not check those.
  The request helper refuses v2 and any present `attest`. It requires
  `|issuedAt - now| <= clockSkewSeconds` and applies present revocation
  (`verifyRevokeNow`) to the authorizer and every retained link, in addition
  to the historical check. A witnessed revoke is `rotation-conflict`. An
  unwitnessed current-key revoke is `revoked-link`. A request outside the
  window is `expired` or `future-record`. Siblings count only when the
  next-key signature and the full Panopticon claim both verify (`auth`,
  `linkId`, `retainedLinks`, and the exact claim shape), checked as of the
  sibling's `issuedAt`, so an expired sibling still forks. Junk and
  unattested siblings are skipped. An identical attested sibling is a retry
  and is not a fork. Priors are the rotations `resolveCurrentKey` accepts. A
  distinct authenticated sibling at the same (principal, seq) is
  `rotation-fork`.
- An unsigned draft (no `nextSig`, `authorizer`, or `attest`) is
  `bad-record` from `checkRotationPublish`. Draft validation is
  `checkRotationDraft` / `check_rotation_draft`, and only the keyring
  builder calls it. A draft's `retainedLinks` still use the signed-record
  rule. An identical attested sibling of that draft is a retry.
- Freshness and present revocation apply only to an unattested request.
  An attested `checkRotationPublish` and `verifyRotate` do not use that
  window. `verifyRotate` checks the attestation as of `issuedAt`, so a
  historical record still verifies after the witness window. The `issuedAt`
  upper bound against `now` remains.
- An unattested OIDC recovery also treats a wallet linked at or before
  `now + clockSkewSeconds` as active (`wallet-required`), including a wallet
  enrolled after the request's `issuedAt`. Attested checks stay as of
  `issuedAt`.
- Present revocation of an unattested request honors `clockSkewSeconds`.
  An offline revoke dated at or before `now + skew` removes the link.
  A revoke dated further ahead is ignored. Historical witnessed checks,
  history admission, and direct `verifyRevokeNow` stay skew-free. The
  request path passes `now + skew` as that present horizon.
- Incrementing `contentEpoch` past `2^53 - 1` is `content-epoch`. A lane id
  is never reused: the keyring keeps every prior lane and refuses a mint of
  the current lane or any of them. Import restores that list
  (`priorLanes` / `import_with_prior_lanes`). Lane ids stay off Gun.
- Authenticated reader-wrap plaintext that is not length-prefixed is
  `wrap-rejected`, and that plaintext is zeroed. Constructing
  `AccountKeyring` without the module seal is `bad-construction`.
- A binding counts toward the two-binding `rotation-fork` only when its
  `issuedAt` is strictly before the first accepted rotation. A later binding is
  skipped with `bad-sequence` and does not freeze a rotated account. With no
  accepted rotation, every valid binding counts. The binding's `issuedAt`
  must be at or before `now` plus the policy clock skew. Its attestation is
  verified as of `issuedAt`, so a binding does not expire after 15 minutes.
- `verifyGenesisEpubRequest` / `verify_genesis_epub_request` checks a
  genesis-epub request before Panopticon attests it: shape, epub canonical
  and distinct from the genesis pub, genesis-key signature, and
  `|issuedAt - now| <= clockSkewSeconds`. A present `attest` is
  `bad-record`. Panopticon still refuses the binding when any rotation
  exists.
- A rotation draft validates `retainedLinks` with the signed-record rule:
  sorted, unique, 64-hex, at most 1024.
- Add shared probes for a valid binding, a bad signature, a bad attestation,
  `iat` not equal to `issuedAt`, a binding issued after the first rotation, two
  attested bindings, a binding epub equal to the genesis pub, a later
  `nextEpub` that reuses the binding, an ignored unwitnessed `genesisEpub`, a
  forged sibling, a junk sibling, and a bad-signature prior.

## sociacl-ids 0.7.0 — merged, not tagged

- Add Rotate v3. A rotation that carries `nextEpub` signs `sociacl-rotate-v3`
  with that SEA point immediately after `nextKey`, and its Panopticon
  attestation is `sociacl-rotate-attest-v3` with the same claim. v2 records,
  which omit `nextEpub`, keep their signing bytes and attestation.
- `resolveCurrentKey` / `resolve_current_key` returns `currentEpub` from each
  accepted rotation. A v3 rotation sets it to that `nextEpub`. A v2 rotation
  sets it to null, including a v2 rotation that follows a v3. Null means the
  encryption public key is unknown: do not seal, and never fall back to Gun's
  `user.epub`. With no accepted v3 rotation, `currentEpub` stays null.
- New rotations must be v3. From 0.7, Panopticon attests only v3 and never
  attests both versions for the same principal and sequence. The library still
  verifies historical v2. Publishing both versions of one transition freezes
  the account with `rotation-fork`.
- Reject a `nextEpub` that equals `nextKey`, genesis, any prior signing key,
  or any prior epub, and reject a later `nextKey` that equals a prior epub,
  with `bad-sequence`.
- Add shared accept and reject vectors for a v3 rotation, a tampered
  `nextEpub`, a missing attestation claim, a malformed point, a signature
  over the v2 byte string, epub reuse, and a v2 rotation that clears the epub.

## sociacl-ids 0.6.0 — superseded before release

- Resolve rotation copies by signing-byte ID. A fully verified copy satisfies
  its ID despite damaged duplicates; unresolved authenticated IDs still fail
  closed, and distinct verified IDs still freeze with `rotation-fork`.
- Preserve authenticated rotation evidence when its unsigned SIWE proof is
  missing or malformed, preventing proof stripping from restoring a retired key.
- Require callers to retain verifying link-map copies and explicitly require
  Panopticon present-revocation checks before attestation. Clients and Panopticon
  must exclude present-revoked credentials from rotation retention.
- Add shared duplicate-proof and caller pre-attestation regressions; deprecate
  the historical `*AtKey` compatibility aliases without changing their behavior.

## sociacl-ids 0.5.0 — superseded before release

- Add explicit present-time `verifyRevokeNow` / `resolveWalletLinkNow` APIs
  (Rust snake_case equivalents). Revokes signed by the final authenticated
  current key need no Panopticon witness for present eligibility.
- Make revoke `attest` optional on the wire while requiring and validating it
  in every historical/as-of and rotation check. Preserve signing bytes and IDs.
- Unwitnessed revokes stop applying when their signer retires; no saved-state
  persistence or timestamp inference across retirement is implemented.
- Add shared present/history/retirement regressions and exercise the exported
  APIs and optional field in the installed-tarball consumer.

## sociacl-ids 0.4.0 — superseded before release

- Freeze authenticated rotation/revocation contradictions with `rotation-conflict`,
  including a compromised witness backdating revokes signed by a retired key.
- After authenticating a rotation signature and attestation, fail with
  `missing-history` when authorizing or retained credential evidence is missing
  or cannot verify. Never silently discard that rotation and return an older key.
- Freeze witnessed wallet-ownership and OIDC-eligibility contradictions during
  history resolution. Preserve diagnostics-only handling of unauthenticated junk.
- Add shared rollback regressions and clarify complete-history, latest-state
  checkpoint and Panopticon availability requirements.

## sociacl-ids 0.3.0 — superseded before release

- Authenticate relevant link witnesses before requesting history; reject or skip
  unrelated, future and forged index records without fetching their history.
- Enforce pre-rotation revocations for every retained credential. Require a
  timestamp attestation on revokes to prevent retired-key rollback on replay.
- Bind the authorizing link and kind into rotation v2 signing bytes and
  attestations. OIDC recovery requires an enrolled, retained, unrevoked OIDC
  credential and no active wallet, with explicit issuer pinning in the context.
- Reject noncanonical did:web ports, encoded unreserved/control URL bytes and
  nonalphabetic final hostname labels. Add shared attack regressions and update
  the normative contract and migration prerequisites.

## sociacl-ids 0.2.0 — superseded before release

- Require Panopticon wallet timestamp attestations and sorted retained-link
  commitments in rotation signatures and attestations. Require authenticated key
  state and reject backdated retired-key revocations and unretained credentials.
- Skip malformed/forged history entries with diagnostics; freeze valid forks;
  resolve external accounts using authenticated history and make equal-time
  wallet bindings deterministic.
- Replace runtime URL parsers with a shared strict ASCII grammar and remove the
  vulnerable `url`/`idna` dependency. Pin SIWE domain/URI/chain; cap attestation
  lifetime and bound optional clock skew.
- Complete TypeScript/Rust parsing API parity, add shared review regressions,
  test packed consumers with an empty cache, and separate release write access
  from package execution. Releases require protected-master ancestry.

## sociacl-ids 0.1.0 — superseded before release

- Add browser/Node ESM `sociacl-ids`, optional Zod adapters, and the
  `sociacl-ids` Rust crate with canonical identity types, path keys and souls.
- Add domain-separated signing bytes, wallet/OIDC link proofs, ES256
  attestations, key rotation/fork detection and credential revocation checks.
- Add shared TS/Rust vectors, property/fuzz/million-mint tests, browser and
  installed-tarball checks, and an `ids-v*` GitHub Release asset workflow.
- Preserve existing callers. Track their implementation sequence in
  `docs/identity-migration-roadmap.md`.

The ids package versions independently of the existing SociACL packages.
Changes to an accept/reject vector, grammar, or signing domain bump MINOR while
below 1.0 and MAJOR from 1.0 onward. Record those changes here before publication.
