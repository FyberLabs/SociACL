# Changelog

## sociacl/gun — unreleased

- Anyone with Check see on a forum need may resolve it. A stated or ham update is accepted only when that Check allows the writer on that need id. An extra chat tag that contains a comma is rejected.
- Forum souls on the s3rch graph. Status is `s3rch/forums/<forumId>/agents/<seaPubkey>` with per-agent `started`, `tokens`, and `runtime`. The template is `distinct-principals` or `role-labels`. Chat is a `GunFeedNode` under `s3rch/items` tagged `forum:<forumId>`. The global alarm is status-tile fan-in and a pinned need at `…/alarm`. Resolve is a dest-ACL write and does not elect. Identity stays the GunDB SEA pubkey. Vectors: `vectors/mesh/forums.json`.
- Pushes to protected `master` create an absent `ids-v*` or `sociacl-v*` tag with `github.token`, then pack and attest that family's npm tarball. `sociacl-v*` does not pack crates or Python. Python has no package version. Tag and pack jobs are not in a concurrency group, so a later push cannot cancel the pack for the commit that created the tag. An unprotected `master` skips the tag ([#60](https://github.com/FyberLabs/SociACL/issues/60)). A tag that already names another commit stays where it is.
- **Breaking:** `FeedItem::canonical_key` does not trim the provider item id before `derive_external_id`. `"x"` and `" x"` do not share an `ext_` id. The spaced id is `whitespace`. The vector is `vectors/mesh/strict-id.json`.
- **Breaking:** `sociacl_gun_normalize_url` returns `too-long` when the normalized form exceeds 256 bytes and `buffer-too-small` when the destination cannot hold it. It does not truncate. The Python caller sizes the destination to the input and surfaces that reason. The same vector covers the C and Python callers.
- The forbidden-names audit flags `import`, `require`, and dynamic `import()` of `"crypto"` or `"node:crypto"` under `typescript/src`. `globalThis.crypto`, `crypto.subtle`, and comments stay allowed. Vectors: `vectors/mesh/crypto-import.json`.
- `UrlLeaf::parse` rejects a normalized permalink longer than 256 bytes with `too-long`, the same reason the C and Python callers return. `buffer-too-small` stays a destination-buffer error.
- The forbidden-names audit and the `typescript/src` crypto scan also read `.mjs`, `.cjs`, `.mts`, and `.cts`.
- The Rust migration vector asserts which id field failed to parse (`object`, `owner`, or `caller`).
- `merge-drops-another-predicates-cancel-when-incoming-wins` also asserts that `same-group` stays denied.
- The release tag named by #60 is `ids-v0.10.0`.
- Close-out of the stored-id rebuild. There is no pre-v2 ACL migration.
  PR 7 is dropped. Deleted helpers: `samePrincipal`, `sameParsed`,
  `sameObjectId`, `canonicalAccessorId`, `canonical_accessor_id`,
  `aclPrincipalKey`, `acl_principal_key`, `aclKey`, `acl_key`,
  `encodeKey`, `encode_key`, `escapeKey`, `escape_key`, `unescape`,
  `itemSoulAlias`, `item_soul_alias`, `objectNames`, `object_names`,
  `accessor_names`, `grantNamesObject`, `canonicalStoredObject`,
  `canonical_object_id`, `folded_see`, `folded_post`,
  `reducibleItemInner`, `reducible_item_inner`, `mayAliasToItemSoul`,
  `may_alias_to_item_soul`, `HELD_CLAIM_PREFIXES`,
  `resolve_wallet_or_soul`, `s3rch_user`, `enrollSigner`,
  `enroll_signer`, `asciiTrim`, `ascii_trim`, `principals_match`,
  `principals_are`, `checkSeeLabel`, `check_see_label`,
  `MemorySeeAcl`, `stateSeeGrant`, `state_see_grant`, `gun-legacy`,
  `CLAIM_PREFIXES`, `user_node_id`, `user_node`, `item_segment`,
  `trim_segment`, `add_wallet`, `s3rch_item`, `S3RCH_USERS`,
  `item_key`, `accountGrantSoul`, `account_grant_soul`,
  `GunNode::user`, `GunNode::feed`, `GunSoul::s3rch_item`,
  `GunUserNode::as_node_id`, `sociacl_gun_item_soul`,
  `sociacl_gun_user_soul`. Deleted modules: `typescript/src/legacy/`,
  `crates/sociacl-gun/src/legacy.rs`, `post_label.rs`,
  `crates/sociacl-encdisc/src/gun_soul.rs`. Refused domains:
  `s3rch-post-grant-v1`, `s3rch-access-request-v1`, `s3rch-request`,
  `sociacl-see-grant-v1`, `sociacl-membership-assent-v1`,
  `sociacl-object-set-v1`, `sociacl-cancel-v1`, `sociacl-cancel-id-v1`,
  plus the seven `s3rch:room` / `chat` / `forum-msg` / `post` /
  `forum-group` / `bot` / `forum` object spellings. The see-vector
  tests also reject `node:crypto` in `typescript/src`. CI runs
  `scripts/audit-forbidden-names.mjs` for that list and for
  `node:crypto`. `typescript/ids/scripts/audit-legacy.mjs` is
  deleted. There is no rejected-id inventory to preserve.
  `vectors/mesh/principals.json` is deleted with its label suite.
- **Breaking:** `S3RCH_ITEMS` is crate-private. `GunNodeKind::User`
  and `GunNodeKind::Feed` are deleted. Only `Claim` remains.
- **Breaking:** `ProtocolMigration.object` is an `ObjectId`.
  `MigrationAdmissionInput.owner` and `caller` are `PrincipalId`s.
- A predicate mismatch keeps the winning edge's cancels. The vector
  is `merge-drops-another-predicates-cancel-when-incoming-wins`.
  `snapshot-of-a-cancel-only-tombstone` is an assent-null row that
  still holds a witnessed cancel. `witnessed-cancel-issuedat-rewrite`
  drops the `zz-` prefix. The `mutate-row` step is a no-op in Rust.
- **Breaking:** `closed_object` does not trim. A leading space on
  `s3rch/meta` is not that closed object. The vector is
  `vectors/encrypted-discovery/closed-object.json`.
- **Breaking:** the builders of `s3rch/users/<wallet>` and
  `s3rch/items/<id>` are deleted: `GunNode::user`, `GunNode::feed`,
  `GunSoul::s3rch_item`, `item_key`, `GunUserNode::as_node_id`, and
  the `S3RCH_USERS` export. Those names are on the forbidden-names list.
- `accountGrantSoul` / `account_grant_soul` are deleted. A grant soul
  is `grantSoul` / `grant_soul` only.
- Rewriting `issuedAt` on a witnessed retired-key cancel is
  `bad-attestation`. The vector is `witnessed-cancel-issuedat-rewrite`.
- **Breaking:** `mergeFrom` / `merge_from` store the mode just verified
  on each copied cancel. A present attested copy replaces a bare copy
  of the same id after rotation. The vector is
  `merge-upgrades-a-present-attested-copy-after-rotation`. Merge does
  not recheck rows already in the graph, and it follows the history
  the caller passes.
- **Breaking:** `mergeFrom` / `merge_from` check each incoming assent and
  cancel against this graph's rotation history before copying the row.
  A retired-key stated-1 is not copied back in after `reverifyGroup`.
  The vector is `merge-does-not-revive-a-retired-assent`.
- **Breaking:** a feed item's Check id is `deriveExternalId`. A core-plane
  person is `add_principal(PrincipalId)`. `IdentitySeeGrant` is keyed on
  `ObjectId` and `PrincipalId`. `add_wallet`, claim-prefix sniffing, and
  the item-soul fallback are deleted. A wallet accessor is refused.
- **Breaking:** `parseObjectId` / `parse_object_id` reject an unbound
  `<kind>_<32 lowercase hex>` id. The minted form and `claim_` / `ext_`
  plus 64 hex stay. A guard test rejects that unbound spelling in
  non-test source. The label path is gone: `legacy.rs`, the label test
  modules, `typescript/src/legacy/gun-legacy.js`, and the `GroupGraph`
  label maps. C exports `sociacl_gun_item_soul` and
  `sociacl_gun_user_soul` are deleted. Encrypted discovery no longer
  keeps `gun_soul.rs`. `contract/migration.ts` sorts accessors in UTF-8
  byte order (`vectors/encrypted-discovery/accessor-order.json`).
- A group cancel's signing bytes are the length-prefixed fields
  `sociacl-cancel-v2`, kind (`membership` or `object-set`), row soul,
  cancel id, decimal `issuedAt`, the prior count, then those prior ids.
- **Breaking:** a group set id is a minted ObjectId of kind `set`. The
  signed set owner is the principal embedded in that id. Membership
  assent is `sociacl-membership-assent-v2`, an object-set row is
  `sociacl-object-set-v2`, and a group cancel is `sociacl-cancel-v2`.
  `membershipSoul` and `objectSetSoul` are the ids builders.
  `checkGroupSee` and `checkGroupPresentation` take branded ids.
  `enrollSigner` / `enroll_signer` and Ed25519 signing are gone from
  the group path. `<principal>/<name>` set ids are refused.
  `vectors/mesh/v2/group.json` is the shared group suite, and
  `members-gate-on-stored-id` uses the minted set id.
- **Breaking:** `MemoryGroupGraph` no longer has `putObject`,
  `bindSignedOwner`, or `unbindSignedOwner`, and `mergeFrom` does not
  copy labels. `checkGroupSee` takes the owner from the principal
  embedded in the object id and requires the admitted signed owner to
  match. An object-set merge unions incoming cancels when that
  admitted owner matches and both edges name the same set and predicate.
  A different set or predicate keeps only the winning edge's cancels.
  `reverifyGroup` rechecks the signatures it
  stored at admission, including object-set cancels. A replacement
  object-set edge for a different set does not keep the previous set's
  cancels.
- **Breaking:** `objectSetSoul(owner, object, predicate, set)` is seven
  segments, `s3rch/acl/<pk>/objset/<predicate>/<set>/<object>`. A cancel
  signed over that soul cannot move to another set or predicate. The
  soul parser accepts 509 characters, the longest object-set soul.
- **Breaking:** a group cancel's signing bytes include the canonical
  decimal `issuedAt`. A witnessed copy of an existing cancel replaces
  the stored bare copy, on admission and on merge. `reverifyGroup`
  drops a retired stated-1 object-set assent and keeps a witnessed
  cancel on that record. A replacement edge keeps prior cancels only
  when the set and the predicate both match. A one-sided stated-1
  membership is not a snapshot removal. `parseSoul` accepts a
  membership soul only when the owner key is the principal embedded
  in the set id.
- **Breaking:** `snapshotUnderstatesGroup` treats an object-set edge
  that is not live as a removal. A stated-1 snapshot understates that
  cancel. A stated-0 snapshot at a hamState at least as high as the
  stored assent does not.
- `parseSoul` accepts an object-set soul only when the set segment is a
  minted set id and the owner key is the principal embedded in the
  object. A membership soul's set segment must also be a minted set id.
  A 510-character soul is `too-long`.
- Group rows live on `GroupGraph.rows` (`MeshSeeGraph.group.rows`).
- **Breaking:** `MemoryGroupGraph` no longer keeps a label map.
  `hasObject`, `objectRecord`, `ownerOf`, and `canonicalObjectId` read
  the admitted signed object record. `see.js` does not copy an owner
  onto a label. An object-set row that arrives before that record is
  dropped. `reverifyGroup` drops an unwitnessed retired-key cancel;
  only a witnessed cancel survives.
- **Breaking:** an access request is `sociacl-access-request-v2`. The
  request id is `hex(sha256)` of `sociacl-request-id-v2`, the requester
  `PrincipalId`, and the object `ObjectId`. `grantApprovedRequest` takes
  `(graph, owner, request, window, members, signer)`. The owner signs
  the v2 see row and, for `read+post`, the v2 post row. Both ceilings
  are checked before either row is written. Ed25519 request signatures,
  `node:crypto` in `request.js`, and the alias helpers in `request.js`
  and `request.rs` are gone. `vectors/mesh/access-request.json` is
  replaced by `vectors/mesh/v2/request.json`.
- **Breaking:** `typescript/src/legacy/post-label.js` and
  `crates/sociacl-gun/src/post_label.rs` are deleted, along with
  `cancelLabelPost`, the group post WeakMap, and `LabelGraph`'s post map.
  Rust `LabelGraph::merge_from` no longer copies post rows. A typed post
  row is `admitPost` / `admit_post` only.
- **Breaking (TypeScript):** `sociacl/group` no longer exports
  `POST_GRANT_DOMAIN`, `POST_GRANT_SCOPE`, `postGrantSigningBytes`, or the
  label `postSoul`. `sociacl/gun` still exports `POST_GRANT_DOMAIN`. Its
  value is the v2 domain `sociacl-post-grant-v2`, the ids `POST_DOMAIN`
  constant. `admitPost`, `postGrantBytes`, and the typed `postSoul`
  (`p_` plus 128 lowercase hex) are the public post signing surface.
  `postSoul` throws when an argument is not an already-parsed id.
- **Breaking (Rust):** `sociacl_gun` no longer exports
  `post_grant_signing_bytes`, `post_soul`, `GunPostEdge`, `MeshPostGrant`,
  `POST_GRANT_DOMAIN`, or `POST_GRANT_SCOPE`. `post_grants`, `post_edge`,
  `state_post_grant`, `unstate_post_grant`, `merge_post_edge`,
  `GunPostEdge`, and `OwnerGrantRows` are removed with `post_label.rs`.
- `reverifyPosts` takes the rotations `reverifyPrincipal` already
  resolved and does not look them up again.
- **Breaking:** `snapshotRow`, `restoreRow`, `snapshotPost`, and
  `restorePost` are removed. Staged see and post tickets are not
  exported. An approved request resolves owner and requester history
  once, admits both rows against that history, and writes both or
  neither. A row that would not replace is `not-kept`.
- An identical approval returns the stored row with `unchanged: true`
  only after the current key resolves, the scalar owns that key, and
  members allow. The stored row must be signed by that current key.
  A retired-key row is signed again at `hamState + 1`. A different
  window is `hamState + 1`. The window is copied once before it is
  checked. Members auto-approve over an owner cancel is `not-kept`.
  A manual approval re-grants above that cancel.
- `admitRow` and `admitPost` take a resolver function and always return
  the admitted row. An approved request verifies both rows, then writes
  both in that same call. There is no prepare or commit ticket.
  `checkSee` and `checkPost` allow a row only when its signed object
  and accessor are the ones that were queried.
- **Breaking (TypeScript):** `MemoryGroupGraph` no longer has
  `plantLabelOwnerForTest`. The label map is module-private.
- When `now` equals the latest rotation time, approval returns
  `rotation-boundary` and writes nothing.
- Members auto-approve compares parsed `PrincipalId`s. A signed
  object's label keeps that canonical spelling. The owner shortcut is
  not membership. A peer `putObject` or `mergeFrom` does not replace
  that signed owner.
- Rust `grant_approved_request` and `request_owner` return `Reason`.
- A packed `sociacl` install ships `ids/src`, which `gun` and `group`
  load. The see and post seal sets stay in those modules. Internal
  modules export only the row maps. `reverifyPrincipal` removes the
  group label with the owner record. `admitGrantPair`, `postKeeps`,
  and `admitResolvedPost` take a resolver. Approval copies the resolver
  context once before either row is written.

## Encrypted discovery — unreleased

- Bound recovery/wrap write generations with `STORE_GENERATION_MAX` (9007199254740991). Preflight increments before mutation: the final representable generation remains readable but rejects writes with `store-rejected`. Shared boundary fixtures cover both stores; counters never reset or saturate (#68 F16).

- Document the year-aware seal-time strength policy (#68 F19). A shared synthetic legacy backup restores in both languages despite failing the current strength gate; new seals still reject its weak passphrase. TypeScript additionally verifies opening at two simulated wall-clock years.

- Add `resolveStoreAccount` / `resolve_store_account` for adapter resolver callbacks. They verify raw history through the identity resolver, preserve diagnostics, and map failed resolution to `store-rejected` before a store observes a head. Production source freshness, trusted policy, and durable floor enforcement remain adapter responsibilities (#68 F14/F16).

- The see path takes stored ids only. `checkSee` / `check_see` have no string
  parameter and no label fallback. A string is the edge parser's reject.
  `CheckObjectId` is `ObjectId` and `AccessorId` is `PrincipalId`. The
  group, feed, and contract-migration copies of those helpers are deleted
  (`typescript/src/legacy/`, `crates/sociacl-gun/src/legacy.rs`). The #55
  rebuild spec is not in this repo; that schedule is also in
  `docs/s3rch-check.md`. `vectors/mesh/forbidden-names.json` scopes the
  banned names to `typescript/src`, `typescript/contract`, `sociacl-gun`,
  `sociacl-encdisc`, and `docs/s3rch-check.d.ts`. `typescript/src` does
  not reference `node:crypto`.
- `parseSeeGrant` / `parse_see_grant` and `seeGrantBytes` / `see_grant_bytes`
  snapshot a `sociacl-see-grant-v2` row. A missing signature or a wrong
  domain is `legacy-row`. `stated` is the exact integer 0 or 1. `parseObjectRecord`
  / `parse_object_record`, `objectRecordBytes` / `object_record_bytes`, and
  `verifyObjectRecord` / `verify_object_record` cover domain `sociacl-object-v2`.
  An object record is valid only when the object id embeds that owner.
  A mismatch is `bad-record` and does not freeze the object. After a
  rotation, `reverifyPrincipal` drops an object record the current key
  does not sign. The same owner can replace that stored record with one
  the current key signs.
- Derive a per-contact inbox lane with HKDF-SHA256 from a contact-lane
  secret that is not the disclosed base `laneId`. Info is length-prefixed
  `sociacl-contact-lane-v1`, version `1`, the recipient, then the sender.
  Salt is 32 zero bytes. Output is 32 bytes. The secret rotates with the
  keyring and keeps its own prior list. Recovery and delivery carry it
  inside the existing keyring plaintext. The recipient signs the lane id
  and encrypts that signature under `sociacl-contact-lane-grant-v1`. The
  outer envelope is the ciphertext. A null `currentEpub` is `epub-unknown`.
  Open failures are `lane-grant-rejected`. Storage indexes the lane id hex
  alone. Refs #64. Follow-ups #70 and #71. #70 inherits this confidential
  channel. Account creation is the only mint of that secret. Import
  refuses a missing contact-lane history with `keyring-rejected`. A second
  device receives the secret through keyring delivery, including at
  sequence 0. The genesis backup does not carry it. The keyring plaintext
  domain is `sociacl-keyring-plain-v2`, and `sociacl-keyring-plain-v1` is
  refused.
- Add a passphrase recovery copy of the account keyring
  (`sociacl-recovery-copy-v1`). Argon2id is pinned to RFC 9106's second
  recommended option (`m=64` MiB, `t=3`, `p=4`, version `0x13`, 32-byte
  output) as both the floor and the ceiling. Salt is 16 through 64 bytes.
  Open refuses a header outside that constant before the KDF. Refs #64.
- Associated data binds the domain, the `PrincipalId`, the keyring version,
  the signing public key, the encryption public key, the KDF parameters, and
  the salt. A wrong passphrase and tampering share `recovery-rejected`. A
  decrypted copy of another version is `recovery-stale`.
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
  TypeScript `encodePassphrase` throws `unicode-version` when the runtime's
  NFC is older than Unicode 16. The probe is U+11382 U+113C9 composing to
  U+11383.
- **Breaking for adapter authors:** every recovery-store and wrap-store
  `put`, `commit`, and `delete` is a signed compare-and-swap on
  `sociacl-store-write-v1`. The store does not take the chain from the
  writer. The adapter injects a resolver, and the store reads the published
  head itself. Panopticon fills that resolver from the Gun chain. The signed
  message is the domain, the `PrincipalId`, the operation, the target, the
  envelope or ciphertext hash, the decimal head, the hash of the row being
  replaced or `none`, the wrap class or `none`, and a per-principal write
  generation. The monotonic floor records every head the resolver reports,
  not only accepted writes, and one floor is shared by the recovery store
  and the wrap store. A pending recovery sequence is not part of the floor.
  A write whose resolved head is below that floor is `store-rejected` and
  changes nothing. A rejected commit leaves
  the pending copy in place. A recovery `put` is accepted only at the
  resolved head, which replaces the current copy and drops any pending
  copy, or at head + 1, which is the only pending copy. Any other sequence
  is `store-rejected`. Commit promotes a pending copy only when its public
  keys equal the resolved current key. A fork stays pending. A signed
  rotation that is not on the published chain stays pending.
  `deleteRecoveryCopy` / `delete_recovery_copy` and `deleteAccountWrap` /
  `delete_account_wrap` use the same signature. Deleting the current
  recovery copy does not promote a pending copy. The genesis backup wrap
  can be replaced, never deleted. The 64-row cap stays. The wrap class is
  covered by the store-write signature. Openers ignore it. Refs #64.
- Seal refuses a weak passphrase with `recovery-weak-passphrase`. The gate
  requires 12 visible code points after NFC, rejects Unicode 16
  default-ignorable and format characters, and requires a zxcvbn score of
  at least 3. TypeScript uses `@zxcvbn-ts/core` 4.2.0 with the English
  dictionary. Rust uses `zxcvbn` 3.1.1. The score is advisory between the
  two. Open does not run the gate. The error returns the score and feedback
  and does not contain the passphrase. Refs #64.
- Import and seal refuse a keyring unless `priorLanes.length` equals
  `rotationSeq` (`bad-lane`). That is SociACL#68 F1 for this path. Refs #64.
- Key the wrap store by principal and wrap id, so a second device delivery
  keeps the first. **Breaking for adapter authors:** `KeyWrapStore.get` /
  `get_wrap` now takes a wrap id, and `list` / `list_wraps` was added.
  A principal holds at most 64 wrap rows. A wrap id stays in the class that
  first stored it (`genesis` or `delivery`); a delivery cannot replace the
  genesis backup's wrap id.
- Verify a delivery signature before parsing the plaintext. `recovery-stale`
  is returned only when that signature also verifies under the key that was
  valid at the older sequence. That key is chosen by each rotation record's
  `seq`, not by array position. `recovery-stale` is not proof the delivery
  is genuine. Codec failures on the delivery path are `wrap-rejected`.
  Delivery uses `sociacl-keyring-delivery-v1` and
  `sociacl-keyring-delivery-sig-v1`.
- The TypeScript wrap store copies a row on put, get, and list. The wrap
  class is a field of the store-write signature, and openers ignore it.
- The recovery plaintext cap does not grow with the salt. `RECOVERY_ENVELOPE_MAX`
  is 262205. The pre-parse ceiling `RECOVERY_ABSOLUTE_MAX` is 262269.

## sociacl-ids 0.10.0 — unreleased

0.10.0 is the next minor after the still-untagged 0.9.0. The release tag
is `ids-v0.10.0`.

- `prepareRetainedLinksNow` / `prepare_retained_links_now` authenticates
  candidate link ids and drops those revoked under the final current key.
- `resolveOidcLinkNow` / `resolve_oidc_link_now` is the present OIDC
  counterpart of `resolveWalletLinkNow`.
- `verifyingLinkMap` / `verifying_link_map` groups copies by signing-byte
  id and keeps one that verifies. A tampered duplicate does not produce
  `missing-history` when a verifying copy is present.
- A wallet rotation with `nextEpub` requires `sociacl-rotate-attest-v4`, the
  v3 claims plus `siweHash` over the SIWE proof. A v3 wallet attestation or a
  hash mismatch is `bad-attestation`. OIDC stays on v3. A rotation without
  `nextEpub` stays v2. Signing bytes are unchanged.
- Resolution lists, link maps, revocation lists, and genesis-epub bindings
  longer than 1024 are `too-long`. Nothing is truncated. `verifyRotate` and
  `verifyRotationRequest` use the same cap.
- A link signed by the new key in the same second as a rotation is
  `bad-signature`. `historyState` still names the preceding key.
- The `*AtKey` aliases are removed. Use the canonical names.

- A new object id embeds its creator's genesis principal:
  `<kind>_<principal-key>_<32 lowercase hex>`. The principal key is the
  existing `p_` + 128 lowercase hex form. The 32 hex digits are a fresh
  128-bit nonce from `mintObjectId(kind, creator)` /
  `mint_object_id(kind, creator)`. Parsing a bound id returns exactly
  that principal through `objectPrincipal` / `object_principal`. The
  longest id is 180 characters, so the path-key maximum is 180. An
  object record whose owner is not that principal, or whose id has no
  embedded principal, is `bad-record`. The older `<kind>_<32 hex>` form
  still parses and is not an object record. The s3r.ch object
  spellings (`s3rch:room`, `s3rch:chat`, `s3rch:forum-msg`,
  `s3rch:post`, `s3rch:forum-group`, `s3rch:bot`, `s3rch:forum`) are
  removed from the grammar. Network ids `s3rch:https://...` stay.
  `post` is a reserved kind. `s3rch:forum:<owner>` has no nonce, so a
  forum id needs a random part when s3r.ch adopts SociACL. Those seven
  spellings parse as `bad-alphabet`. A non-string `owner`, `object`, or
  `accessor` on a see or post row is `not-string`. `unknown` is the reason
  when a post row has no admitted object record. Rust `Reason` is
  `#[non_exhaustive]` and includes `Reason::Unknown`.
- `parsePostGrant` / `verifyPostGrant` and `parse_post_grant` /
  `verify_post_grant` cover `sociacl-post-grant-v2`. A retired cancel
  is `stated` 0 in those signed bytes. A retired `stated` 1 row is
  refused. An uppercase `P_` tag on a bound object id is `non-canonical`.
- `requestId` / `request_id` and `parseAccessRequest` /
  `parse_access_request` cover `sociacl-request-id-v2` and
  `sociacl-access-request-v2`. The request id is the hash of the
  requester and the object. An empty message is allowed. A wrong
  domain or a missing signature is `legacy-row`. `verifyAccessRequest`
  / `verify_access_request` uses `verifySignedAt` / `verify_signed_at`.
  A retired key is refused. A missing or non-string `scope`, `status`,
  `message`, `requester`, or `object` is `not-string` in both languages.
  `historyState` still uses the preceding key for a same-second revoke.
  The new key signs records strictly after the rotation timestamp.
  `Reason` adds `withdrawn`, `owner-mismatch`, `not-member`,
  `see-ceiling`, `post-ceiling`, `not-kept`, and `rotation-boundary`.
  The package version stays 0.10.0.

## sociacl-ids 0.9.0 — unreleased

0.9.0 was not tagged. New ids work from that cut is recorded here. The
release tag moved to `ids-v0.10.0`.

- Export the shared length-prefix encoder `lengthPrefixed` / `length_prefixed`.
  Integer fields are decimal strings. The public encoder accepts only real
  strings, rejects lone surrogates, and rejects a field of 4 GiB or more
  instead of truncating its length. It reads `length` once and validates each
  element as it goes, so a sparse array stops at the first hole. A throwing
  length or element access is `bad-record`. Valid strings stay byte-identical
  to the post and request copies.
- `verifyKeySignature` / `verify_key_signature` checks a SEA P-256 signature
  over SHA-256. The signature is raw r||s, base64url. High-S and low-S both
  verify. `signWithKeyring` / `sign_with_keyring` signs a 32-byte SEA scalar
  only when its public key equals the expected current key. The working copy
  of the scalar is wiped. Bad key material is `bad-key`.
- `verifySignedAt` / `verify_signed_at` takes the principal, rotations,
  resolution context, bytes, signature, and `issuedAt`. It does not take a
  kind or an attestation. It resolves the current key first and returns that
  failure unchanged. A negative or fractional `issuedAt` is `bad-record`.
  Clock skew must be an integer from 0 through 300. `issuedAt` past `now`
  plus that skew is `future-record`. A present key returns
  `{key, mode: "present"}`, or `bad-signature` when the signature fails.
  Every retired-key row passed to `verifySignedAt` is
  `unwitnessed-retired-key`. That function stays kind-free. A see cancel is
  `verifySeeGrant` / `verify_see_grant`: one parse, then the signing bytes,
  and a retired row counts only when those bytes are `sociacl-see-grant-v2`
  with `stated` 0 and the attestation matches them. `sociacl-cancel-v2` is
  the later group-cancel domain. `mode: "witnessed"` is that see-cancel result.
  `parseSeeGrant` / `parse_see_grant` and `seeGrantBytes` / `see_grant_bytes`
  are that snapshot. A missing signature or a wrong domain is `legacy-row`.
  `stated` is the exact integer 0 or 1, so `-0` is `bad-record`. An
  attestation on a current-key row is capped at 16384 characters.
  `parseObjectRecord` / `parse_object_record`, `objectRecordBytes` /
  `object_record_bytes`, and `verifyObjectRecord` / `verify_object_record`
  are the `sociacl-object-v2` owner record. A retired key is
  `unwitnessed-retired-key`. A missing signature is `bad-signature`. A null
  or numeric signature is `not-string`.
- `verifyAclAttestation` / `verify_acl_attestation` checks claim type
  `sociacl-acl-attest-v1`. The token is capped at 16384 characters before it
  is parsed. The claim is exactly `{typ, principal, recordId, iat, exp}`,
  `iat` equals `issuedAt`, and `exp - iat` is at most 900. It is verified
  like the other attestations against `ctx.jwks` with `now` set to
  `issuedAt`. Nothing in this package issues the claim.
- Add `membershipSoul` (seven segments) and `objectSetSoul` (five segments),
  and the matching `parseSoul` templates. The Rust predicate is an enum.
  `post`, `member`, and `objset` are reserved native kinds and mint or parse
  as `reserved-kind`. The legacy form `s3rch:post:<eip55>:<ts>:<hex>` is
  accepted read-only. Its wallet and timestamp are not read out.

## sociacl-ids 0.8.0 — unreleased

0.8.0 is still untagged. The witnessed genesis-epub binding is recorded in
this version. Later ids changes are 0.9.0. It replaces the unwitnessed
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
