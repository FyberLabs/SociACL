# sociacl-ids

Canonical identity boundaries and credential proofs for SociACL, s3r.ch and
Panopticon. Browser ESM and Node.js 24+. Runtime dependencies are
`@noble/curves` and `@noble/hashes`; the optional `sociacl-ids/zod` export uses the
consumer's Zod 4 peer. No Node built-ins occur in the runtime dependency graph.

The stable account identity is the **genesis SEA P-256 public key**. Wallets and
tenant-scoped OIDC subjects are credentials linked to that identity. Names,
labels, handles, email addresses and wallet text are never account join keys.

```ts
import {
  parsePrincipalId, mintObjectId, grantSoul,
  type PrincipalId, type ObjectId,
} from 'sociacl-ids';

const owner = parsePrincipalId(untrustedGenesisPublicKey);
const accessor = parsePrincipalId(untrustedAccessorPublicKey);
if (!owner.ok || !accessor.ok) throw Error('invalid identity');
const object = mintObjectId('room', owner.value);
if (!object.ok) throw Error('invalid identity');
const soul = grantSoul(owner.value, object.value, accessor.value);
// s3rch/acl/p_<point hex>/room_p_<creator hex>_<128-bit nonce>/p_<point hex>
```

Parse once at an untrusted edge; carry the brand through the core. Stored values
are never trimmed, lowercased, escaped, inferred from a soul, or repaired.
Equality is `===`. `parseWalletInput` is the only UI conversion: it accepts an
all-lower/all-upper hexadecimal address and returns its exact EIP-55 form.
`parseEip55` accepts only that exact form, including addresses whose checksum
naturally consists entirely of lowercase or uppercase letters.

The Rust equivalent is `crates/sociacl-ids`. Its private-field newtypes validate
`FromStr`, `TryFrom<&str>` and serde deserialization. `OidcCredential` has a
canonical JSON `Display`/`AsRef<str>` representation; wire input is still an
object. Rust cannot represent an unpaired UTF-16 surrogate in `str`;
`parse_json_input` rejects that case at the JSON boundary.

## API

| Surface | Exports |
| --- | --- |
| Edge parsers | `parsePrincipalId`, `parsePrincipalKey`, `parsePathKey`, `principalFromSec1`, `parseJsonInput`, `parseEip55`, `parseWalletInput`, `parseTenantId`, `parseOidcCredential`, `parseObjectId`, `parseNetworkId`, `parseSourceKey`, `parseSoul` |
| Keys | `formatPrincipalKey`, `formatWalletKey`, `formatOidcKey`, `formatNetworkKey`, `formatSourcePathKey`, `objectKey` |
| Souls | `objectSoul`, `userSoul`, `aclSoul`, `grantSoul`, `postSoul`, `membershipSoul`, `objectSetSoul` |
| Creation | `mintObjectId`, `deriveClaimId`, `deriveExternalId` |
| Signing | `lengthPrefixed`, `signingBytes`, `linkId`, `verifyKeySignature`, `signWithKeyring` |
| Proofs | `verifySignedAt`, `verifyAclAttestation`, `verifyWalletLink`, `verifyOidcLink`, `verifyRotate`, `verifyRotationRequest`, `verifyGenesisEpubRequest`, `verifyRevoke` |
| Present eligibility | `verifyRevokeNow`, `resolveWalletLinkNow`, `resolveOidcLinkNow`, `prepareRetainedLinksNow` |
| Link map | `verifyingLinkMap` |
| Histories | `resolveCurrentKey`, `resolveWalletLink`, `historyState`, `checkRotationPublish`, `checkRotationDraft` |

Every parser/verifier returns `{ok:true,value}` or `{ok:false,reason}`. Scalar
parsers check the input type before examining it. Object parsers snapshot own
data properties, reject accessors and unknown fields, and never coerce an
object into an identifier. Returned records and nested credentials are frozen.

Souls have fixed templates. `parseSoul` is the only inverse; object results
include `[collection, objectId]`, user/ACL results `[principal]`, grant/post
results `[owner, objectId, accessor]`, membership results
`[owner, predicate, setObjectId, accessor]`, and object-set results
`[owner, objectId]`. A membership predicate is `same-group` or `named-circle`.
All derived path keys exclude
`/ . # $ [ ] ~ %`. Gun's `~pub` user soul is the explicit exception: the `~`
marker and public key separator are part of Gun's user-space syntax, not a
path key. SHA-256 path keys use domain-separated, little-endian length-prefixed
UTF-8 fields. Hash collision resistance is computational, not a mathematical
claim of injectivity.

New object ids are `<kind>_<principal-key>_<32 lowercase hex>`. The
principal key is the creator's genesis principal as `p_` plus 128
lowercase hex. `objectPrincipal` reads that one principal back out.
`claim_<64hex>` and `ext_<64hex>` still parse. The older
`<kind>_<32 hex>` form is rejected (`bad-alphabet`). The s3r.ch object spellings
do not parse: `s3rch:room`, `s3rch:chat`, `s3rch:forum-msg`, `s3rch:post`,
`s3rch:forum-group`, `s3rch:bot`, and `s3rch:forum` are `bad-alphabet`.
`post` is a reserved kind, so a s3r.ch post cannot use kind `post`.
`s3rch:forum:<owner>` has no random part. A forum id needs a nonce before
it can be an object id. `claim`, `ext`, `post`, `member`, and `objset`
cannot be minted as native kinds. Native mints take the creator and use
`crypto.getRandomValues` (Rust: `getrandom`) for 128 bits.
A path key may be 180 characters.

`SourceKey` ports the canonical SourceRef format from s3r.ch Views. s3r.ch owners
are genesis principals; open protocols retain DID, FID, Nostr key, ActivityPub
actor URI and RSS origin rules. Percent encoding exists only in SourceRef's
wire representation. Its storage key is `s_<sha256>`, never an escaped Gun key.

## Proof verification and caller responsibilities

Signing bytes are `LP(domain) LP(field1) …`, with a 32-bit little-endian UTF-8
byte length on each field. `linkId` is SHA-256 of these bytes and does not depend
on an ECDSA signature. SEA proofs are raw P-256 `r||s` in canonical unpadded
base64url; both high-S and low-S verify. SEA envelopes are not accepted.
`verifySignedAt(principal, rotations, ctx, bytes, sig, issuedAt)`
does not take a kind or an attestation. It resolves the current key first. A present key returns
`{key, mode: "present"}` or `bad-signature`. Every retired-key row is
`unwitnessed-retired-key`. `verifySeeGrant(row, rotations, ctx)` is the see-row
check: it parses once, encodes `sociacl-see-grant-v2` from that value, and
accepts a retired key only when `stated` is 0 and the attestation binds those
bytes. A retired `stated` 1 row is refused even when witnessed.
`mode: "witnessed"` is that result. `sociacl-cancel-v2` is not a see cancel.
A negative or fractional `issuedAt` is `bad-record`.
`clockSkewSeconds` must be an integer from 0 through 300; a larger, non-finite,
or non-numeric skew is `bad-record`. `issuedAt` past `now` plus that skew is
`future-record`. `signWithKeyring(scalar, bytes, expectedKey)` signs only when
the scalar's public key is `expectedKey`, and it wipes its copy of the scalar.
Bad key material is `bad-key`. `lengthPrefixed` reads `length` once, then reads and validates each element once, returning on the first bad field. A throwing length or element access is `bad-record`.

Wallet proofs are EIP-4361 messages signed with EIP-191 `personal_sign`. The
statement is exactly `SociACL link: <signing-byte sha256>`, the address must
match, and the nonce and issuance time are bound to the wallet link. Optional
SIWE expiration, not-before, request-id and resource fields are validated in
order. The record timestamp is a safe, nonnegative integer in seconds; RFC3339
SIWE timestamps must represent the same instant. Leap-second spellings are
rejected. Recovery supports ordinary secp256k1 signatures, including high-S.
There is no RPC or EIP-1271 contract-wallet verification. An unsupported proof
shape returns `unsupported-wallet`; a nonmatching recovered address returns
`bad-signature`.

Panopticon proofs are compact ES256 JWS with a unique `kid` in the **caller-pinned**
JWKS. JWS duplicate JSON members, foreign algorithms, remote-key headers,
unbound claims, wrong key use and expired proofs are rejected. The OIDC issuer
must be an exact member of `pinnedIss`; tenant, subject, principal, timestamp
and nonce must all match. A rotation always requires Panopticon attestation,
including when a wallet authorizes it. This package performs no token fetching,
login, storage, nonce consumption or enrollment.

Every pinned witness JWK now requires `notBefore` and `notAfter`: safe,
nonnegative integer Unix seconds with `notBefore < notAfter`. The shared
verifier requires `notBefore <= iat < notAfter`; missing or invalid metadata
and issuance outside this window return `bad-attestation`. These are trusted
configuration fields, never values copied from an incoming proof. Clock skew
does not expand the key window. Historical verification checks issuance, so
normal key retirement does not erase older proofs. `exp` may extend past the
key window, but the existing 900-second lifetime and request expiry checks
still apply. This is a required caller-configuration change in the unreleased
0.10 package; record signing bytes and JWS claims are unchanged.

Publishers must provide authoritative windows before clients adopt this gate.
Retain old public keys and their original bounds for history; use a new key and
`kid` for each new issuance period. Bounds limit backdating, but a compromised
key can still forge any timestamp within its permitted window. Independent
authenticated checkpoints or additional witnesses are needed to distinguish
such forgeries. See the [witness trust policy](../../docs/identity-review-amendment.md#witness-key-validity-windows).

The 0.6 contract requires wallet timestamp attestations and witnessed revokes
for history, and permits current-key offline revokes for present lookups. Rotation
retention commitments and an enrolled credential are bound into the v2 rotation
signature and attestation. OIDC recovery is limited to accounts with no active
wallet. See the [normative amendment](../../docs/identity-review-amendment.md) for
signing fields, exact claims, grammar, and migration requirements.

`verifyWalletLink(record, jwks, policy, now, keyState)` and
`verifyOidcLink(record, jwks, pinnedIss, now, keyState, clockSkewSeconds?)`
require authenticated `KeyState`. There is no genesis fallback. `keyState.key`
is the signing key active before the record's timestamp; `currentKey` is the
key at the evaluation horizon. `retainedLinks` is `null` when no rotation
followed the record, otherwise the intersection of every later rotation's
retained IDs. Both verifiers reject an unretained link. For a proven unrotated
account, explicitly supply `{key: genesis, currentKey: genesis, retainedLinks: null}`.
Never derive this state from a claimed key inside an incoming record.

`policy` requires exact `allowedDomains`, `allowedUris`, and `allowedChainIds`
arrays. Optional `clockSkewSeconds` defaults to zero and is capped at 300 seconds.
It applies to direct proof issuance/expiration checks; it never changes signing
bytes, timestamp equality, or the exact horizon of history resolution. OIDC
accepts the same optional tolerance as its last argument (Rust:
`verify_oidc_link_with_skew`). Every attestation's lifetime is at most 900 seconds.

`verifyRevoke(record, currentKey, jwks, now)` requires the key current at the
evaluation horizon and a Panopticon timestamp witness bound to the revoke's
canonical signing-byte hash and exact issuance time. Before accepting a rotation,
the verifier authenticates its authorizer and every retained ID and rejects links
revoked at or before that rotation under the preceding current key. A witnessed
revoke that conflicts with the authenticated rotation freezes resolution with
`rotation-conflict`; it never returns an earlier key. This also handles a witness
colluding with a retired key to backdate a revoke. An unwitnessed revoke cannot
affect history. The service assigns witness timestamps and computes retained
sets from authenticated state. Issuing witnessed revokes and rotations requires
Panopticon availability.

`verifyRevokeNow(record, currentKey, now)` needs no witness or JWKS; it checks
present authority under the final authenticated current key. `Revoke.attest` is
optional: omit it for offline revokes. Explicit null, empty or non-string values
are rejected. A supplied witness string is not certified by this present-only
API. The signature still binds principal, target link ID and issuance time.
Direct callers must match those fields to the credential being revoked.

`resolveWalletLinkNow(address, links, revocations, context)` uses that rule for
present wallet eligibility. `resolveOidcLinkNow(cred, links, revocations, context)`
is the same lookup for an OIDC credential (`iss`, `tenant`, `sub`). A current-key offline revoke blocks the newest
binding without resurrecting an older one. **When its signer retires, an
unwitnessed revoke stops applying.** There is no authenticated saved-state
persistence in this API. Remove the link from the retained set, or use a
witnessed revoke consistent with the transition, to preserve removal across
rotation. The same offline revoke is ignored by historical/as-of
`resolveWalletLink`, `verifyRotate` and `resolveCurrentKey`; never use a `Now`
API for a historical query or choose its current key from `issuedAt`.

Panopticon and clients **MUST exclude present-revoked links from `retainedLinks`**
when constructing a rotation. Call `prepareRetainedLinksNow(candidates, context)`.
It authenticates each candidate, drops ids revoked under the final current key, and returns each id once.
A candidate issued after `context.now` fails with `future-record` before history
lookup or proof verification, even within the clock-skew allowance. A link issued
exactly at `now` is eligible. Historical proof validity does not make a future
credential eligible for present retention.
It does not issue an attestation. Panopticon **MUST check present revocation before
attesting any rotation or login**. For wallet authorization, use
`resolveWalletLinkNow` and require the selected link ID to equal the authorizer
ID. For OIDC, use `resolveOidcLinkNow`. A revoked authorizer denies the attempt even
if omitted from retention. Check every candidate retained credential, including
credentials of the other kind. Clients sign the filtered set; Panopticon
independently verifies it and rechecks if account state changes. Historical
rotation verification does not perform this present authorization step. Cached
JWKS and enrollment proofs still authenticate existing links;
complete authenticated history and a trusted latest-state checkpoint remain
necessary. The offline revoke itself requires no network request.

`ResolutionContext` contains `{jwks, pinnedIss, links, revocations?, now, policy, history, genesisEpubBindings?}`.
`history(principal, issuedAt, until)` is required and returns `Result<KeyState>`
from a complete authenticated snapshot through `until`. `historyState` computes
that state from previously verified rotations. It does **not** authenticate its
arguments. `resolveCurrentKey` resolves its own account internally and calls
`history` for other accounts, so a rotated conflicting account's link is checked
with its actual historical key. Unknown context returns `missing-history`;
a fork in the required context propagates `rotation-fork`. Wallet lookup filters
the requested address and checks time, SIWE and attestation before requesting
history. Revokes use the already authenticated current key and never select a
history lookup. Unrelated or unwitnessed index entries cannot cause a fatal
context failure.

`resolveCurrentKey(genesis, rotations, context)` returns
`{ok:true,value:{currentKey,currentEpub,bindingEpub,rotations},diagnostics}` or
`{ok:false,reason,diagnostics}`. The rotation version is inferred from whether
`nextEpub` is present; record `v` stays 1. Each accepted rotation replaces
`currentEpub`: a v3 record sets it to that `nextEpub`, and a v2 record sets it
to null. Null means the encryption public key is unknown. Do not seal, and
never fall back to Gun's `user.epub`. With no accepted rotation, `currentEpub`
is the witnessed `genesis-epub` binding, or null when there is none. A v2
rotation still sets `currentEpub` to null. Pass those
records as `ResolutionContext.genesisEpubBindings`. The genesis key signs
domain `sociacl-genesis-epub-v1`. Panopticon attests typ
`sociacl-genesis-epub-attest-v1` with `iat` equal to `issuedAt`, at most one
binding per principal, only before the first rotation, across every instance
and signing key (panopticon#499). Panopticon sets `iat` itself, with
`exp <= iat + 900`, and verifies the genesis-key signature. Two valid bindings
issued strictly before the first accepted rotation freeze the account. A
binding issued at or after that rotation is skipped with `bad-sequence` and
does not freeze a rotated account. `issuedAt` uses the policy clock skew.
Once a rotation is accepted, that binding epub joins the reuse
set. An unwitnessed `genesisEpub` string is ignored. New rotations must be v3,
and from 0.7 Panopticon attests only v3. From 0.8, Panopticon calls
`checkRotationPublish` before it attests. That function calls
`verifyRotationRequest` when the candidate has no attestation, then checks
chain sequence, sibling forks, and epub reuse. Freshness and present
revocation apply only to that unattested request. An attested candidate does
not use them, and `verifyRotate` checks the attestation as of `issuedAt`.
Present revocation honors clock skew for an offline revoke dated at or before
`now + skew`. The request helper covers one
v3 request: no `attest` field, `|issuedAt - now|` within clock skew, the
next-key signature, the authorizer, the links, the retained set, historical
revocation, and present revocation of the authorizer and every retained link.
It does not check chain sequence or epub reuse. An unsigned draft is
`bad-record` from the publish check. `checkRotationDraft` is only the keyring
builder's pre-signature check. `verifyGenesisEpubRequest`
checks a genesis-epub request (shape, signature, freshness) before Panopticon
attests it. A binding attestation is verified as of its `issuedAt`, and a
sibling attestation is verified as of that sibling's `issuedAt`. A sibling
counts only when its signature and the full claim match, including `auth`,
`linkId`, and `retainedLinks`. An identical attested sibling is a retry and is not a
fork. An unsigned draft is `bad-record`. Junk is skipped.
It refuses a v2 record with `bad-record` and two versions of one
`(principal, seq)` with `rotation-fork`. It does not replace `verifyRotate`.
The library still verifies historical v2.
Panopticon never attests both versions for the same principal and sequence;
publishing both freezes the account with `rotation-fork`. `nextEpub` must not
equal `nextKey`, genesis, any prior signing key, or any prior epub, and a later
`nextKey` must not equal any prior epub (`bad-sequence`). It sorts sequences, verifies each candidate,
skips unauthenticated malformed/forged candidates, and reports `{source,index,reason}` diagnostics.
Once a rotation's new-key signature and attestation authenticate its references,
copies are compared by signing-bytes hash. Any fully verified copy satisfies
that rotation ID; a damaged duplicate cannot veto it in either input order.
Failed copies still produce diagnostics. Missing/unverifiable authorizer or
retained-link evidence, or missing/malformed rotation SIWE, is fatal
`missing-history` only if no copy of that authenticated ID fully verifies.
A valid different ID cannot substitute for it. A witnessed revocation or
wallet-eligibility contradiction returns fatal `rotation-conflict`. Neither failure returns a current key or
partial successful account state; callers must never fall back to genesis.
Accepted transitions start at one, are contiguous, strictly increase in time,
and never reuse an earlier signing key or an earlier epub. Invalid/gapped candidates do not change
the current key. Exact duplicate transitions are idempotent. Two distinct valid
transitions at the same sequence freeze resolution with `rotation-fork`.

Historical proofs are checked at issuance; `now` excludes future history.
An expired enrollment attestation does not retroactively invalidate a completed
rotation. A rotation's new key signs records issued **after** its timestamp;
a same-second revoke by the preceding key can block that rotation. A link
signed by the new key in that same second is `bad-signature`: `historyState`
still names the preceding key (`issuedAt < at`). Once the
rotation is accepted, its retained set is authoritative at that horizon.
`verifyRotate(record, currentKey, context)` checks the proof, authorizing link,
every retained link, and pre-rotation revocations. OIDC authorizers name an
enrolled, retained, unrevoked OIDC link with a pinned issuer; the rotation
attestation binds its ID. An active wallet blocks OIDC recovery with
`wallet-required`, including a wallet omitted from the candidate's retained set.
History resolution treats that witnessed contradiction as `rotation-conflict`.
Use `resolveCurrentKey` to apply untrusted history with revocation and conflicting
wallet-owner checks.

`resolveWalletLink(address, links, revocations, context)` returns a wallet link
and diagnostics using the same result envelope. Distinct equal-time links are
ambiguous even for the same principal. Identical record IDs are idempotent.
Revoking the newest link never resurrects an older one. Invalid unrelated entries
are reported and skipped. Link maps are examined in sorted key order in both
languages. Diagnostics identify input positions; they are not authorization.

Rust returns `Resolution<T> { result: Result<T, Reason>, diagnostics }`.
Historical checks stay on `resolveWalletLink`, `verifyRevoke`, `verifyRotate`,
and `resolveCurrentKey`. A `present` field on the context does not switch them.

`verifyingLinkMap(copies, context)` groups wallet and OIDC copies by signing-byte
id and keeps one copy that verifies. A tampered sibling does not remove that id,
in either input order. An id with no verifying copy is omitted. If every copy of
an id fails with `missing-history`, `rotation-fork`, or `rotation-conflict`, the
call returns that reason. `ResolutionContext.links` still holds one proof copy
per id. Callers **must** put a verifying copy there; this builder is how.

The context must include complete known link, revocation, and rotation history;
a pure verifier cannot discover omitted records or establish global freshness.
Never treat a partial offline snapshot as proof that an account has no rotations
or active wallets. Resolution lists, the link map, revocation lists, and
genesis-epub bindings are capped at `MAX_RESOLUTION_INPUT` (1024). A longer list
is `too-long`. The functions do not truncate. `verifyRotate` and
`verifyRotationRequest` use that cap.

A wallet rotation with `nextEpub` requires `sociacl-rotate-attest-v4`: the v3
claims plus `siweHash`. That hash is hex(sha256(length-prefixed
`sociacl-siwe-proof-v1`, the SIWE message, and the SIWE signature)). A v3
wallet attestation, or a hash that does not match the proof, is
`bad-attestation` before SIWE verification. OIDC rotations stay on v3. A
rotation without `nextEpub` stays v2. The rotation signing bytes stay
`sociacl-rotate-v3` when `nextEpub` is present.

V4 wallet rotation recovery treats the witnessed transition separately from its
replaceable SIWE proof copy. If the next-key signature and transition attestation
verify but the SIWE copy does not match `siweHash`, resolution fails with
`missing-history` unless another copy of the same signing-byte ID fully verifies.
Direct `verifyRotate` still returns `bad-attestation` for a mismatched proof.
An unrelated valid rotation cannot satisfy the missing ID. Publication also
counts a damaged but authenticated different sibling as a fork.

`Reason` additionally includes `missing-history`, `unretained-link`, and
`wallet-required` and `rotation-conflict`, alongside proof, ordering, fork, revocation, ambiguity,
unsupported-wallet and RNG errors.

## Validation and distribution

From the repository root:

```sh
./scripts/test-all.sh
```

Focused checks:

```sh
npm ci --prefix typescript/ids
cargo test -p sociacl-ids --locked
node --test typescript/ids/test/*.js
npm run --prefix typescript/ids typecheck
npm run --prefix typescript/ids browser
npm run --prefix typescript/ids consumer
```

Both suites execute every case in `vectors/ids/*.json`, compare exact rejection
reasons, and emit manifests that CI compares with the vector files themselves.
The suites run 10,000 generated cases covering roundtrips, idempotence, path-key
separation, distinct-value keys and soul templates; 100,000 arbitrary inputs;
and one million CSPRNG mints each. Signing-byte and record vectors share fixed
**public test-only** private scalars. `scripts/generate-vectors.mjs` and
`scripts/generate-signed-at.mjs` are manual fixture authoring tools, not part
of CI: changing expectations requires review.

`npm pack` builds declarations and ESM into the tarball. The consumer example at
`examples/consumer` is copied to a fresh directory with an empty npm cache, installs that local tarball,
compiles against its exported types, runs its parsers, and exercises the
present/historical revocation boundary. The browser check
bundles the runtime dependency graph and rejects Node imports. Node built-ins
are used only in build/test tooling, outside the shipped runtime.

A push to protected `master` creates `ids-v` plus the `typescript/ids` version when that tag is absent. The job uses `github.token` and the Git refs API. If `master` is not protected, it records a notice and exits without creating the tag, because the pack job would refuse it ([#60](https://github.com/FyberLabs/SociACL/issues/60)). A tag that already points at another commit is left unchanged. A tag that already points at this commit is not recreated; pack still runs so an unpublished release can finish. Pack waits for `test` and `msrv`, requires protected `master`, requires ancestry of `origin/master`, and requires the tag to resolve to this commit and to `ids-v` plus the package version. It installs with scripts disabled, builds, and records a SHA-256. The release job does not check out source. It checks that digest, attests build provenance for the tarball, and attaches `sociacl-ids-0.10.0.tgz` and its SHA-256 file when the GitHub release is absent. A maintainer can still push `ids-v*` directly. The workspace crates use the same automation on `sociacl-v*`. Consumers then install:

```sh
npm install https://github.com/FyberLabs/SociACL/releases/download/ids-v0.10.0/sociacl-ids-0.10.0.tgz
```

Commit the consumer lockfile with tarball integrity. This URL becomes usable
only after that release exists. This PR does not publish a tag or migrate a
consumer. Grammar, vector acceptance/rejection, or signing-domain changes bump
the minor version before 1.0, and the major version from 1.0 onward.

## Signed witness-policy exports

`verifyWitnessPolicyEnvelope(envelopeJson, pinnedRoot, audience, now)` authenticates
Panopticon's exact-byte export in browsers and Node. Rust exposes the matching
`verify_witness_policy_envelope`. Neither function installs JWKS or supplies
rollback protection. See [the client contract](../../docs/witness-policy-client.md)
for independent root provisioning, durable floors, bootstrap freshness, and the
required checks before a production resolver may use the result.


`advanceWitnessPolicy(envelopeJson, previousJson, pinnedRoot, audience,
minimumRevision, now)` and Rust's `advance_witness_policy` calculate a candidate
policy state with a revision floor and permanent observed-key history. Previous
state must come from trusted storage. The caller must serialize the transition
and atomically commit the entire result before exposing JWKS. No persistence,
root reset, or latest-policy discovery is supplied by this pure function.


### Browser witness policy persistence

`sociacl-ids/indexeddb` provides `openWitnessPolicyStore` with explicit `bootstrap`,
`refresh`, `read` and `close` operations. Strict IndexedDB transactions commit the
revision, registry and permanent observed-key history before returning trust.
Missing/corrupt storage fails closed; there is no automatic bootstrap or memory
fallback. Trusted root/audience/floor/clock configuration and protected origin
storage remain required. See the [adapter contract](../../docs/witness-policy-client.md#indexeddb-browser-adapter)
for restart, expiry, lost-response and storage-rollback limitations. The browser
acceptance run is `npm run test:browser-store` after installing Playwright Chromium.


### HTTPS policy client

`sociacl-ids/witness-client` exports `openWitnessPolicyClient` to connect the
signed-policy HTTP endpoint to the durable browser store. Downloads require HTTPS,
reject redirects and non-200/non-JSON responses, omit credentials, enforce byte
and time limits, and return only after verified storage commits. Bootstrap stays
explicit; refresh failures never erase history or silently return old trust.
See the [client contract](../../docs/witness-policy-client.md#browser-https-client)
for cancellation, freshness and trusted-configuration requirements.

## Management checkpoint authentication

`verifyWitnessCheckpoint(checkpointJson, policyEnvelopeJson, expected)` verifies
a request-bound, complete-history management signature and the matching live
policy signature. Independently provision all `WitnessCheckpointExpectations`,
including distinct management/policy roots, exact root epoch, audience, enrollment
client, fresh 32-byte base64url challenge, revision floor and trusted Unix time.
The maximum signed lease is 300 seconds. Returns immutable candidate metadata and
state or `bad-attestation`; it does not consume challenges or install trust.
See [wire format and adapter obligations](../../docs/witness-checkpoint.md).
The existing IndexedDB/client APIs cannot restore checkpoint history; do not pass
this result directly to a production resolver or treat it as recovery permission.


### Durable checkpoint refresh

`sociacl-ids/checkpoint-store` exports `openWitnessCheckpointStore` for existing
browser state: `beginRefresh`, one-use `install`, historical `readInstalled`, gated
`readFresh`, `cancel` and `close`. It atomically installs authenticated full history,
checks local continuity, and bounds freshness by UTC plus monotonic time. Restart
requires renewal. It supplies no bootstrap, recovery, migration or HTTP transport.
The shared `advanceWitnessCheckpoint` helper (Rust: `advance_witness_checkpoint`)
performs the pure continuity comparison. See the
[refresh contract](../../docs/witness-checkpoint.md#continuity-reconciliation-and-browser-refresh)
for configuration, schema upgrade and failure semantics.


### Authenticated checkpoint transport

`sociacl-ids/checkpoint-client` exports `openWitnessCheckpointClient`. Supply the
checkpoint-store configuration, an independently provisioned HTTPS `url`, and a
management enrollment `getAccessToken(signal)` provider. `refresh({signal})` sends
a fresh challenge, authenticates the response and installs it durably before
returning. Credential/download/storage failures invalidate this handle's freshness;
`readInstalled()` remains historical and `readFresh()` requires a live lease.
There is no automatic retry, bootstrap or recovery. See the
[HTTP and cancellation contract](../../docs/witness-checkpoint-client.md).
