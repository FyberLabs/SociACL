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
const object = mintObjectId('room');
if (!owner.ok || !accessor.ok || !object.ok) throw Error('invalid identity');
const soul = grantSoul(owner.value, object.value, accessor.value);
// s3rch/acl/p_<point hex>/room_<128-bit random hex>/p_<point hex>
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
| Souls | `objectSoul`, `userSoul`, `aclSoul`, `grantSoul`, `postSoul` |
| Creation | `mintObjectId`, `deriveClaimId`, `deriveExternalId` |
| Signing | `signingBytes`, `linkId` |
| Proofs | `verifyWalletLink`, `verifyOidcLink`, `verifyRotate`, `verifyRevoke` |
| Present eligibility | `verifyRevokeNow`, `resolveWalletLinkNow` |
| Histories | `resolveCurrentKey`, `resolveWalletLink`, `historyState` |

Every parser/verifier returns `{ok:true,value}` or `{ok:false,reason}`. Scalar
parsers check the input type before examining it. Object parsers snapshot own
data properties, reject accessors and unknown fields, and never coerce an
object into an identifier. Returned records and nested credentials are frozen.

Souls have fixed templates. `parseSoul` is the only inverse; object results
include `[collection, objectId]`, user/ACL results `[principal]`, and grant/post
results `[owner, objectId, accessor]`. All derived path keys exclude
`/ . # $ [ ] ~ %`. Gun's `~pub` user soul is the explicit exception: the `~`
marker and public key separator are part of Gun's user-space syntax, not a
path key. SHA-256 path keys use domain-separated, little-endian length-prefixed
UTF-8 fields. Hash collision resistance is computational, not a mathematical
claim of injectivity.

Object ids are `<kind>_<32 lowercase hex>`, `claim_<64hex>`, `ext_<64hex>`, or the
specified read-only `s3rch:` legacy formats. `claim`/`ext` cannot be minted as
native kinds. Legacy timestamps retain the specified 1–12 decimal digit limit;
legacy identifiers are opaque and confer no ownership authority. Native mints
use `crypto.getRandomValues` (Rust: `getrandom`) for 128 bits.

`SourceKey` ports the canonical SourceRef format from s3r.ch Views. s3r.ch owners
are genesis principals; open protocols retain DID, FID, Nostr key, ActivityPub
actor URI and RSS origin rules. Percent encoding exists only in SourceRef's
wire representation. Its storage key is `s_<sha256>`, never an escaped Gun key.

## Proof verification and caller responsibilities

Signing bytes are `LP(domain) LP(field1) …`, with a 32-bit little-endian UTF-8
byte length on each field. `linkId` is SHA-256 of these bytes and does not depend
on an ECDSA signature. SEA proofs are raw P-256 `r||s` in canonical unpadded
base64url; both high-S and low-S verify. SEA envelopes are not accepted.

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
present wallet eligibility. A current-key offline revoke blocks the newest
binding without resurrecting an older one. **When its signer retires, an
unwitnessed revoke stops applying.** There is no authenticated saved-state
persistence in this API. Remove the link from the retained set, or use a
witnessed revoke consistent with the transition, to preserve removal across
rotation. The same offline revoke is ignored by historical/as-of
`resolveWalletLink`, `verifyRotate` and `resolveCurrentKey`; never use a `Now`
API for a historical query or choose its current key from `issuedAt`.

Panopticon and clients **MUST exclude present-revoked links from `retainedLinks`**
when constructing a rotation. Panopticon **MUST check present revocation before
attesting any rotation or login**. For wallet authorization, use
`resolveWalletLinkNow` and require the selected link ID to equal the authorizer
ID. For OIDC, authenticate the enrolled link and check `verifyRevokeNow` using the
final authenticated current key: match principal, target ID and
`revoke.issuedAt >= link.issuedAt`. A revoked authorizer denies the attempt even
if omitted from retention. Check every candidate retained credential, including
credentials of the other kind. Clients sign the filtered set; Panopticon
independently verifies it and rechecks if account state changes. Historical
rotation verification does not perform this present authorization step. Cached
JWKS and enrollment proofs still authenticate existing links;
complete authenticated history and a trusted latest-state checkpoint remain
necessary. The offline revoke itself requires no network request.

`ResolutionContext` contains `{jwks, pinnedIss, links, revocations?, now, policy, history}`.
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
`{ok:true,value:{currentKey,currentEpub,rotations},diagnostics}` or
`{ok:false,reason,diagnostics}`. The rotation version is inferred from whether
`nextEpub` is present; record `v` stays 1. Each accepted rotation replaces
`currentEpub`: a v3 record sets it to that `nextEpub`, and a v2 record sets it
to null. Null means the encryption public key is unknown. Do not seal, and
never fall back to Gun's `user.epub`. With no accepted v3 rotation,
`currentEpub` stays null. New rotations must be v3, and from 0.7 Panopticon
attests only v3. The library still verifies historical v2. Panopticon never
attests both versions for the same principal and sequence; publishing both
freezes the account with `rotation-fork`. `nextEpub` must not equal `nextKey`,
genesis, any prior signing key, or any prior epub, and a later `nextKey` must
not equal any prior epub (`bad-sequence`). It sorts sequences, verifies each candidate,
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
a same-second revoke by the preceding key can block that rotation. Once the
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

Rust returns `Resolution<T> { result: Result<T, Reason>, diagnostics }`. Both
languages expose `*_at_key` / `*AtKey` aliases for the explicit proof/history APIs;
these are deprecated compatibility aliases. Use the canonical names in new
code. They remain witness-only and do not alias the present-time entry points.

`ResolutionContext.links` accepts one proof copy per ID. Callers **must retain
a copy that verifies** against authenticated key state and pinned witnesses;
keep alternatives until this verification is possible. Neither first-write nor
last-write wins over untrusted copies is safe: link IDs exclude signature/SIWE/
attestation bytes, and a corrupt copy must not overwrite a verified one. Missing
required evidence remains fatal. There is no storage/index deduplication adapter
in this package.

The context must include complete known link, revocation, and rotation history;
a pure verifier cannot discover omitted records or establish global freshness.
Never treat a partial offline snapshot as proof that an account has no rotations
or active wallets. Enforce input-size and work budgets at the caller; never
silently truncate a history to satisfy those budgets.

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
**public test-only** private scalars. `scripts/generate-vectors.mjs` is a manual
fixture authoring tool, not part of CI: changing expectations requires review.

`npm pack` builds declarations and ESM into the tarball. The consumer example at
`examples/consumer` is copied to a fresh directory with an empty npm cache, installs that local tarball,
compiles against its exported types, runs its parsers, and exercises the
present/historical revocation boundary. The browser check
bundles the runtime dependency graph and rejects Node imports. Node built-ins
are used only in build/test tooling, outside the shipped runtime.

After review and merge, tag `ids-v0.7.0`. The release job waits for the full test
job, requires a protected `master` and verifies the tag commit is its ancestor.
A read-only job installs dependencies with scripts disabled, explicitly builds,
and checks the tag against `package.json`. A separate write-token job only
downloads the resulting artifact, checks its SHA-256, and attaches
`sociacl-ids-0.7.0.tgz` and its SHA-256 file. Consumers then install:

```sh
npm install https://github.com/FyberLabs/SociACL/releases/download/ids-v0.7.0/sociacl-ids-0.7.0.tgz
```

Commit the consumer lockfile with tarball integrity. This URL becomes usable
only after that release exists. This PR does not publish a tag or migrate a
consumer. Grammar, vector acceptance/rejection, or signing-domain changes bump
the minor version before 1.0, and the major version from 1.0 onward.
