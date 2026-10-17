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
| Edge parsers | `parsePrincipalId`, `parseEip55`, `parseWalletInput`, `parseTenantId`, `parseOidcCredential`, `parseObjectId`, `parseNetworkId`, `parseSourceKey`, `parseSoul` |
| Keys | `formatPrincipalKey`, `formatWalletKey`, `formatOidcKey`, `formatNetworkKey`, `formatSourcePathKey`, `objectKey` |
| Souls | `objectSoul`, `userSoul`, `aclSoul`, `grantSoul`, `postSoul` |
| Creation | `mintObjectId`, `deriveClaimId`, `deriveExternalId` |
| Signing | `signingBytes`, `linkId` |
| Proofs | `verifyWalletLink`, `verifyOidcLink`, `verifyRotate`, `verifyRevoke` |
| Histories | `resolveCurrentKey`, `resolveWalletLink` |

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

`verifyWalletLink(record, now, currentKey?)` and
`verifyOidcLink(record, jwks, pinnedIss, now, currentKey?)` default to the genesis
key. For a link made after rotation, provide the authenticated key that was
current at its issuance. A verifier cannot infer that history from the link.
`verifyRevoke(record, currentKey, now)` similarly requires the historical key.
Rust exposes the explicit variants as `*_at_key` functions.

`resolveCurrentKey(genesis, rotations, {jwks, links, revocations, now})` verifies
history chronologically, checks the stable principal and previous key, and
requires contiguous sequence numbers starting at one. Each rotation timestamp
must strictly increase. A rotation takes effect for records issued **after**
its integer timestamp; same-second revocations are checked with the preceding
key and prevent recovery. This removes ambiguous ordering inside one second.
Out-of-order input is sorted, exact duplicate transitions are idempotent, and
two different valid transitions at one sequence return `rotation-fork`.

Historical proofs are checked at issuance; `now` prevents future history.
An expired enrollment attestation does not retroactively invalidate a completed
rotation. Direct proof verification checks expiration against the supplied
`now`. The history resolver re-verifies wallet links, checks their content hash
against the map key, applies revocations, and refuses recovery through a wallet
with a newer conflicting principal binding. `verifyRotate` alone is a proof
check against the supplied active-link context; use the resolver when applying
untrusted history.

`resolveWalletLink` selects the latest verified wallet binding. Equal-time
bindings to different principals return `ambiguous-link`. Revoking the newest
link does not resurrect an earlier link. For histories spanning several
accounts, supply a trusted `keyAt(principal, issuedAt)` callback (Rust:
`resolve_wallet_link_at_key`). Obtain that callback from authenticated histories,
never from a claimed signing key inside an incoming record. Feed complete known
link/revocation history into resolution: a pure verifier cannot discover omitted
records or prove that an offline snapshot is globally current.

`Reason` includes the grammar failures and the additional proof/history errors
required by these APIs: `bad-record`, `bad-signature`, `bad-attestation`,
`untrusted-issuer`, `expired`, `future-record`, `bad-sequence`, `rotation-fork`,
`unknown-link`, `revoked-link`, `ambiguous-link`, `unsupported-wallet`, and
`rng-failure`.

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
`examples/consumer` is copied to a fresh directory, installs that local tarball,
compiles against its exported types and runs its parsers. The browser check
bundles the runtime dependency graph and rejects Node imports. Node built-ins
are used only in build/test tooling, outside the shipped runtime.

After review and merge, tag `ids-v0.1.0`. The release job waits for the full test
job, verifies the tag matches `package.json`, and attaches
`sociacl-ids-0.1.0.tgz` and its SHA-256 file. Consumers then install:

```sh
npm install https://github.com/FyberLabs/SociACL/releases/download/ids-v0.1.0/sociacl-ids-0.1.0.tgz
```

Commit the consumer lockfile with tarball integrity. This URL becomes usable
only after that release exists. This PR does not publish a tag or migrate a
consumer. Grammar, vector acceptance/rejection, or signing-domain changes bump
the minor version before 1.0, and the major version from 1.0 onward.
