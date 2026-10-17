# sociacl-ids 0.4 review amendment

This amendment and the updated record sections of the
[package specification](sociacl-ids-package-spec.md) define the 0.4 contract.
Versions 0.1, 0.2 and 0.3 were never released. The review changes require a minor
version bump because they change signing bytes, record shapes and URL grammar.
Wallet and revoke timestamp attestations, rotation retention commitments, and
skipping invalid history with diagnostics were explicitly approved during review.

## Timestamp witnesses

Wallet records require `attest`, a compact ES256 JWS signed by a unique `kid` in
the pinned Panopticon JWKS. Its exact payload fields are:

```json
{"typ":"sociacl-wallet-attest-v1","principal":"<genesis>","linkId":"<64 lowercase hex>","iat":1700000000,"exp":1700000600}
```

`linkId` hashes the canonical wallet signing bytes, binding the wallet,
principal, issuance time and nonce. `iat` must equal `issuedAt`. Panopticon must
assign that time after checking the wallet proof and authenticated account state;
accepting arbitrary client timestamps would defeat this guarantee.

Revoke records also require `attest`, with these exact claims:

```json
{"typ":"sociacl-revoke-attest-v1","principal":"<genesis>","recordId":"<64 lowercase hex>","iat":1700000020,"exp":1700000620}
```

`recordId` is SHA-256 of the canonical revoke signing bytes (not the target
link's ID), and `iat` must equal `issuedAt`. The signing bytes remain
`LP("sociacl-revoke-v1") LP(principal) LP(linkId) LP(decimal(issuedAt))`.
`verifyRevoke(record, currentKey, jwks, now)` checks the key signature and the
timestamp witness. Panopticon must assign the time and verify current-key
authority. An unwitnessed backdated revoke cannot invalidate a past rotation.
If a compromised witness signs contradictory history, resolution freezes as
specified below; it must not restore the retired key. Revocation and rotation
currently both require Panopticon availability. An unwitnessed revoke has no
effect under this contract.

## Recovery records

Rotations require `retainedLinks`: at most 1024 distinct 64-character lowercase
hexadecimal IDs, in ascending ASCII order. Empty is allowed. Both authorizer
kinds name an enrolled credential: `{kind:"wallet",link,siwe}` or
`{kind:"oidc-fresh-login",link}`. The canonical signing bytes are:

```text
LP("sociacl-rotate-v2") LP(principal) LP(decimal(seq)) LP(prevKey)
LP(nextKey) LP(decimal(issuedAt)) LP(authorizer.kind) LP(authorizer.link)
LP(decimal(retainedLinks.length)) LP(retainedLinks[0]) ... LP(retainedLinks[n-1])
```

The exact rotation attestation claims are:

```json
{"typ":"sociacl-rotate-attest-v2","principal":"<genesis>","nextKey":"<SEA public key>","seq":1,"iat":1700000030,"exp":1700000630,"auth":"wallet","linkId":"<authorizer link ID>","retainedLinks":["<retained link ID>"]}
```

`auth` equals the authorizer kind, `linkId` equals `authorizer.link`, and
`retainedLinks` exactly equals the signed array. The new key signature and the
wallet SIWE proof, when present, cover the v2 bytes. Old rotation encodings and
attestations are rejected; consumers must pin package version and integrity.

The verifier authenticates the authorizing credential and **every retained ID**
against the pre-rotation state. Each must belong to the principal and remain
retained through all previous rotations. It rejects any of these links revoked
at or before the candidate's timestamp under the key current immediately before
that rotation. A rotation therefore cannot revive a revoked link. A verified
witnessed revoke conflicting with an authenticated rotation returns the fatal
`rotation-conflict` error, including same-second conflicts. This remains fatal
when the witness colludes with a retired key and backdates the revoke: no
current key or partial successful history is returned. The authorizer may be
omitted from the new retained set, allowing it to authorize its own removal.

OIDC recovery additionally requires an enrolled, retained, unrevoked OIDC link
whose issuer belongs to `pinnedIss`. Its attestation must bind that link, and
Panopticon must verify a fresh login to that exact issuer/tenant/subject. Any
active wallet link for the principal blocks OIDC recovery with `wallet-required`
in direct proof verification, including a wallet the candidate attempts to drop.
During history resolution, that contradiction with the witnessed rotation is
fatal `rotation-conflict`. Conflicting wallet ownership also freezes resolution.
These restrictions use complete pre-rotation link and revocation history.

Every rotation at or after a link's issuance must retain its ID for it to remain
usable. The history adapter returns the intersection of these commitments.
A later rotation cannot restore an ID omitted by an earlier one. New enrollment
must create a new link ID. Revokes at an evaluation horizon are checked against
its current key; the pre-rotation checks above enforce the revocation decision
before that key is retired. Same-second revokes use the preceding key and can
block recovery; the new key signs records issued strictly after the rotation.

## Trust and resolution

`ResolutionContext` requires `{jwks, pinnedIss, links, now, policy, history}` and
optionally `revocations`. There is no default historical key lookup.
`HistoryResolver` must authenticate complete account history through its
requested horizon. In TypeScript it returns
`Result<{key,currentKey,retainedLinks}>`; Rust uses `Result<KeyState,Reason>`.
The caller must never construct it by trusting an incoming record's key or
silently assume no rotations when history is unavailable. `historyState` is
arithmetic over already authenticated rotations, not a verifier.

Wallet lookup filters the requested address and checks time, SIWE and the
Panopticon witness before requesting history. Revocation checks filter the
principal, target ID and time and use the already authenticated current key;
a revoke never chooses which principal's history to fetch. Unrelated or forged
index records cannot force a lookup of unavailable or forked account history.
Missing history for a relevant, independently witnessed link fails with
`missing-history`; a verified fork in that required context propagates failure.

Malformed records, bad rotation signatures/attestations and gapped sequences
are skipped with source/index/reason diagnostics. They cannot advance the key
or manufacture a fork. After a rotation's new-key signature and Panopticon
attestation authenticate its references, a missing or unverifiable authorizer or
retained link is fatal `missing-history`. This includes tampered link signatures,
SIWE proofs and attestations, and a missing valid wallet proof for the rotation
itself. Referenced fork/conflict errors propagate. Discarding such a rotation
would silently restore an older key. Unrelated invalid index entries remain
skippable; they cannot trigger these failures without an authenticated reference.
Distinct **valid** transitions at the same sequence freeze the account. Duplicate record IDs are idempotent.
Distinct wallet links tied at the newest timestamp are ambiguous, including
links to the same principal. A revoked newest binding does not revive an older
binding. Direct proof verification is distinct from applying full history.

The caller must supply complete authenticated snapshots, including links and
revocations: a pure verifier cannot discover an omitted wallet or prove global
freshness. These checks also cannot detect an entirely omitted rotation or
replace a trusted latest-state checkpoint. Consumers must not authenticate from
an untrusted index's assertion that a history is complete. Panopticon remains
the trusted timestamp witness and OIDC login attestor; its index output alone is not account authority. Callers also enforce
input-size and work budgets before invoking these synchronous verifiers. The
package does not silently truncate history, since doing so could omit a revoke
or fork. Individual record fields and retained sets have explicit bounds.

SIWE policy pins the complete domain string (including an optional scheme),
exact URI and chain ID string. Attestation lifetime is at most 900 seconds.
Optional clock skew is an integer from 0 to 300 seconds (default zero) for direct
wallet/OIDC/rotation checks; signed times must still match exactly. Revokes and
history admission apply no skew. Historical witnesses are verified at issuance,
so their later expiry does not invalidate recorded transitions.

## Shared URL grammar

Identity URL inputs use a literal ASCII grammar implemented in both languages;
no WHATWG parsing, IDNA mapping, decoding repair or normalization occurs.

- Hosts have at least two lowercase DNS labels, each 1–63 ASCII letters/digits/
  hyphens with alphanumeric ends, at most 253 bytes overall. The final label is
  entirely alphabetic. `xn--` labels and the private/special suffix list are
  rejected; IDN hosts are unsupported.
- Web URLs use `https://` (RSS origins also permit `http://`). No credentials,
  query or fragment is accepted, including empty `?`/`#` delimiters.
- Explicit ports are canonical decimal 1–65535; default web ports are omitted.
  `did:web` ports use uppercase `%3A`, canonical decimal, and omit port 443.
  s3rch network identities retain their separately specified mandatory port.
- Actor/SIWE/resource URLs require `/` and RFC3986 path characters. Uppercase
  `%HH` escapes cannot encode ASCII controls, DEL, or unreserved characters.
  Dot segments are rejected. Reserved escapes remain literal, distinct values:
  callers must not decode them and compare them as authorization identifiers.
  RSS origins have no path or trailing slash.
- OIDC issuers remain exact pinned strings under the original issuer grammar;
  they are not normalized or reinterpreted as network origins.

Shared fixtures exercise host/port/path combinations and both signed SIWE URI
positions. Both CI runners compare exact results against every corpus entry.
Removing `url` also removes its vulnerable `idna` dependency, described by
[RUSTSEC-2024-0421](https://rustsec.org/advisories/RUSTSEC-2024-0421.html).

## Release and adoption

The packed-consumer test uses a new empty cache and permits npm to fetch the
pinned runtime dependencies. Release builds have read-only repository access,
disable dependency lifecycle scripts and checkout credentials, and require the
tagged commit to be on protected `master`. Only the artifact publishing job has
write permission; it executes no package source. Branch protection still needs
repository configuration before a release; this PR does not change admin settings.

The source audit and persisted-ID inventory prerequisite are recorded in the
[migration roadmap](identity-migration-roadmap.md). Consumer migrations and
Panopticon attestation endpoints remain separate reviewable deliveries after
this package contract is approved and released.
