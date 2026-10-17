# sociacl-ids 0.2 review amendment

This amendment replaces the identified parts of the original
[package specification](sociacl-ids-package-spec.md). The original document is
retained as supplied. The user confirmed both recovery protections and skipping
invalid history with diagnostics during review of SociACL #57. Version 0.1 was
never released; these grammar/signing changes increment the package minor to 0.2.

## Recovery records

Wallet records gain required `attest`, a compact ES256 JWS signed by a unique
`kid` in the pinned Panopticon JWKS. Its exact payload fields are:

```json
{"typ":"sociacl-wallet-attest-v1","principal":"<genesis>","linkId":"<64 lowercase hex>","iat":1700000000,"exp":1700000600}
```

`linkId` hashes the existing canonical wallet signing bytes, binding the wallet,
principal, issuance time and nonce. `iat` must equal `issuedAt`. Panopticon must
assign that time after checking the wallet proof and authenticated account state;
accepting arbitrary client timestamps would defeat this guarantee.

Rotations gain required `retainedLinks`: at most 1024 distinct 64-character
lowercase hexadecimal IDs, in ascending ASCII order. Empty is allowed. Their
canonical signing bytes are:

```text
LP("sociacl-rotate-v1") LP(principal) LP(decimal(seq)) LP(prevKey)
LP(nextKey) LP(decimal(issuedAt)) LP(decimal(retainedLinks.length))
LP(retainedLinks[0]) ... LP(retainedLinks[n-1])
```

The rotation attestation additionally requires `retainedLinks` exactly equal to
the signed array, alongside `typ`, `principal`, `nextKey`, `seq`, `iat`, `exp`,
and `auth`. The fixed domain retains its original label because no v1 bytes were
published; consumers must pin package version/integrity and cannot mix 0.1 and
0.2 rotation encodings.

Every rotation at or after a link's issuance must retain its ID for it to remain
usable. This applies to wallet and OIDC link verification. The history adapter
returns the intersection of these commitments. A later rotation cannot restore
an ID omitted by an earlier one. New enrollment must create a new link ID.
Revokes are checked against the key current at the evaluation horizon, not a
key selected by the revoke's self-declared timestamp. Rotation commitments carry
forward the revocation decision when retiring that key.

## Trust and resolution

There is no default historical key lookup. `HistoryResolver` must authenticate
complete account history through its requested horizon. In TypeScript it returns
`Result<{key,currentKey,retainedLinks}>`; Rust uses `Result<KeyState,Reason>`.
The caller must never construct it by trusting an incoming record's key or
silently assume no rotations when history is unavailable. Missing context fails
with `missing-history`; a verified fork in required context propagates failure.
`historyState` is arithmetic over already authenticated rotations, not a verifier.

Malformed records, bad signatures, invalid attestations, gapped sequences and
unusable recovery candidates are skipped with source/index/reason diagnostics.
They cannot advance the key or manufacture a fork. Distinct **valid** transitions
at the same sequence freeze the account. Duplicate record IDs are idempotent.
Distinct wallet links tied at the newest timestamp are ambiguous, including
links to the same principal. A revoked newest binding does not revive an older
binding. Direct proof verification is distinct from applying full history.

SIWE policy explicitly pins the complete domain string (including an optional
scheme), exact URI and chain ID string. Attestation lifetime is at most 900
seconds. Optional clock skew is an integer from 0 to 300 seconds (default zero)
for direct proof checks; signed times must still match exactly and history never
applies future entries. Token expiry is exclusive after that tolerance.

## Shared URL grammar

Identity URL inputs use a literal ASCII grammar implemented in both languages;
no WHATWG parsing, IDNA mapping, decoding repair or normalization occurs.

- Hosts have at least two lowercase DNS labels, each 1–63 ASCII letters/digits/
  hyphens with alphanumeric ends, at most 253 bytes overall. `xn--` labels,
  numeric final labels and the existing private/special suffix list are rejected.
- Web URLs use `https://` (RSS origins also permit `http://`). No credentials,
  query or fragment is accepted, including empty `?`/`#` delimiters.
- Explicit ports are canonical decimal 1–65535; default web ports are omitted.
  s3rch network identities retain their separately specified mandatory port.
- Actor/SIWE/resource URLs require `/` and a path consisting of RFC3986 pchars,
  slash and uppercase `%HH` escapes. Dot segments, including `%2E` equivalents,
  are rejected. RSS origins have no path or trailing slash.
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
