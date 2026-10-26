# sociacl-ids 0.6 review amendment

This amendment and the updated record sections of the
[package specification](sociacl-ids-package-spec.md) define the 0.6 contract.
sociacl-ids 0.7 adds the Rotate v3 section below and does not change the v2 record.
Versions 0.1 through 0.5 were never released. The review changes require a minor
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

Revoke records permit an optional `attest` on the wire. Historical verification
requires it, with these exact claims:

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
specified below; it must not restore the retired key. Issuing a witnessed revoke
or a rotation requires Panopticon availability. Present-time revocation has the
separate contract below.

## Present-time offline revocation

`verifyRevokeNow(record, currentKey, now)` verifies the revoke's structure, time
and signature under the **final authenticated current key**. It needs no JWKS or
Panopticon request. `resolveWalletLinkNow(address, links, revocations, context)`
uses that rule for present eligibility after authenticating the wallet link and
resolving its account's current key. Rust exposes `verify_revoke_now` and
`resolve_wallet_link_now` with the same behavior.

| Check | Revoke authority | Timestamp witness |
| --- | --- | --- |
| Present lookup (`resolveWalletLinkNow`) or direct present proof (`verifyRevokeNow`) | Final authenticated current key | Optional |
| Historical/as-of lookup (`resolveWalletLink`), `verifyRevoke`, `verifyRotate`, `resolveCurrentKey` | Key current at the evaluation horizon | Required |

Omit `attest` for an offline revoke; explicit null, empty and non-string values
are malformed. Present verification does not certify an attached witness, even
if a string is supplied. Historical verification validates it strictly. Signing
bytes and record IDs are identical with or without a witness.

An unwitnessed revoke affects only present state while its signing key remains
current. **It stops applying when that key retires.** The package does not
persist revocations across key retirement or infer their authenticity from a
claimed `issuedAt`. A retired-key revoke cannot block a present lookup, freeze a
rotation or rewrite history without the historical witness requirements. A
current-key offline revoke also cannot establish pre-rotation eligibility or
remove a wallet from historical OIDC recovery checks.

Panopticon and clients **MUST exclude every present-revoked credential** when
constructing `retainedLinks`. Panopticon **MUST run the present-revocation check
before attesting any rotation or login**, against the final authenticated current
key and the same complete snapshot used to construct the transition. For a wallet
authorizer, use `resolveWalletLinkNow` and require that its selected link ID equals
the authorizer ID. For OIDC, authenticate the enrolled credential and use
`verifyRevokeNow`, matching principal, target ID and `revoke.issuedAt >= link.issuedAt`.
A matching revoke denies the login or recovery attempt; it is not enough merely
to omit a revoked authorizer from the retained set.

Check every candidate retained credential as well as the authorizer, including
credentials of the other kind. Clients construct the filtered set before signing;
Panopticon independently checks that set before attesting and refuses an
inconsistent request. Recheck on account-state changes. Shared caller-integration
vectors demonstrate retention filtering and refusal of a revoked wallet before
attestation. The package provides these verification primitives; Panopticon's
endpoint implementation remains a separate delivery.

These are additional present authorization checks. Rotation-history verification
remains witness-only, and its pre-rotation credential rules still apply. To
preserve removal across a rotation, omit the credential from the retained set
or obtain a witnessed revoke consistent with the authenticated transition.
Never treat a past success from `verifyRevokeNow` as a historical timestamp.

Offline lookup can use cached enrollment witnesses, pinned keys and complete
authenticated account history. It still requires that trusted context and a
latest-state checkpoint; an arbitrary stale snapshot cannot establish which key
is current. Missing history, a fork, or a witnessed rotation conflict still fails
closed. No new enrollment witness or network request is needed to verify the
current-key revoke itself.

## Recovery records

The passphrase recovery copy of an account keyring is specified in
[Passphrase recovery copy](encrypted-discovery.md#passphrase-recovery-copy).
This section is the rotation `retainedLinks` record.

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
wallet SIWE proof, when present, cover the v2 bytes. Encodings older than v2
are rejected. A record with no `nextEpub` remains this v2 record. Consumers
must pin package version and integrity.

## Rotate v3 (`nextEpub`)

sociacl-ids 0.7 adds an encryption public key to a rotation without changing
the v2 record. `nextEpub` is optional. When it is absent, the v2 domain and
attestation above are unchanged. When it is present, the record version stays
`v: 1` and the signing bytes are:

```text
LP("sociacl-rotate-v3") LP(principal) LP(decimal(seq)) LP(prevKey)
LP(nextKey) LP(nextEpub) LP(decimal(issuedAt)) LP(authorizer.kind) LP(authorizer.link)
LP(decimal(retainedLinks.length)) LP(retainedLinks[0]) ... LP(retainedLinks[n-1])
```

`nextEpub` is a SEA P-256 point in the same 87-character form as `nextKey`,
parsed by `parsePrincipalId` / `parse_principal_id`. It names the encryption
public key after the rotation. It is not an account id and it is not a second
account keypair.

The v3 attestation uses typ `sociacl-rotate-attest-v3` and the v2 claims plus
`nextEpub`. That claim equals the signed field. A v3 attestation on a v2
record, a v2 attestation on a v3 record, a missing `nextEpub` claim, a
malformed point, or a signature over a different byte string does not verify.

The version is inferred from whether `nextEpub` is present. Record `v` stays
1. New rotations MUST be v3. From sociacl-ids 0.7, Panopticon attests only v3
(`sociacl-rotate-attest-v3`). The library still verifies historical v2
records. Panopticon never attests both versions for the same principal and
sequence. Publishing both versions of one transition produces two signing-byte
IDs at that sequence and freezes the account with `rotation-fork`. Clients
must not publish a v2 retry of a v3 rotation.

`resolveCurrentKey` / `resolve_current_key` returns `currentEpub` from the
accepted chain. Each accepted rotation replaces it after the witnessed checks
already in this package: a v3 rotation sets `currentEpub` to that record's
`nextEpub`, and a v2 rotation sets `currentEpub` to null. Null means the
encryption public key for the current signing key is unknown. Consumers must
not seal, and they must never fall back to Gun's `user.epub` or any other
unwitnessed point. With no accepted rotation, `currentEpub` is the witnessed
`genesis-epub` binding, or null when there is none. A v2 rotation still sets
`currentEpub` to null. Gun `user.epub` is never that value.
`historyState` stays signing-key state and carries no epub.

## Genesis epub binding

A fresh account gets an encryption public key from a `genesis-epub` record,
not from Gun. The record is `{v:1, kind:"genesis-epub", principal, epub,
issuedAt, keySig, attest}`. The genesis key signs domain
`sociacl-genesis-epub-v1`: length-prefixed principal, epub, and the decimal
`issuedAt`. `epub` is a canonical on-curve SEA point and must not equal the
genesis pub. Panopticon attests it with typ `sociacl-genesis-epub-attest-v1`
and claims `principal`, `epub`, `iat`, and `exp`. `iat` must equal `issuedAt`.
No wallet and no Keycloak login are required.

Panopticon attests at most one binding per principal, and only before the
first rotation. It refuses a binding when any rotation already exists. That
one-per-principal record is global across instances and signing keys
(panopticon#499). Panopticon calls `verifyGenesisEpubRequest` /
`verify_genesis_epub_request` before it attests: shape, canonical epub
distinct from the genesis pub, genesis-key signature, and
`|issuedAt - now| <= clockSkewSeconds`. It then sets `iat` equal to that
`issuedAt`, with `exp <= iat + 900`. Callers pass the records
as `ResolutionContext.genesisEpubBindings`. Invalid or junk bindings are
skipped with a diagnostic. The fork count runs only over bindings whose
`issuedAt` is strictly before the first accepted rotation. With no accepted
rotation, every valid binding counts, and two distinct ones freeze the account
with `rotation-fork`. The diagnostic source `genesis-epub` distinguishes that
freeze from a rotation fork. A binding issued at or after the first accepted
rotation's `issuedAt` is skipped with `bad-sequence` and does not freeze the
account or join the reuse set. `issuedAt` must be at or before `now` plus
the policy clock skew. The attestation is verified as of `issuedAt`, so a
binding stays valid after its 15-minute witness window.

With no accepted rotation, `currentEpub` is that binding's epub, or null when
none is in force. After a rotation is accepted, `currentEpub` still comes from
the rotation chain, and the in-force binding epub is reused like any prior
epub: a later `nextEpub` or `nextKey` equal to it is `bad-sequence`. An
unwitnessed `genesisEpub` string on the context is ignored. `verifyRotate`
does not take that string either. The binding is applied inside
`resolveCurrentKey`.

`confirm` and `import` accept a genesis-only keyring when its `epriv` matches
the witnessed binding epub. A null `currentEpub` still refuses a new seal.

`nextEpub` must be a fresh point. It must not equal `nextKey`, the genesis
signing key, any prior signing key, or any prior `nextEpub`. A later `nextKey`
must not equal any prior `nextEpub`. Those collisions are `bad-sequence`, the
same reason as signing-key reuse. Direct `verifyRotate` rejects `nextEpub`
equal to `nextKey` or `prevKey`. During resolution the colliding candidate is
skipped and the prior key and epub stay in place.

## Attest and publish

Panopticon runs the same reuse and sequence checks as `resolveCurrentKey`
before it attests a rotation. Clients run those same checks before they
publish. `checkRotationPublish` / `check_rotation_publish` is that shared
check. It is not a second rotation scheme and it does not replace
`verifyRotate`.

The check refuses a v2 record (no `nextEpub`) with `bad-record`. Historical
`verifyRotate` still accepts a v2 record. The check refuses two versions, or
two signing-byte ids, offered for one `(principal, seq)` with `rotation-fork`.
Panopticon must not attest a v2 record and must not attest both versions for
that pair. A client must not publish either.

Before it attests, Panopticon calls `checkRotationPublish` /
`check_rotation_publish` (panopticon#499). That function calls
`verifyRotationRequest` / `verify_rotation_request` for a signed candidate
with no attestation, then applies chain sequence, sibling forks, and epub
reuse. The request helper is not sufficient on its own. It covers a v3
request only: it refuses v2 and any present `attest`; it requires
`|issuedAt - now| <= clockSkewSeconds`; it checks the next-key signature,
the authorizer, the links, and the retained set; it applies historical
revocation at `issuedAt` and present revocation at `now`
(`verifyRevokeNow` / `resolveWalletLinkNow`) to the authorizer and every
retained link. Freshness and present revocation apply only to that
unattested request. An attested candidate does not use the window: its
attestation is checked as of `issuedAt`, and revocation is the witnessed
check at `issuedAt`. Present revocation honors `clockSkewSeconds` for an
offline revoke dated at or before `now + skew`. A revoke dated further
ahead is ignored. Historical witnessed checks and direct `verifyRevokeNow`
stay skew-free. It does not check chain sequence or historical epub reuse.
Panopticon requires that window, sets `iat` equal to the client-signed
`issuedAt`, and sets `exp <= iat + 900`. It runs that present-revocation
check before attesting. It also attests at most one `genesis-epub` binding
per principal, only before the first rotation, across every instance and
signing key. Before attesting a binding it calls `verifyGenesisEpubRequest`
/ `verify_genesis_epub_request` (shape, canonical epub distinct from the
genesis pub, genesis-key signature, and the same freshness window) and
refuses the binding when any rotation exists. The publish check
uses the rotations `resolveCurrentKey` accepts as the prior chain, including
an in-force binding epub in the reuse set. A sibling counts only when its
next-key signature and the full Panopticon claim both verify, including
`auth`, `linkId`, `retainedLinks`, and the exact claim shape. Junk and
unattested siblings are skipped and are not a fatal parse error. A distinct
authenticated sibling at the same `(principal, seq)` is `rotation-fork`. An
identical attested sibling is a retry and is not a fork. An unsigned draft
is `bad-record` here. `checkRotationDraft` / `check_rotation_draft` is the
builder's check before a signature exists, and Panopticon does not call it.
A draft's `retainedLinks` use the signed-record rule, and an identical
attested sibling of that draft is a retry. A bad-signature prior does not
block a later valid record. A null `currentEpub` still means do not seal
and never fall back to Gun `user.epub`. `verifyRotate` checks an attested
record as of its `issuedAt`, so a historical record still verifies after
the witness window.

The verifier authenticates the authorizing credential and **every retained ID**
against the pre-rotation state. Each must belong to the principal and remain
retained through all previous rotations. It rejects any of these links revoked
at or before the candidate's timestamp by a witnessed revoke under the key
current immediately before that rotation. A rotation therefore cannot revive a
historically revoked link. A verified witnessed revoke conflicting with an
authenticated rotation returns the fatal
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
These restrictions use complete pre-rotation link and revocation history. A
malicious Panopticon witness can force this visible freeze by attesting contradictory OIDC
recovery on an account with an active wallet. It cannot thereby obtain account
authority; callers must not fall back to an earlier key after a freeze.

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

Unauthenticated malformed records, bad rotation signatures/attestations and
gapped sequences are skipped with source/index/reason diagnostics. At each
sequence, resolution compares copies by rotation ID (the signing-bytes hash).
A fully verified copy satisfies that ID; another copy with damaged SIWE proof
cannot veto it, regardless of input order. Failed copies remain diagnostics.
Two distinct fully verified IDs at the same sequence freeze with `rotation-fork`.

After a new-key signature and Panopticon attestation authenticate a rotation's
references, missing or unverifiable evidence is fatal only if **no copy of that
ID fully verifies**. Missing/tampered authorizer and retained links, and missing
or malformed SIWE proofs on the rotation itself, return `missing-history`.
Witnessed contradictions and referenced fork/conflict errors remain fatal.
A valid copy of a different ID cannot discharge this requirement. Discarding an
unresolved authenticated ID could otherwise restore an older key. No proof bytes
are repaired into an accepted rotation; success always uses a fully verified copy.

`ResolutionContext.links` holds one copy per link ID. Because link IDs exclude
`keySig`, `siwe` and `attest`, callers **MUST preserve a verifying copy** when
assembling this map. Keep alternative copies until credential signatures,
witnesses and the relevant authenticated key state can be checked. Never use
first-write/last-write wins over untrusted proof copies, or let a damaged copy
overwrite an authenticated one. If no required copy verifies, fail with
`missing-history`; do not omit the authenticated rotation. The package does not
provide a storage/index deduplication adapter.

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


## Draft checks and current-key compromise

`checkRotationDraft` / `check_rotation_draft` is never an attestation gate.
Success checks a builder's draft, not authorization to sign a witness record.
Panopticon must use `checkRotationPublish` / `check_rotation_publish` on the
signed request and apply its own issuance policy.

A thief holding the authenticated current signing key can sign revokes of that
account's recovery links. A witness cannot distinguish that signature from one
made by the owner. Present-only revokes can remove recovery eligibility even
while a witness is unavailable; they do not remain effective after that key
retires unless historical verification has the required timestamp evidence.
A timestamp records when a signed revoke existed, not whether the owner intended
it. Do not treat witness availability or a retained wallet/OIDC link as protection
against a thief who still holds the current key.

For an unattested rotation request, the present-revocation path evaluates the
current-key signature through `now + clockSkewSeconds`. A witnessed revoke
inside that horizon also counts through this present path: its witness is not
required or certified by `verifyRevokeNow`. This does not admit a future revoke
into authenticated history. Historical witnessed checks and direct
`verifyRevokeNow` calls at unadjusted `now` remain skew-free. A retired key's
signature cannot use this present-only path to revoke a link.
