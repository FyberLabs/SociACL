# Spec: `sociacl-ids`, the shared identity package (TypeScript + Rust)

Status: initial design dated 2026-10-16, amended for sociacl-ids 0.6 during review of #57 and for sociacl-ids 0.7 Rotate v3 (#64). Sections 4.4–4.6 below reflect the current record contract. The [normative review amendment](identity-review-amendment.md) supersedes the original grammar and history rules where stated; the [package README](../typescript/ids/README.md) documents the implemented API.

Repos referenced:
- `FyberLabs/SociACL`: Rust workspace `crates/*`, JS package `typescript/` (ESM, JSDoc, `tsc --strict`), vectors in `vectors/`.
- `FyberLabs/s3r.ch`: Next.js/TypeScript client using Gun, viem and TanStack Query.
- `FyberLabs/panopticon`: Python services plus a Next.js `frontend/` (zod, openapi-typescript, TanStack Query).

Line references are as of SociACL `main@7279ef6`, SociACL PR #56 head `d51e33f`, s3r.ch `feat/views-route@da3a396` and panopticon `main`.

---

## 1. Purpose and first principles

Today SociACL and s3r.ch identify objects and accounts by *strings in several spellings*: a raw id or `s3rch/items/<id>`; a wallet, `s3rch/users/<wallet>` or a Gun `.get()` chain. The code then reconciles those spellings at every comparison. That design produced an access bypass (a Gun-chain accessor spoof, SociACL #54), lossy keys (`room.alpha`, `room_alpha` and `room/alpha` were all one key), and a grant-soul collision in PR #56. The fix is the shared package specified here.

Rules. Each rule is normative.
1. **One minter per id.** Every id type has exactly one place that creates it (table in §2). Nothing else creates or "repairs" ids.
2. **Identity is never derived from display data.** Names, labels, titles, descriptions, handles, ENS names, email and wallet text are attributes or lookup keys. They never serve as a join key or as an identity.
3. **Canonicalize once, at the edge.** Untrusted input becomes a branded id through one `parse*` function. After that the value is passed through as-is and is never re-parsed, re-escaped or "normalized" again.
4. **The core accepts branded types only.** Permission code (`checkSee`, `checkPost`, grant writers and the like) takes branded ids, never `string`.
5. **Fail closed.** Unknown, non-canonical or ambiguous input is rejected with a reason. There is no fallback spelling, no alias folding, no trimming or case-folding of stored data, and no "best effort" parse.
6. **No escaping scheme.** Every path-key alphabet is safe in Gun paths by construction. Input outside the alphabet is rejected, not escaped.
7. **Equality is `===`** on canonical strings in TypeScript, and `==` on newtypes in Rust. There is no `sameX()` helper.

## 2. Locked decisions

| Id | Canonical identity | Minted by | Notes |
|---|---|---|---|
| `PrincipalId` (account) | The **genesis** Gun SEA P-256 public key `pub`, exactly as SEA emits it | The account's first enrolled client, once | Never changes. The *current* signing key may rotate (§4.6). |
| `Eip55` (wallet) | EIP-55 checksummed address | Wallet | A **linked credential** for login and recovery. Never a principal. |
| OIDC credential | `(iss, tenant, sub)` | Panopticon Keycloak | A linked credential. A Panopticon attestation is required (§4.6). Linked per tenant. |
| `TenantId` | Panopticon tenant UUID (lowercase, hyphenated) | Panopticon | Panopticon uses `uuid.UUID` (`core/auth-service/src/auth_service/enrollment.py:231`). |
| `ObjectId` (native object) | `<kind>_<principal-key>_<32 lowercase hex>`. The principal key is the creator's genesis `PrincipalId` in the existing `p_` + 128 hex form. The 32 hex digits are 128 fresh bits. | The creating client | Stored on the object. Parsing the id returns that one principal. Gun souls are derived from it one way (§3.6). |
| `LegacyObjectId` | Removed. The seven `s3rch:room` / `chat` / `forum-msg` / `post` / `forum-group` / `bot` / `forum` spellings are not object ids. | — | `post` is a reserved kind. `s3rch:forum:<owner>` has no nonce, so a forum id needs a random part before s3r.ch can adopt it. Network ids `s3rch:https://...` stay. |
| `DerivedObjectId` | `sha256` of a canonical external id (held claim, external feed item) | Deterministic | Used for ids whose source alphabet isn't path-safe (`ens:alice.eth`, `rss3:act/1#x`). |
| `NetworkId` | `s3rch:https://<host>:<port>;key=<64hex>` or one of `atproto`, `farcaster`, `nostr`, `activitypub`, `rss` | The deployment's permitted key / the protocol | Same grammar as s3r.ch `lib/views-source-ref.ts:94-116`. |
| `SourceKey` | `formatCanonical(SourceRef)` from s3r.ch `lib/views-source-ref.ts:225-227` (`sr1:` + pct(network) `/` pct(owner) `/` pct(source) `/` kind) | Deterministic | For s3r.ch networks, `owner` becomes a `PrincipalId` (follow-up call site, Appendix B). |

Why the bound `ObjectId` uses the principal key: the 87-character principal contains `.`, and `.` is reserved in a path key. `p_` + lowercase hex is the path form that already exists, it is canonical, and it decodes to exactly one on-curve principal. The id is `<kind>_<principal-key>_<32 lowercase hex>`. Kind is 2–16 characters, the principal key is 130 characters, and the nonce is 32 hex digits, so the longest id is 180 characters. A path key may be 180 characters. A membership soul that carries a longest id is 472 characters and still fits the 512-character soul parser. `claim`, `ext`, `post`, `member`, and `objset` stay reserved and cannot be the kind. The older `<kind>_<32 lowercase hex>` form still parses. It has no embedded principal, and an object record cannot use it.

Why the original random form was `<kind>_<32 lowercase hex>` with 128 bits from a CSPRNG.
- **Hex, not base32:** hex has exactly one encoding per value. Base32 needs a rule about unused trailing bits.
- **Not UUIDv7 or ULID:** those leak creation time, and ordering comes from the object's `ts` field.
- **128 bits:** collision chance is negligible, about 2^64 objects for a 50% birthday bound. Today's ids carry only 32 bits (`lib/rooms.ts:60-64`).
- **Path-safe:** the alphabet `[a-z0-9_]` needs no escaping in Gun paths.
- **Typed kind prefix:** helps debugging and branded sub-types. Code never derives authority from it.

## 3. Grammar

All rules match the **entire** string (anchored). All characters are ASCII unless stated. Input is first rejected if it is not a JS `string` (or Rust `&str`), contains a control character (`U+0000-U+001F`, `U+007F-U+009F`), contains `U+FEFF`, `U+200B-U+200F`, `U+2028`, `U+2029` or `U+FFFD`, or contains an unpaired surrogate. **Nothing is trimmed.** Leading or trailing whitespace is a reject.

```abnf
; 3.1 Principal
b64u          = ALPHA / DIGIT / "-" / "_"
b64u-last     = "A" / "E" / "I" / "M" / "Q" / "U" / "Y" / "c" / "g" / "k" / "o" / "s" / "w" / "0" / "4" / "8"
                ; the 43rd char of 32 bytes: its 2 low bits must be 0 (canonical base64url, no padding)
principal-id  = 42b64u b64u-last "." 42b64u b64u-last          ; exactly 87 chars
principal-key = "p_" 128HEXL                                    ; x||y raw point bytes, lowercase hex, 130 chars

; 3.2 Wallet
eip55         = "0x" 40( DIGIT / %x41-46 / %x61-66 )           ; and the EIP-55 checksum must match exactly
wallet-key    = "w_" 40HEXL                                     ; 42 chars

; 3.3 Tenant / OIDC
tenant-id     = 8HEXL "-" 4HEXL "-" 4HEXL "-" 4HEXL "-" 12HEXL  ; 36 chars; version bits not enforced
oidc-iss      = "https://" 1*2040VCHAR-NO-WS                   ; exact byte match against a pinned issuer; no normalization
oidc-sub      = 1*255( %x21-7E )                                ; OIDC Core §2: ≤255 ASCII, case-sensitive, opaque
oidc-key      = "k_" 64HEXL                                     ; sha256(LP("sociacl-oidc-v1") LP(iss) LP(tenant) LP(sub))

; 3.4 Objects
kind          = %x61-7A 1*15( %x61-7A / DIGIT )                 ; 2..16 chars, NOT one of: "claim" "ext" "post" "member" "objset"
bound-object  = kind "_" principal-key "_" 32HEXL               ; creator's genesis key; 166..180 chars
object-id     = kind "_" 32HEXL                                 ; older unbound form; ≤ 49 chars; not an object record
derived-id    = ( "claim" / "ext" ) "_" 64HEXL
                ; claim_ = sha256(LP("sociacl-claim-v1") LP(claimText)); claimText is the existing held-claim id, e.g. "ens:alice.eth"
                ; ext_   = sha256(LP("sociacl-ext-v1") LP(sourceKey) LP(providerItemId))
any-object    = bound-object / object-id / derived-id
object-key    = any-object                                      ; already path-safe; the path key is the id itself

; 3.5 Network / SourceKey
network-id    = "atproto" / "farcaster" / "nostr" / "activitypub" / "rss"
              / "s3rch:https://" public-hostname ":" port ";key=" 64HEXL   ; rules: s3r.ch views-source-ref.ts:69-116
network-key   = "n_" 64HEXL                                     ; sha256(LP("sociacl-network-v1") LP(networkId))
source-key    = "sr1:" ...                                      ; exactly s3r.ch parseCanonical(); ≤ 8192 chars
source-key-pk = "s_" 64HEXL                                     ; sha256(LP("sociacl-source-v1") LP(sourceKey))

HEXL          = DIGIT / %x61-66
LP(x)         = u32-little-endian(byteLength(utf8(x))) || utf8(x)  ; same encoding as SociACL request.js:295 / request.rs:408
```

**3.6 Path keys and souls.** The path-key alphabet is `[A-Za-z0-9_:-]`. **Reserved characters are never allowed** in any path key: `/ . # $ [ ] ~ %`, whitespace, control characters and anything outside ASCII.
- Every path key starts with a type tag (`p_`, `w_`, `k_`, `n_`, `s_`), or is an `any-object` whose kind is at least 2 characters or which starts with `s3rch:`. So keys of different types can never be equal.
- Max path-key length: 180. A bound object id is the longest path key. Typed tags (`p_`, `w_`, `k_`, `n_`, `s_`) are shorter.

Soul builders take branded values only, and always produce a fixed number of segments:
```
objectSoul(collection, o)   = "s3rch/" collection "/" objectKey(o)          ; collection ∈ {items, rooms, users-legacy}
userSoul(p)                 = "~" p                                         ; Gun user space; link records live here
aclSoul(owner)              = "s3rch/acl/" principalKey(owner)              ; 3 segments
grantSoul(owner, o, acc)    = "s3rch/acl/" pk(owner) "/" objectKey(o) "/" pk(acc)              ; exactly 5 segments
postSoul(owner, o, acc)     = "s3rch/acl/" pk(owner) "/post/" objectKey(o) "/" pk(acc)         ; exactly 6 segments
membershipSoul(setOwner, predicate, set, member)
                        = "s3rch/acl/" pk(setOwner) "/member/" predicate "/" objectKey(set) "/" pk(member)
                        ; predicate ∈ {"same-group","named-circle"}; exactly 7 segments
objectSetSoul(owner, object)
                        = "s3rch/acl/" pk(owner) "/objset/" objectKey(object)                 ; exactly 5 segments
```
Debug builds must assert the segment count. **No function parses a soul back** into ids, except `parseSoul(text)`, which accepts exactly these templates and returns `{template, ids}`, or rejects.

## 4. TypeScript API (`typescript/ids`, ESM, zero runtime dependencies besides `@noble/curves` and `@noble/hashes`)

The package must run unchanged in browsers (s3r.ch client) and Node ≥ 24. **Do not use `node:crypto`.** Existing `typescript/src/request.js:52` uses it; this package must not.

### 4.1 Types
```ts
declare const brand: unique symbol;
export type Brand<T, B extends string> = T & { readonly [brand]: B };

export type PrincipalId     = Brand<string, "PrincipalId">;
export type PrincipalKey    = Brand<string, "PrincipalKey">;      // "p_..."
export type Eip55           = Brand<string, "Eip55">;
export type TenantId        = Brand<string, "TenantId">;
export type OidcCredential  = { readonly iss: string; readonly tenant: TenantId; readonly sub: string };
export type ObjectId        = Brand<string, "ObjectId">;          // bound-object | object-id | derived-id | legacy-id
export type MintedObjectId  = ObjectId & Brand<string, "Minted">;
export type NetworkId       = Brand<string, "NetworkId">;
export type SourceKey       = Brand<string, "SourceKey">;
export type PathKey         = Brand<string, "PathKey">;
export type Soul            = Brand<string, "Soul">;

export type Reason =
  | "not-string" | "empty" | "too-long" | "control-char" | "invisible-char" | "unpaired-surrogate"
  | "whitespace" | "bad-alphabet" | "bad-length" | "non-canonical" | "bad-checksum" | "not-on-curve"
  | "reserved-kind" | "unknown-network" | "bad-host" | "bad-port" | "gun-chain" | "bad-template";
export type Result<T> = { ok: true; value: T } | { ok: false; reason: Reason };
```

### 4.2 Parsers
Parsers never throw on any input, including non-strings and objects with `toString`/`valueOf`: they check `typeof x === "string"` first. They are pure.
```ts
parsePrincipalId(x: unknown): Result<PrincipalId>     // §3.1 regex + base64url decode + re-encode equality + p256 point validity
parseEip55(x: unknown): Result<Eip55>                 // stored data: exact checksummed form only
parseWalletInput(x: unknown): Result<Eip55>           // UI edge only: all-lower or all-upper hex accepted → EIP-55; mixed case must match checksum
parseTenantId(x: unknown): Result<TenantId>           // lowercase only; uppercase = "non-canonical"
parseOidcCredential(x: unknown): Result<OidcCredential>   // {iss, tenant, sub}; iss compared later against a pinned issuer, never normalized
parseObjectId(x: unknown): Result<ObjectId>           // bound-object | object-id | derived-id | legacy-id
objectPrincipal(x: unknown): Result<PrincipalId>       // the one genesis principal in a bound-object; bad-template otherwise
parseNetworkId(x: unknown): Result<NetworkId>
parseSourceKey(x: unknown): Result<SourceKey>         // port of s3r.ch parseCanonical + validateSourceRef; s3rch owner must be a PrincipalId
parseSoul(x: unknown): Result<{ template: "object"|"user"|"acl"|"grant"|"post"|"membership"|"objset"; ids: readonly string[] }>
```
Any string that contains `.get(`, `get(`, `['get']`, `["get"]`, or a backslash is rejected with reason `"gun-chain"` before any other parsing. A defensive tag only; the alphabets already exclude these.

### 4.3 Format, path keys, mint
```ts
formatPrincipalKey(p: PrincipalId): PrincipalKey      // "p_" + hex(x||y)
formatWalletKey(w: Eip55): PathKey                    // "w_" + lowercase hex
formatOidcKey(c: OidcCredential): PathKey
formatNetworkKey(n: NetworkId): PathKey
formatSourcePathKey(s: SourceKey): PathKey
objectKey(o: ObjectId): PathKey                       // identity
objectSoul / userSoul / aclSoul / grantSoul / postSoul / membershipSoul / objectSetSoul   // §3.6, branded args only, return Soul
lengthPrefixed(fields: unknown): Result<Uint8Array>   // u32-le UTF-8 lengths; non-strings and lone surrogates are rejected
verifyKeySignature(key: PrincipalId, sig: string, bytes: Uint8Array): Result<true>
signWithKeyring(scalar: Uint8Array, bytes: Uint8Array, expectedKey: PrincipalId): Result<string>
  // expectedKey is the resolver's current key. The scalar copy is wiped. Bad material or a different pub is "bad-key".
mintObjectId(kind: string, creator: PrincipalId, rng?: (n: number) => Uint8Array): Result<MintedObjectId>   // default rng = crypto.getRandomValues
deriveClaimId(claimText: string): Result<ObjectId>    // claimText validated as non-empty, ≤2048, no controls
deriveExternalId(source: SourceKey, providerItemId: string): Result<ObjectId>
```
Equality is `===` everywhere. Export no comparison helpers.

### 4.4 Signing bytes
All signatures cover `LP(domain) LP(field1) … LP(fieldN)` (§3).

| Record | Domain | Fields, in order |
|---|---|---|
| Key → wallet link | `sociacl-link-wallet-v1` | principal, eip55, issuedAt (decimal seconds), nonce |
| Key → OIDC link | `sociacl-link-oidc-v1` | principal, iss, tenant, sub, issuedAt, nonce |
| Rotation v2 | `sociacl-rotate-v2` | principal, seq (decimal), prevKey, nextKey, issuedAt, authorizer.kind, authorizer.link, retainedLinks.length (decimal), each retained ID in order. Used when `nextEpub` is absent |
| Rotation v3 | `sociacl-rotate-v3` | the v2 fields, with `nextEpub` immediately after `nextKey`. Used when `nextEpub` is present |
| Revocation | `sociacl-revoke-v1` | principal, linkId, issuedAt |

`linkId` = lowercase hex sha256 of the record's signing bytes. Record identity never depends on signature bytes (ECDSA malleability).

### 4.5 Signatures
- **SEA key signatures:** ECDSA P-256 over SHA-256 of the signing bytes, a raw 64-byte `r||s`, base64url without padding. These can be produced from the SEA pair with WebCrypto, as s3r.ch `lib/views-backup.ts` already does for manifests. Verifiers accept high-S and low-S. The SEA `SEA{m,s}` envelope is **not** used.
- **SIWE:** an EIP-4361 message whose `statement` is exactly `SociACL link: ` + hex(sha256(signing bytes)) and whose `address` is the `Eip55`. Signed with EIP-191 `personal_sign` (secp256k1, keccak256). Verification recovers the address and compares it with `===`. EIP-1271 smart-contract wallets: reject with `"unsupported-wallet"` (out of scope).
- **Panopticon attestation:** compact JWS, `alg` = `ES256`, unique `kid` required in the caller-pinned JWKS. `iat` must equal the record's `issuedAt`; `exp` must be later and no more than 900 seconds after `iat`. Exact claims:
  - Wallet: `{typ:"sociacl-wallet-attest-v1", principal, linkId, iat, exp}`.
  - OIDC: `{typ:"sociacl-oidc-attest-v1", iss, tenant, sub, principal, iat, exp, nonce}`.
  - Rotation v2: `{typ:"sociacl-rotate-attest-v2", principal, nextKey, seq, iat, exp, auth:"wallet"|"oidc-fresh-login", linkId, retainedLinks}`. `linkId` equals `authorizer.link` and `retainedLinks` equals the signed array. Required when the record has no `nextEpub`.
  - Rotation v3: `{typ:"sociacl-rotate-attest-v3", principal, nextKey, nextEpub, seq, iat, exp, auth:"wallet"|"oidc-fresh-login", linkId, retainedLinks}`. Same claims as v2, plus `nextEpub` equal to the signed field. Required when the record has `nextEpub`.
  - Revoke: `{typ:"sociacl-revoke-attest-v1", principal, recordId, iat, exp}`. `recordId` hashes the revoke signing bytes, including its target link and timestamp.
  - ACL witness: `{typ:"sociacl-acl-attest-v1", principal, recordId, iat, exp}`. `recordId` is hex(sha256(bytes)) and `iat` equals the row `issuedAt`. Defined and verified by `verifyAclAttestation`. Not issued. A compact JWS is capped at 16384 characters before it is parsed.
- Panopticon assigns wallet/revoke timestamps after verifying the proofs and current account state. A client-supplied date is not a timestamp witness. OIDC rotation additionally requires a fresh login to the exact credential named by the enrolled link.

### 4.6 Records
```ts
export type WalletLink = { v: 1; kind: "wallet"; principal: PrincipalId; address: Eip55; issuedAt: number; nonce: string;
  keySig: string /* SEA key over link-wallet bytes */; siwe: { message: string; signature: `0x${string}` };
  attest: string /* Panopticon timestamp JWS */ };
export type OidcLink = { v: 1; kind: "oidc"; principal: PrincipalId; cred: OidcCredential; issuedAt: number; nonce: string;
  keySig: string; attest: string /* Panopticon JWS */ };
export type Rotate = { v: 1; kind: "rotate"; principal: PrincipalId; seq: number /* 1.. */; prevKey: PrincipalId; nextKey: PrincipalId;
  nextEpub?: PrincipalId /* SEA point; present only for rotation v3 */;
  issuedAt: number; retainedLinks: readonly string[] /* sorted unique link IDs, at most 1024 */;
  nextSig: string /* new key over rotation v2 bytes, or v3 bytes when nextEpub is present */;
  authorizer: { kind: "wallet"; link: string /* linkId */; siwe: {message:string; signature:`0x${string}`} }
            | { kind: "oidc-fresh-login"; link: string /* enrolled OIDC linkId */ };
  attest: string /* Panopticon JWS, required in both cases */ };
export type Revoke = { v: 1; kind: "revoke"; principal: PrincipalId; linkId: string; issuedAt: number;
  keySig: string; attest?: string /* required for history; optional for present current-key revokes */ };
export type GenesisEpub = { v: 1; kind: "genesis-epub"; principal: PrincipalId; epub: PrincipalId;
  issuedAt: number; keySig: string /* sociacl-genesis-epub-v1 */; attest: string /* sociacl-genesis-epub-attest-v1 */ };

verifyWalletLink(r: unknown, jwks: Jwks, policy: SiwePolicy, now: number, keyState: KeyState): Result<WalletLink>
verifyOidcLink(r: unknown, jwks: Jwks, pinnedIss: ReadonlySet<string>, now: number, keyState: KeyState, clockSkewSeconds?: number): Result<OidcLink>
verifyRevoke(r: unknown, currentKey: PrincipalId, jwks: Jwks, now: number): Result<Revoke>
verifyRevokeNow(r: unknown, currentKey: PrincipalId, now: number): Result<Revoke>
verifyRotate(r: unknown, currentKey: PrincipalId, context: ResolutionContext): Result<Rotate>
verifyRotationRequest(r: unknown, currentKey: PrincipalId, context: ResolutionContext): Result<Rotate>
verifyGenesisEpubRequest(r: unknown, genesis: PrincipalId, now: number, policy: SiwePolicy): Result<GenesisEpub>
resolveCurrentKey(genesis: PrincipalId, rotations: readonly unknown[], context: ResolutionContext): Resolution<{currentKey: PrincipalId; currentEpub: PrincipalId | null; bindingEpub: PrincipalId | null; rotations: readonly Rotate[]}>
checkRotationPublish(candidate: unknown, siblings: readonly unknown[], genesis: PrincipalId, acceptedPrior: readonly unknown[], context: ResolutionContext): Result<Rotate>
checkRotationDraft(candidate: unknown, siblings: readonly unknown[], genesis: PrincipalId, acceptedPrior: readonly unknown[], context: ResolutionContext): Result<Rotate>
resolveWalletLink(address: Eip55, links: readonly unknown[], revocations: readonly unknown[], context: ResolutionContext): Resolution<WalletLink>
resolveWalletLinkNow(address: Eip55, links: readonly unknown[], revocations: readonly unknown[], context: ResolutionContext): Resolution<WalletLink>
verifySignedAt(principal: PrincipalId, rotations: readonly unknown[], ctx: ResolutionContext, bytes: Uint8Array, sig: string, issuedAt: number): Result<{ key: PrincipalId, mode: "present" | "witnessed" }>
verifySeeGrant(row: unknown, rotations: readonly unknown[], ctx: ResolutionContext): Result<{ key: PrincipalId, mode: "present" | "witnessed", grant: SeeGrant, bytes: Uint8Array }>
verifyAclAttestation(jws: string, jwks: Jwks, issuedAt: number, bytes: Uint8Array): Result<{ typ: "sociacl-acl-attest-v1", principal: PrincipalId, recordId: string, iat: number, exp: number }>
```

`verifySignedAt` resolves the current key first and returns that failure unchanged. `issuedAt` must be a nonnegative safe integer; a negative or fractional value is `bad-record`. `issuedAt` past `now + clockSkewSeconds` is `future-record`. `clockSkewSeconds` must be an integer from 0 through 300; anything else, including NaN, Infinity, a string, or 301, is `bad-record`. A signature under the current key returns `{key, mode: "present"}`, or `bad-signature` when it fails. Kind is not an argument, and there is no attestation argument. A retired key is `unwitnessed-retired-key`. See rows go through `verifySeeGrant`, which parses the row once and encodes `sociacl-see-grant-v2` from that value. A retired see cancel is `stated === 0` inside those bytes, with an attestation over the same bytes. A retired `stated === 1` row is refused even when witnessed. `mode: "witnessed"` is that see-cancel result. `sociacl-cancel-v2` is the group-cancel domain (membership and object-set), not a see cancel.

`Resolution<T>` adds `{source,index,reason}` diagnostics to the success/failure
result. `ResolutionContext` requires pinned `jwks`, `pinnedIss`, `policy`, `now`,
a link map and a `history` resolver; it optionally includes `revocations` and
`genesisEpubBindings`. `genesisEpubBindings` is the list of witnessed
`genesis-epub` records. Gun `user.epub` is not that list and is never read.
`KeyState` contains the signing key before a record's timestamp, the current key
at the horizon, and the intersection of retained IDs from subsequent rotations
(or `null` when none followed). The caller must authenticate complete history;
`historyState` only computes state from previously verified rotations.

Rules:
- A link's SEA signature uses its key at issuance. Every subsequent rotation must retain the link ID for it to remain usable. A retired key cannot enroll a new backdated credential through an earlier retained set.
- The rotation version is inferred from whether `nextEpub` is present, not from record `v` (which stays 1). A rotation without `nextEpub` is v2: signing domain `sociacl-rotate-v2` and attestation typ `sociacl-rotate-attest-v2`. A rotation with `nextEpub` is v3. `nextEpub` is a SEA P-256 point in the same 87-character form as `nextKey`, parsed by `parsePrincipalId`. It is the encryption public key after that rotation. It is not an account id. New rotations MUST be v3. From package 0.7, Panopticon attests only v3. The library still verifies historical v2 records. Panopticon never attests both versions for the same principal and sequence. Publishing both versions of one transition yields two signing-byte IDs at that sequence and freezes the account with `rotation-fork`. `resolveCurrentKey` sets `currentEpub` from each accepted rotation after the signature, attestation, authorizer, retained-link, and revocation checks below: a v3 rotation sets it to that `nextEpub`, and a v2 rotation sets it to null. Null means unknown. Consumers must not seal, and they must never fall back to Gun's `user.epub`. With no accepted rotation, `currentEpub` is the in-force witnessed `genesis-epub` binding, or null when there is none. A `genesis-epub` record is signed by the genesis key under domain `sociacl-genesis-epub-v1` and attested with typ `sociacl-genesis-epub-attest-v1`. `iat` must equal `issuedAt`. The epub must be a canonical on-curve SEA point and must not equal the genesis pub. No wallet or Keycloak proof is required. Panopticon attests at most one binding per principal, only before the first rotation, and that limit is global across instances and signing keys (panopticon#499). It sets `iat` itself, with `exp <= iat + 900`, and verifies the genesis-key signature. Two valid bindings issued strictly before the first accepted rotation freeze the account with `rotation-fork` (diagnostic source `genesis-epub`). A binding issued at or after that rotation is skipped with `bad-sequence` and does not freeze the account. With no accepted rotation, every valid binding counts. `issuedAt` must be at or before `now` plus the policy clock skew. The binding attestation is verified as of `issuedAt`, so it does not expire. Once a rotation is accepted, the in-force binding epub joins the reuse set: a later `nextEpub` or `nextKey` equal to it is `bad-sequence`. An unwitnessed genesis epub string is ignored. `verifyGenesisEpubRequest` checks a binding request before attestation: shape, canonical epub distinct from the genesis pub, genesis-key signature, and `|issuedAt - now| <= clockSkewSeconds`. A present `attest` is `bad-record`. It does not check that no rotation exists. `verifyRotationRequest` is the local pre-attestation check for one v3 rotation request: it refuses v2 and any present `attest`; it requires `|issuedAt - now| <= clockSkewSeconds`; it checks the next-key signature, the authorizer, the links, the retained set, historical revocation at `issuedAt`, and present revocation at `now` on the authorizer and every retained link. Freshness and present revocation apply only to that unattested request. Present revocation honors `clockSkewSeconds`: an offline revoke issued at or before `now + skew` removes the link, and one dated further ahead is ignored. Historical witnessed checks and direct `verifyRevokeNow` stay skew-free. It does not check chain sequence, sibling forks, or epub reuse. `checkRotationPublish` calls it when the candidate has no attestation, then applies those checks, and is the shared client-publish and Panopticon-attest check. An unsigned draft is `bad-record`. `checkRotationDraft` is the keyring builder's check before a signature exists; Panopticon does not call it. Panopticon must call `checkRotationPublish`. A sibling attestation is verified as of that sibling's `issuedAt`, so an expired sibling still counts. A sibling counts only when its signature and the full Panopticon claim both verify, including `auth`, `linkId`, `retainedLinks`, and the exact claim shape. Junk is skipped. An identical attested sibling is a retry and is not a fork. A draft validates `retainedLinks` with the signed-record rule. `verifyRotate` checks the attestation as of `issuedAt`, so a historical record still verifies after the witness window. The prior chain is whatever `resolveCurrentKey` accepts. The check refuses a v2 record (no `nextEpub`) with `bad-record`, and refuses two versions or two signing-byte ids for one (principal, seq) with `rotation-fork`. It does not replace `verifyRotate`. Historical v2 records still verify there. A null `currentEpub` still means do not seal and never fall back to Gun's `user.epub`. `nextEpub` must not equal `nextKey`, genesis, any prior signing key, or any prior epub, and a later `nextKey` must not equal any prior epub. Those collisions are `bad-sequence`. `historyState` stays signing-key state and carries no epub.
- Rotations use contiguous sequences starting at one, strictly increasing timestamps, matching previous keys and no signing-key reuse. Two distinct valid records at the same sequence freeze the account with `rotation-fork`. Unauthenticated malformed/forged candidates are skipped with diagnostics. Copies are compared by signing-bytes hash; any fully verified copy satisfies that rotation ID, regardless of damaged-copy input order. After the new-key signature and attestation authenticate an ID, missing/unverifiable authorizer or retained-link evidence (including missing/malformed rotation SIWE) is fatal `missing-history` only if no copy of that ID fully verifies. A valid different ID cannot substitute. Failed copies remain diagnostics; no proof is repaired into an accepted transition.
- The rotation's authorizer and every retained ID must be valid links of that principal in the pre-rotation state. Any revoke witnessed at or before the rotation and signed by its preceding current key conflicts with retaining or authorizing with that link. After the rotation signature and attestation verify, this is fatal `rotation-conflict`; no current key is returned. An omitted ID cannot be restored by a later rotation.
- OIDC recovery requires a retained, unrevoked enrolled OIDC link, a pinned issuer and a rotation attestation bound to that link. Any active wallet of that principal blocks OIDC recovery, even if the candidate drops that wallet from `retainedLinks`. Direct verification returns `wallet-required`; resolution freezes with `rotation-conflict`. Conflicting wallet ownership likewise freezes an authenticated rotation instead of discarding it.
- Historical revoke verification uses the key current at the evaluation horizon and a mandatory timestamp witness. The pre-rotation check enforces earlier revocations before retiring that key; an unwitnessed backdated revoke cannot affect history, and a witness that signs conflicting backdated revocations causes a freeze instead of rollback. Same-second revokes use the preceding key; the new key signs records strictly after the rotation timestamp.
- Present-only `verifyRevokeNow` and `resolveWalletLinkNow` accept a revoke signed by the final authenticated current key without a witness. Omit `attest` for offline revokes; explicit null/empty/non-string values are malformed. These APIs do not certify a supplied witness string. Match principal, target ID and time when using direct verification. Signing bytes and IDs are unchanged by witness presence.
- An unwitnessed revoke stops applying when its signing key retires. No saved-state persistence across retirement is implemented. It never counts in historical/as-of queries, rotation checks or `*AtKey` aliases. Historical APIs cannot be switched into present mode by input/context fields. Before authorizing new login/recovery, consumers must check present revocation eligibility separately; historical rotation verification does not replace that check. Preserve removal across a rotation through the retained set or a witnessed revoke consistent with the transition.
- Panopticon and clients **MUST exclude present-revoked links from `retainedLinks`** when constructing rotations. Panopticon **MUST run present revocation checks before attesting any rotation or login** using final authenticated key state: `resolveWalletLinkNow` must select the authorizing wallet link ID; for an authenticated OIDC link, `verifyRevokeNow` must be matched by principal, target ID and `revoke.issuedAt >= link.issuedAt`. Refuse a revoked authorizer even if it is dropped from retention. Check every retained candidate, including other credential kinds. Clients sign the filtered set; Panopticon independently checks it and rechecks on state changes. Historical rotation constraints also remain required.
- Callers building `ResolutionContext.links` **MUST preserve a verifying copy per link ID**, retaining alternatives until signatures, witnesses and historical key state can be checked. A link ID excludes its signature/SIWE/attestation bytes; first-write/last-write wins over untrusted copies is unsafe. If no required copy verifies, fail with `missing-history`. Storage deduplication is outside the package.
- Present lookup may use cached proofs/keys but still requires complete authenticated history and a trusted latest-state checkpoint. A record's claimed timestamp never selects the key for present revocation.
- Wallet lookup filters the requested address and verifies time, SIWE and timestamp attestation before requesting history. Revokes are filtered by target/principal/time and cannot request unrelated history. Missing history or a fork is fatal only for relevant, independently witnessed links.
- The newest valid wallet link wins. Distinct equal-time links are ambiguous, even for the same principal. Revoking the newest binding never revives an older binding.
- Historical witnesses are checked at issuance; their later expiry does not invalidate history. Direct wallet/OIDC proof checks allow explicitly configured clock skew of 0–300 seconds. An attested rotation is checked as of its `issuedAt`. Freshness on an unattested rotation request is `|issuedAt - now| <= clockSkewSeconds`. History admission applies no skew. Direct `verifyRevokeNow` applies no skew. Present revocation inside an unattested rotation request does: an offline revoke at or before `now + clockSkewSeconds` removes the link.
- A pure verifier cannot detect omitted history, prove the absence of an omitted wallet, fetch trusted keys or consume nonces. Callers must supply complete authenticated state and enforce input/work budgets without silently truncating histories.
- Link records are published under `userSoul(principal)` (Gun `~pub` space). Private keys, PRF wraps and SIWE session cookies are never published.
- Wrapped key backups live in Panopticon storage. That is outside this package.

### 4.7 zod
Subpath export `sociacl-ids/zod`, with `zod` as a **peerDependency** so the core package doesn't depend on it. Each schema is `z.unknown().transform(parseX)`, surfacing the reason as a zod issue. There is exactly one validator per id; the zod schemas call the parsers.

## 5. Rust API (`crates/sociacl-ids`, a workspace member)

- Newtypes: `PrincipalId`, `PrincipalKey`, `Eip55`, `TenantId`, `OidcCredential`, `ObjectId`, `NetworkId`, `SourceKey`, `PathKey`, `Soul`. Each has `FromStr<Err = Reason>`, `Display`, `AsRef<str>`, `Eq`, `Hash` and `Ord`, and none has a public tuple field.
- `TryFrom<&str>` is identical to `FromStr`. There is no `From<String>`.
- Functions mirror §4.2–4.6 in snake_case and return `Result<T, Reason>`. `Reason` is an enum whose kebab-case names are identical to the TS strings.
- **String semantics:** reject on the Unicode-scalar level the same way TS does. Do not use `str::trim` or `char::is_whitespace` anywhere, since Rust's notion of whitespace differs from JS `trim()` on `U+FEFF`.
- Crates:
  - `p256` (ecdsa, arithmetic): the workspace already pins `=0.13.2` in `crates/sociacl-encdisc/Cargo.toml:18`; reuse that pin.
  - `sha2`: already in the workspace.
  - `k256` (ecdsa, for secp256k1 recovery) and `sha3` (Keccak-256), for SIWE.
  - A JWS/JWK verifier for ES256: use `p256` directly with a minimal compact-JWS parser.
  - `serde` / `serde_json`: already present.
  - `getrandom` for minting.
  - Pick versions compatible with the existing lockfile and commit `Cargo.lock`. Don't use `--locked` drift.
- Expose a C-ABI shim later via `sociacl-c` (non-goal here).

## 6. Shared test vectors (`vectors/ids/*.json`)

Format, one file per id family, loaded by **both** the TS and Rust test suites (and Python through `sociacl-c` later):
```json
{ "v": 1, "family": "principal",
  "accept": [ { "name": "genesis-1", "input": "<87 chars>", "canonical": "<same>", "pathKey": "p_<128 hex>" } ],
  "reject": [ { "name": "trailing-space", "input": "<87 chars> ", "reason": "whitespace" } ] }
```
`input` may be any JSON value, so non-string inputs are vectors too. Required families: `principal`, `wallet`, `tenant`, `oidc`, `object`, `network`, `source-key`, `soul`, `signing-bytes`, `records` (wallet link, OIDC link, rotate, fork, revoke, each with fixed test keys and the expected verify result).

Required reject cases. Each must be present and rejected identically in both languages.
- **Gun chains (#54 item 1):**
  - `0xattacker.get('s3rch').get('users').get('0xvictim')`
  - `gun.get('s3rch').get('users').get('0xbob')`
  - `0xattacker.get ('s3rch')`
  - `0xattacker['get']('s3rch')`
  - `x\u002eget(`
- **The fold triple:** `room.alpha`, `room/alpha` and `room_alpha` as `ObjectId`. All three are rejected with `bad-alphabet`. Only minted, derived or legacy ids are accepted.
- **Grant-soul collision (#56):** `grantSoul` must make it impossible to build `("0xalice","doc","0xbob/x")` vs `("0xalice/doc","0xbob","x")`. All six components are invalid ids, so they're rejected at parse. Add an accept-side vector with two distinct valid triples whose souls differ and contain exactly 5 segments.
- **Paths:** `../meta`, `s3rch/meta`, `s3rch/acl/x`, `s3rch/users/0x…` as `PrincipalId`. All rejected; there's no alias form.
- **Escape remnants:** `room~1alpha`, `~0`, `%2F`, `a%2Eb`. All rejected.
- **Controls and invisibles:**
  - `a\u0000b`, `\u0085x`, `\uFEFFx`, `x\u200B`, `\u2028`, and an unpaired `\uD800`.
  - A leading space, a trailing tab, and an NBSP `\u00A0` (bad-alphabet).
- **Lookalikes:** fullwidth `．`, `∕` (U+2215), `／` (U+FF0F), Cyrillic `а` in a hex position, `０` (fullwidth zero) in a wallet.
- **Case:**
  - A wallet with a wrong mixed-case checksum. An all-lowercase wallet: rejected by `parseEip55`, accepted by `parseWalletInput`.
  - An uppercase tenant UUID.
  - An uppercase hex `ObjectId`.
- **Principal:**
  - 86 or 88 chars, a missing `.`, two dots, padding `=`, a non-canonical last char (e.g. ending `B`), a standard-base64 `+` or `/`.
  - A valid-looking string that isn't a point on P-256.
- **Stateful object:** `{ toString(){…} }` gives `not-string`.
- **#54 items 2–4** are request-layer behaviours. Add record-level vectors so that a `Rotate`/`Link` whose `principal` is a non-string object is rejected, and so that a fork at the same `seq` gives `rotation-fork`.

Property tests (fast-check in TS, proptest in Rust; at least 10k cases per property in CI):
1. `parse(format(x)) == x` for every generated valid value of every family.
2. `format` is injective: distinct canonical values give distinct canonical strings and distinct path keys, including across families (no `PathKey` collisions between `p_`, `w_`, `k_`, `n_`, `s_` and object keys).
3. `parse(canonical) == canonical`: parsing a canonical string is the identity, i.e. idempotent.
4. No path key or soul segment contains `/ . # $ [ ] ~ %`. Every soul has its template's exact segment count.
5. Every `reject` vector is rejected in both languages with the same `reason`.
6. `mintObjectId` output always parses, and 1e6 mints have no duplicates.
7. TS and Rust produce byte-identical signing bytes and `linkId`s for every `signing-bytes` vector.

## 7. Packaging, versioning, CI

- **Location:** SociACL repo, at `typescript/ids/` (package name `sociacl-ids`, ESM, own `package.json`, `"private": false`) and `crates/sociacl-ids/` (workspace member). Vectors go in `vectors/ids/`.
- **Distribution:** GitHub Release asset `sociacl-ids-<version>.tgz` produced by `npm pack`. s3r.ch and Panopticon depend on the tarball URL, which the lockfile pins with integrity. This needs no registry token, and avoids the GHCR/Packages auth failures we've hit. s3r.ch stops vendoring `docs/s3rch-check.d.ts` for ids (the current state is described in `typescript/package.json`: "s3r.ch still copies docs/s3rch-check.d.ts and does not import this package").
- **Versioning:** independent tag track `ids-vMAJOR.MINOR.PATCH`, starting at `ids-v0.1.0`. Any change to an `accept` or `reject` vector, a grammar or a signing domain is a MAJOR change. While below 1.0, bump MINOR for it and record it in `CHANGELOG.md`.
- **CI** (extend `scripts/test-all.sh` and `.github/workflows/ci.yml`; the CI's Node ≥ 24 check stays):
  - `cargo test -p sociacl-ids --locked`, including proptests.
  - `node --test typescript/ids/test/*.js`, including fast-check.
  - `tsc --strict --noEmit` on `typescript/ids`.
  - A browser-compat check: bundle with esbuild for `--platform=browser` and fail if `node:` imports appear.
  - A vector check that fails if any `vectors/ids/*.json` case isn't loaded by both suites. Each suite emits the vector names it ran, and CI compares the two sets.
  - Release job on tag: `npm pack`, attach the tgz to the release, and publish a sha256 of the tgz.

## 8. Non-goals (this PR)

- No changes to callers: SociACL `src/*.js`, the existing `crates/sociacl-gun`, s3r.ch and Panopticon stay as they are. Appendix B lists them for later PRs.
- No alias folding, no `sameObjectId`/`sameAccessor`-style helpers, and no acceptance of `s3rch/users/<wallet>` or raw-vs-soul spellings.
- No wallet-as-identity: `Eip55` never converts to `PrincipalId`.
- No permission logic: no `checkSee`, grants, HAM or epochs.
- No storage of records, no Gun I/O, no Panopticon endpoints. The package only defines the formats and verifies them.
- No EIP-1271, no ENS resolution, no handle registry, no search indexing.
- No migration of existing Gun data.

## 9. Acceptance criteria

- [ ] `typescript/ids` and `crates/sociacl-ids` implement §3–§5 and nothing more.
- [ ] Every parser is total (never throws or panics) on arbitrary input. A fuzz test with 1e5 random strings or values is included in both languages.
- [ ] The core API has no function that takes `string`/`&str` where a branded id is expected, except the `parse*` functions. A type test proves that `grantSoul("a","b","c")` fails to compile in TS.
- [ ] Vectors in `vectors/ids/` cover every case in §6, and both suites load 100% of them (CI-enforced).
- [ ] All 7 property tests pass in both languages.
- [ ] TS and Rust produce identical signing bytes, `linkId`s, path keys and souls.
- [ ] Verification works end to end with fixed test keys for a wallet link, an OIDC link (test JWKS), a rotate via wallet, a rotate via fresh OIDC login, a fork, and a revoke.
- [ ] No `node:` imports in `typescript/ids` (browser bundle check).
- [ ] The release job produces `sociacl-ids-0.1.0.tgz` on tag `ids-v0.1.0`. A sample consumer (an `examples/consumer` folder in the SociACL repo) installs it from the local tgz and runs the parsers.
- [ ] The PR touches only `typescript/ids/**`, `crates/sociacl-ids/**`, `vectors/ids/**`, `Cargo.toml` (members), `Cargo.lock`, `scripts/test-all.sh`, `.github/workflows/ci.yml`, `CHANGELOG.md` and docs.

---

## Appendix A: why the old scheme failed (evidence)

- SociACL `typescript/src/post.js:49-90` (main): an unanchored `.get(` chain parser turned `0xattacker.get('s3rch').get('users').get('0xvictim')` into `0xvictim`.
- SociACL `typescript/src/gun.js:43-61` (main): `encodeKey` folded `. # $ [ ]` to `_`, and `aclKey` also folded `/` to `_`. Result: `room.alpha` = `room_alpha` = `room/alpha`.
- SociACL PR #56 `d51e33f`: unescaped principals in `grantSoul` (`gun.js:96-100`, Rust `soul.rs:110-120`) made `("0xalice","doc","0xbob/x")` and `("0xalice/doc","0xbob","x")` the same soul.
- s3r.ch `lib/identity/check.ts:478-492`: `grantNamesObject` matched `object.endsWith('/chat/'+id)`, so a grant could cross rooms.
- At least 8 copies of key encoding across TS and Rust: `gun.js`, `post.js`, `group.js`, `request.js`, `contract/migration.ts`, `soul.rs`, `encdisc/migration.rs`, plus s3r.ch `lib/identity/check.ts:219-300`.

## Appendix B: call sites to migrate later (not in this PR)

**SociACL**, `main@7279ef6` unless marked #56 (`d51e33f`):
- TS key encoding and accessors:
  - `typescript/src/gun.js:20-61` (`samePrincipal`, `canonicalStoredObject`, `grantNamesObject`, `encodeKey`, `itemSoul`, `userSoul`, `aclKey`, `aclPrincipalKey`, `aclSoul`, `grantSoul`)
  - `typescript/src/post.js:40-135` (`aclKey`, `aclPrincipalKey`, `itemSoulAlias`, `objectNames`, `canonicalAccessorId`). #56: `post.js:66-91, 142, 160-161, 216-217`.
  - `typescript/src/group.js` (#56): `373-385` encode/acl/principal keys, `433-444` membership/object-set souls, `1605` `grantKey`, `1222` `enrolledKey`.
  - `typescript/src/request.js` (#56): `182-258` canonical request accessor/object and `reducibleItemInner`, `295` `lengthPrefixed` (keep the encoding, move into ids), `459` enrolled-key lookup.
  - `typescript/contract/migration.ts:45-77`.
- Rust:
  - `crates/sociacl-gun/src/soul.rs`: `16-60` (escape), `101-120` (soul builders), `183-202` (principal key).
  - `crates/sociacl-gun/src/mesh.rs`: `614-626` (`object_record`, `canonical_object_id`), `731-742` (`grant_soul`, `acl_soul`).
  - `crates/sociacl-gun/src/post.rs:137` (`post_soul`).
  - `crates/sociacl-gun/src/group.rs`: `331` (membership soul), `398-425` (enroll and lookup), `1546` (set id from key).
  - `crates/sociacl-gun/src/request.rs`: `115-140`, `380-417`.
  - `crates/sociacl-gun/src/feed.rs:263-292`.
  - `crates/sociacl-encdisc/src/migration.rs:795-830`.

**s3r.ch** (`feat/views-route@da3a396`):
- Identity: `lib/identity/check.ts:138-145` (string `CheckObjectId`/`AccessorId` types), `219-300` (encodeKey, itemSoul, roomSoul, userSoul, aclKey, aclPrincipalKey), `451-528` (`accessorAliases`, `sameAccessor`, `grantNamesObject`, `userObjectId`, `ownerOwnsObject`), `632-645` (lowercase dedupe).
- Account keys:
  - `lib/identity/mesh.ts:51-79`: a SEA pair is minted per device and keyed by wallet. One key per account needs SociACL #24.
  - `lib/identity/idb.ts:20-22`: the "address is session subject" record.
  - `lib/identity/mesh-link.ts:7-28`: the wallet-signed statement becomes a `WalletLink`.
  - `lib/identity/link.ts:37-41, 51-56`: `IdentityPerson.owner` is the wallet, and the OIDC handle lacks tenant and issuer.
  - `lib/identity/wrap.ts:51-66`: envelope `address` becomes the principal.
- Objects: `lib/users.ts:2,309` (user soul `s3rch/users/<wallet>`), `lib/rooms.ts:60-64,143`, `lib/chat.ts:48-52,123`, `lib/forum.ts:488,652,1123` (mint sites move to `mintObjectId`).
- Forum: `lib/forum.ts:368,408,648` (label used as identity), `590` (handle lookup not scoped by channel).
- Views:
  - `lib/views-source-ref.ts:146-153`: the s3r.ch owner must be a `PrincipalId`, not a wallet.
  - `lib/views-picker.ts`: `73` (lowercase owner compare), `247` (label copied into the window), `284-286` (`labelFor` linear scan).
  - `lib/views-access.ts:45` (`roomSoul(ref.source)`).
  - `lib/views-backup.ts:104-109,216,253` (owner in AAD and manifest becomes the principal).
  - `lib/views-store.ts` (keyed by wallet).
  - `components/ViewRoute.tsx:34` (`selfNetwork: ""` placeholder).

**Panopticon frontend** (`main`):
- `frontend/src/lib/private-model-upload.ts:40`: upload grant chosen by `file.name`; use the file index or sha256.
- The OIDC link attestation (§4.5) is a new Panopticon endpoint, in a separate PR.
