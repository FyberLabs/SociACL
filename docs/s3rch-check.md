# Light Check consume contract (s3r.ch)

This is the artifact the s3r.ch Next app reimplements against.

**File:** [s3rch-check.d.ts](s3rch-check.d.ts)

The Next app runs Check **in the browser** on the Gun mesh. It does **not** import this Rust crate, NAPI, or WASM. Do not `npm install sociacl`. Copy the `.d.ts` or re-type the same names. WASM later is optional and is **not** the lab-feed path.

`crates/sociacl-gun` in this repo is the reference implementation. It is not a runtime they load.

## What they implement

`CHECK(see, object, accessor)` at `now`.

| Name | Meaning |
| --- | --- |
| `object` | `GunFeedNode` at `s3rch/items/<encodeKey(id)>`, or a held claim id itself (`ens:…` / `unstoppable:…` / `fc:…` / `lens:…` / `rss3:…`) linked from `GunUserNode.indicators`, or a later opaque post/room `CheckObjectId` |
| `accessor` | wallet / Gun peer (`s3rch/users/{wallet}`) |
| `see` | dest Check `read` |
| grant | jointly stated `IdentitySeeGrant` / mesh `MeshSeeGrant`; hopcap **1** (no friend-of-friend) |
| revoke | immediate privilege-down on the dest object (`cancelSee`) |
| hint | `HandoffHint` — untrusted; never a grant |
| hop | optional Social Light `HopFactor`; never a grant; missing does not fail |
| wrap | `WrappedKey` to a SEA `epub` or a group epoch key; never a grant; never mints |
| admit | dest re-authorizes **before** `put()` into `items` |

`s3rch/meta` is seed cache. It is not a Check object. A permalink / RSS3 / RSS / issuer URL is a `UrlLeaf`, not a node and not a grant.

Later, on request: more verbs on the TS spec for granted distribution. Not this cut. Wrapped keys, recipient-side discovery, and group predicates are named in [encrypted-discovery.md](encrypted-discovery.md). They are not extra verbs. The portable plane in `typescript/` is a copyable reference for Panopticon and other adapters. s3r.ch still copies this file and does not `npm install sociacl`.

## Fixed Gun paths (do not fork)

```
gun.get('s3rch').get('items').get(encodeKey(id))  → GunFeedNode
gun.get('s3rch').get('meta')                     → seed meta (not a Check object)
gun.get('s3rch').get('users').get(wallet)        → GunUserNode
gun.get('s3rch').get('acl').get(aclPrincipalKey(owner))
     .get(aclKey(object)).get(aclPrincipalKey(accessor))  → MeshSeeGrant
```

`encodeKey`: `id.replace(/[.#$\[\]]/g, '_')`.

`aclKey`: `encodeKey` then `/` → `_` so dest-ACL souls stay five segments. Not a second `encodeKey` for items or users.

Held-claim object id is the **claim id itself** (`ens:name.eth`, `unstoppable:…`, `fc:…`, `lens:…`, `rss3:0x…`), linked from `GunUserNode.indicators` on `s3rch/users/<wallet>`. Mesh Check treats those ids the same as `GunFeedNode` ids. Do not invent `s3rch/users/<wallet>/claims/…`. Overlay uses the same `GunUserNode` shape until s3r.ch `prepareShareUserIntoMesh` / `prepareShareClaimIntoMesh`. Do not invent `s3rch/posts/…` — s3r.ch owns post/room souls; treat them as opaque `CheckObjectId`s.

The Rust crate in this repo remains the full plane. See [gun.md](gun.md) for that map. Social Light hop wire: [social-light.md](social-light.md).

## Mesh

This is the cut the s3r.ch design engineer wires after held-claims land.

**Copy / re-type:** [s3rch-check.d.ts](s3rch-check.d.ts) (one file; Mesh section is at the bottom). Do not `npm install sociacl`.

### Dest ACL soul

See grants are Gun nodes under the **object owner's dest ACL**, not under `items` or `users`:

```
s3rch/acl/<aclPrincipalKey(owner)>/<aclKey(object)>/<aclPrincipalKey(accessor)>
```

`s3rch/users/<wallet>` collapses to the wallet on dest ACL. Examples:

```
s3rch/acl/0xalice/rss3:act_1_x/0xbob          // feed item rss3:act/1#x
s3rch/acl/0xalice/ens:alice_eth/0xbob         // held claim ens:alice.eth
```

Each field HAM-merges. `MeshSeeGrant.stated` is `1` (live) or `0` (cancelled). Cancel is owner-only and **must bump Gun HAM state** so privilege-down wins the next merge. Each peer runs `checkSee` on its locally HAM-merged graph at `now`. Do not cache an allow across a privilege-down merge.

`s3rch/acl` itself is not a Check object (same as `meta`).

### Objects in scope

| Object | Id | In-graph? |
| --- | --- | --- |
| Feed item | `s3rch/items/<encodeKey(id)>` | yes, after dest admit |
| Held claim | claim id itself (`ens:…` / `unstoppable:…` / `fc:…` / `lens:…` / `rss3:…`), linked from `GunUserNode.indicators` | yes, after dest admit / s3r.ch `prepareShareClaimIntoMesh` |
| Post / room | opaque `CheckObjectId` (s3r.ch names the soul later) | yes, after dest admit |
| Mine overlay | same `GunUserNode` shape, local only | **no** until s3r.ch `prepareShare*` then `putObject` |
| Permalink / RSS3 / issuer HTTP | `UrlLeaf` | never |

### Hop factor

`checkSee(graph, object, accessor, now, hint?, hop?)`.

- hop missing does not fail.
- hop alone never allows.
- `hop` may only factor an already-named grant or owner path. Direct membership is the same rule on `checkGroupSee` (spec, below).
- `acceptHop` / `decodeHop` do not verify and do not mint (mirror `acceptHint`).
- URL handoffs stay untrusted `HandoffHint`. A hint plus a hop still fail closed without dest ACL.

Reuse SociACL Social Light (`convention-badge` / `enrolled-station`, SLHP v1). Do not reimplement the hop frame.

## Private rows and group predicates (spec)

[encrypted-discovery.md](encrypted-discovery.md) is the spec. s3r.ch product draft: [FyberLabs/s3r.ch#108](https://github.com/FyberLabs/s3r.ch/pull/108) (`docs/encrypted-discovery.md` there). This repo does not edit s3r.ch.

Copy the new names from [s3rch-check.d.ts](s3rch-check.d.ts) (`WrappedKey`, `BlindedGrantRow`, `MeshMembership`, `checkGroupSee`, `rotateOnRevoke`). The reference crate still evaluates plaintext `MeshSeeGrant` only. `GunFeedNode` and `GunUserNode` stay as they are. Do not `npm install sociacl`.

A wrap of a DEK to a reader SEA `epub` is not a grant. SEA `priv` and `epriv` never go on Gun. Check must still pass. A hop, a hint, or a wrap never mints. SociACL decides who receives a wrap: only a principal the live grant or direct membership already names.

`same-group` and `named-circle` are hopcap **1** and jointly stated. The object names the set, and the accessor has a direct `member-of` or `in-circle` edge. Membership does not inherit across groups or circles. Hop may factor that direct edge. Hop alone never allows.

Each reader account has exactly one private inbox lane. Scanning a shared bucket is not allowed. Entries are append-only. The entry id is the SHA-256 (lowercase hex) of the length-prefixed lane, ciphertext, commitment, and wrap. The visible row has no owner id, no owner SEA pub, and no `hamState`. Order between a live grant and a cancel is a monotonic `grantRevision` inside the signed payload. The greatest revision wins. The verifier holds that high-water mark and rejects a presentation below it. `grant`, `owner`, and `grantRevision` must match the payload decoded from the signed bytes. At a tied revision, stated 0 wins before any digest comparison. A live payload does not replace a cancellation. When stated matches and a digest is already stored, the smaller payload digest wins. An empty payload digest raised from a status proof is unknown. The first payload with the same revision and the same stated is accepted and that digest is stored. The empty string is not the smallest digest. The status proof names this accessor and this grantRevision. The owner signs the length-prefixed encoding of the object, the epoch, the revision, the accessor, that grantRevision, stated, the times, and the zookie. The grant, the proof, the zookie, and the epoch view name one object and one epoch. A mismatch fails closed before a nonce is spent. A verified proof with a higher grantRevision, or stated 0 at the same revision, updates the verifier record. The status proof must also name the verifier's current read key. A live row at a lower or equal revision does not undo a cancel. When the grant is same-group or named-circle, the call takes PresentedGroup and runs checkGroupSee. An ordinary see grant omits it and runs checkSee. A group object with no group argument fails closed. When the grant names an encrypted item, the signed payload includes that item's ciphertext digest. The call compares the SHA-256 of the fetched ciphertext to that digest. A mismatch fails closed. The graph snapshot hash is not that digest. The commitment is a hash of a fresh blinding plus the canonical grant. The blinding is in the presentation and not on the visible row. An unsalted hash of the grant bytes is not the commitment. The holder presents the opened grant at the destination. Check recomputes the commitment from that blinding, checks the signature with the enrolled SEA pub from that presentation, checks a presenter binding against a verifier-held nonce (single use, with expiry) or an `AuthenticatedPresenterChannel` instance whose private brand the transport set, and requires a fresh owner-signed epoch/status proof beside the zookie. The channel's accessor and `readerPub` must be the grant's accessor and that accessor's enrolled pub. The brand is an ECMAScript private field and a module `WeakSet`, and the instance is frozen. An object literal is not that channel. Copying the brand onto another object fails. A channel for another principal fails closed. The graph exposes `objectVersion(object)` and `snapshotHash(object)` for the object the zookie names. `signedAt` must fall within the verifier's skew allowance, and the age must be within the smaller of the proof's `maxAgeMs` and the verifier's `policyMaxAgeMs`. A proof alone grants nothing. The owner signs the item plaintext digest and the epoch revision, then encrypts the body and that signature together. The ciphertext digest is not an input to the signature. Row counts, timing, and sizes still leak. The destination learns the owner. Private information retrieval and zero-knowledge proofs are future work, not this spec.

Each account has one SEA keypair. Devices inherit it through enrollment. `priv` and `epriv` never go on Gun. The author may unwrap from a local DEK. That fast path is not a grant. Two devices can mint different keys for the same next epoch. `revisionId` is the SHA-256 (lowercase hex) of the length-prefixed manifest body: object, epoch, previous epoch, device id, key commitment, settleWindowMs, and the ACL snapshot. The snapshot is one row per accessor: the accessor, that accessor's grantRevision, stated, from, until, scope, set id, and hamState. There is no single cancel number across accessors. A group or circle row uses MeshMembership.hamState, and a lower hamState does not hide a removal. A stated-1 entry whose until has passed does not settle. epochStepCurrent takes the winning snapshot and the ACL this replica has merged. During the window a presentation names the settled epoch, not the pending candidate epoch. The manifest signature covers revisionId. The owner publishes a new key that was not wrapped to that accessor. Each replica recomputes the winner as the smallest `finalizationId` among the verified finalizations it has seen for the current parent. A later smaller id replaces the previous winner and takes descendant epochs that named the displaced parent off the current chain. The owner rebuilds those epochs outward, parent before child, each with a new finalization. The owner signature covers `finalizationId`, not the revision id alone. The owner signs `settleWindowMs` on the object manifest, or the same number on `GroupEpochConfig` for a group. The default is 24 hours, the minimum is 1 hour, and the maximum is 72 hours. Readers keep the last settled key while a candidate is pending and switch once that signed window passes. The window does not freeze the set and does not delay a cancel. Every wrap carries its revision inside the authenticated payload. A device id is not a Gun device record.

The reader chooses who may append. The default is public writes (`public-filtered`) with a local spam filter. The writer id comes from a branded channel or a signature over the entry id, checked against the verifier's enrollment map before quotas. A claimed pub that is not the enrolled pub fails closed. The stored row still has no writer pub. The relay that accepts the append learns that writer id. A peer that only replicates the row does not. Outstanding admission challenges are one per nonce. First contact is a writer absent from the verifier's `knownSenders`. It requires proof-of-work against a verifier-issued nonce and difficulty, or a stamp signed by an issuer the verifier trusts, both bound to that row's entry id. The verifier holds one quota counter per sender and one shared `laneRemaining` for the lane. A writer-claimed quota, a first-contact flag, or an unverified token is not evidence. `named-writers` is the allowlist. The hook is not a grant. First contact carries the sender's SEA `epub` and `pub`, bound by an enrollment lookup or by a length-prefixed account signature over the account, pub, and epub. The one lane is scanned by rescanning whole daily shards and deduplicating. A per-device cursor is not the scan.

Revoke on the plaintext edge is `stated: 0` plus a `hamState` bump, then a new epoch wrapped to the remaining readers. On a private row the same deny is a new append whose signed `grantRevision` is greater and whose `stated` is 0. That deny is immediate for a current verifier and does not wait for the settle window. A revoked reader is left out of every candidate epoch's wraps. Remaining readers keep reading the last settled key until the window passes. New writes after the cancel stay buffered until the winner settles, then use that key. They are not written under the last settled key or under a candidate that can still lose. If a smaller finalizationId later displaces that settled winner, content encrypted under the displaced revision is not current. The owner re-encrypts those writes under the new winner and issues wraps that match the new snapshot. Readers keep bytes they already unwrapped. A snapshot that lists a cancelled accessor as live, omits that accessor, or cancels that accessor below the revision this replica already has is ignored. `forward-only` leaves ciphertext already written under the old key. `re-encrypt` rewrites the soul under the candidate, and remaining readers use the copy they already unwrapped until they switch. Otherwise freshness is bounded by the status proof's max-age and the verifier's skew allowance. The proof names the accessor and that accessor's grantRevision. Bytes a revoked reader already unwrapped stay readable to that reader. A member offline through the window applies a missed cancel as soon as they see it.

Applying a new protocol version encrypts existing data in place. Only the owner re-encrypts and issues wraps. Each reader keeps the old copy until that reader acknowledges receipt of the wrap. A version at the gate does not by itself drop plaintext. There is no single flag that drops plaintext for every reader at once. A plaintext replica already stored elsewhere remains a historical leak.

SociACL runs no index. One public index for public content. Each private group runs its own. Individuals push and pull, then index a small set on device. An index hit is not a grant.

Group epoch length, whether plaintext `MeshSeeGrant` stays for public content, and group search tokens are open. See the spec.
