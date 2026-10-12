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

Each reader account has exactly one private inbox lane. Scanning a shared bucket is not allowed. Entries are append-only and content-addressed by the hash of the ciphertext. The visible row has no owner id and no owner SEA pub. The holder presents the opened grant at the destination. Check recomputes the commitment, checks the signature with the enrolled SEA pub from that presentation, checks a presenter binding (a destination nonce signed by the reader's SEA key, or an authenticated channel), and requires a fresh owner-signed epoch/status proof beside the zookie. A proof alone grants nothing. An owner signature over the item ciphertext digest sits inside the encrypted item. Row counts, timing, and sizes still leak. The destination learns the owner. Private information retrieval and zero-knowledge proofs are future work, not this spec.

Each account has one SEA keypair. Devices inherit it through enrollment. `priv` and `epriv` never go on Gun. The author may unwrap from a local DEK. That fast path is not a grant. Two devices can mint different keys for the same next epoch. An owner-signed epoch manifest names a revision id (hash of the previous epoch and the device id) and the smallest revision id wins. Readers reject a superseded revision. A device id is not a Gun device record.

The reader chooses who may append. The default is public writes (`public-filtered`) with a local spam filter, a first-contact proof-of-work or stamp, and a quota per sender that is separate from the reader's capacity. `named-writers` is the allowlist. The hook is not a grant. First contact carries the sender's SEA `epub` and `pub`, with an account binding signed by `pub`. The one lane is scanned with a cursor per sender device, or by rescanning whole daily shards and deduplicating. One clock high-water mark is not a cursor.

Revoke is `stated: 0` plus a `hamState` bump, then a new epoch wrapped to the remaining readers. That deny is immediate for a current verifier. Otherwise it is bounded by the status proof's max-age. The owner chooses `forward-only` or `re-encrypt`. Bytes a revoked reader already unwrapped stay readable to that reader.

Applying a new protocol version encrypts existing data in place. Only the owner re-encrypts and issues wraps. Readers keep the old copy until that migration arrives. Plaintext is removed only after that. A plaintext replica already stored elsewhere remains a historical leak.

SociACL runs no index. One public index for public content. Each private group runs its own. Individuals push and pull, then index a small set on device. An index hit is not a grant.

Group epoch length, whether plaintext `MeshSeeGrant` stays for public content, and group search tokens are open. See the spec.
