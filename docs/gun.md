# Gun adapter

Authority-plane mapping for GunDB. This is not the s3r.ch product surface.

[FyberLabs/s3r.ch](https://github.com/FyberLabs/s3r.ch) owns feed, UX, and the TypeScript graph. That work lives on s3r.ch PR #7 (`cursor/gundb-feed-rearchitecture-9b12`). s3r.ch does **not** import this Rust crate. Reimplement the types below in TypeScript. The Gun adapter surface for that product is **Check + `delegate` only**.

This crate maps the locked s3r.ch Gun graph onto existing SociACL Check predicates and the keep-operating `delegate` grant. It does not add a Gun-only verb. It does not fork that graph.

## Product split

| Piece | Owner | Lives |
| --- | --- | --- |
| Graph, named predicates, Check, `delegate` | SociACL | `crates/sociacl-core` |
| Soul / URL / handoff types and dest Check | SociACL | `crates/sociacl-gun` |
| C accept / Check / remint / cancel | SociACL | `crates/sociacl-c` |
| Feed, UX, Gun peers, TypeScript graph | s3r.ch | s3r.ch PR #7 |
| Elect, wills, devices, Case C mint | SociACL core only | not on the s3r.ch Gun surface |

s3r.ch stores **only Gun-native objects** under this adapter. In-graph Gun data is the native ACL. Check evaluates graph relations on souls and nodes.

A Check **object** is a Gun-native **feed item** or a **held claim** on the user node. Same item shape. Not only identity claims. Accessor is a wallet / Gun peer. Lighter Check is `CHECK(see, object, accessor)` at now. Hopcap 1. Grants are jointly stated. Revoke is immediate.

Non-Gun data is a URL. RSS3 GI, RSS/Atom, KYC / email / phone issuer HTTP calls are **leaf pointers**, not Gun nodes and not grants. Crossing them (`/api/ingest`, seeder) is an **untrusted handoff**. Destination re-authorizes on the way back, then may `put` a native object into `items`. A URL 200 is not `see`.

Execute-without-read is the existing `delegate` primitive (action mask `execute` without `read`). Elect from a hop, hint, or delegate remains refuse-closed.

A Social Light hop can factor Check. It cannot mint.

Case C may Check a frozen bundle the way the rest of SociACL does. The client has no mint path for new Gun grants.

## Locked s3r.ch graph (consume, do not fork)

Gun root: `s3rch`.

```
gun.get('s3rch').get('items').get(encodeKey(id))  → GunFeedNode
gun.get('s3rch').get('meta')                     → seed meta (not a Check object)
gun.get('s3rch').get('users').get(wallet)        → GunUserNode
```

`encodeKey`: `id.replace(/[.#$\[\]]/g, '_')`.

`GunFeedNode` (in-graph = native SociACL object):

```
{ id, source: rss3|rss|atom, kind, author, body, ts, permalink, tags: string, provenance }
```

`FeedItem` is UX only (`tags: string[]`). Mapping is `toGunNode` / `fromGunNode`. Unknown `source` is not a feed node. Empty `kind` maps to `"activity"` (same as s3r.ch `fromGunNode`). Dedupe: canonical id, else normalized permalink.

`FeedTab` is `"public" | "mine" | "network"`. UX only. Not a Check object.

`GunUserNode` (typed, later): `{ id, indicators: string[], provenance, ts }`. Indicators are a comma-separated string on the Gun wire, same as tags. Do not invent a second user node.

`IdentityClaimKind`: `wallet | rss3 | ens | kyc_attestation | email | phone`. Issuers prove a claim to the holder. They are not grants.

`IdentitySeeGrant`: `{ claimId, accessor, from, until }`. Maps onto keep-operating `delegate` read with `until`. hopcap 1. Jointly stated. Revoke immediate. Not Elect. Dest Check `until` is exclusive (existing `delegate`). `from` is inclusive and is **not** on the dest edge — `check_see_grant` ANDs dest Check with `now ∈ [from, until)`. `CHECK(see, object, accessor)` at now.

Arrays cannot live in Gun. Tags (and later indicators) are a comma-separated string on the wire.

Graphs: public cache vs personal overlay vs later explicit share-into-mesh. Observing public traces is not dumping a private overlay.

## TypeScript handoff surface

Reimplement these named fields. Do not pull `sociacl-core`.

```ts
type GunSoul = { segments: string[] }
// user: ['s3rch', 'users', wallet]
// item: ['s3rch', 'items', encodeKey(id)]
// meta: ['s3rch', 'meta']   // not a Check object
// claim object id: the claim id, linked from the user node

type UrlLeaf = { url: string }  // RSS3 / RSS / Atom / issuer HTTP; not a node; not a grant

type HandoffHint = {
  principal: string   // wallet / agent id as we name them
  target: string      // claimed soul, feed item, or claim object id
  verb?: string       // see | execute | write | …
  context?: string    // optional; the URL being crossed is not a grant
}

type IdentitySeeGrant = {
  claimId: string
  accessor: string
  from: number
  until: number
}

type FeedTab = "public" | "mine" | "network"  // UX only; not a Check object
type IdentityClaimKind = "wallet" | "rss3" | "ens" | "kyc_attestation" | "email" | "phone"
```

`accept_hint` / decode does not verify and does not mint. Destination Check against the live ACL (including `delegate` grants) is the grant. A hint alone fails closed.

### Hint wire (`SGH1` v1)

Optional binary form for C / Python. Distinct from Social Light `SLHP` and Case C `SACL`. Decode still does not verify.

```
magic        4 bytes   "SGH1"
version      u16 LE    1
payload_len  u32 LE
payload
  principal  u32 LE length + UTF-8
  target     u32 LE length + UTF-8
  has_verb   u8 (0 none, 1 present)
  verb       u32 LE length + UTF-8 if has_verb
  has_ctx    u8
  context    u32 LE length + UTF-8 if has_ctx
```

Max string 4096. Fail closed on a bad magic, version, or length.

## Mapping

| s3r.ch / Gun | SociACL |
| --- | --- |
| `see` | Check `read` on a Gun-native object |
| object | `GunFeedNode` or a held claim (same Check) |
| accessor | wallet / Gun peer (`s3rch/users/<wallet>`) |
| execute-without-view | `delegate` mask `execute` without `read` |
| `IdentitySeeGrant` | `delegate` read + `until`; `check_see_grant` ANDs `[from, until)` at now; cancel is undelegate |
| cancel | owner `undelegate` / unstate on the dest object |
| remint | refresh only if the current ACL already names the principal |
| permalink / RSS3 / RSS / KYC HTTP | `UrlLeaf` (handoff, not a node) |
| handoff | `HandoffHint` (untrusted factor) |
| hopcap | 1. No friend-of-friend |

`see` is an adapter alias for `read`. `ActionMask` still matches `read` / `write` / `execute`. The adapter maps `see` before dest Check.

## File layout

```
docs/gun.md                    this page
crates/sociacl-gun             types + dest Check + delegate mapping
crates/sociacl-c/include       encode / accept / Check / see-grant / remint / cancel / elect
python/sociacl                 thin ctypes of the C ABI
```

Elect is visible and always fails (`sociacl_gun_elect`). Case C mint is visible and always fails (`client_mint_grant`).

## What this does not do

- Open or edit FyberLabs/s3r.ch
- Invent a second graph schema or a second user node
- Add a Gun-only Check verb
- Treat a seeder or `/api/ingest` fetch as a grant
- Put lease tickets on this plane
- Bolt Elect, wills, or devices onto the s3r.ch Gun surface
- Host accounts, add SaaS, or invent tokenomics
- Implement LightIFF
