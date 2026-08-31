# Gun adapter

Authority-plane mapping for GunDB. This is not the s3r.ch product surface.

[FyberLabs/s3r.ch](https://github.com/FyberLabs/s3r.ch) owns feed, UX, and the TypeScript graph. That work lives on s3r.ch PR #7 (`cursor/gundb-feed-rearchitecture-9b12`). s3r.ch does **not** import this Rust crate. Reimplement the types below in TypeScript. The Gun adapter surface for that product is **Check + `delegate` only**.

This crate maps Gun souls and URL leaves onto existing SociACL Check predicates and the keep-operating `delegate` grant. It does not add a Gun-only verb. It does not fork the locked s3r.ch graph.

## Product split

| Piece | Owner | Lives |
| --- | --- | --- |
| Graph, named predicates, Check, `delegate` | SociACL | `crates/sociacl-core` |
| Soul / URL / handoff types and dest Check | SociACL | `crates/sociacl-gun` |
| C accept / Check / remint / cancel | SociACL | `crates/sociacl-c` |
| Feed, UX, Gun peers, TypeScript graph | s3r.ch | s3r.ch PR #7 |
| Elect, wills, devices, Case C mint | SociACL core only | not on the s3r.ch Gun surface |

In-graph Gun data is the native ACL. Check evaluates graph relations on souls and nodes. Non-Gun data is a URL: a permalink / ingest URL is a **leaf pointer**, not a Gun node and not an ACL grant.

Edge handoff is an **untrusted hint**. It names a principal, a claimed target, and an optional verb/context. Decode does not verify. Decode does not mint. Destination re-checks the live ACL and issues its own grant. Cancel stays on the destination ACL (owner undelegate / unstate). Privilege-down is immediate. Privilege-up can wait.

Execute-without-read is the existing `delegate` primitive (action mask `execute` without `read`). Elect from a hop, hint, or delegate remains refuse-closed.

Issuers and attestations prove a claim to the holder. They are not grants and do not publish the footprint. A Social Light hop, if present, is the same optional factor as keep-operating delegate: missing hop does not fail Check; a hop alone does not mint.

Case C may Check a frozen bundle the way the rest of SociACL does. The client has no mint path for new Gun grants.

## Locked s3r.ch graph (consume, do not fork)

Item shape (same everywhere; Gun stores `tags` as a comma-separated string):

```
{ id, source, kind, author, body, ts, permalink, tags[], provenance }
```

Dedup key: `id` else normalized permalink URL.

Identity: primary key is wallet address(es).

```
gun.get('s3rch').get('users').get(wallet)
```

Linked held claims hang off that node. Do not invent a second user node.

Visibility: a claim on the identity graph is the object. Accessor is another wallet / Gun peer. Lighter Check is `CHECK(see, claim, accessor)` at now. Hopcap 1 (no friends-of-friends). Grant is jointly stated.

Graphs: public cache vs personal overlay vs later explicit share-into-mesh. Observing public traces is not dumping a private overlay.

## TypeScript handoff surface

Reimplement these named fields. Do not pull `sociacl-core`.

```ts
type GunSoul = { segments: string[] }
// user: ['s3rch', 'users', wallet]  → NodeId "s3rch/users/<wallet>"
// claim object id: the item `id` (dedup key). Not a second user node.

type UrlLeaf = { url: string }  // normalized permalink; not a node; not a grant

type HandoffHint = {
  principal: string   // wallet / agent id as we name them
  target: string      // claimed soul or claim object id
  verb?: string       // see | execute | write | …
  context?: string
}
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
| `see` | Check `read` on the claim object |
| execute-without-view | `delegate` mask `execute` without `read` |
| cancel | owner `undelegate` / unstate on the dest object |
| remint | refresh only if the current ACL already names the principal |
| wallet | person `NodeId` `s3rch/users/<wallet>` |
| claim | protected object (the Check target) |
| permalink | `UrlLeaf` (not a node) |
| handoff | `HandoffHint` (untrusted factor) |
| hopcap | 1. No friend-of-friend |

`see` is an adapter alias for `read`. `ActionMask` still matches `read` / `write` / `execute`. The adapter maps `see` before dest Check.

## File layout

```
docs/gun.md                    this page
crates/sociacl-gun             types + dest Check + delegate mapping
crates/sociacl-c/include       encode / accept / Check / remint / cancel / elect
python/sociacl                 thin ctypes of the C ABI
```

Elect is visible and always fails (`sociacl_gun_elect`). Case C mint is visible and always fails (`client_mint_grant`).

## What this does not do

- Open or edit FyberLabs/s3r.ch
- Invent a second graph schema or a second user node
- Add a Gun-only Check verb
- Put lease tickets on this plane
- Bolt Elect, wills, or devices onto the s3r.ch Gun surface
- Host accounts, add SaaS, or invent tokenomics
- Implement LightIFF
