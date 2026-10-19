# Gun adapter

Authority-plane mapping for GunDB. This is not the s3r.ch product surface.

[FyberLabs/s3r.ch](https://github.com/FyberLabs/s3r.ch) owns feed, UX, and the TypeScript graph. That work lives on s3r.ch PR #7 (`cursor/gundb-feed-rearchitecture-9b12`). s3r.ch does **not** import this Rust crate, NAPI, or WASM. Check runs in the browser on the Gun mesh. WASM later is optional and is **not** the lab-feed path.

The consume contract they reimplement is **[s3rch-check.d.ts](s3rch-check.d.ts)** ([s3rch-check.md](s3rch-check.md)). Copy the file or re-type the names. Do not `npm install sociacl`. The Gun adapter surface for that product is **light Check + `delegate` only**.

This crate maps the fixed s3r.ch Gun graph onto existing SociACL Check predicates and the keep-operating `delegate` grant. It does not add a Gun-only verb. It does not fork that graph.

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

A Social Light hop can factor Check. It cannot mint. The consume contract names this `HopFactor` on `checkSee(..., hint?, hop?)`. Decode (`acceptHop` / `decodeHop`) does not verify and does not mint. See [social-light.md](social-light.md).

Mesh see grants are Gun-native dest-ACL nodes under `s3rch/acl/<owner>/<object>/<accessor>`. Post grants are a separate row under `s3rch/acl/<owner>/post/<object>/<accessor>` (`postSoul`). They do not fork `items` or `users`. Each peer Checks its locally HAM-merged graph at now. Cancel is owner-only privilege-down (`stated: 0` and a `hamState` bump) and must be visible on the next Check after merge (no cached allow). `checkPost` allows only when see also passes. A hop, a hint, a wrap, a request, or an inbox delivery never grants. Soul helpers: `aclKey`, `aclPrincipalKey`, `aclSoul`, `grantSoul`, `postSoul` in [s3rch-check.d.ts](s3rch-check.d.ts).

Wrapped-key grants, recipient-side discovery, and rotation on revoke are specified in [encrypted-discovery.md](encrypted-discovery.md). That part is spec only. This crate evaluates plaintext `MeshSeeGrant` rows, plaintext `MeshPostGrant` rows (`checkPost`), and direct `same-group` / `named-circle` edges. A wrap is not a grant. A hop, a hint, a wrap, a request, or an inbox delivery never mints. SEA `priv` and `epriv` never go on Gun. SociACL runs no index. A per-contact inbox lane, when a product stores one, is indexed by its lane id hex alone, never under a principal soul or a `~pub` path. The contact-lane secret stays off Gun. The disclosed base lane id is not that secret. This crate does not wire that index. See [encrypted-discovery.md](encrypted-discovery.md). s3r.ch product draft: [FyberLabs/s3r.ch#108](https://github.com/FyberLabs/s3r.ch/pull/108). This repo does not edit s3r.ch.

Case C may Check a frozen bundle the way the rest of SociACL does. The client has no mint path for new Gun grants.

## Fixed s3r.ch graph (consume, do not fork)

Gun root: `s3rch`.

```
gun.get('s3rch').get('items').get(<item key>)  → GunFeedNode
gun.get('s3rch').get('meta')                     → seed meta (not a Check object)
gun.get('s3rch').get('users').get(wallet)        → GunUserNode
gun.get('s3rch').get('acl').get(aclPrincipalKey(owner))
     .get(aclKey(object)).get(aclPrincipalKey(accessor))  → MeshSeeGrant
gun.get('s3rch').get('acl').get(aclPrincipalKey(owner))
     .get('post').get(aclKey(object)).get(aclPrincipalKey(accessor))  → MeshPostGrant
```

The item key escapes `~ . # $ [ ]` and leaves `/` alone. That escape is a closed label detail, not a public helper. Dest-ACL keys also escape `/`, so dest-ACL souls stay five segments. `room.alpha`, `room_alpha`, and `room/alpha` are three keys. `aclPrincipalKey` is not that escape. It accepts an exact `s3rch/users/<wallet>` or a bare id. `.` is allowed inside a principal. `.` and `..` alone are rejected. `/ # $ [ ] ~`, an inner space, a control, Unicode whitespace, a format character, and `.get(` are rejected. Longer than 256 scalar values is rejected. TypeScript also rejects an unpaired surrogate. A failed parse is null, not an empty string, and is not a soul segment. Trim is ASCII whitespace only, so U+FEFF and U+0085 are rejected. `.`, `..`, and `...` are not principals. An object id with leading or trailing whitespace is rejected, including tab, space, U+0085, U+00A0, U+3000, U+2028, and U+FEFF. It does not alias to the inner id, and `putObject` does not replace an existing owner through an alias such as an item soul. Group see and group presentation reject that id before lookup and do not trim it. Those group queries are in `vectors/mesh/principals.json`. Protocol migration uses the same principal rejection, including `...`. Peer merge drops a post row whose owner or accessor does not parse. Shared principal and object-id cases are in `vectors/mesh/principals.json`. `s3rch/acl` is dest ACL, not a Check object.

`GunFeedNode` (in-graph = native SociACL object):

```
{ id, source: rss3|rss|atom, kind, author, body, ts, permalink, tags: string, provenance }
```

`FeedItem` is UX only (`tags: string[]`). Mapping is `toGunNode` / `fromGunNode`. Unknown `source` is not a feed node. Empty `kind` maps to `"activity"` (same as s3r.ch `fromGunNode`). Dedupe: canonical id, else normalized permalink.

`FeedTab` is `"public" | "mine" | "network"`. UX only. Not a Check object.

`GunUserNode` (fixed): `{ id, indicators: string[], provenance, ts }` at `s3rch/users/<wallet>`. `indicators` are held-claim ids — the claim id itself (`ens:…` / `unstoppable:…` / `fc:…` / `lens:…` / `rss3:…`). Same Mesh Check path as a `GunFeedNode` id. Indicators are a comma-separated string on the Gun wire, same as tags. Overlay uses this same shape until s3r.ch `prepareShare*`. Do not invent a second user node. Do not invent `s3rch/users/<wallet>/claims/…`.

`IdentityClaimKind`: `wallet | rss3 | ens | kyc_attestation | email | phone`. Issuers prove a claim to the holder. They are not grants.

`IdentitySeeGrant`: `{ claimId, accessor, from, until }`. Maps onto keep-operating `delegate` read with `until`. hopcap 1. Jointly stated. Revoke immediate. Not Elect. Dest Check `until` is exclusive (existing `delegate`). `from` is inclusive and is **not** on the dest edge — `check_see_grant` ANDs dest Check with `now ∈ [from, until)`. `CHECK(see, object, accessor)` at now.

Arrays cannot live in Gun. Tags (and later indicators) are a comma-separated string on the wire.

Graphs: public cache vs personal overlay vs later explicit share-into-mesh. Observing public traces is not dumping a private overlay.

## Group and circle rows

`same-group` and `named-circle` are direct dest-ACL rows. Hopcap is 1. An object names one set (`ObjectSetName`, its own `hamState`). A member has one `MeshMembership` in that set, with its own `hamState`. Both edges must be stated 1. One-sided membership is stored and is not a grant. Nested sets do not grant. `checkGroupSee` reads those edges. The owner still sees their object. A hop may factor a membership the graph already names. A hop, a hint, or a wrap never mints.

A group presentation is allowed only when that check allows and the decoded payload is stated 1 with `now` in `[from, until)`. A live edge does not override a cancel or a closed window. A live group edge with no `PresentedGroup` fails closed. A stated-0 object-set row is not that name, so an ordinary see grant still runs `checkSee`.

A lower `hamState` does not hide a removal this replica has merged. Member `hamState` does not stand in for the object-set edge. The set id is a minted ObjectId of kind `set`. The set owner is the principal embedded in that id and the signed set-owner field. Check denies a membership row whose set id, accessor, or predicate is not the one it asked for, and an object-set row whose object is not the one it asked for. Merge stores a row under the soul recomputed from those signed fields. An object-set row is kept only when this graph already holds the admitted signed object record and that owner is the row's owner. A row that arrives before the record is dropped, and a later record does not revive it. Merge unions object-set cancels only when both edges name the same set and predicate. A different set or predicate keeps only the winning edge's cancels, so a stale peer's cancel does not revoke the edge the owner moved to. Cancels are a grow-only set of 64-hex ids. A live assent lists every known cancel. Each party's assent is signed by that party under the present key. A retired-key grant is refused. A retired-key cancel is accepted only when witnessed. `reverifyGroup` drops an unwitnessed retired-key cancel. Only a witnessed cancel survives that recheck. An object-set row is signed by the object owner. The object-set soul commits to the set and the predicate, so a cancel cannot move to another set. A stated-1 snapshot of an object-set edge that is not live understates that revoke. The snapshot acknowledges it only when stated is 0 and its hamState is at least the stored assent's. A stated-0 snapshot below that hamState understates, and so does one that names another set. A later edge that lists the cancel is live again. A later edge that does not list it stays a removal. Replacing an object's owner drops that object's set edge. Check denies an edge whose recorded object owner is not the current owner.

Souls, under dest ACL, not grant souls and not Check objects:

```
s3rch/acl/<setOwner key>/member/<predicate>/<set>/<member key>
s3rch/acl/<objectOwner key>/objset/<predicate>/<set>/<object>
```

`GunFeedNode` and `GunUserNode` stay as they are.

## TypeScript consume contract

Canonical file: [s3rch-check.d.ts](s3rch-check.d.ts). How to consume it: [s3rch-check.md](s3rch-check.md). Lab-feed and initial sharing are light Check only. Later, on request: more verbs on the TS spec for granted distribution.

`acceptHint` does not verify and does not mint. Destination Check against the live ACL (including see grants) is the grant. A hint alone fails closed.

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
| hop | `HopFactor` (Social Light SLHP; optional; never a grant) |
| dest ACL grant | `MeshSeeGrant` / `GunAclEdge` at `s3rch/acl/…` |
| hopcap | 1. No friend-of-friend |

`see` is an adapter alias for `read`. `ActionMask` still matches `read` / `write` / `execute`. The adapter maps `see` before dest Check.

## File layout

```
docs/s3rch-check.d.ts          TS consume contract (browser Check + Mesh; copy / re-type)
docs/s3rch-check.md            how s3r.ch consumes that file (Mesh section)
docs/encrypted-discovery.md    spec: wrapped keys, private rows, group predicates
docs/gun.md                    this page (Rust adapter map)
docs/social-light.md           SLHP hop factor Check may consume
crates/sociacl-gun             reference implementation (MeshSeeGraph + hop)
crates/sociacl-c/include       C encode / accept / Check / see-grant / remint / cancel
python/sociacl                 thin ctypes of the C ABI
```

Elect is visible and always fails (`sociacl_gun_elect`). Case C mint is visible and always fails (`client_mint_grant`).

## What this does not do

- Open or edit FyberLabs/s3r.ch
- Evaluate wrapped keys or blinded grant rows (spec only; see [encrypted-discovery.md](encrypted-discovery.md))
- Run an index (one public index, per-group indexes, and local indexes are product storage)
- Add a second graph schema or a second user node
- Add a Gun-only Check verb
- Treat a seeder or `/api/ingest` fetch as a grant
- Put lease tickets on this plane
- Bolt Elect, wills, or devices onto the s3r.ch Gun surface
- Host accounts, add SaaS, or invent tokenomics
- Implement signal-based identification
