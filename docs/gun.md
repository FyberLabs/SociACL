# Gun adapter

Signed mesh ownership and permission checks for GunDB.

The TypeScript package's `exports` map defines its supported import boundary:
`sociacl`, `sociacl/gun`, and `sociacl/group`. Files under
`src/internal` are implementation details, not API. Consumers must not bypass
the export map with absolute paths, bundler aliases, or source-tree imports.
Those files hold mutable admission maps: deleting a cancel there can permit an
older signed grant to be admitted again. Public inspection APIs return copies;
the mutation hooks used to test this boundary live under `tests/` and are not
shipped. This boundary assumes trusted code in the JavaScript process; it is
not a sandbox for hostile code sharing that process.

## Signed ownership boundary

Gun ownership comes only from a verified `sociacl-object-v2` record. TypeScript
callers use `putObject(graph, record, resolver)` from `sociacl/gun`; Rust callers
use `MeshSeeGraph::put_object(record, resolver, context)`. Supply authenticated
identity history and a current verification context. Both check the object's
embedded principal, the owner's signature, and signing-key history before
admission. A valid id, an author label, a derived `claim_` or `ext_` id, or a core
`Plane` owner does not establish mesh ownership. The current signed object
format requires a minted id with an embedded principal; derived ids remain
feed/claim identifiers and cannot acquire an owner through these APIs.

[#81](https://github.com/FyberLabs/SociACL/issues/81) removes the unsigned
`sociacl/ir` entry and `MemoryDelegateAcl.putObject(object, owner)`. It also
removes the Rust core-plane adapter's `add_principal`, `add_claim`, `add_item`,
`add_feed_node`, `apply_see_grant`, free `check*`, `cancel`, `remint`, `elect_*`,
and `client_*` functions and `GunCheckResult`. Use signed `MeshSeeGraph`
admission and checks. There is no conversion from an unsigned core plane.

The corresponding C `sociacl_gun_check`, `sociacl_gun_check_see_grant`,
`sociacl_gun_remint`, `sociacl_gun_cancel`, and `sociacl_gun_elect` exports and
Python `Plane.check_gun`, `check_see_grant`, `remint_gun`, `cancel_gun`, and
`elect_gun` methods are removed. C/Python retain hint encode/decode and URL
normalization; they do not yet bind the signed mesh. Generic core-plane APIs
are separate trusted application state and are not a substitute for Gun record
verification. The AImmune/Brewnix copyable logical-site contract is still a
product contract, not an exported signed-identity implementation.

Request approval validates see/post rows on a private graph and publishes them
without calling caller code between the two writes. Resolver callbacks and
nested context getters see the previously committed state. A throw publishes
neither grant; a reentrant change to either destination row or its admitted
owner aborts the pair and preserves that change. Histories are resolved once
per distinct principal, including self-requests. Members timestamps are
nonnegative safe integers in both TypeScript and Rust.

[FyberLabs/s3r.ch](https://github.com/FyberLabs/s3r.ch) owns feed, UX, and the TypeScript graph. That work lives on s3r.ch PR #7 (`cursor/gundb-feed-rearchitecture-9b12`). s3r.ch does **not** import this Rust crate, NAPI, or WASM. Check runs in the browser on the Gun mesh. WASM later is optional and is **not** the lab-feed path.

The consume contract they reimplement is **[s3rch-check.d.ts](s3rch-check.d.ts)** ([s3rch-check.md](s3rch-check.md)). Copy the file or re-type the names. Do not `npm install sociacl`. The Gun adapter surface for that product is **light Check + `delegate` only**.

This crate verifies signed object and ACL records in the fixed s3r.ch Gun graph, then checks admitted ownership and grants. It does not fork that graph.

## Product split

| Piece | Owner | Lives |
| --- | --- | --- |
| Graph, named predicates, Check, `delegate` | SociACL | `crates/sociacl-core` |
| Signed mesh admission / Check and transport types | SociACL | `crates/sociacl-gun` |
| C hint encode/decode and URL normalization | SociACL | `crates/sociacl-c` |
| Feed, UX, Gun peers, TypeScript graph | s3r.ch | s3r.ch PR #7 |
| Elect, wills, devices, Case C mint | SociACL core only | not on the s3r.ch Gun surface |

s3r.ch stores **only Gun-native objects** under this adapter. In-graph Gun data is the native ACL. Check evaluates graph relations on stored ids.

A Check **object** is an `ObjectId` backed by an admitted signed record. Only minted ids embed the owner principal required by that record; derived claim/feed ids alone are data. The accessor is a `PrincipalId`. A wallet and a `s3rch/users/<wallet>` path are not principals. Lighter Check is `CHECK(see, object, accessor)` at now. Hopcap 1. Grants are jointly stated. Revoke is immediate. SociACL never launched, so there is no pre-v2 ACL row to migrate.

Non-Gun data is a URL. RSS3 GI, RSS/Atom, KYC / email / phone issuer HTTP calls are **leaf pointers**, not Gun nodes and not grants. Crossing them (`/api/ingest`, seeder) is an **untrusted handoff**. Destination re-authorizes on the way back, then may `put` a native object into `items`. A URL 200 is not `see`.

The generic core plane has execute-without-read, Elect, and Case C operations. Those operations are not exposed as Gun adapter authority.

A Social Light hop can factor Check. It cannot mint. The consume contract names this `HopFactor` on `checkSee(..., hint?, hop?)`. Decode (`acceptHop` / `decodeHop`) does not verify and does not mint. See [social-light.md](social-light.md).

Mesh see grants are Gun-native dest-ACL nodes under `grantSoul`: `s3rch/acl/<owner key>/<object>/<accessor key>`. Post grants are `postSoul`: `s3rch/acl/<owner key>/post/<object>/<accessor key>`. Owner and accessor keys are `p_` plus 128 lowercase hex. They do not fork `items` or `users`. Each peer Checks its locally HAM-merged graph at now. Cancel is owner-only privilege-down (`stated: 0` and a `hamState` bump) and must be visible on the next Check after merge (no cached allow). `checkPost` allows only when see also passes. A hop, a hint, a wrap, a request, or an inbox delivery never grants. Soul builders are `grantSoul`, `postSoul`, `membershipSoul`, and `objectSetSoul`. `aclKey` and `aclPrincipalKey` are deleted.

Wrapped-key grants, recipient-side discovery, and rotation on revoke are specified in [encrypted-discovery.md](encrypted-discovery.md). `crates/sociacl-encdisc` implements that path. This crate evaluates plaintext `MeshSeeGrant` rows, plaintext `MeshPostGrant` rows (`checkPost`), and direct `same-group` / `named-circle` edges. A wrap is not a grant. A hop, a hint, a wrap, a request, or an inbox delivery never mints. SEA `priv` and `epriv` never go on Gun. SociACL runs no index. A per-contact inbox lane, when a product stores one, is indexed by its lane id hex alone, never under a principal soul or a `~pub` path. The contact-lane secret stays off Gun. The disclosed base lane id is not that secret. This crate does not wire that index. See [encrypted-discovery.md](encrypted-discovery.md). s3r.ch product draft: [FyberLabs/s3r.ch#108](https://github.com/FyberLabs/s3r.ch/pull/108). This repo does not edit s3r.ch.

Case C remains a generic core-plane feature. The signed mesh does not accept ownership from a frozen core bundle.

## Fixed s3r.ch graph (consume, do not fork)

Gun root: `s3rch`.

```
gun.get('s3rch').get('items').get(<item key>)  → GunFeedNode (UX). Derived ext_ identifies feed data
gun.get('s3rch').get('meta')                     → seed meta (not a Check object)
s3rch/acl/<owner key>/<object>/<accessor key>    → MeshSeeGrant (grantSoul)
s3rch/acl/<owner key>/post/<object>/<accessor key> → MeshPostGrant (postSoul)
```

The item key escapes `~ . # $ [ ]` and leaves `/` alone. That escape is a closed UX detail, not a public helper and not a Check id. Dest-ACL souls are the ids builders above. `room.alpha`, `room_alpha`, and `room/alpha` are three strings and none of them is an object id. A wallet, `s3rch/users/<wallet>`, a Gun chain, `.`, `..`, and `...` are not principals. `/ # $ [ ] ~`, an inner space, a control, Unicode whitespace, a format character, and `.get(` are rejected. Longer than 256 scalar values is rejected. TypeScript also rejects an unpaired surrogate. A failed parse is not a soul segment. An object id with leading or trailing whitespace is rejected, including tab, space, U+0085, U+00A0, U+3000, U+2028, and U+FEFF. It does not alias to the inner id. Group see and group presentation reject that id before lookup and do not trim it. A wallet, a Gun chain, and a label do not parse. Live rows are `vectors/mesh/v2/`. Protocol migration uses the same principal rejection, including `...`. Peer merge drops a post row whose owner or accessor does not parse. `s3rch/acl` is dest ACL, not a Check object. This crate does not build `s3rch/users/<wallet>` or `s3rch/items/<id>`.

`GunFeedNode` (in-graph = native SociACL object):

```
{ id, source: rss3|rss|atom, kind, author, body, ts, permalink, tags: string, provenance }
```

`FeedItem` is UX only (`tags: string[]`). Mapping is `toGunNode` / `fromGunNode`. Unknown `source` is not a feed node. Empty `kind` maps to `"activity"` (same as s3r.ch `fromGunNode`). Dedupe: canonical id, else normalized permalink. The provider item id is not trimmed before `derive_external_id`. `"x"` and `" x"` do not share an `ext_` id; the spaced id is `whitespace`. `UrlLeaf::parse` returns `too-long` when the normalized form exceeds 256 bytes. `sociacl_gun_normalize_url` returns that reason, and `buffer-too-small` when the destination cannot hold the form. It does not truncate.

`FeedTab` is `"public" | "mine" | "network"`. UX only. Not a Check object.

`GunUserNode` (fixed): `{ id, indicators: string[], provenance, ts }`. It is not a core-plane principal, and this crate does not build `s3rch/users/<wallet>`. `indicators` list held-claim text (`ens:…` / `unstoppable:…` / `fc:…` / `lens:…` / `rss3:…`). The `claim_` id identifies that claim text; it does not establish an owner. Indicators are a comma-separated string on the Gun wire, same as tags. Overlay uses this same shape until s3r.ch `prepareShare*`. Do not invent a second user node. Do not invent `s3rch/users/<wallet>/claims/…`.

`IdentityClaimKind`: `wallet | rss3 | ens | kyc_attestation | email | phone`. Issuers prove a claim to the holder. They are not grants.

`IdentitySeeGrant`: `{ object, accessor, from, until }` is an unsigned data
shape. Its time-window helpers do not authorize anything. Signed mesh grant
rows enter through `admitRow` / `MeshSeeGraph::admit_row`, alongside an admitted
object record. A grant alone cannot create an object owner.

Arrays cannot live in Gun. Tags (and later indicators) are a comma-separated string on the wire.

Graphs: public cache vs personal overlay vs later explicit share-into-mesh. Observing public traces is not dumping a private overlay.

## Group and circle rows

`same-group` and `named-circle` are direct dest-ACL rows. Hopcap is 1. An object names one set (`ObjectSetName`, its own `hamState`). A member has one `MeshMembership` in that set, with its own `hamState`. Both edges must be stated 1. One-sided membership is stored and is not a grant. Nested sets do not grant. `checkGroupSee` reads those edges. The owner still sees their object. A hop may factor a membership the graph already names. A hop, a hint, or a wrap never mints.

A group presentation is allowed only when that check allows and the decoded payload is stated 1 with `now` in `[from, until)`. A live edge does not override a cancel or a closed window. A live group edge with no `PresentedGroup` fails closed. A stated-0 object-set row is not that name, so an ordinary see grant still runs `checkSee`.

A lower `hamState` does not hide a removal this replica has merged. Member `hamState` does not stand in for the object-set edge. The set id is a minted ObjectId of kind `set`. The set owner is the principal embedded in that id and the signed set-owner field. Check denies a membership row whose set id, accessor, or predicate is not the one it asked for, and an object-set row whose object is not the one it asked for. Merge stores a row under the soul recomputed from those signed fields. Merge checks each incoming assent and cancel against this graph's rotation history before copying the row. It does not recheck rows already in the graph. It is only as good as the history the caller passes: a caller that passes the genesis history can copy a retired row back in. A retired-key stated-1 is not copied when the caller passes the current history, so a stale peer does not restore access after reverify. The verified mode is stored on the copied cancel, so a present copy that now verifies as witnessed replaces a bare copy of the same id. An object-set row is kept only when this graph already holds the admitted signed object record and that owner is the row's owner. A row that arrives before the record is dropped, and a later record does not revive it. Merge unions object-set cancels only when both edges name the same set and predicate. A different set or predicate keeps only the winning edge's cancels, so a stale peer's cancel does not revoke the edge the owner moved to. When the predicates differ and the incoming edge wins, that edge replaces the local one. The vector is `merge-drops-another-predicates-cancel-when-incoming-wins`. The `mutate-row` vector step edits the row the TypeScript runner still holds. Rust copies the row at admission, so that step is a no-op in the Rust runner. Admitting a replacement edge keeps the previous cancels only when the set and the predicate both match. A witnessed copy of a cancel replaces a bare copy with the same id. `reverifyGroup` drops a retired stated-1 object-set assent and keeps a witnessed cancel on that record, so the next edge for the same set and predicate still sees it. Cancels are a grow-only set of 64-hex ids. A live assent lists every known cancel. Each party's assent is signed by that party under the present key. A retired-key grant is refused. A retired-key cancel is accepted only when witnessed. `reverifyGroup` drops an unwitnessed retired-key cancel. Only a witnessed cancel survives that recheck. An object-set row is signed by the object owner. The object-set soul commits to the set and the predicate, so a cancel cannot move to another set. A stated-1 snapshot of an object-set edge that is not live understates that revoke. The snapshot acknowledges it only when stated is 0 and its hamState is at least the stored assent's. A stated-0 snapshot below that hamState understates, and so does one that names another set. A later edge that lists the cancel is live again. A later edge that does not list it stays a removal. A one-sided stated-1 membership is not a removal. A stated-0 assent or an uncovered cancel is. Replacing an object's owner drops that object's set edge. Check denies an edge whose recorded object owner is not the current owner.

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
| object | admitted signed object record on a minted `ObjectId` |
| accessor | `PrincipalId` |
| `IdentitySeeGrant` | unsigned data only; admission requires signed mesh rows |
| cancel | verified signed cancel on the destination ACL |
| permalink / RSS3 / RSS / KYC HTTP | `UrlLeaf` (handoff, not a node) |
| handoff | `HandoffHint` (untrusted factor) |
| hop | `HopFactor` (Social Light SLHP; optional; never a grant) |
| dest ACL grant | `MeshSeeGrant` / `GunAclEdge` at `s3rch/acl/…` |
| hopcap | 1. No friend-of-friend |

`see` is an adapter alias for `read`. `ActionMask` still matches `read` / `write` / `execute`. The pure `map_action` helper maps that spelling; it does not admit an object or run a core-plane Check.

## File layout

```
docs/s3rch-check.d.ts          TS consume contract (browser Check + Mesh; copy / re-type)
docs/s3rch-check.md            how s3r.ch consumes that file (Mesh section)
docs/encrypted-discovery.md    spec: wrapped keys, private rows, group predicates
docs/gun.md                    this page (Rust adapter map)
docs/social-light.md           SLHP hop factor Check may consume
crates/sociacl-gun             reference implementation (MeshSeeGraph + hop)
crates/sociacl-c/include       C hint encode / accept and URL normalization
python/sociacl                 thin ctypes of the C ABI
```

Elect and Case C mint have no Gun adapter entry points.

## What this does not do

- Open or edit FyberLabs/s3r.ch
- Evaluate wrapped keys or blinded grant rows (`sociacl-encdisc` does; see [encrypted-discovery.md](encrypted-discovery.md))
- Run an index (one public index, per-group indexes, and local indexes are product storage)
- Add a second graph schema or a second user node
- Add a Gun-only Check verb
- Treat a seeder or `/api/ingest` fetch as a grant
- Put lease tickets on this plane
- Bolt Elect, wills, or devices onto the s3r.ch Gun surface
- Host accounts, add SaaS, or invent tokenomics
- Implement signal-based identification
