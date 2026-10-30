# Light Check consume contract (s3r.ch)

This is the artifact the s3r.ch Next app reimplements against.

**File:** [s3rch-check.d.ts](s3rch-check.d.ts)

The Next app runs Check **in the browser** on the Gun mesh. It does **not** import this Rust crate, NAPI, or WASM. Do not `npm install sociacl`. Copy the `.d.ts` or re-type the same names. WASM later is optional and is **not** the lab-feed path.

`crates/sociacl-gun` in this repo is the reference implementation. It is not a runtime they load.

## What they implement

`CHECK(see, object, accessor)` at `now`.

| Name | Meaning |
| --- | --- |
| `object` | stored minted `ObjectId` backed by a verified `sociacl-object-v2` record; derived `claim_` / `ext_` ids alone carry no ownership |
| `accessor` | `PrincipalId`. A wallet and `s3rch/users/<wallet>` are not principals |
| `see` | dest Check `read` |
| grant | admitted signed mesh row; `IdentitySeeGrant` is only an unsigned data shape; hopcap **1** (no friend-of-friend) |
| revoke | immediate privilege-down on the dest object (`cancelSee`) |
| hint | `HandoffHint` — untrusted; never a grant |
| hop | optional Social Light `HopFactor`; never a grant; missing does not fail |
| wrap | `WrappedKey` to a SEA `epub` or a group epoch key; never a grant; never mints |
| admit | dest re-authorizes **before** `put()` into `items` |

`s3rch/meta` is seed cache. It is not a Check object. A permalink / RSS3 / RSS / issuer URL is a `UrlLeaf`, not a node and not a grant.

Later, on request: more verbs on the TS spec for granted distribution. Not this cut. Wrapped keys, recipient-side discovery, and group predicates are named in [encrypted-discovery.md](encrypted-discovery.md). They are not extra verbs. The portable plane in `typescript/` is a copyable reference for Panopticon and other adapters. s3r.ch still copies this file and does not `npm install sociacl`.

## Fixed Gun paths (do not fork)

```
gun.get('s3rch').get('items').get(<item key>)  → GunFeedNode (UX). Check id is ext_ derived
gun.get('s3rch').get('meta')                     → seed meta (not a Check object)
s3rch/acl/<owner key>/<object>/<accessor key>    → MeshSeeGrant (grantSoul)
s3rch/acl/<owner key>/post/<object>/<accessor key> → MeshPostGrant (postSoul)
```

Owner and accessor keys are `p_` plus 128 lowercase hex. The object segment is the stored `ObjectId`. `grantSoul`, `postSoul`, `membershipSoul`, and `objectSetSoul` are the ids builders. `aclKey` and `aclPrincipalKey` are deleted. This crate does not build `s3rch/users/<wallet>` or `s3rch/items/<id>`.

A feed item key may escape `~ . # $ [ ]` for the UX node. That escape is not a Check id and not a dest-ACL key. `room.alpha`, `room_alpha`, and `room/alpha` do not parse as one object.

A held claim's Check id is `claim_` derived from the claim text (`ens:…` / `unstoppable:…` / `fc:…` / `lens:…` / `rss3:…`). `GunUserNode.indicators` may list that text. Check does not read the text as an object id. Do not invent `s3rch/users/<wallet>/claims/…`. A post or room is a minted object id when it is created.

The Rust crate in this repo remains the full plane. See [gun.md](gun.md) for that map. Social Light hop wire: [social-light.md](social-light.md).

## Forums

### Baseline acceptance for the Squad pilot

The shared baseline tracked by [#129](https://github.com/FyberLabs/SociACL/issues/129)
is exercised from [forums.json](../vectors/mesh/forums.json) by
[TypeScript](../typescript/tests/test_forums.js) and
[Rust](../crates/sociacl-gun/tests/forums.rs):

| Case | Required result |
| --- | --- |
| No destination ACL | Check denies the accessor; the admitted owner remains the owner. |
| Live grant followed by cancel | The very next Check denies, including equal-HAM cancellation. |
| SGH1 or decoded handoff hint | Neither the hint nor a hop grants access. Rust round-trips the shared wire bytes. |
| Need marked resolved | Data cannot admit an owner or restore a cancelled grant. Rust additionally exercises the need transition API. |
| Chat item | The ordinary feed-node conversion preserves the forum tag; the collection is `s3rch/items`. |

The TypeScript baseline tests the existing Check and feed conversion boundaries;
it does not implement the Rust offer/need transition state machine or a product
UI. The Rust tests also exercise status, need, offer, alarm, template,
role-membership, subtask and update soul builders against the filled shared
strings. Pass the SEA pubkey as one Gun `get` segment, including its literal
`.`; splitting it changes the graph path.

This baseline is the prerequisite for the
[Squad follow-up #123](https://github.com/FyberLabs/SociACL/issues/123).
Group-based offer admission, pause/reassign privilege reduction and additional
drawer admit rules remain there. Business and Fleet contracts remain in
[#124](https://github.com/FyberLabs/SociACL/issues/124) and
[#125](https://github.com/FyberLabs/SociACL/issues/125).

### Offer admission through a group

`checkForumSee` (`check_forum_see` in Rust) checks the need's stored object id.
It accepts the admitted owner or a live direct see grant, then checks the
owner-signed `same-group` or `named-circle` object-set binding and its live,
jointly signed membership. The accessor does not supply a predicate or set.
Membership in a forum, a role label, a parent forum, or a shared ancestor alone
is insufficient. This remains hopcap 1; neither hint nor hop is an input to
this helper. Group rows still require authenticated admission and re-verification
when account-key history changes; this helper does not fetch or refresh history.

Rust uses this check when posting an offer, when re-checking its helper at
acceptance, and for the existing see-gated need HAM update. Acceptance still
requires the stored live offer and the need owner or subject as writer; only
the owner reopens. Offer withdrawal keeps its existing helper/owner/subject
rules, including after membership is removed. No offer becomes an admitted
object owner, and resolving never changes ownership.

Direct and group access are independent grants. Cancelling a direct see row
does not withdraw a separately authorized group binding. To remove all access,
cancel every applicable path: direct grant and group membership or object-set
binding. An existing offer must fail acceptance immediately when its helper
has lost all such paths. An owner remains authorized by ownership.

Shared `forum-*` cases in [group.json](../vectors/mesh/v2/group.json) cover
both predicates, missing/one-sided membership, destination binding, immediate
cancellation and independent grant paths. Both language runners execute them;
the Rust forum integration additionally posts and accepts a group-only offer,
then refuses acceptance and a new post after the binding is withdrawn.
Pause/reassign coordination and drawer child write admission remain in #123.

### Drawer child admission

Subtasks, updates and artifact records use these paths:

```
s3rch/forums/<forumId>/agents/<seaPubkey>/subtasks/<objectId>
s3rch/forums/<forumId>/agents/<seaPubkey>/updates/<objectId>
s3rch/forums/<forumId>/agents/<seaPubkey>/artifacts/<objectId>
```

The corresponding Rust builders are `forum_subtask_soul`, `forum_update_soul`
and `forum_artifact_soul`; copied consumer names are `forumSubtaskSoul`,
`forumUpdateSoul` and `forumArtifactSoul`. Each requires a minted child id,
and preserves the complete SEA pubkey as one segment. Building a path grants
nothing. These are owned child records, not shared-object mounts.

Before the first child put, admit its agent-signed object record through
`putObject`. `checkForumChildWrite` (`check_forum_child_write` in Rust) then
requires that authenticated child owner to equal the drawer agent. The agent
may write; a delegate needs a live direct see grant **and** a separate live post
grant on that exact child. The existing post ceiling applies. Access to the
forum, agent status, a sibling, or a group read binding does not supply either
grant. Unknown children fail closed even for the principal embedded in the id.
A cancelled or expired see/post grant denies the next write.

Authenticate the writer independently, validate the child payload, and run
this check against current admitted state immediately before every put.
The helper is a permission decision, not a signed-write verifier or a storage
transaction. Peers must enforce the same boundary on incoming writes. Reads
use `checkForumSee` on the child itself; the drawer path never substitutes for
its ACL. Moving a record into another agent's drawer requires a newly owned
record and fresh authorization, not relabelling its path.

An artifact record may reference an external URL or another object. Permission
to write or read the reference does not grant access to that target; the target
requires its own Check. The status node's existing comma-separated `artifacts`
list remains data and does not admit child records.

Shared `drawer-*` cases in the post/group vectors cover owner/delegate writes,
read-only refusal, group-read refusal, see/post cancellation, the post ceiling,
unknown children, wrong drawer agents and invalid forum kinds. This supplies
the library contract for #123's drawer gap; product adoption is still separate.
Pause/reassign privilege reduction remains open.

### Soul helpers and stored data

The account identity is the GunDB SEA pubkey (`PrincipalId`). A wallet and a Panopticon OAuth subject are linked credentials. They are not the agent key and not a second identity plane. Copy the forum names from [s3rch-check.d.ts](s3rch-check.d.ts). The consumer implements `forumAgentSoul`, `forumNeedSoul`, `forumOfferSoul`, `forumAlarmSoul`, `forumTemplateSoul`, `forumRoleSoul`, `forumSubtaskSoul`, `forumUpdateSoul`, `forumArtifactSoul`, and `forumChatTag`. Filled soul strings are in [vectors/mesh/forums.json](../vectors/mesh/forums.json). That file also has the need-resolve row, the offer soul, alarm pin rows (open, resolved, wrong forum), and accept or reject rows for both role modes.

```
s3rch/forums/<forumId>/agents/<seaPubkey>                 → ForumAgentStatus
s3rch/forums/<forumId>/needs/<needId>                     → ForumNeed
s3rch/forums/<forumId>/needs/<needId>/offers/<offerId>   → ForumOffer
s3rch/forums/<forumId>/alarm                              → ForumAlarm (pinned emergency)
s3rch/forums/<forumId>/template                           → ForumTemplate
s3rch/forums/<forumId>/roles/<roleToken>/<seaPubkey>      → ForumRoleMembership
gun.get('s3rch').get('items').get(<item key>)             → ForumChatItem (a GunFeedNode)
```

`forumId` is a minted object id of kind `forum`. `seaPubkey` is the SEA pubkey, not a `p_` key and not a wallet. `<needId>` is a minted object id of kind `need`. `<offerId>` is a minted object id of kind `offer`. The embedded principal is the helper. `ForumNeed.subject` is the SEA pubkey the need is about. It is not compared to the forum id or to the principal embedded in that id. Check `see` uses the admitted object id. The soul is the Gun location. State is data, not a grant.

Per-agent status stores `task`, `result`, `needs`, `progress`, `state`, `lastPrompt`, `lastUpdate`, `type`, `started`, `tokens`, and `runtime`. `started`, `tokens`, and `runtime` are that agent's counters. `tokens` is not a transfer. Optional `hb`, `batt`, and `link` are vitals on the same node. `needs` and `artifacts` are comma-separated object ids. Subtasks and updates are child souls under the agent, or feed item ids in `artifacts`.

The template mode is `distinct-principals` or `role-labels`. Distinct principals: each role token names a different SEA principal. Role labels: one SEA principal wears several role tokens. The role token is lowercase letters, digits, and hyphen. A display title is not the token. A role token is not a Check predicate. An `@role` in chat is addressing, not authority.

Chat is a `GunFeedNode` under `s3rch/items`. `ForumChatItem` is that type. `tags` includes `forum:<forumId>`. Extra tags stay as written. A tag that is not already lowercase is rejected, and so is the tag `chat`. A comma in one extra tag is rejected. There is no `s3rch/chat` soul and no `s3rch/forums/<forumId>/chat` soul. `GunFeedNode` does not gain a field.

The global alarm reads status tiles whose `state` is `emergency` and the pinned need at `forumAlarmSoul`. The pin counts when that need is an open emergency (`severity` `emergency`, `stated` 1). Either input is enough. The alarm node is not a grant.

Anyone with Check see on a need may post a `ForumOffer`. The graph stores that live offer. The helper owns that offer and may withdraw it (`stated` 0). The need's owner, or the subject the need is about, accepts one live offer only when that helper still passes Check see on the need and the graph holds the live offer that helper posted. A caller-supplied offer that was not posted is refused. When the subject is the helper, that principal may accept their own offer. That accept sets `acceptedOffer` and `stated` 0. Cancelling an offer, or leaving it, keeps the need open. A resolved need refuses withdrawal of the offer it names. The need stays resolved until the owner reopens (`stated` 1) and clears `acceptedOffer`. Earlier offers stay. `body` and `severity` stay as posted. `spec`, when set, is an object id of a function contract and stays as posted. A ham update that keeps `stated` and `acceptedOffer` is accepted only when Check see allows the writer on that need id. A missing admission does not accept the update. The admitted object owner stays the owner. A missing dest-ACL row denies the offer post. A cancel of that row is visible on the next Check. An SGH1 hint alone fails closed. A status node, a chat tag, a hop, and a hint do not mint. Hopcap is 1. An offer does not spend the status `tokens` counter.

## Mesh

This is the cut the s3r.ch design engineer wires after held-claims land.

**Copy / re-type:** [s3rch-check.d.ts](s3rch-check.d.ts) (one file; Mesh section is at the bottom). Do not `npm install sociacl`.

### Dest ACL soul

See grants are Gun nodes under the **object owner's dest ACL**, not under `items` or `users`:

```
s3rch/acl/<owner key>/<object>/<accessor key>
```

`grantSoul(owner, object, accessor)` builds that soul. The owner and accessor arguments are `PrincipalId`s. The object argument is an `ObjectId`. A wallet, `s3rch/users/<wallet>`, a Gun chain, a label, and the fold triple `room.alpha` / `room/alpha` / `room_alpha` do not parse. There is no collapse onto a wallet and no `escapeKey`. Live grant rows are `vectors/mesh/v2/`.

Each field HAM-merges. `MeshSeeGrant.stated` is `1` (live) or `0` (cancelled). Cancel is owner-only and **must bump Gun HAM state** so privilege-down wins the next merge. Each peer runs `checkSee` on its locally HAM-merged graph at `now`. Do not cache an allow across a privilege-down merge.

The stored-id see path keeps one row per owner, object, and accessor. Higher `hamState` wins. At an equal `hamState` a cancel (`stated` 0) wins, then a window that is strictly inside the other: its `from` is at least the other's `from`, its `until` is at most the other's `until`, and one bound is strict. Equal windows are not inside each other. When neither window contains the other, the smaller `sociacl-see-grant-v2` bytes win. When those bytes are equal, the copy whose `sociacl-acl-attest-v1` witness validates replaces the copy whose witness does not. A string that is not a valid witness does not win. Two invalid witnesses, or two valid ones, keep the first copy. That copy only adds the witness. It does not re-open a row. Typed rows move only through `admitRow` / `admit_row` and `putObject` / `put_object`. A label merge does not carry them.

An object owner is a signed `sociacl-object-v2` record. The fields are the object, the owner `PrincipalId`, and `issuedAt`, length-prefixed under that domain. The owner signs it with the current key. The object id must be the bound form in the ids spec: `<kind>_<principal-key>_<32 lowercase hex>`, and the record's owner must be the embedded genesis principal. An id with no embedded principal, or an owner that is not that principal, is `bad-record`. It is not admitted. A later record from the same owner is a no-op while the stored record still verifies. A stored record is replaced only when the new `issuedAt` is strictly newer and the stored record no longer verifies. A newer record signed by a key that stored history marks retired does not replace it, even when the resolver goes backwards. An older record does not downgrade a newer one, including when the resolver hands back a stale history. A retired-key object record is refused, including one that carries a valid see witness. `putObject` parses the record before it asks the resolver for that owner's history. `reverifyPrincipal` checks object records again. After a rotation, a record the current key does not sign stops counting until a record signed by that key is admitted. Missing history drops that principal's see rows and object records. An owner allow comes only from an admitted object record. Object records are added in PR 2 of the #55 rebuild. PR 7 is dropped: there are no legacy objects to re-sign. The owner re-signs a bound object record on rotation, in this see path, by admitting the new signature.

### Post grant

A post grant is a second dest-ACL row, domain `sociacl-post-grant-v2`. The fields match a see grant: owner, object, accessor, `stated`, `from`, `until`, `hamState`, `issuedAt`. The owner is the admitted object record, not a caller string. There is one row per `postSoul(owner, object, accessor)`. Higher `hamState` wins. At an equal `hamState` a cancel (`stated` 0) wins, then a strictly contained window, then the smaller v2 signing bytes, then a validating `sociacl-acl-attest-v1` witness. A retired-key post cancel is recognized only from `stated` 0 in those signed bytes. A retired `stated` 1 row is refused even when witnessed. Check does not verify. `admitPost` does.

`checkPost` takes an `ObjectId` and a `PrincipalId`. It allows only when the typed `checkSee` allows the same triple. The object owner may post without a post row. Any other accessor needs a live post row with `now` in `[from, until)`. A cancelled post row is `cancelled`. A missing or out-of-window row is `missing`. A see denial is returned as that see result. A label see grant does not satisfy this check. Hopcap is **1**. Hop missing does not fail. Hop alone never allows. A hop, a hint, a wrap, a request, or an inbox delivery never grants.

`postGrantBytes` is the length-prefixed encoding: domain `sociacl-post-grant-v2`, owner, object, accessor, decimal `stated`, decimal `from`, decimal `until`, decimal `hamState`, and decimal `issuedAt`. `postSoul` puts each principal in a `p_` plus 128 lowercase hex segment. It throws when an argument is not an already-parsed id. A parsed triple returns the soul string.

Rust `sociacl-gun` and `typescript/src/post.js` both load `vectors/mesh/v2/post.json`.

### Access request

A request is an untrusted hint. It never grants. Check does not read it. The owner's own client may turn an approved pending request into owner-signed grant rows. There is no hosted evaluator. Explicit deny and the policy queue are s3r.ch policy. SociACL has no standing deny. A withdrawal is not an approval.

`requestId(requester, object)` is the SHA-256 (lowercase hex, 64 characters) of a length-prefixed encoding: domain `sociacl-request-id-v2`, the requester `PrincipalId`, and the object `ObjectId`. Scope, message, and status are not inputs. The request id is computed from those two parsed ids, so the id and the graph object are the same object and cannot disagree. `room.alpha`, `room_alpha`, `room/alpha`, and `s3rch/items/room_alpha` are parse rejects. An object record uses a creator-bound id (`kind` + `_` + `p_` + 128 lowercase hex + `_` + 32 lowercase hex). A non-string requester or object, including an object with a stateful `toString`, is `not-string` before any coercion.

`accessRequestBytes` is the length-prefixed encoding the requester signs: domain `sociacl-access-request-v2`, the request id, requester, object, scope `read` or `read+post`, status `pending` or `withdrawn`, the message, and decimal `issuedAt`. The message is at most 280 Unicode scalar values and may be empty. A well-formed UTF-16 surrogate pair is one scalar. An unpaired surrogate is rejected. Any other scope or status is rejected. A wrong domain, including `s3rch-access-request-v1` and `s3rch-request`, or a missing signature, is `legacy-row`. Lengths are uint32 little-endian. Building the bytes does not grant.

`grantApprovedRequest(graph, owner, request, window, members, signer)` runs on the owner's client. `owner` is a `PrincipalId`. The requester signature goes through `verifySignedAt` with no kind argument. Only the requester's present key counts. A retired key is `unwitnessed-retired-key`, witnessed or not. An Ed25519 signature is `bad-signature`. The owner then signs the `sociacl-see-grant-v2` row, and the `sociacl-post-grant-v2` row when the scope is `read+post`, under the owner's current key. `issuedAt` on those rows is the resolver's `now`. Both rows are checked, including `hamState + 1` staying at or below 9007199254740991, before either is written. If the see row cannot advance, nothing is written (`see-ceiling`). If the post row cannot, no see row is written either (`post-ceiling`). A withdrawn request writes nothing. A caller who is not the admitted object owner writes nothing (`owner-mismatch`). Members auto-approve passes the stored object id and the requester to `checkGroupSee` and writes only when that allows. A request that names `s3rch/items/` plus the stored id is a parse reject, not `not-member`. Hop and hint are not inputs. Hopcap stays **1**. A hop, a hint, a wrap, a request, or an inbox delivery never grants. `factorGrants("request")` is false.

Rust `sociacl-gun` and the TypeScript request runner both load `vectors/mesh/v2/request.json`.

History for the owner and the requester is resolved once. Both rows are admitted against that same history, including `kept`, and then both are written or neither is. Nothing runs between the two writes. There is no staged ticket. `snapshotRow`, `restoreRow`, `snapshotPost`, and `restorePost` are not part of the surface. A row that would not replace the stored row is `not-kept`.

An identical approval is a no-op only after the current key resolves, the owner's scalar owns that key, and members allow. The stored verified row must be signed by that current key and already have the same owner, object, accessor, `stated` 1, and window. `grantApprovedRequest` then returns that row with `unchanged: true`. It does not sign again and it does not bump `hamState`. A wrong scalar is `bad-key`. A non-member is `not-member`. A stored row signed by a retired key is signed again at `hamState + 1`. A different window is a new owner decision and uses `hamState + 1`. For `read+post`, both rows must match and both must be signed by the current key. A matching see row with a missing or different post row still writes the post row at `hamState + 1` and leaves the see row. The window's `from` and `until` are copied once before those checks.

Members auto-approve does not revive an owner cancel. When `members` is set and the see row, or the post row for `read+post`, has `stated` 0, the result is `not-kept` and nothing is written. A manual approval (`members` null) is a new owner decision. It re-grants at `hamState + 1` above that cancel.

Members auto-approve uses the admitted signed object owner. `checkGroupSee` takes that same owner from the principal embedded in the object id, and the admitted record must match. `hasObject` is true for that signed record. The owner shortcut (`reason` `owner`) is not membership. Only `same-group` or `named-circle` allows. A peer merge cannot auto-approve. Merge does not recheck rows already in the graph. It checks only the incoming rows, and only against the history the caller passes. The `mutate-row` vector step edits the row the TypeScript runner still holds. Rust copies the row at admission, so that step is a no-op in the Rust runner. An object-set row merged in before the signed record is dropped, and a later record does not revive it.

Requests have no expiry. Approving an older pending copy grants only the window and the scope on that call. There is no withdraw ordering across copies. Scope is approve or refuse only. The owner cannot downscope. The window is owner-only. The accessor is the parsed requester.

`members-gate-on-stored-id` uses a minted set id. The set owner is the principal embedded in that id. `alice/friends` is `bad-alphabet`.

When `now` equals the latest resolved rotation time, `grantApprovedRequest` writes nothing and returns `rotation-boundary`. Retry on the next second. One second before that rotation, the preceding key still signs. `historyState` stays strictly before the timestamp: the new key signs records issued after the rotation, and a same-second revoke still uses the preceding key.

`members-missing-is-not-member` denies when there is no live membership. `members-grant-uses-the-signed-owner` grants a live member from the admitted signed owner.

### Objects in scope

| Object | Id | In-graph? |
| --- | --- | --- |
| Feed item | `ext_` derived from the source key and the provider item id | yes, after dest admit |
| Held claim | `claim_` derived from the claim text. `GunUserNode.indicators` still lists the claim text; Check does not read that text as an object id | yes, after dest admit |
| Post / room | opaque `CheckObjectId` (s3r.ch names the soul later) | yes, after dest admit |
| Mine overlay | same `GunUserNode` shape, local only | **no** until s3r.ch `prepareShare*` then `putObject` |
| Permalink / RSS3 / issuer HTTP | `UrlLeaf` | never |

### Hop factor

`checkSee(graph, object, accessor, now, hint?, hop?)` takes an `ObjectId` and a `PrincipalId`. A string argument is the edge parser's reject and does not reach a label check. Check allows a delegate only on an admitted, verified `sociacl-see-grant-v2` row. A retired key counts only when the signed `stated` field is `0` and the attestation binds those bytes. Hint and hop never grant. `CheckObjectId` is `ObjectId`. `AccessorId` is `PrincipalId`.

- hop missing does not fail.
- hop alone never allows.
- `hop` may only factor an already-named grant or owner path. Direct membership is the same rule on `checkGroupSee` (spec, below).
- `acceptHop` / `decodeHop` do not verify and do not mint (mirror `acceptHint`).
- URL handoffs stay untrusted `HandoffHint`. A hint plus a hop still fail closed without dest ACL.

Reuse SociACL Social Light (`convention-badge` / `enrolled-station`, SLHP v1). Do not reimplement the hop frame.

### Legacy helper deletion

The #55 rebuild spec is not in this repository. This section is the deletion schedule.

`checkSee` / `check_see` do not import the alias helpers. The post, request, group, feed, encrypted-discovery, and contract migration copies are deleted. `typescript/src/legacy/gun-legacy.js`, `crates/sociacl-gun/src/legacy.rs`, the label test modules, and the label maps on `GroupGraph` are gone.

| Caller | Delete the copy in |
| --- | --- |
| post | PR 3 |
| request | PR 4 |
| group | PR 5 |
| feed, encrypted discovery, and the contract migration module | PR 6 |

### Amendments

The #55 rebuild spec stays out of this repository. This list is the amendment record.

- **PR 7:** dropped. SociACL never launched, so there is no old graph and no pre-v2 ACL row to read. There is no `migrateAclRows` / `migrate_acl_rows`, no `objectMap`, and no wallet or `s3rch/users/<wallet>` resolver. Old domains stay `legacy-row` and never reach Check. Owners mint fresh v2 rows. Do not preserve a rejected id and do not infer ownership from one. [#81](https://github.com/FyberLabs/SociACL/issues/81) removes the unsigned `sociacl/ir` entry and Rust core-plane adapter, including C/Python authority wrappers. Use signed `sociacl-object-v2` admission; see [the API replacement guide](gun.md#signed-ownership-boundary).

`vectors/mesh/forbidden-names.json` lists the banned names and the globs that must not contain them. Scopes cover `typescript/src`, `typescript/contract`, `sociacl-gun`, `sociacl-encdisc`, and `docs/s3rch-check.d.ts`. The same see-vector tests fail when `typescript/src` imports `node:crypto` or `crypto`. WebCrypto and comments stay allowed. The scan includes `.mjs`, `.cjs`, `.mts`, and `.cts`. `vectors/mesh/access-request.json`, `vectors/mesh/post-grant.json`, and `vectors/mesh/principals.json` are gone. `principals.json` was the old label suite.

`acl-snapshot-utf8-order` still names U+E000 and U+10000. Those scalars are not principals, so a typed snapshot entry cannot carry them. The shared field vector and the Rust suite keep that order. Inbox and wrap vectors use minted object ids. `contract/migration.ts` sorts accessors in UTF-8 byte order. The vector is `vectors/encrypted-discovery/accessor-order.json`, with the strings `a`, `B`, `-`, and `_`. `crates/sociacl-encdisc/src/gun_soul.rs` is deleted. The C exports `sociacl_gun_item_soul` and `sociacl_gun_user_soul` are deleted. `sociacl_gun_encode_key` was already gone.

Both parsers reject an unbound `<kind>_<32 lowercase hex>` object id. `claim_` and `ext_` plus 64 lowercase hex stay, and so does the minted form `kind_p_<128 hex>_<32 hex>`. The native object vector that used to accept the unbound form now rejects it. A guard test fails when non-test `.js`, `.ts`, `.mjs`, or `.rs` source builds that unbound form. Encrypted-discovery wrap and delivery vectors were regenerated after the id change.

A group cancel is length-prefixed UTF-8. Each field is a little-endian `u32` byte length followed by those bytes. Integer fields are decimal strings. The fields, in order, are domain `sociacl-cancel-v2`, kind (`membership` or `object-set`), `rowSoul`, `cancelId`, `issuedAt`, the prior count, then each prior cancel id. `issuedAt` is inside those bytes. Rewriting it on a present-key cancel is `bad-signature`. Rewriting it on a witnessed retired-key cancel is `bad-attestation`.

A group set id is a minted ObjectId of kind `set`. The owner is the principal embedded in that id and the signed set-owner field. An object-set soul is `s3rch/acl/<owner key>/objset/<predicate>/<set>/<object>`. A cancel signed over that soul cannot move to another set or predicate. An object-set row merged in before this graph holds the admitted signed object record is dropped. `reverifyGroup` drops an unwitnessed retired-key cancel. Only a witnessed cancel survives that recheck. The request path writes owner-signed `sociacl-see-grant-v2` and `sociacl-post-grant-v2` rows. `typescript/src/legacy/post-label.js` and `crates/sociacl-gun/src/post_label.rs` are deleted.

These s3r.ch object spellings are deleted from `parseObjectId` / `parse_object_id` and from `vectors/ids/object.json`. Network ids of the form `s3rch:https://...` are a different grammar and stay. `post` is a reserved kind, so a s3r.ch post cannot use kind `post` when that product adopts SociACL. `s3rch:forum:<owner>` has no random part. A forum id needs a nonce, or a derived id, before it can be an object id. The seven deleted forms are:

- `s3rch:room:<eip55>:<ts>:<hex>`
- `s3rch:chat:<eip55>:<ts>:<hex>`
- `s3rch:forum-msg:<eip55>:<ts>:<hex>`
- `s3rch:post:<eip55>:<ts>:<hex>`
- `s3rch:forum-group:<eip55>:<hex>`
- `s3rch:bot:<eip55>:<hex>`
- `s3rch:forum:<eip55>`

## Private rows and group predicates (spec)

[encrypted-discovery.md](encrypted-discovery.md) is the spec. s3r.ch product draft: [FyberLabs/s3r.ch#108](https://github.com/FyberLabs/s3r.ch/pull/108) (`docs/encrypted-discovery.md` there). This repo does not edit s3r.ch.

Copy the new names from [s3rch-check.d.ts](s3rch-check.d.ts) (`WrappedKey`, `BlindedGrantRow`, `MeshMembership`, `checkGroupSee`, `rotateOnRevoke`, `MeshPostGrant`, `checkPost`). `crates/sociacl-gun` evaluates plaintext `MeshSeeGrant` rows, plaintext `MeshPostGrant` rows (`checkPost`), and direct `same-group` / `named-circle` edges (`checkGroupSee`). `crates/sociacl-encdisc` implements the account key, the wrap edge, the canonical ids, blinded rows, `checkPresentedGrant`, inbox admission (`filterInboxAppend`, one lane per reader, daily-shard rescan), epoch admission (`epochRevisionId`, convergent `EpochFinalization`, `epochStepCurrent`, `settledKeyOpen`), `rotateOnRevoke`, and in-place migration (`applyProtocolMigration`). Wrapped keys are not an input to that check. A shard-close watermark is not implemented. `GunFeedNode` and `GunUserNode` stay as they are. Do not `npm install sociacl`.

A wrap of a DEK to a reader SEA `epub` is not a grant. SEA `priv` and `epriv` never go on Gun. Check must still pass. A hop, a hint, or a wrap never mints. SociACL decides who receives a wrap: only a principal the live grant or direct membership already names.

`same-group` and `named-circle` are hopcap **1** and jointly stated. The object names the set, and the accessor has a direct `member-of` or `in-circle` edge. Membership does not inherit across groups or circles. Hop may factor that direct edge. Hop alone never allows.

Each reader account has exactly one private inbox lane. Scanning a shared bucket is not allowed. Entries are append-only. The entry id is the SHA-256 (lowercase hex) of the length-prefixed lane, ciphertext, commitment, and wrap. The visible row has no owner id, no owner SEA pub, and no `hamState`. Order between a live grant and a cancel is a monotonic `grantRevision` inside the signed payload. The greatest revision wins. The verifier holds that high-water mark and rejects a presentation below it. `grant`, `owner`, and `grantRevision` must match the payload decoded from the signed bytes. At a tied revision, stated 0 wins before any digest comparison. A live payload does not replace a cancellation. When stated matches and a digest is already stored, the smaller payload digest wins. An empty payload digest raised from a status proof is unknown. The first payload with the same revision and the same stated is accepted and that digest is stored. The empty string is not the smallest digest. The status proof names this accessor and this grantRevision. The presenter binding is a length-prefixed signature over the domain, the nonce, the commitment hash, and the verifier-chosen audience. A different audience does not spend the nonce. The owner signs the length-prefixed encoding of the object, the epoch, the revision, the accessor, that grantRevision, stated, the times, and the zookie. The grant, the proof, the zookie, and the epoch view name one object and one epoch. A mismatch fails closed before a nonce is spent. A verified proof with a higher grantRevision, or stated 0 at the same revision, updates the verifier record. The status proof must also name the verifier's current read key. A live row at a lower or equal revision does not undo a cancel. When the grant is same-group or named-circle, the call takes PresentedGroup and runs checkGroupSee. That call does not read stated, from, or until. The payload must be stated 1 and now must sit in [from, until). A live membership edge does not allow a cancel or an expired payload. An ordinary see grant omits it and runs checkSee. A group object with no group argument fails closed. When the grant names an encrypted item, the signed payload includes that item's ciphertext digest. The call compares the SHA-256 of the fetched ciphertext to that digest. A mismatch fails closed. The graph snapshot hash is not that digest. The commitment is a hash of a fresh blinding plus the canonical grant. The blinding is in the presentation and not on the visible row. An unsalted hash of the grant bytes is not the commitment. The holder presents the opened grant at the destination. Check recomputes the commitment from that blinding, requires the decoded owner to equal graph.ownerOf(object), checks the signature against the verifier's enrollment map for that graph owner, checks a presenter binding against a verifier-held nonce (single use, with expiry) or an `AuthenticatedPresenterChannel` instance whose private brand the transport set, and requires a fresh owner-signed epoch/status proof beside the zookie. The channel's accessor and `readerPub` must be the grant's accessor and that accessor's enrolled pub. The brand is an ECMAScript private field and a module `WeakSet`, and the instance is frozen. An object literal is not that channel. Copying the brand onto another object fails. A channel for another principal fails closed. The graph exposes `objectVersion(object)` and `snapshotHash(object)` for the object the zookie names. `signedAt` must fall within the verifier's skew allowance, and the age must be within the smaller of the proof's `maxAgeMs` and the verifier's `policyMaxAgeMs`. A proof alone grants nothing. The owner signs the item plaintext digest and the epoch revision, then encrypts the body and that signature together. The ciphertext digest is not an input to the signature. Row counts, timing, and sizes still leak. The destination learns the owner. Private information retrieval and zero-knowledge proofs are future work, not this spec.

Each account has one SEA keypair. Devices inherit it through enrollment. `priv` and `epriv` never go on Gun. The author may unwrap from a local DEK bound to that manifest's revisionId. A DEK for another revision of the same epoch does not open the winning body. That fast path is not a grant. Two devices can mint different keys for the same next epoch. `revisionId` is the SHA-256 (lowercase hex) of the length-prefixed manifest body: object, epoch, previous epoch, device id, key commitment, settleWindowMs, and the ACL snapshot. The snapshot is one row per accessor: the accessor, that accessor's grantRevision, stated, from, until, scope, set id, and hamState. There is no single cancel number across accessors. A group or circle row uses MeshMembership.hamState, and a lower hamState does not hide a removal. The snapshot also names the object-to-set edge and that edge's hamState. Member hamState does not stand in for it. A stated-1 entry whose until has passed does not settle. settledKeyOpen repeats that check after settlement and also takes the replica ACL. A cancel, a higher grantRevision, an earlier until, or a later from on that ACL closes the key. A pending successor finalization closes it too. New writes stay buffered until a replacement that excludes that accessor settles. epochStepCurrent takes the winning snapshot and the ACL this replica has merged. During the window a presentation names the settled epoch, not the pending candidate epoch. checkPresentedGrant takes the same snapshot and replica ACL. While epochStepCurrent is false, a proof for the pending candidate fails closed. A group config is ordered by configRevision. Its signature covers the set owner, and ownerOfSet must name that account. Each finalization candidate id must resolve to a manifest for that same object and epoch. A private-row revoke carries a signed cancel payload and a status proof. A plaintext edge does not cancel that row. The manifest signature covers revisionId. The owner publishes a new key that was not wrapped to that accessor. Each replica recomputes the winner as the smallest `finalizationId` among the verified finalizations it has seen for the current parent. A later smaller id replaces the previous winner and takes descendant epochs that named the displaced parent off the current chain. The owner rebuilds those epochs outward, parent before child, each with a new finalization. The owner signature covers `finalizationId`, not the revision id alone. The owner signs `settleWindowMs` on the object manifest, or the same number on `GroupEpochConfig` for a group. The default is 24 hours, the minimum is 1 hour, and the maximum is 72 hours. Readers keep the last settled key while a candidate is pending and switch once that signed window passes. The window does not freeze the set and does not delay a cancel. Every wrap carries its revision inside the authenticated payload. A device id is not a Gun device record.

The reader chooses who may append. The reference crate runs `filterInboxAppend`. The default is public writes (`public-filtered`) with a local spam filter. The writer id comes from a branded channel or a signature over the entry id, checked against the verifier's enrollment map before quotas. The channel is minted only after a possession signature over `s3rch-writer-channel-v1` and the writer id. A claimed pub that is not the enrolled pub fails closed. The stored row still has no writer pub. The relay that accepts the append learns that writer id. A peer that only replicates the row does not. Outstanding admission challenges are one per nonce. First contact is a writer absent from the verifier's `knownSenders`. It requires proof-of-work that names one outstanding nonce, or a stamp signed by an issuer the verifier trusts, both bound to that row's entry id. Only the named nonce is spent. After that evidence verifies, a new sender's counter starts at the verifier's firstContactRemaining. The writer does not set that number. The writer signature is the length-prefixed domain and the entry id. A replicated row is not admitted until this verifier records the entry id, and a substituted body under that id is not admitted. The canonical entry length is checked against 64 KiB before the body is hashed. `laneId` is 32 lowercase hex bytes. The reserved writer names are the shared `forbidden-names.json` list. The row still has no writer pub and no admission receipt. The verifier holds one quota counter per sender and one shared `laneRemaining` for the lane. A writer-claimed quota, a first-contact flag, or an unverified token is not evidence. `named-writers` is the allowlist. The hook is not a grant. First contact carries the sender's SEA `epub` and `pub`, bound by an enrollment lookup or by a length-prefixed account signature over the account, pub, and epub. The enrollment record holds pub, epub, and identityPub. A record that holds only pub does not accept the introduction. An account-signature is checked under identityPub, not under the introduced pub. The one lane is scanned by rescanning whole daily shards and deduplicating. A per-device cursor is not the scan. A shard-close watermark is not implemented.

Revoke on the plaintext edge is `stated: 0` plus a `hamState` bump, then a new epoch wrapped to the remaining readers. On a private row the same deny is a new append whose signed `grantRevision` is greater and whose `stated` is 0. That deny is immediate for a current verifier and does not wait for the settle window. A revoked reader is left out of every candidate epoch's wraps. Remaining readers keep reading the last settled key until the window passes. New writes after the cancel stay buffered until the winner settles, then use that key. They are not written under the last settled key or under a candidate that can still lose. If a smaller finalizationId later displaces that settled winner, content encrypted under the displaced revision is not current. The owner re-encrypts those writes under the new winner, bumps each remaining accessor's grantRevision, publishes a status proof for that revision, and issues wraps that match the new snapshot. Readers keep bytes they already unwrapped. A snapshot that lists a cancelled accessor as live, omits that accessor, or cancels that accessor below the revision this replica already has is ignored. `forward-only` leaves ciphertext already written under the old key. `re-encrypt` rewrites the soul under the candidate, and remaining readers use the copy they already unwrapped until they switch. Otherwise freshness is bounded by the status proof's max-age and the verifier's skew allowance. The proof names the accessor and that accessor's grantRevision. Bytes a revoked reader already unwrapped stay readable to that reader. A member offline through the window applies a missed cancel as soon as they see it.

Applying a new protocol version encrypts existing data in place. The reference crate runs `applyProtocolMigration`. Only the owner re-encrypts and issues wraps. A live grant whose window has not ended is a current reader, including one whose `from` is still ahead of `now`. The edge soul is `grantSoul(owner, object, accessor)`. The epoch and `revisionId` are the replica's current read key, and that key is open for a new write. The owner compares the soul's current ham state and body to the prepared snapshot before applying receipts. A mismatch aborts. The row wrap is the recorded wrap. Opening the item verifies the owner item-auth signature. Each reader keeps the old copy until that reader's authenticated wrap receipt verifies. The receipt is a SEA signature over the length-prefixed fields `s3rch-wrap-receipt-v1`, object, accessor, decimal `toVersion`, `revisionId`, and `entryId`. A version at the gate does not by itself drop plaintext. There is no single flag that drops plaintext for every reader at once. A reader already cancelled (`stated: 0` and a bumped `hamState`) is not wrapped and does not block the others. Items the owner keeps on the public plaintext path are not rewritten. A plaintext replica already stored elsewhere remains a historical leak. An opened wrap is not a grant.

SociACL runs no index. One public index for public content. Each private group runs its own. Individuals push and pull, then index a small set on device. An index hit is not a grant.

### Encrypted item consume checks

Identity for a manifest, a grant proof, a status statement, a `StatusAuthorityBinding`, and a group-inbox `ssig` is the current account SEA pub. A hop, a status statement, and a chat node do not mint a grant.

The Check object id stays the item. Every ciphertext envelope, including the first revision, is fetched from `s3rch/items/<itemId>/r/<rev>`. There is no root-ciphertext fallback. The root is a write-once locator `{ v: 2, enc: 1, first }`. It is not a Check object and not a grant. `envDigest` is the SHA-256 of the length-prefixed fields `s3rch-env-digest-v1`, item id, decimal epoch, rev, alg, iv, and ciphertext. The destination checks it against that revision node before accepting the body.

The signed grant tuple includes `manifest`, the soul `s3rch/items/<itemId>/m/<rev>`. Those bytes are `s3rch-grant-manifest-v1`. They sit outside `s3rch-grant-payload-v1`, so payload digests of that encoding stay. CHECK rejects a missing soul or a soul that is not that item and rev. The node is `{ v: 1, manifest, msig }`. `manifest` is `{ itemId, e, rev, parent, keyId, envDigest, statusAuthPub? }`. `statusAuthPub` is omitted from the canonical manifest when it is absent. An empty `statusAuthPub` is rejected. `msig` is the current account SEA signature over that encoding. The node carries no account pub. An author-lane copy does not satisfy a grantee. The manifest is not a grant.

`EpochManifest` gains optional `statusAuthPub`. Absent, the field is omitted from `epochRevisionId`. An empty `statusAuthPub` is rejected. Present, the pub is the last field of that id. A status proof signed by the current account key stands on its own. A proof signed by any other key verifies only when that key equals `statusAuthPub` on `StatusAuthorityBinding` and on the manifest for that rev, the binding account equals the log head account, the consumer has verified the binding signature under the current account key, and `seq` is the account-key log head. `bindingSignedByCurrent` is that result. The check does not verify the signature. A missing binding refuses every other signer. The authority pub cannot sign a manifest, a grant proof, or a replacement binding. It is not an account identity. The proof does not mint.

A v2 group-inbox entry at `s3rch/ginbox/<tag>/<entryId>` is `{ v: 1, senderPub, eph, ct, iv, ssig }`. `ssig` is the sender's current account SEA signature over `(tag, entryId, senderPub, H(eph || ct || iv))`. A signature under a key derived from the group epoch key is refused before unwrap. `senderPub` must be in the current epoch's member set and must be that account's current SEA pub. `member`, `signatureUnderSender`, and `derivedFromGroupKey` are the consumer's results. The check does not verify `ssig`, membership, or that derivation. The consumer must do those checks before passing true. `ssig` does not mint `see` or a membership. The group key encrypts only.

`AccountKeyLogEntry` is `{ account, keyPub, seq, prev }`. `seq` starts at 0 and then increases by 1. `prev` is the hash of the previous entry, or `none` at seq 0. The provider or the wallet signs the canonical head bytes (`s3rch-account-key-head-v1`, account, decimal seq, `entryHash`, decimal `issuedAt`, decimal `maxAgeMs`). The verifier checks that signature. The head and every chain entry must name the account being resolved. A valid head for another account is refused. The account SEA pub does not sign that head. The provider signing key must not equal any linked `keyPub`. The signed `issuedAt` and `maxAgeMs` are checked against `now`, `skewAllowanceMs`, and `policyMaxAgeMs`. The bound is the smaller of the signed max-age, the verifier cap, and `ACCOUNT_KEY_HEAD_MAX_AGE_MS` (300000). A head outside that window is `stale`, including a first contact with no anchor. Before any of the five statements above is accepted, the verifier fetches the head and a hash chain that links it to seq 0 or to an entry already accepted for the same account. An anchor stores that entry. The check recomputes its hash. It is a floor. A head below that seq is refused. The walk must reach that exact entry. The same-account next-seq shortcut still counts. Reaching seq 0 does not replace the anchor. The walk covers a head at `KEYRING_HISTORY_MAX`. A missing head, a signature that does not verify, a stale head, a chain that does not link, a `prev` mismatch, or no answer refuses the statement. The highest cached `seq` is not the current key. A superseded `keyPub` does not authenticate a new statement. The log entry is not a grant. The ids-plane account id remains the genesis `PrincipalId`. Keyring import still uses `resolveCurrentKey`.

Vectors: `vectors/encrypted-discovery/consume.json`.

Group epoch length, whether plaintext `MeshSeeGrant` stays for public content, and group search tokens are open. See the spec.
