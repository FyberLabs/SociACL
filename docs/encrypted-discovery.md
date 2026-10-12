# Encrypted discovery (spec)

Status: spec only. Nothing on this page changes Check, the Gun reference crate, or the plaintext dest-ACL path those already evaluate.

s3r.ch product draft: [FyberLabs/s3r.ch#108](https://github.com/FyberLabs/s3r.ch/pull/108) (`docs/encrypted-discovery.md` on that branch). This repository does not edit s3r.ch. Where the two pages differ, this page is the SociACL contract and that pull request is the product draft. The hardening on this page answers the Codex review on that pull request. It adds no verb.

The types live in [s3rch-check.d.ts](s3rch-check.d.ts). How to copy them: [s3rch-check.md](s3rch-check.md). Adapter map: [gun.md](gun.md).

## What stays locked

Light Check stays `CHECK(see, object, accessor)` at `now`.

- Hopcap is **1**. No friend-of-friend and no transitive inheritance.
- Grants stay **jointly stated**.
- A hop, a hint, or a wrap **never mints** a grant, an owner, or a membership.
- Hop missing does not fail. Hop alone never allows. Hop may only factor an already-named grant, owner path, or direct membership.
- `acceptHint`, `acceptHop`, and `decodeHop` do not verify and do not mint.
- Privilege-down is immediate for a current verifier. Cancel is owner-only, sets `stated: 0`, and bumps `hamState`. The next Check after that verifier has merged the cancel denies. Do not cache an allow across that merge. A verifier that does not hold a fresh owner-signed epoch/status proof is bounded by that proof's max-age. See [Revocation freshness](#revocation-freshness).
- `meta`, dest-ACL souls, and `UrlLeaf` fail closed.
- This page adds no verb. `crates/sociacl-gun` still evaluates plaintext `MeshSeeGrant` rows only.

Plaintext dest ACL today is a `MeshSeeGrant` on a `GunAclEdge` (`hamState`) at `grantSoul(owner, object, accessor)`, under `aclSoul(owner)`:

```
s3rch/acl/<aclPrincipalKey(owner)>/<aclKey(object)>/<aclPrincipalKey(accessor)>
```

Those helpers are the mesh consume contract ([#15](https://github.com/FyberLabs/SociACL/pull/15); the light Check file started in [#13](https://github.com/FyberLabs/SociACL/pull/13)). Private rows replace **enumeration** of that path. They do not fork `items` or `users`. Each reader has exactly one inbox lane. That lane is not a new locked collection name in this spec, and it is not a bucket shared with other readers.

## Wrapped-key grant edge

A private item has a data encryption key (DEK) for the current epoch. Ciphertext may sit on the shared graph. The DEK does not.

**Per reader.** The owner wraps that DEK to each reader's SEA `epub`. The wrap is ECDH-derived: an ephemeral pair and `SEA.secret` against the reader's `epub`, then authenticated encryption of the DEK. SEA `priv` and `epriv` never go on Gun.

**Per group, per epoch.** A group or named circle has one group key for an epoch. The owner wraps that group key to each member's SEA `epub`. The item DEK is wrapped once to the group's epoch key, not once per member. Membership is still a direct edge. A wrap to the group key does not add a member.

SociACL decides who receives a wrap. A wrap is written only for a principal the live grant or direct membership already names. The wrap bytes do not decide the set.

A wrap is not a grant. `checkSee` and `checkSeeGrant` do not take wrap bytes and do not read them when setting `allowed`. Check must still pass before a destination treats the item as granted (show it, reply, re-share, or write). Holding a DEK decrypts bytes the holder already fetched. It does not make Check allow. A hop, a hint, or a wrap never mints.

`WrappedKey` is the key material. A visible `BlindedGrantRow` may carry one beside ciphertext of the grant. The row stores a `GrantCommitment` (a hash). It does not store the owner's SEA pub. The holder opens that commitment in a `GrantPresentation` at the destination. See [Hidden authorship](#hidden-authorship).

## One inbox lane

Each reader account has **exactly one** private inbox lane (`RecipientInbox`). Every private grant row for that account is appended to that lane. The reader scans that lane and no other.

Scanning a shared bucket is not allowed. A lane is not a bucket many readers trial-decrypt. There is no second lane per device, per sender, or per epoch. Devices of one account share the account lane because they share one SEA keypair. See [Account key](#account-key).

`laneId` is not the plaintext accessor id and not `grantSoul`. This spec does not lock a new Gun collection name. The lane is one opaque soul. The reader discloses `laneId` to principals the [write policy](#inbox-write-policy) allows. Writers address that soul. They do not learn a shared bucket to scan.

## Append-only inbox entries

An inbox entry is append-only and content-addressed. `entryId` is the hash of the ciphertext. That hash is the entry's key. A different ciphertext is a different key. A body that does not hash to the key is rejected by the reader and by any relay that stores the lane. Nothing replaces an entry in place. The entry has no `hamState` contest.

A cancel or a newer grant is a new entry. Check on the opened grant still decides `stated`. The entry rule does not mint.

Where the writer is already known to the relay (`named-writers`), the entry may be a writer-signed outer envelope over that same hash. The relay verifies the signature without opening the grant. The default public lane does not use that envelope. A writer pub on every public row would name the writer. Content-addressing stops replacement, and the visible grant row still has no owner pub.

A hop, a hint, a wrap, or an envelope is not a grant.

## Lane scan

The account still has one lane. A cursor is not a second lane. A daily shard is a layout of that same lane, not a bucket and not a lane per device.

Clock skew between a sender's devices, or a restored clock, can place a new entry at or below one saved high-water mark. A cursor that is only the greatest observed time skips those entries for good. It is not a lossless cursor.

The reader uses one of these, and deduplicates by `entryId`:

- a cursor per sender device id, advanced only for that device
- a rescan of each whole daily shard, then dedup against entries already accepted

The device id is the same local enrollment id as on an [epoch manifest](#epoch-manifest). It is not a Gun device record and not a grant.

## Hidden authorship

Authorship is hidden by default. A visible grant row does not carry the owner id or the owner's SEA pub. Peers that replicate the lane cannot read the owner off the row. Check at the destination still verifies.

The owner's SEA pub is not a field on that row. A signature over the grant, made with the account SEA key, sits **inside** the ciphertext.

The visible row holds:

- ciphertext of the canonical grant (object, accessor, `from`, `until`, `stated`, epoch, and the owner's id). When the grant names an encrypted item, those bytes include the item ciphertext digest, so the commitment covers that digest
- a `GrantCommitment`: the hash of those canonical bytes
- the wrapped DEK, when this row carries a key
- `entryId`: the hash of the ciphertext

There is no `hamState` on the entry. A later grant is a new entry. See [Append-only inbox entries](#append-only-inbox-entries).

The holder presents a `GrantPresentation` to the destination. The presentation is not written back to Gun. It contains the opened grant, the owner id, the signature, and the owner's SEA pub. The destination:

1. Recomputes the commitment from the opened grant and checks it against the row. A mismatch fails closed. The presented grant is then the grant that was committed, not a substitute.
2. Verifies the signature with the SEA pub in the presentation, and checks that pub is the one enrolled for the owner named in the opened grant. The pub comes from the presentation and the account enrollment, not from a copy on the row.
3. Checks [presenter binding](#presenter-binding). A proof alone grants nothing.
4. Checks a fresh [epoch/status proof](#revocation-freshness) beside the zookie. A missing or stale proof fails closed.
5. Runs `checkSee` / `checkSeeGrant` (or `checkGroupSee`) on the opened grant. A hop, a hint, or a wrap still never mints.

A row that fails the commitment check, the signature check, the presenter binding, or the freshness check is not a grant. Blinded storage does not skip Check.

### What the verification leaks

This is not private information retrieval and not a zero-knowledge proof. Both are future work. This spec claims neither.

| Who | Learns | Does not learn from the row alone |
| --- | --- | --- |
| Replicating peer | Row counts on the lane, timing, ciphertext sizes | The owner. The row has no owner id and no owner SEA pub |
| Destination, after a presentation | The owner, the accessor, the window, and that the signature matches the enrolled SEA pub | Nothing further is written to Gun |
| Relay used for an enrollment lookup | Which account's SEA pub was fetched, if the destination does not already have it cached | The grant window, unless the presentation was sent to that relay |
| Relay storing the lane | Entry hashes, sizes, timing, and a first-contact stamp | The owner, on the default content-addressed row. A `named-writers` envelope shows a writer pub that relay was already allowed to know |

The destination must learn the owner. Check cannot name an owner it has not been shown. Caching the enrolled pub avoids a fresh lookup. A lookup that hits a relay leaks the account id to that relay. The presentation itself is the holder's disclosure to that destination.

Padding and batching can reduce size and timing leaks. They are not promised here. An observer who already stored a plaintext `MeshSeeGrant` keeps that copy. New private rows do not hide history that already replicated in the clear.

Lane disclosure has its own leak. A principal who knows `laneId`, and any peer who replicates that soul, sees that lane's row counts, timing, and sizes. They do not get other readers' rows from it, because there is no shared bucket.

## Presenter binding

A `GrantPresentation` shows what was committed and which owner signed the grant. It does not show that the presenter holds the reader's SEA key. Anyone who only carries the opened proof can replay it on another channel. A proof alone grants nothing.

The destination sends a nonce. The presenter signs it with the reader's SEA key. The signed bytes are the nonce and the grant commitment hash. The destination checks that signature with the enrolled SEA `pub` for the accessor named in the opened grant. A bad signature, a different pub, or a different nonce fails closed.

An authenticated channel that already proves the presenter holds that same reader key is the same check. The destination records which accessor the channel authenticated. No nonce signature and no such channel fails closed.

The binding is not a grant. Check still runs after it. A hop, a hint, or a wrap never mints. A valid binding does not set `allowed`.

## Item content authenticity

Every reader of an item holds that item's DEK, so authenticated encryption shows that the writer had the DEK. It does not show that the owner wrote the body. A reader can encrypt a replacement and put it at the same item soul.

The owner signs `(item id, epoch, version, digest of the ciphertext)`. `ItemContentAuth` is that signature. It lives **inside** the encrypted item. The visible grant row does not carry it and does not carry the owner's SEA pub. When the grant names the item, the canonical grant bytes include that digest, so `GrantCommitment` covers the digest. Either placement keeps authorship hidden. This spec uses both: the signature stays inside the item, and the commitment covers the digest.

A reader recomputes the digest and checks the signature with the enrolled owner pub they already have to open the grant. A mismatch fails closed. Other readers reject the replacement. The signature is not a grant. Holding the DEK does not mint one. Check still runs.

The signature also names the winning `revisionId` from [Epoch manifest](#epoch-manifest). A body bound to a superseded revision fails this check.

## Author fast unwrap

The author has a local path that does not scan a lane and does not present a commitment.

The author keeps the item DEK on the device that encrypted it. Unwrap uses that local DEK. The fast path is not a Gun row and not a grant. Check for the author remains the owner path. The visible row still does not name the owner.

A device enrolled to the same account holds the same SEA keypair, so it can unwrap a self-wrap addressed to that `epub`. The self-wrap, if the author writes one, goes in the author's single lane like any other wrap and still omits the owner pub. Other readers do not use this path. Holding the author's DEK is not a way for them to skip Check, and it is not a way to forge a body that passes [item content authenticity](#item-content-authenticity).

## Account key

Each account has one SEA keypair. `pub` and `epub` may sit on the user node. `priv` and `epriv` never go on Gun.

Devices do not mint a second SEA keypair. A device inherits the account keypair through enrollment. Enrollment copies the keypair onto the device. It does not write `priv` or `epriv` to Gun, and it does not mint a grant. The inbox lane stays one per account, not one per device. Wraps for that account use the one `epub`.

## Epoch manifest

Those devices share the account key, so two of them can each mint a different key for epoch `e+1` and publish ciphertext and wraps under the same epoch number. The epoch number alone does not say which key is current. A field-wise merge can keep one item body and a wrap for the other key.

The owner device publishes an `EpochManifest`, signed with the account SEA key. Devices check that signature with the account `pub` they already hold. The manifest is a self-wrap in the author's one lane, or it sits inside the encrypted item. It is not an owner pub on a visible grant row. It is not a grant. Publishing it does not mint.

`revisionId` is the hash of the previous epoch and the device id, lowercase hex: `hash(utf8(previousEpoch) || 0x00 || utf8(deviceId))`. The device id is local to that enrollment. It is not a Gun device record, not a second SEA keypair, and not a grant. Enrollment still does not mint.

Two devices racing the same next epoch produce two revision ids. The winner is the lexicographically smallest `revisionId` among manifests that verify under the account `pub` and name the same object, the same next epoch, and the same previous epoch. A reader applies that rule to the owner-signed manifests they can open. The smallest revision id in that set is current, and every other revision in the set is superseded. A second body under an existing `revisionId` is rejected. The manifest is append-only and content-addressed by `revisionId`, so a merge cannot swap the key commitment.

Readers reject current content, wraps, and further writes bound to a superseded revision, including when the epoch number matches the winner. They also reject content under an epoch the winning manifest has superseded. Bytes a reader already unwrapped stay readable to them, as in [Rotation on revoke](#rotation-on-revoke). A device that lost adopts the winning manifest and does not keep publishing under the superseded revision. An offline device that later publishes under a superseded epoch or revision is not current.

How long an epoch lasts is still open. See [Open choices](#open-choices).

## First contact

A first introduction on the one lane carries the sender's SEA `epub` and SEA `pub`, and an account binding signed by `pub`.

The binding is a signature by `pub` over the sender account, `pub`, and `epub`. The reader checks it with `pub`. A missing `epub`, a missing binding, or an `epub` that was not the one signed fails closed. `pub` alone can verify a signature and still leave the reader unable to wrap to that sender.

The introduction is not a grant. It does not open a second lane. It does not mint. Later wraps to that sender use the bound `epub`. `priv` and `epriv` still never go on Gun. First contact under the public policy also needs a stamp. See [Inbox write policy](#inbox-write-policy).

## Inbox write policy

The reader chooses who may append to their one lane. The hook is `filterInboxAppend` (`InboxWriteHook`). The default policy is `public-filtered`. Public stays the default. `named-writers` stays the allowlist.

| Policy | Who may append | First contact | Quotas |
| --- | --- | --- | --- |
| `public-filtered` (default) | Any principal | Proof-of-work or a stamp, bound to that introduction's `entryId`. A self-signature is not enough | One quota per sender, separate from the reader's own capacity. Spending a sender's quota does not reduce any other sender and does not spend the reader's capacity |
| `named-writers` | Only principals listed on the hook | Unlisted first contact is refused before the row is a candidate grant | The same per-sender quotas |

The user sets the policy. The stamp and the quotas run on the reader. A relay may check the stamp, or that the body hashes to the entry key, without opening the grant. SociACL does not run the filter and does not store a spam score. Oversized rows and rows over the reader's own capacity are still local drops. A commitment mismatch is `checkPresentedGrant`, not a score. A row the hook accepts is still not a grant. A hop, a hint, a wrap, or a stamp never mints. Being allowed to append does not confer `see`.

## Rotation on revoke

Revoke of an encrypted object always starts with privilege-down, then a new epoch. The owner chooses what happens to ciphertext that already exists. `RevokeCipherMode` records the choice. `rotateOnRevoke` names the operation. The reference crate does not run it.

1. **Privilege-down, immediate for a current verifier.** `stated: 0` on the grant (or on the direct membership) and a `hamState` bump, same as `cancelSee`. The next Check after that verifier has merged the cancel denies. Do not cache an allow across that merge. Freshness for every other verifier is [Revocation freshness](#revocation-freshness).
2. **New epoch.** A new DEK, or a new group epoch key, wrapped only to the remaining readers. New ciphertext uses the new key. The epoch is the winning [epoch manifest](#epoch-manifest). A second key under the same epoch number does not become current.
3. **Ciphertext choice**, one of:

| Mode | What the owner does | What a revoked reader can still read |
| --- | --- | --- |
| `forward-only` | Leaves existing ciphertext under the old DEK. Only later writes use the new epoch | Old ciphertext, if they already unwrapped the old DEK or saved the old bytes. Not the new epoch |
| `re-encrypt` | Rewrites existing ciphertext in place under the new DEK and bumps merge state so the new ciphertext wins | A local copy, or plaintext they already unwrapped. The replaced soul no longer serves the old ciphertext to peers that merged the new record |

A wrap for an older epoch does not mint a grant. Check denies the revoked accessor after step 1 even when they still hold the old DEK.

**Honest limit, both modes.** Content the revoked party already unwrapped stays readable to them. `re-encrypt` replaces the soul's ciphertext. It does not erase a copy or a DEK they already hold. `forward-only` does not pretend to hide the old epoch.

Removing a reader is this revoke, including the owner's choice of mode. Whether adding a member, or a quiet boundary with no removal, also starts a new group epoch is open. See [Open choices](#open-choices).

## Revocation freshness

Privilege-down is immediate only for a current verifier, as in [Rotation on revoke](#rotation-on-revoke). A stale, partitioned, or offline verifier has not merged that cancel. Absence of a cancel in its copy is not proof the grant is live.

Destination re-check of an encrypted grant requires an owner-signed `EpochStatusProof` beside the Check zookie. The proof names the object, the epoch, the winning revision, and `stated`. The owner signs it with the account SEA key. The destination checks that signature with the enrolled owner `pub` from the presentation, not from a field on the visible row. The zookie is the existing Check freshness token: object, object version, and snapshot hash. A zookie bound to an older object version is not a cached allow.

`maxAgeMs` is the bound. A current verifier has merged the privilege-down, when there is one, and holds a proof with `now - signedAt <= maxAgeMs`. That verifier denies immediately when `stated` is 0 or the merged grant is cancelled. Do not cache an allow across that merge.

Every other verifier may rely on a proof only while it is inside max-age. A missing proof, a proof older than max-age, a proof for a superseded revision, or a zookie for an older object version fails closed. Revocation is immediate only for a current verifier. Otherwise it is bounded by max-age. A revoked reader cannot present a proof after that bound.

The proof is not a grant. It does not mint. It does not change hopcap 1.

## Group predicates

`same-group` and `named-circle` already exist on the core Check plane. This spec names them on the s3r.ch light contract. Hopcap stays 1. Edges stay jointly stated. There is no transitive inheritance, no nested group, and no friend-of-friend walk.

The object names one of `delegate`, `same-group`, or `named-circle`. The accessor does not pick a richer one. An object with no named predicate stays on today's `delegate` / `MeshSeeGrant` path.

Owner allow does not depend on that name. The owner sees their object.

Check then evaluates only the named predicate. Both edges in a group or circle check must be `stated: 1`.

| Predicate | Holds when |
| --- | --- |
| `owner` | The accessor is the object's owner. Unchanged. |
| `delegate` | A live `IdentitySeeGrant` / `MeshSeeGrant` names this accessor, and `now` is in `[from, until)`. This is today's per-accessor see path. |
| `same-group` | `ObjectSetName` names a group, stated 1. The accessor has a jointly stated direct `member-of` edge to that group (`MeshMembership`). |
| `named-circle` | `ObjectSetName` names a circle, stated 1. The accessor has a jointly stated direct `in-circle` edge to that circle. |

One-sided membership is stored and is not a grant. `stated: 0` plus a higher `hamState` wins the next merge. `checkGroupSee` is that Check. Hop may factor an already-named direct membership. Hop alone never allows. A wrap never mints a membership.

The group epoch key opens group ciphertext. It does not replace the membership edge. Check reads the edge. The key opens bytes.

A member of group A is not thereby a member of group B. A member's other grants are not inherited by the rest of the group. A circle does not contain another circle for Check.

`posix-mode` and `same-network` stay on the core plane. They are not added to this light contract.

## Index model

SociACL runs no index. Check does not call an index. An index hit is not a grant.

| Tier | Who keeps it | What it holds |
| --- | --- | --- |
| Public | One public index | Public content only. Private items never enter it. |
| Private group | That group | The group's own index, opened with the group's current epoch key. A removed member does not receive the next epoch's index key. |
| Individual | That person, on device | Push and pull of their small set, then a local index. No shared index for this tier. |

`ContentIndexTier` names those three tiers so a product can say which one a record belongs to. The record is not a Check object. s3r.ch may store the public index and a group's index on Gun. That storage is product data, not a SociACL service.

Whether a private group's index is addressed by search tokens, and what those tokens leak to whoever serves the index, is not decided. See [Open choices](#open-choices). This spec does not define a token construction.

## Contract types

Copy or re-type [s3rch-check.d.ts](s3rch-check.d.ts). Do not `npm install sociacl`. Do not import `crates/sociacl-gun`.

| Type or function | Role |
| --- | --- |
| `AccountSeaKey` | One SEA keypair per account. Devices inherit it through enrollment. `priv` / `epriv` stay off Gun |
| `WrappedKey` | DEK wrapped to a reader SEA `epub`, group key wrapped to a member, or item DEK wrapped to a group epoch key |
| `GrantCommitment` | Hash of the canonical grant. Covers the item ciphertext digest when the grant names an encrypted item. Not an owner SEA pub |
| `ItemContentAuth` | Owner signature over item id, epoch, version, and ciphertext digest. Inside the encrypted item |
| `BlindedGrantRow` | One append-only lane entry. `entryId` is the hash of the ciphertext. No owner field. No `hamState` |
| `InboxEnvelope` | Optional writer-signed outer envelope for `named-writers`. Relays verify it without opening the grant |
| `GrantPresentation` | What the holder shows the destination. Not written to Gun. A proof alone grants nothing |
| `PresenterBinding` | Destination nonce signed by the reader's SEA key. Or an authenticated channel |
| `checkPresentedGrant` | Commitment, owner signature, presenter binding, fresh status proof, then Check |
| `RecipientInbox` | The one lane for that account. Not a shared bucket |
| `LaneScanCursor` / `DailyShardScan` | Cursor per sender device, or a whole-shard rescan with dedup. Not a second lane |
| `AuthorFastUnwrap` | Local author DEK. Not a grant row |
| `FirstContactIntro` | Sender `pub` and `epub`, with an account binding signed by `pub` |
| `InboxWriteHook` / `filterInboxAppend` | Who may append. Default `public-filtered`. First contact needs a stamp. Quota per sender |
| `EpochManifest` | Owner-signed epoch revision. Smallest `revisionId` wins. Readers reject a superseded epoch |
| `GrantStorage` | `public-plain` or `private-row` (whether public-plain stays is open) |
| `MeshMembership` | Direct `same-group` or `named-circle` edge. Hopcap 1 |
| `ObjectSetName` | The group or circle an object names |
| `GroupSeeGraph` / `checkGroupSee` | Check for those two predicates |
| `CancelledGrant` | `stated: 0` and the bumped `hamState` on a see grant or a membership |
| `RevokeCipherMode` | `forward-only` or `re-encrypt`. The owner chooses at revoke |
| `EpochRotation` / `rotateOnRevoke` | Privilege-down, new epoch, then the ciphertext mode |
| `EpochStatusProof` | Owner-signed epoch/status beside the zookie, with `maxAgeMs` |
| `ProtocolMigration` | Owner-only in-place encryption. Plaintext removal waits on the owner's migration |
| `ContentIndexTier` | `public`, `private-group`, or `local`. SociACL does not store it |
| `EncryptedDiscoveryVector` | Stub names for the conformance cases below. The reference crate does not run them |

`GunFeedNode` and `GunUserNode` are unchanged. Predicate and membership are ACL rows, not feed fields. The user node may carry the account SEA `pub` and `epub`. It does not carry `priv`, `epriv`, or a copy of a grant row's owner field.

## Migration

Applying a new protocol version encrypts existing shared items in place. It does not leave those items on the plaintext path and encrypt only later writes. Only the owner re-encrypts a shared item and issues the new wraps. A reader does not choose a replacement DEK, does not re-encrypt the shared soul, and does not issue wraps for other readers. The reference crate does not run the migration.

For each existing item that moves onto the version:

1. The object id and item soul stay. The owner generates a DEK and the ciphertext for the existing body. `version` on that ciphertext is `toVersion`. The plaintext body stays in place through this step.
2. The owner keeps that DEK for [author fast unwrap](#author-fast-unwrap).
3. The owner writes each current reader a `WrappedKey` and a `BlindedGrantRow` in that reader's one lane. The commitment hides the owner and covers the item ciphertext digest, as in [Hidden authorship](#hidden-authorship) and [Item content authenticity](#item-content-authenticity).
4. Readers keep the old copy, and may keep reading it, until they have merged that owner migration: the new ciphertext and their wrap.
5. Only after that migration is published does the owner remove plaintext. The ciphertext replaces the body, merge state bumps so the ciphertext wins, and the old plaintext `MeshSeeGrant` is cancelled (`stated: 0` and a `hamState` bump). Check after that merge denies the clear row for a current verifier. The private row is the live grant for readers who can open it.
6. `ProtocolMigration` records `fromVersion`, `toVersion`, the object, the wraps the owner issued, and `ownerMigrationArrived`. Readers do not set `ownerMigrationArrived`. Plaintext removal waits until it is set.

Items the owner keeps on the public plaintext path are not rewritten. Whether that path stays is open. See [Open choices](#open-choices).

**Honest limit.** Peers that already replicated the plaintext body or the plaintext grant keep that copy. In-place replacement updates the soul for peers that merge the new record. It does not claw back an old replica. A reader who has not merged the owner's migration still has the old copy and does not invent a second ciphertext to fill the gap.

## Conformance vectors

Stubs only. The names are `EncryptedDiscoveryVector` in [s3rch-check.d.ts](s3rch-check.d.ts). The reference crate does not run them. In every vector, a wrap, a hop, a hint, an introduction, a binding, or a stamp never mints.

### Content authenticity

`content-auth-accept`. The ciphertext digest matches the owner signature over (item id, epoch, version, digest). The signature is inside the encrypted item. The row commitment covers that digest. The reader accepts the body as authentic. Accepting it is not a grant.

`content-auth-reader-forge`. A reader who holds the item DEK writes a different body at the item soul. The digest no longer matches the owner signature, and the commitment does not cover the new digest. Other readers reject the body.

`content-auth-owner-pub-hidden`. The visible row bytes do not contain the owner SEA pub. The signature stays inside the encrypted item.

### Inbox replacement

`inbox-content-address-distinct`. Two different ciphertexts have two entry ids. Each id is the hash of its ciphertext.

`inbox-replace-rejected`. A put whose body does not hash to the entry id is rejected. A different body under an existing entry id does not replace the first ciphertext.

### First contact

`intro-epub-required`. An introduction with `pub` and no `epub` fails closed.

`intro-binding-ok`. The account, `pub`, and `epub` are covered by a signature that verifies with `pub`. The introduction is accepted as first contact. It is not a grant and it does not open a second lane.

`intro-binding-swap-epub`. The same signature with a different `epub` fails closed.

`intro-not-a-grant`. A valid introduction does not set `allowed`.

### Presenter binding

`presenter-proof-alone`. A `GrantPresentation` with a matching commitment and a valid owner signature, and with no nonce signature and no authenticated channel, fails closed. The proof does not grant.

`presenter-nonce-ok`. The destination's nonce, signed by the reader's SEA key, verifies with the enrolled pub for the named accessor. Check then runs. Check may still deny.

`presenter-bad-key`. The nonce signature verifies under a different key. The destination rejects it.

`presenter-binding-not-a-grant`. A valid binding with a Check deny stays a deny.

## Open choices

Not decided:

1. **Group epoch length.** How long an epoch lasts, and whether every membership change forces a new epoch. Removal of a reader still follows [Rotation on revoke](#rotation-on-revoke): privilege-down, a new DEK or epoch key for the remaining readers, and the owner's `forward-only` or `re-encrypt` choice.
2. **Public-content mode.** Whether plaintext `MeshSeeGrant` stays for public content, with private rows only when the item is encrypted. Migration skips items that stay on that path.
3. **Group search tokens.** Whether a private group's index is addressed by search tokens, and what those tokens leak to whoever serves the index. No token scheme is fixed here.

## What this does not do

- Change Check's allow rules for a hop or a hint
- Put SEA `priv` or `epriv` on Gun
- Put the owner's SEA pub on a visible grant row
- Treat a wrap, a presentation, an inbox append, an introduction, a content signature, an epoch manifest, a presenter binding, a status proof, or a stamp as a grant
- Accept a presentation that does not bind the presenter to the reader's SEA key
- Treat a missing or expired epoch/status proof as a live grant
- Let a reader re-encrypt a shared item, or remove plaintext before the owner's migration arrives
- Use one clock high-water mark as a cursor for every sender device
- Add a second inbox lane, or a Gun device record, for a device id
- Allow a reader to scan a shared bucket
- Claim private information retrieval or a zero-knowledge proof (future work only)
- Add an index, or a group search-token scheme, to SociACL
- Fork `items`, `users`, or the five-segment `grantSoul` path
- Edit FyberLabs/s3r.ch
