# Encrypted discovery (spec)

Status: spec only. Nothing on this page changes Check, the Gun reference crate, or the plaintext dest-ACL path those already evaluate.

s3r.ch product draft: [FyberLabs/s3r.ch#108](https://github.com/FyberLabs/s3r.ch/pull/108) (`docs/encrypted-discovery.md` on that branch). This repository does not edit s3r.ch. Where the two pages differ, this page is the SociACL contract and that pull request is the product draft.

The types live in [s3rch-check.d.ts](s3rch-check.d.ts). How to copy them: [s3rch-check.md](s3rch-check.md). Adapter map: [gun.md](gun.md).

## What stays locked

Light Check stays `CHECK(see, object, accessor)` at `now`.

- Hopcap is **1**. No friend-of-friend and no transitive inheritance.
- Grants stay **jointly stated**.
- A hop, a hint, or a wrap **never mints** a grant, an owner, or a membership.
- Hop missing does not fail. Hop alone never allows. Hop may only factor an already-named grant, owner path, or direct membership.
- `acceptHint`, `acceptHop`, and `decodeHop` do not verify and do not mint.
- Privilege-down is immediate. Cancel is owner-only, sets `stated: 0`, and bumps `hamState`. The next Check after HAM merge denies. Do not cache an allow across that merge.
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

## Hidden authorship

Authorship is hidden by default. A visible grant row does not carry the owner id or the owner's SEA pub. Peers that replicate the lane cannot read the owner off the row. Check at the destination still verifies.

The visible row holds:

- ciphertext of the canonical grant (object, accessor, `from`, `until`, `stated`, epoch, and the owner's id)
- a `GrantCommitment`: the hash of those canonical bytes
- the wrapped DEK, when this row carries a key
- `hamState`

The owner's SEA pub is not a field on that row. A signature over the grant, made with the account SEA key, sits **inside** the ciphertext.

The holder presents a `GrantPresentation` to the destination. The presentation is not written back to Gun. It contains the opened grant, the owner id, the signature, and the owner's SEA pub. The destination:

1. Recomputes the commitment from the opened grant and checks it against the row. A mismatch fails closed. The presented grant is then the grant that was committed, not a substitute.
2. Verifies the signature with the SEA pub in the presentation, and checks that pub is the one enrolled for the owner named in the opened grant. The pub comes from the presentation and the account enrollment, not from a copy on the row.
3. Runs `checkSee` / `checkSeeGrant` (or `checkGroupSee`) on the opened grant. A hop, a hint, or a wrap still never mints.

A row that fails the commitment check or the signature check is not a grant. Blinded storage does not skip Check.

### What the verification leaks

This is not private information retrieval and not a zero-knowledge proof. Both are future work. This spec claims neither.

| Who | Learns | Does not learn from the row alone |
| --- | --- | --- |
| Replicating peer | Row counts on the lane, timing, ciphertext sizes | The owner. The row has no owner id and no owner SEA pub |
| Destination, after a presentation | The owner, the accessor, the window, and that the signature matches the enrolled SEA pub | Nothing further is written to Gun |
| Relay used for an enrollment lookup | Which account's SEA pub was fetched, if the destination does not already have it cached | The grant window, unless the presentation was sent to that relay |

The destination must learn the owner. Check cannot name an owner it has not been shown. Caching the enrolled pub avoids a fresh lookup. A lookup that hits a relay leaks the account id to that relay. The presentation itself is the holder's disclosure to that destination.

Padding and batching can reduce size and timing leaks. They are not promised here. An observer who already stored a plaintext `MeshSeeGrant` keeps that copy. New private rows do not hide history that already replicated in the clear.

Lane disclosure has its own leak. A principal who knows `laneId`, and any peer who replicates that soul, sees that lane's row counts, timing, and sizes. They do not get other readers' rows from it, because there is no shared bucket.

## Author fast unwrap

The author has a local path that does not scan a lane and does not present a commitment.

The author keeps the item DEK on the device that encrypted it. Unwrap uses that local DEK. The fast path is not a Gun row and not a grant. Check for the author remains the owner path. The visible row still does not name the owner.

A device enrolled to the same account holds the same SEA keypair, so it can unwrap a self-wrap addressed to that `epub`. The self-wrap, if the author writes one, goes in the author's single lane like any other wrap and still omits the owner pub. Other readers do not use this path. Holding the author's DEK is not a way for them to skip Check.

## Account key

Each account has one SEA keypair. `pub` and `epub` may sit on the user node. `priv` and `epriv` never go on Gun.

Devices do not mint a second SEA keypair. A device inherits the account keypair through enrollment. Enrollment copies the keypair onto the device. It does not write `priv` or `epriv` to Gun, and it does not mint a grant. The inbox lane stays one per account, not one per device. Wraps for that account use the one `epub`.

## Inbox write policy

The reader chooses who may append to their one lane. The hook is `filterInboxAppend` (`InboxWriteHook`). The default policy is `public-filtered`.

| Policy | Who may append | What the reader does next |
| --- | --- | --- |
| `public-filtered` (default) | Any principal | Drops a row that is oversized, over the reader's local rate, or whose commitment does not match the opened bytes. Remaining rows still need Check |
| `named-writers` | Only principals listed on the hook | Refuses anyone else before the row is treated as a grant. The same local spam filter still runs |

The user sets the policy. Public writes are the default, with that spam filter. The filter runs on the reader. SociACL does not run it and does not store a spam score. A row the hook accepts is still not a grant. A hop, a hint, or a wrap never mints. Being allowed to append does not confer `see`.

## Rotation on revoke

Revoke of an encrypted object always starts with privilege-down, then a new epoch. The owner chooses what happens to ciphertext that already exists. `RevokeCipherMode` records the choice. `rotateOnRevoke` names the operation. The reference crate does not run it.

1. **Privilege-down, immediate.** `stated: 0` on the grant (or on the direct membership) and a `hamState` bump, same as `cancelSee`. The next Check after HAM merge denies. Do not cache an allow across that merge.
2. **New epoch.** A new DEK, or a new group epoch key, wrapped only to the remaining readers. New ciphertext uses the new key.
3. **Ciphertext choice**, one of:

| Mode | What the owner does | What a revoked reader can still read |
| --- | --- | --- |
| `forward-only` | Leaves existing ciphertext under the old DEK. Only later writes use the new epoch | Old ciphertext, if they already unwrapped the old DEK or saved the old bytes. Not the new epoch |
| `re-encrypt` | Rewrites existing ciphertext in place under the new DEK and bumps merge state so the new ciphertext wins | A local copy, or plaintext they already unwrapped. The replaced soul no longer serves the old ciphertext to peers that merged the new record |

A wrap for an older epoch does not mint a grant. Check denies the revoked accessor after step 1 even when they still hold the old DEK.

**Honest limit, both modes.** Content the revoked party already unwrapped stays readable to them. `re-encrypt` replaces the soul's ciphertext. It does not erase a copy or a DEK they already hold. `forward-only` does not pretend to hide the old epoch.

Removing a reader is this revoke, including the owner's choice of mode. Whether adding a member, or a quiet boundary with no removal, also starts a new group epoch is open. See [Open choices](#open-choices).

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
| `GrantCommitment` | Hash of the canonical grant. Visible row. Not an owner SEA pub |
| `BlindedGrantRow` | One lane entry. Ciphertext, commitment, optional wrap. No owner field |
| `GrantPresentation` | What the holder shows the destination. Not written to Gun |
| `checkPresentedGrant` | Commitment match, then signature against the presented enrolled pub, then Check |
| `RecipientInbox` | The one lane for that account. Not a shared bucket |
| `AuthorFastUnwrap` | Local author DEK. Not a grant row |
| `InboxWriteHook` / `filterInboxAppend` | Who may append. Default `public-filtered` |
| `GrantStorage` | `public-plain` or `private-row` (whether public-plain stays is open) |
| `MeshMembership` | Direct `same-group` or `named-circle` edge. Hopcap 1 |
| `ObjectSetName` | The group or circle an object names |
| `GroupSeeGraph` / `checkGroupSee` | Check for those two predicates |
| `CancelledGrant` | `stated: 0` and the bumped `hamState` on a see grant or a membership |
| `RevokeCipherMode` | `forward-only` or `re-encrypt`. The owner chooses at revoke |
| `EpochRotation` / `rotateOnRevoke` | Privilege-down, new epoch, then the ciphertext mode |
| `ProtocolMigration` | In-place encryption when a new protocol version is applied |
| `ContentIndexTier` | `public`, `private-group`, or `local`. SociACL does not store it |

`GunFeedNode` and `GunUserNode` are unchanged. Predicate and membership are ACL rows, not feed fields. The user node may carry the account SEA `pub` and `epub`. It does not carry `priv`, `epriv`, or a copy of a grant row's owner field.

## Migration

Applying a new protocol version encrypts existing data in place. It does not leave old private items on the plaintext path and encrypt only later writes. The reference crate does not run the migration.

For each existing item that moves onto the version:

1. The object id and item soul stay. The owner generates a DEK, replaces the plaintext body with ciphertext, and bumps merge state so the ciphertext wins the next HAM merge.
2. The owner keeps that DEK for [author fast unwrap](#author-fast-unwrap).
3. Each current reader gets a `WrappedKey` and a `BlindedGrantRow` in their one inbox lane. The commitment hides the owner, as in [Hidden authorship](#hidden-authorship).
4. The old plaintext `MeshSeeGrant` is cancelled: `stated: 0` and a `hamState` bump. Check after that merge denies the clear row. The private row is the live grant for readers who can open it.
5. `ProtocolMigration` records `fromVersion`, `toVersion`, and the object. `version` on the new ciphertext is `toVersion`.

Items the owner keeps on the public plaintext path are not rewritten. Whether that path stays is open. See [Open choices](#open-choices).

**Honest limit.** Peers that already replicated the plaintext body or the plaintext grant keep that copy. In-place replacement updates the soul for peers that merge the new record. It does not claw back an old replica.

## Open choices

Not decided:

1. **Group epoch length.** How long an epoch lasts, and whether every membership change forces a new epoch. Removal of a reader still follows [Rotation on revoke](#rotation-on-revoke): privilege-down, a new DEK or epoch key for the remaining readers, and the owner's `forward-only` or `re-encrypt` choice.
2. **Public-content mode.** Whether plaintext `MeshSeeGrant` stays for public content, with private rows only when the item is encrypted. Migration skips items that stay on that path.
3. **Group search tokens.** Whether a private group's index is addressed by search tokens, and what those tokens leak to whoever serves the index. No token scheme is fixed here.

## What this does not do

- Change Check's allow rules for a hop or a hint
- Put SEA `priv` or `epriv` on Gun
- Put the owner's SEA pub on a visible grant row
- Treat a wrap, a presentation, or an inbox append as a grant
- Allow a reader to scan a shared bucket
- Claim private information retrieval or a zero-knowledge proof (future work only)
- Add an index, or a group search-token scheme, to SociACL
- Fork `items`, `users`, or the five-segment `grantSoul` path
- Edit FyberLabs/s3r.ch
