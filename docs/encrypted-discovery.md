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

Those helpers are the mesh consume contract ([#15](https://github.com/FyberLabs/SociACL/pull/15); the light Check file started in [#13](https://github.com/FyberLabs/SociACL/pull/13)). Private rows replace **enumeration** of that path. They do not fork `items` or `users`, and they do not add a second locked Gun root while the blinding choice below is open.

## Wrapped-key grant edge

A private item has a data encryption key (DEK) for the current epoch. Ciphertext may sit on the shared graph. The DEK does not.

**Per reader.** The owner wraps that DEK to each reader's SEA `epub`. The wrap is ECDH-derived: an ephemeral pair and `SEA.secret` against the reader's `epub`, then authenticated encryption of the DEK. SEA `priv` and `epriv` never go on Gun.

**Per group, per epoch.** A group or named circle has one group key for an epoch. The owner wraps that group key to each member's SEA `epub`. The item DEK is wrapped once to the group's epoch key, not once per member. Membership is still a direct edge. A wrap to the group key does not add a member.

SociACL decides who receives a wrap. A wrap is written only for a principal the live grant or direct membership already names. The wrap bytes do not decide the set.

A wrap is not a grant. `checkSee` and `checkSeeGrant` do not take wrap bytes and do not read them when setting `allowed`. Check must still pass before a destination treats the item as granted (show it, reply, re-share, or write). Holding a DEK decrypts bytes the holder already fetched. It does not make Check allow. A hop, a hint, or a wrap never mints.

`WrappedKey` is the key material. `BlindedGrantRow` may carry one beside a `MeshSeeGrant`. `GrantCommitment` is the owner signature or commitment over that grant.

## Recipient-side discovery

Plaintext rows at `s3rch/acl/<owner>/<object>/<accessor>` tell every replicating peer who may read what. The same leak exists for any clear delivery copy that names the accessor. Private grants replace those clear rows. Readers do not ask the mesh what they can see. Each accessor scans an inbox of its own rows, opens the ones it can, and then runs Check.

Example, not a closed choice: the row key is blinded with a secret shared by the owner and the accessor, and each accessor scans only tags it can derive. The other open shape stores the encrypted row under a recipient inbox soul. See [Open choices](#open-choices). No new Gun root is locked until that choice closes. `RecipientInbox` names the scan target without fixing the path.

Check at the destination still verifies. The row carries an owner signature or a commitment over the grant fields (`GrantCommitment`). Both the holder and the destination can check it, under whichever verifier the row names. A row that fails that check is not a grant. Blinded storage does not skip Check. Fail closed.

### What still leaks

This is not private information retrieval and not a zero-knowledge proof. Both are future work. This spec claims neither.

A replicating peer or relay can still observe:

| Leak | What an observer sees |
| --- | --- |
| Row counts | How many rows sit under a tag or inbox soul, including a burst of writes that tracks audience size |
| Timing | When a row is created or updated, and which tags a given peer fetches |
| Sizes | Ciphertext length, and length changes when a row is replaced on revoke |

Padding, batching, and dummy rows can reduce some of that. They are not promised here. An observer who already stored a plaintext `MeshSeeGrant` keeps that copy. New private rows do not hide history that already replicated in the clear.

## Rotation on revoke

Revoke of an encrypted object is two steps, in this order:

1. **Privilege-down, immediate.** `stated: 0` on the grant (or on the direct membership) and a `hamState` bump, same as `cancelSee`. The next Check after HAM merge denies. Do not cache an allow across that merge.
2. **New epoch.** A new DEK, or a new group epoch key, wrapped only to the remaining readers. New ciphertext uses the new key. `EpochRotation` is that record. `rotateOnRevoke` names the operation. The reference crate does not run it.

A wrap for an older epoch does not mint a grant. Check denies the revoked accessor after step 1 even when they still hold the old DEK.

**Honest limit.** Content the revoked party already unwrapped stays readable to them. Rotation stops new epochs. It does not claw back plaintext or keys they already hold. Re-encrypting old ciphertext and dropping the old DEK is optional owner work. It does not erase a local copy.

Removing a reader is this revoke. Whether adding a member, or a quiet boundary with no removal, also starts a new group epoch is open. See [Open choices](#open-choices).

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

## Contract types

Copy or re-type [s3rch-check.d.ts](s3rch-check.d.ts). Do not `npm install sociacl`. Do not import `crates/sociacl-gun`.

| Type or function | Role |
| --- | --- |
| `WrappedKey` | DEK wrapped to a reader SEA `epub`, group key wrapped to a member, or item DEK wrapped to a group epoch key |
| `GrantCommitment` | Owner signature or commitment. Holder and destination both check it |
| `GrantRowBlinding` | `static-tag`, `epoch-tag`, or `inbox-soul` (open) |
| `GrantVerifier` | `sea-pub` or `principal-key` (open) |
| `GrantStorage` | `public-plain` or `private-row` (whether public-plain stays is open) |
| `BlindedGrantRow` | Private grant row. Not a plaintext `grantSoul` path |
| `RecipientInbox` | Accessor scan target. Not a Check object |
| `MeshMembership` | Direct `same-group` or `named-circle` edge. Hopcap 1 |
| `ObjectSetName` | The group or circle an object names |
| `GroupSeeGraph` / `checkGroupSee` | Check for those two predicates |
| `CancelledGrant` | `stated: 0` and the bumped `hamState` on a see grant or a membership |
| `EpochRotation` / `rotateOnRevoke` | Privilege-down first, then re-wrap the next epoch to remaining readers |
| `ContentIndexTier` | `public`, `private-group`, or `local`. SociACL does not store it |

`GunFeedNode` and `GunUserNode` are unchanged. Predicate and membership are ACL rows, not feed fields.

## Open choices

Not decided:

1. **Blinding scheme.** An ECDH-derived row tag that stays static for the owner/accessor pair, the same tag rotated per epoch, or encrypted rows under a recipient inbox soul.
2. **Group epoch length.** How long an epoch lasts, and whether every membership change forces a new epoch. Removal of a reader still follows [Rotation on revoke](#rotation-on-revoke): privilege-down, then a new DEK or epoch key for the remaining readers.
3. **Grant verifier.** Whether destinations check the owner signature or commitment with the owner's SEA pub or with a SociACL principal key. Whichever the row names, both the holder and the destination must be able to check it.
4. **Public-content mode.** Whether plaintext `MeshSeeGrant` stays for public content, with private rows only when the item is encrypted.

## What this does not do

- Change Check's allow rules for a hop or a hint
- Put SEA `priv` or `epriv` on Gun
- Treat a wrap as a grant
- Claim private information retrieval or a zero-knowledge proof (future work only)
- Lock a new Gun root before the blinding choice closes
- Add an index to SociACL
- Fork `items`, `users`, or the five-segment `grantSoul` path
- Edit FyberLabs/s3r.ch
