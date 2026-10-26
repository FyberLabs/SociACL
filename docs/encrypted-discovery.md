# Encrypted discovery (spec)

Status: spec. `crates/sociacl-encdisc` implements the account SEA key, device enrollment, the wrapped-key edge, the length-prefixed SHA-256 ids, blinded grant rows, commitment opening, author fast unwrap, `checkPresentedGrant` (verifier nonce, audience, and the branded presenter channel), inbox admission (one `RecipientInbox` per reader, `filterInboxAppend`, and the daily-shard rescan), and per-contact inbox lanes (HKDF-SHA256 of a contact-lane secret that is not the disclosed lane id, sealed to the sender). `epochStepCurrent`, `settledKeyOpen`, epoch admission, `rotateOnRevoke`, and in-place migration run in that crate. A shard-close watermark is not implemented. `crates/sociacl-gun` evaluates plaintext `MeshSeeGrant` rows, plaintext `MeshPostGrant` rows (`checkPost`), and direct `same-group` / `named-circle` edges (`checkGroupSee`). It does not evaluate a wrap. An inbox delivery is not a grant. Nothing on this page changes that Check or the plaintext dest-ACL path. This page adds no verb.

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
- This page adds no verb. `crates/sociacl-gun` evaluates plaintext `MeshSeeGrant` rows, plaintext `MeshPostGrant` rows (`checkPost`), and direct group and circle membership. A wrap is not an input to that check. An inbox delivery is not a grant.

Plaintext dest ACL today is a `MeshSeeGrant` on a `GunAclEdge` (`hamState`) at `grantSoul(owner, object, accessor)`, under `aclSoul(owner)`:

```
s3rch/acl/<owner key>/<object>/<accessor key>
```

The owner and accessor keys are `p_` plus 128 lowercase hex. `aclKey` and `aclPrincipalKey` are deleted. Private rows replace **enumeration** of that path. They do not fork `items` or `users`. Each reader has exactly one inbox lane. That lane is not a new locked collection name in this spec, and it is not a bucket shared with other readers.

## Wrapped-key grant edge

A private item has a data encryption key (DEK) for the current epoch. Ciphertext may sit on the shared graph. The DEK does not.

**Per reader.** The owner wraps that DEK to each reader's SEA `epub`. The wrap is ECDH-derived: an ephemeral pair and `SEA.secret` against the reader's `epub`, then authenticated encryption of the DEK. SEA `priv` and `epriv` never go on Gun.

**Per group, per epoch.** A group or named circle has one group key for an epoch. The owner wraps that group key to each member's SEA `epub`. The item DEK is wrapped once to the group's epoch key, not once per member. Membership is still a direct edge. A wrap to the group key does not add a member.

SociACL decides who receives a wrap. A wrap is written only for a principal the live grant or direct membership already names. The wrap bytes do not decide the set.

A wrap is not a grant. `checkSee` and `checkSeeGrant` do not take wrap bytes and do not read them when setting `allowed`. Check must still pass before a destination treats the item as granted (show it, reply, re-share, or write). Holding a DEK decrypts bytes the holder already fetched. It does not make Check allow. A hop, a hint, or a wrap never mints.

`WrappedKey` is the key material. A visible `BlindedGrantRow` may carry one beside ciphertext of the grant. The row stores a `GrantCommitment` (a blinded hash). The blinding is not on the row. It does not store the owner's SEA pub. The holder opens that commitment in a `GrantPresentation` at the destination. See [Hidden authorship](#hidden-authorship).

## One inbox lane

Each reader account has **exactly one** disclosed base inbox lane (`RecipientInbox`). Every private grant row for that account is appended to that lane. The reader scans that lane and no other. A per-contact lane is not a second `RecipientInbox`.

Scanning a shared bucket is not allowed. A lane is not a bucket many readers trial-decrypt. There is no second `RecipientInbox` per device, per epoch, or per contact. Devices of one account share one SEA keypair and one disclosed base lane. A per-contact inbox lane is HKDF of a separate contact-lane secret, not of that disclosed lane. See [Per-contact inbox lanes](#per-contact-inbox-lanes). A keyring rotation replaces the disclosed base lane. It does not add a device lane.

`laneId` is 32 bytes of lowercase hex. It is the disclosed base lane. It is not the contact-lane secret, not the plaintext accessor id, and not `grantSoul`. Registration rejects any other shape. This spec does not lock a new Gun collection name. The lane is one opaque soul. The reader discloses `laneId` to principals the [write policy](#inbox-write-policy) allows. That disclosure is the base lane only. It does not disclose the contact-lane secret, and a writer who holds the base lane cannot compute another contact's lane. Writers address that soul. They do not learn a shared bucket to scan.

## Append-only inbox entries

An inbox entry is append-only and content-addressed. `entryId` is the hash of the canonical entry: `laneId`, the ciphertext, the commitment, and the wrap. A change to any of those is a different key. A body that does not hash to the key is rejected by the reader and by any relay that stores the lane. Replacing the wrap or the commitment under the same ciphertext does not keep the old key. The entry has no `hamState` contest.

A cancel or a newer grant is a new entry. The visible entry still has no `hamState`. Order is `grantRevision` inside the signed grant payload (`SignedGrantPayload`). The owner signature covers that number. For one object and accessor, the greatest `grantRevision` wins. A `stated: 1` payload does not undo a `stated: 0` payload at a lower or equal `grantRevision`. Check on the winning opened grant still decides `stated`. The entry rule does not mint.

Where the writer is already known to the relay (`named-writers`), the entry may be a writer-signed outer envelope over that same hash. The relay verifies the signature without opening the grant. The default public lane does not use that envelope. A writer pub on every public row would name the writer. Content-addressing stops replacement, and the visible grant row still has no owner pub.

A hop, a hint, a wrap, or an envelope is not a grant.

## Lane scan

The account still has one lane. A daily shard is a layout of that same lane, not a bucket and not a lane per device.

The scan is a rescan of each whole daily shard, then dedup by `entryId`. Clock skew between a sender's devices, or a restored clock, can place a new entry at or below a saved high-water mark. Reading the whole shard still finds that entry.

A cursor per sender device is not part of this contract. The visible row has no device id and no per-device sequence, because those fields would name the writer. Putting the same fields inside the ciphertext does not fix the cursor: the reader would have to open every entry to learn which cursor it belongs to, which is already a full read of the shard, and an entry opened under the wrong cursor would still be skipped. The shard rescan needs neither field. Authorship stays hidden. Dedup is the content-addressed `entryId`.

The reference crate implements that rescan. A trusted shard-close watermark is not part of this spec and is not implemented.

## Hidden authorship

Authorship is hidden by default. A visible grant row does not carry the owner id or the owner's SEA pub. Peers that replicate the lane cannot read the owner off the row. Check at the destination still verifies.

The owner's SEA pub is not a field on that row. A signature over the grant, made with the account SEA key, sits **inside** the ciphertext.

The visible row holds:

- ciphertext of the canonical grant (object, accessor, `from`, `until`, `stated`, epoch, the owner's id, monotonic `grantRevision`, and `itemCiphertextDigest`). When the grant names an encrypted item, `itemCiphertextDigest` is the SHA-256 of that item ciphertext, so the commitment and the owner signature cover it. The destination compares it to the fetched item. When the grant names no encrypted item, the field is empty
- a `GrantCommitment`: SHA-256 of a fresh 32-byte blinding plus those canonical fields, including the item ciphertext digest. The blinding is inside the ciphertext. The visible row stores the hash only
- the wrapped DEK, when this row carries a key
- `entryId`: the hash of the canonical entry (`laneId`, ciphertext, commitment, wrap)

There is no `hamState` on the entry. A later grant is a new entry. See [Append-only inbox entries](#append-only-inbox-entries).

The holder presents a `GrantPresentation` to the destination. The presentation is not written back to Gun. It contains the opened grant, the commitment blinding, the owner id, the signature, and the owner's SEA pub. The blinding is not a field of the visible row. An unsalted hash of the grant bytes is not the commitment. Guessing the owner, the window, the epoch, or the revision does not open the row. The destination:

1. Recomputes the commitment from the blinding and the opened grant and checks it against the row. A mismatch fails closed. The presented grant is then the grant that was committed, not a substitute. When the grant names an encrypted item, the destination also passes the SHA-256 of the fetched ciphertext into `checkPresentedGrant`. A mismatch with `itemCiphertextDigest` fails closed. `SeeGraph.snapshotHash` is not that digest.
2. Checks that the owner named in the opened grant equals `graph.ownerOf(object)`. A missing owner or a different account fails closed before the signature is accepted and before verifier state changes. Then verifies the signature with the SEA pub in the presentation, and checks that pub against `VerifierEnrollmentState` for that graph owner. The status proof uses the same pub. The same map checks the presenter-binding pub and the channel pub for the accessor. A missing account or a different pub fails closed. The presenter does not supply the map. The pub is not a copy on the row.
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
| Relay that accepts an append | The authenticated writer id for that `entryId`, plus hashes, sizes, timing, and a first-contact stamp | The grant owner from the stored public row. The stored row still has no writer pub. This spec does not define an unlinkable admission credential |
| Relay that only replicates the lane | Entry hashes, sizes, timing | The writer and the grant owner. The stored public row has neither pub |

The destination must learn the owner. Check cannot name an owner it has not been shown. Caching the enrolled pub avoids a fresh lookup. A lookup that hits a relay leaks the account id to that relay. The presentation itself is the holder's disclosure to that destination.

Padding and batching can reduce size and timing leaks. They are not promised here. An observer who already stored a plaintext `MeshSeeGrant` keeps that copy. New private rows do not hide history that already replicated in the clear.

Lane disclosure has its own leak. A principal who knows the base `laneId`, and any peer who replicates that soul, sees that lane's row counts, timing, and sizes. They do not see contact lanes, and they do not get other readers' rows from it, because there is no shared bucket.

## Presenter binding

A `GrantPresentation` shows what was committed and which owner signed the grant. It does not show that the presenter holds the reader's SEA key. Anyone who only carries the opened proof can replay it on another channel. A proof alone grants nothing.

The destination issues a nonce and keeps it in `VerifierChallengeState`. That state is the verifier's, not a field the presenter supplies. The presenter signs the outstanding nonce with the reader's SEA key. The signed bytes are the length-prefixed fields `s3rch-presenter-binding-v1`, the nonce, the grant commitment hash, and `audience`. `audience` is a string the verifier chooses and stores on that challenge. It names that verifier. A concatenated string with no lengths does not verify. A signature that omits `audience`, or names a different one, does not verify, and the nonce stays outstanding. `checkPresentedGrant` accepts the signature only when the nonce is still outstanding, `now` is before `expiresAt`, the signed `audience` equals the audience on that challenge, and the signature matches the enrolled SEA `pub` for the accessor named in the opened grant. The call then marks that nonce spent. A second presentation of the same nonce fails closed. A bad signature, a different pub, an unknown nonce, a different audience, or an expired challenge fails closed.

`AuthenticatedPresenterChannel` is the other check. Its brand is an ECMAScript private field `#channelBrand` and a module-private `WeakSet` filled by the constructor. The constructor freezes `accessor` and `readerPub`. `checkPresentedGrant` accepts a channel only when `channel instanceof AuthenticatedPresenterChannel`, `hasTransportBrand()` is true, the instance is in that set, `channel.accessor` is the accessor named by the grant, and `channel.readerPub` is the enrolled SEA pub for that accessor. An object literal fails the type checker and the runtime check. Copying the brand onto another object fails, because the private field is not a reflectable property and the copy is not in the set. A transport-minted channel for a different principal fails closed. No nonce signature and no transport-minted channel fails closed.

`checkPresentedGrant` decodes one `SignedGrantPayload` from `grantBytes`. `grant`, `owner`, and `grantRevision` must match that payload. A mismatch fails closed before verifier state changes. Check uses the decoded payload.

It also takes `VerifierGrantRevisionState`, the highest signed `grantRevision` this verifier has accepted for that object and accessor, and the payload digest of that record. The presenter does not supply it. A presented revision lower than that record fails closed. At the same revision, `stated: 0` wins before any digest comparison. A live payload does not replace a cancellation. When `stated` matches and the stored digest is already a digest, the smaller payload digest wins. An empty digest raised from a status proof is unknown. It is not the smallest digest. The first payload with the same `grantRevision` and the same `stated` is accepted, and its digest is stored. A cancel at that revision still beats a live payload. A higher signed revision replaces the record.

The status proof names this accessor and this `grantRevision`, and the signature covers those fields plus `stated`, the epoch, the revision, the times, and the zookie. The decoded grant, the proof, the zookie, and `EpochReplicaView` name the same object. The proof's accessor is the grant's accessor. While the settle window is open and a settled revision exists, the grant epoch and the proof epoch are `settledEpoch`, the epoch of that settled key, not the pending candidate epoch. After the window elapses they match the candidate epoch. A mismatch fails closed before the verifier spends a nonce or changes its record. A verified proof that carries a higher `grantRevision`, or `stated: 0` at the same revision as a stored live row, updates the record from the proof. The holder cannot keep that record on an older live row by withholding the cancel.

`status.revisionId` must be the read key from `epochStepCurrent`, which takes the winning snapshot and the replica's ACL. While that function is false, including when the timer has elapsed and the snapshot still names an expired or cancelled recipient, the read key is `settledRevisionId`. A proof for the pending candidate fails closed. After the function is true, the read key is the recomputed winner. A proof for any other revision fails closed. When the grant is `same-group` or `named-circle`, the same call takes `PresentedGroup` and runs `checkGroupSee` on a `GroupSeeGraph` after those checks. `checkGroupSee` does not see `stated`, `from`, or `until`. The decision is that call together with the decoded payload. `stated` must be 1 and `now` must sit in `[from, until)`, `from` inclusive and `until` exclusive. A cancel or a payload outside that window stays a deny while a stale membership edge is still live. The revision record may store the cancel. A group object with no `PresentedGroup` fails closed. An ordinary see grant omits `PresentedGroup` and runs `checkSee`.

The binding is not a grant. Check still runs after it. A hop, a hint, or a wrap never mints. A valid binding does not set `allowed`.

## Item content authenticity

Every reader of an item holds that item's DEK, so authenticated encryption shows that the writer had the DEK. It does not show that the owner wrote the body. A reader can encrypt a replacement and put it at the same item soul.

The owner signs a length-prefixed encoding: domain `s3rch-item-auth-v1`, item id, epoch, version, SHA-256 of the raw plaintext, and `revisionId`. `ItemContentAuth` is that signature. The owner produces the signature first, then encrypts the plaintext and the signature together. The ciphertext digest is not an input to the signature, so constructing the item does not need a fixed point. The signature lives **inside** the encrypted item. The visible grant row does not carry it and does not carry the owner's SEA pub. When the grant names the item, the canonical grant bytes include the ciphertext digest, computed after encryption, so `GrantCommitment` covers those bytes. The signature covers the plaintext digest.

A reader decrypts, recomputes the plaintext digest, and checks the signature with the enrolled pub of `graph.ownerOf(object)`, the same pub used to open the grant. A pub the presenter names in place of that graph owner does not verify. A mismatch fails closed, including when only `revisionId` changed. Other readers reject the replacement. The signature is not a grant. Holding the DEK does not mint one. Check still runs.

`revisionId` is the winning revision from [Epoch manifest](#epoch-manifest). A body bound to a superseded revision fails this check.

## Author fast unwrap

The author has a local path that does not scan a lane and does not present a commitment.

The author keeps the item DEK on the device that encrypted it, together with the `revisionId` of the manifest that DEK belongs to. Unwrap uses that local DEK only for that revision. The epoch number is not enough: a DEK cached for a displaced manifest of the same epoch does not open the winning body. The fast path is not a Gun row and not a grant. Check for the author remains the owner path. The visible row still does not name the owner.

A device enrolled to the same account holds the same SEA keypair, so it can unwrap a self-wrap addressed to that `epub`. The self-wrap, if the author writes one, goes in the author's single lane like any other wrap and still omits the owner pub. Other readers do not use this path. Holding the author's DEK is not a way for them to skip Check, and it is not a way to forge a body that passes [item content authenticity](#item-content-authenticity).

## Account key

Each account has one SEA keypair. The account **is** its genesis signing `pub`: the `sociacl-ids` `PrincipalId` (SEA `base64url(x).base64url(y)`). `principalFromSec1` / `principal_from_sec1` takes a 65-byte uncompressed SEC1 point (`0x04 || x || y`). The path key is `formatPrincipalKey` (`p_` plus the lowercase hex of the 64 coordinate bytes), not an escaped copy of the pub. `pub` and `epub` may sit on the user node (`userSoul(principal)`). `priv` and `epriv` never go on Gun, in any encoding.

Rust account creation and restoration use `GenesisAccount::generate()` and
`GenesisAccount::import(lane_id, pub, priv, epub, epriv)`. There is no separate
account label: import derives and checks the `PrincipalId` against the signing
key and verifies the encryption key pair. The former public
`AccountSeaSecret::generate(label)` and `import_local` constructors are removed
([SociACL#65](https://github.com/FyberLabs/SociACL/issues/65)). Existing content,
epoch, introduction, and inbox operations take the validated device-local
secret returned by `GenesisAccount::into_secret()`. Conversion moves the same
keypair and lane; it does not mint another identity. To retain the genesis
handle as well, clone it before conversion. These operations are for the
genesis key; a rotated account uses `AccountKeyring` with authenticated history.
TypeScript already uses `importGenesis` without a separate account label.
Both languages reject the shared wallet, handle, OIDC-subject, and label inputs
at that constructor boundary. Existing reader-wrap bytes remain unchanged:
they bind the encryption key and content labels, not a free account label.

Devices do not mint a second SEA keypair and do not mint an identity. A device inherits that one keypair through enrollment. The sealing device encrypts to the new device's transport public key. That public key arrives out of band: the existing device scans a QR code, or the two devices compare a short code. Panopticon stores the ciphertext and the index. It must not be the only channel that delivers the transport public key. The transport key is not a `PrincipalId` and it is not stored as an account. The opener keeps the transport scalar and passes the expected account `PrincipalId`. The wrap's KDF info and AES-GCM associated data bind that principal, the wrap id, the transport public key, and the ephemeral public key under `sociacl-account-key-bind-v1` (not the content-wrap domain). The account's current signing key, from `resolveCurrentKey`, signs the wrap. Open verifies that signature before import. Enrollment does not write `priv` or `epriv` to Gun, and it does not mint a grant. The encrypted backup of the keypair lives in a Panopticon index and wrap store. That store is an adapter. It is not the authority and it does not choose the current key. The inbox lane stays one per account, not one per device. Wraps for that account use the account `epub`.

Wallets and OIDC subjects are linked credentials (`WalletLink`, `OidcLink`) only after `verifyWalletLink` / `verifyOidcLink`. They are not principals. The current signing key, when it differs from genesis, is whatever `resolveCurrentKey` returns under the package's witnessed rotation rules. This page does not define a second rotation scheme.

The `rotations` passed to seal and to open, and the resolution context those calls use, must be the trusted latest-state checkpoint from sociacl-ids §4.6. Panopticon alone does not supply that checkpoint. Passing no rotations leaves the current key equal to genesis, so a genesis-signed wrap opens.

The account keyring holds the current signing scalar, the current encryption scalar, the retired encryption scalars, the current `laneId`, every lane id already issued, a 32-byte contact-lane secret, and every contact-lane secret already issued. Import checks that pair against `resolveCurrentKey`'s `(currentKey, currentEpub)` and rejects a mismatch. A null `currentEpub` refuses a new seal and never falls back to Gun `user.epub`. A genesis-only keyring is accepted when its `epriv` matches the witnessed `genesis-epub` binding. That binding, not an unwitnessed Gun field, is what `resolveCurrentKey` uses before the first rotation. Rotation mints a new signing pair, a fresh epub, and a new lane id. A mint of the current lane or any prior lane, or of the current contact-lane secret or any prior contact-lane secret, is `bad-lane`. A new lane id that equals a contact-lane secret, or a new contact-lane secret that equals a disclosed lane id, is `bad-lane`. Creating a brand-new account (`createAccount` / `create_account`) is the only path that mints a contact-lane secret. It does that once, at sequence 0. `fromGenesis` / `from_genesis` does not mint. Restoring a sequence-0 keyring requires the contact-lane secret the creator already holds. Import requires the current contact-lane secret and the full prior contact-lane history. `priorContactSecrets.length` must equal `rotationSeq`. A missing secret or a history of the wrong length is `keyring-rejected`. `import` and `import_with_prior_lanes` do not mint a history. Recovery and device delivery restore the secret through the keyring codec (`import_with_contact_secrets` in Rust; the TypeScript `import` arguments after `priorLanes`). The genesis backup does not carry the contact-lane secret. A second device, including one at sequence 0, receives the keyring only through keyring delivery. `rotationSeq` must be a safe non-negative integer before any import allocates or loops. `Infinity` and a value above `2^53-1` are `keyring-rejected`. When a rotation mint omits `contactLaneSecret`, rotation draws a fresh one that is disjoint from the disclosed lanes and from the contact-lane secrets already held. Import, seal, and rotation refuse a keyring unless `priorLanes.length` equals `rotationSeq` (`bad-lane`). A contact-lane secret that collides with a disclosed lane is `bad-lane`. The keyring plaintext domain is `sociacl-keyring-plain-v2`. A plaintext whose domain is `sociacl-keyring-plain-v1` is `recovery-rejected`. That length check is [SociACL#68](https://github.com/FyberLabs/SociACL/issues/68) F1 for this path. Rotation names every trusted device except the lost one. `rotateAndReseal` / `rotate_and_reseal` seals a recovery copy of the new version. Delivery of that keyring to a device uses the keyring delivery wrap. It advances the content epoch. Incrementing `contentEpoch` past `2^53-1` is `content-epoch`. The draft is always Rotate v3. The builder runs `confirm` before it retires the current epub, then `checkRotationDraft` on that draft before returning it. `checkRotationPublish` rejects the same unsigned draft with `bad-record`. The builder refuses an epub or signing pub it already holds, including any older signing pub in the accepted chain and the witnessed genesis epub. It refuses the rotation when the retired set already holds 1024 keys, before it appends the current epub. `contentEpoch` must be a safe integer (`<= 2^53-1`) on import in both languages. The `AccountKeyring` constructor is sealed to this module; a caller without the seal gets `bad-construction`. `createAccount`, `fromGenesis`, `import`, and `rotateKeyring` are the entry points. `create_account` is the Rust creation path. The account id stays the genesis signing pub. `priv`, `epriv`, retired `epriv` values, and lane ids never go on Gun. Content wraps stay on `s3rch-wrapped-key-v1` with KDF `s3rch-sea-secret-v1`. A tampered wrap, or authenticated plaintext that is not the length-prefixed reader wrap, is `wrap-rejected`. The reader scalar and the opened plaintext are zeroed. Epoch, reader epub, object, and revision are inside the authenticated plaintext.

Per-contact inbox lanes are derived from a separate contact-lane secret. See [Per-contact inbox lanes](#per-contact-inbox-lanes). The account still has one current base lane. Rotation replaces that lane id and keeps the old one so it cannot be minted again. Seal and open refuse an empty passphrase and a whitespace-only passphrase. Seal also refuses a weak passphrase. Open does not.

## Per-contact inbox lanes

The account keeps exactly one disclosed base lane: the keyring `laneId`, 32 random bytes stored as 64 lowercase hex characters. Writers and replicating peers see that value. It is not the HKDF input. The HKDF input is a separate contact-lane secret, another 32 random bytes. That secret rotates with the keyring. `priorContactSecrets` keeps the secrets already issued, and its length equals `rotationSeq`, the same length rule as `priorLanes`. The contact-lane secret is not a Gun field, and it is not an index key. `priv`, `epriv`, and this secret never go on Gun. A per-contact inbox lane is HKDF-SHA256 (RFC 5869) of that secret and the sender's canonical `PrincipalId`. There is no second keypair and no `inboxPub`. The disclosed base lane stays one per account. Contact lanes are not a second `RecipientInbox`.

The hash is SHA-256. The salt is 32 zero bytes, the RFC 5869 default of HashLen zeros. The input keying material is the 32 raw bytes of the contact-lane secret, decoded from lowercase hex. The hex text is not the input. The disclosed base lane id is not the input. Info is length-prefixed UTF-8 with little-endian uint32 lengths, in this fixed order. The ids are not sorted. Direction is the order:

1. Domain `sociacl-contact-lane-v1` (23 bytes).
2. Version `1` (1 byte). The version is its own field. The `-v1` suffix does not replace it.
3. Recipient `PrincipalId`, the lane owner, in canonical sociacl-ids form (87 characters).
4. Sender `PrincipalId`, in that same form (87 characters).

The byte layout is `u32le(23) || "sociacl-contact-lane-v1" || u32le(1) || "1" || u32le(87) || recipient || u32le(87) || sender`. The info length is 214 bytes. Extract is `HMAC-SHA256(salt, IKM) = PRK`. Expand is one block, `HMAC-SHA256(PRK, info || 0x01)`. Output length is 32 bytes. The lane id is those bytes as 64 lowercase hex characters. Both languages implement HKDF with HMAC so the input keying material, the PRK, and the output can be wiped. The info bytes are public and are not wiped. Node `hkdfSync` is the TypeScript test oracle. It is not the implementation. Rust wipes with `zeroize`. TypeScript fills the secret `Uint8Array` copies with zero.

`parsePrincipalId` / `parse_principal_id` is the only parser. The field is the parsed canonical value. A non-canonical id fails closed with the sociacl-ids reason.

Swapping recipient and sender yields a different lane. A second sender yields a different lane. A different contact-lane secret yields a different lane. The output is not the contact-lane secret and not the disclosed base lane. HKDF-SHA256 of the disclosed base lane id is a different value, so a writer who holds that lane cannot compute a contact lane. An outsider who does not hold the contact-lane secret cannot link lanes across contacts and cannot tell who the contact is. The lane id is 64 lowercase hex characters, so it cannot contain an 87-character `PrincipalId`, a `.`, or a base64url character outside the hex alphabet.

`resolveContactLane` / `resolve_contact_lane` takes a sequence `S`. `priorContactSecrets.length` must equal `rotationSeq`. That is the same length rule as `priorLanes`, which is [SociACL#68](https://github.com/FyberLabs/SociACL/issues/68) F1, relied on here and not changed. The secret at `S` is `priorContactSecrets[S]` when `S` is below `rotationSeq`, and the current contact-lane secret when `S` equals `rotationSeq`. A sequence above `rotationSeq` is `bad-lane`. A derived id that equals a disclosed base lane, current or prior, or that equals a contact-lane secret, current or prior, is `bad-lane`. Rotation still rejects minting the current or a prior base lane, and the current or a prior contact-lane secret, with `bad-lane` before confirm. It also rejects a contact-lane secret that equals a disclosed lane, and a lane id that equals a contact-lane secret. Lane ids change when the contact-lane secret rotates. A prior per-contact lane stays resolvable exactly as far as that `priorContactSecrets` rule allows.

The sender cannot derive its lane. The recipient delivers it. On accept, the recipient signs the derived lane id and then encrypts that signature to the sender's resolved `currentEpub`. The wrap is the account-key construction: ECDH P-256, the 32-byte shared x coordinate, AES-256-GCM. The blob is version byte `0x01`, the 65-byte uncompressed ephemeral point, a 12-byte nonce, and the ciphertext with its tag. The domain is `sociacl-contact-lane-grant-v1`. The signature domain is `sociacl-contact-lane-grant-sig-v1`. Those domains are separate, in the style of keyring delivery. A null `currentEpub` is `epub-unknown`. Seal does not take a Gun user-encryption public key and does not fall back to one. The public seal resolves the sender, then calls `epubForNewSeal` / `epub_for_new_seal` with that `currentEpub` and no fallback. The blob is at most 4096 bytes.

The grant KDF is SHA-256, not HKDF. The input is length-prefixed: `sociacl-contact-lane-grant-v1`, the lowercase hex of the shared x, the recipient, the sender, the sender's encryption public key, the ephemeral SEA public key, and the canonical decimal `rotationSeq`. Associated data is length-prefixed and holds no shared secret: the domain, recipient, sender, sender encryption public key, ephemeral public key, and the decimal sequence. Those party ids stay outside the ciphertext only as associated data. They are not a signature a carrier can verify. The signature is made before encryption. Its message is length-prefixed: `sociacl-contact-lane-grant-sig-v1`, the derived lane id, the recipient, the sender, the sender's encryption public key, and the decimal sequence. It does not cover the blob. The signature is P-256 ECDSA-SHA256, low-s, hex `r || s`. The plaintext is length-prefixed: the domain, the derived lane id (64 hex characters, not the secret), the recipient `PrincipalId`, the decimal sequence, and that signature.

The outer grant is `ciphertextHex` alone. The lane id and the signature sit only inside the ciphertext. `priv`, `epriv`, the contact-lane secret, the recipient, and the sender are not fields. Shared x, the AES key, the plaintext, the signing scalar, and `epriv` are wiped after use. [SociACL#70](https://github.com/FyberLabs/SociACL/issues/70) inherits this confidential channel. A first-contact request carries the grant blob. It does not attach a publicly verifiable signature, and it does not put the recipient or the sender in the clear beside the blob.

Open derives the sender's encryption public key from `epriv`. The sequence is the length of the recipient chain the caller supplies, so a stale grant fails authenticated decryption. The plaintext recipient and sequence must match that caller. The signature verifies under the chain's current key. Open already requires the chain length to be the sequence the grant was sealed at, so that current key is the key at the sequence. A stale grant, a forged grant, a tampered blob, the wrong sender, and the wrong recipient are one error, `lane-grant-rejected`. Open has no error-code argument and maps every inner failure to that code. Seal keeps its own errors (`epub-unknown`, `bad-lane`, `bad-key`).

`regrantContactLanes` / `regrant_contact_lanes` seals a fresh grant for each contact after the contact-lane secret rotates. It resolves every contact's `currentEpub` first. One null epub fails the whole call with `epub-unknown` before any grant is returned.

`laneLookupKey` / `lane_lookup_key` returns the lane id hex. Storage indexes a contact lane by that string alone. The index key is not either `PrincipalId` and not a `~pub` path. Message authenticity is the recipient signature inside the sealed envelope. It is not the path the bytes were stored under. A lane is delivery only. It does not grant. Hopcap stays 1.

This crate does not wire Panopticon or Gun, and it does not open a first-contact public request channel. The request channel is [SociACL#70](https://github.com/FyberLabs/SociACL/issues/70). The lane-id index and its write-spam limits are [SociACL#71](https://github.com/FyberLabs/SociACL/issues/71). The shared vector is `vectors/encrypted-discovery/contact-lane.json`. `typescript/tests/support/generate-contact-lane.ts` rebuilds it. The deterministic seal that pins the ephemeral and the nonce is test-only. It is not a public export. It still confirms the recipient keyring and does not read Gun.

## Passphrase recovery copy

The account keyring can be sealed under a passphrase the user keeps. The passphrase is an argument to seal and open. It is not stored, not sent, and not written to Gun. The ciphertext goes to a `RecoveryCopyStore`. That store is an adapter of the same kind as `KeyWrapStore`. Panopticon may be that adapter. It stores the envelope and the index. It is not the authority, it does not see the passphrase, and it does not see the plaintext. `priv`, `epriv`, retired `epriv` values, and lane ids stay out of the envelope's cleartext and out of `gunDocument`.

The domain is `sociacl-recovery-copy-v1`. The envelope version byte is 1. The header is little-endian: Argon2 version, memory in KiB, iterations, parallelism, hash length, salt length, then the keyring version as a u64. The keyring version is `rotationSeq`. Salt follows the header, then a 12-byte AES-GCM nonce, then the ciphertext and tag. Seal draws the salt and the nonce internally. A caller does not pass them.

Argon2id is version `0x13`. The floor is RFC 9106's second recommended option: memory `m=65536` KiB (64 MiB), `t=3`, `p=4`, hash length 32. Those cost parameters are also the ceiling, held in one constant in each language. A sealed copy cannot ask for less memory, and a hostile copy cannot ask for more. Mobile uses this same 64 MiB profile. Salt length is the only range: 16 through 64 bytes. Production seal uses 16. Open checks the header numbers, including the declared salt length, before it slices the salt and before it runs the KDF. A value just below the floor or just above the ceiling is `recovery-params`. An empty passphrase, and a whitespace-only passphrase, are `recovery-params`. The shared vectors pin the floor, the ceiling, and a reject row on each side of each bound.

A passphrase string is normalized to Unicode NFC, in the style of an RFC 8265 OpaqueString, and then encoded as UTF-8. The assigned set is Unicode 16.0.0. A code point unassigned in that version is `recovery-params` before NFC, so a Unicode 17 mark such as U+1ACF cannot reorder. The TypeScript string API checks the runtime before it normalizes. The probe is U+11382 followed by U+113C9, which Unicode 16 NFC composes to U+11383. A runtime whose normalization data is older than Unicode 16 fails that probe, and `encodePassphrase` throws `unicode-version` without deriving a key. The byte API does not run that probe. `encode_passphrase` / `encodePassphrase` do that, and the string seal and open APIs call them. The byte API does not normalize again. It applies the same Unicode 16 assignment check and the same whitespace check, so a string sealed in one language opens in the other. Whitespace is one explicit set in both languages, the Unicode 16 `White_Space` property, including U+0085 NEXT LINE. U+FEFF is not in that set. Leading and trailing whitespace on a passphrase that also contains a non-whitespace character is preserved. Composed and decomposed `é` derive the same key. Empty and whitespace-only passphrases, including a string of only U+0085, are `recovery-params`.

A passphrase is also checked for strength, and only at seal. Open does not run this gate, so a copy that already exists still opens. After NFC, a passphrase that contains a Unicode 16 default-ignorable or format character (U+200B, U+FEFF, U+00AD, and the rest of that set) is `recovery-weak-passphrase`. Those characters are not counted. The visible length is the number of remaining code points, and it must be at least 12. The passphrase must also score at least 3 under zxcvbn. TypeScript uses `@zxcvbn-ts/core` 4.2.0 with `@zxcvbn-ts/language-common` 4.1.3 and `@zxcvbn-ts/language-en` 4.1.1. Rust uses the `zxcvbn` crate 3.1.1. Both receive the account's `PrincipalId` and, when the caller knows it, the account handle, as user inputs. The two estimators have advisory parity: they can disagree near the threshold. The shared vector pins clear pass and fail rows, not a byte-exact score. The error carries the score, the warning, and the suggestions so the UI can say why the passphrase was refused. The error does not contain the passphrase. Callers must not log the passphrase. Empty and whitespace-only passphrases stay `recovery-params`, and that check still runs on open.

The TypeScript KDF is hash-wasm 4.12.0. That build has no pthreads. Its Argon2 implementation walks lanes in a serial loop, in both the C source and the JavaScript that drives it, so `p=4` runs one lane after another. A browser loads that same module. The Rust crate is `argon2` 0.5.3 with the `alloc`, `std`, and `zeroize` features and without its defaults. The shared small vector (`password`, `somesalt`, `m=32` KiB, `t=3`, `p=4`, 32-byte output) matches across the two libraries. `m=32` is below the floor and is refused for a real envelope.

AES-256-GCM is the same construction as the account-key wrap. Associated data is length-prefixed: the domain, the canonical `PrincipalId`, the decimal keyring version from the header, the signing public key, the encryption public key, the decimals of memory, iterations, parallelism, and hash length, the decimal Argon2 version, and the lowercase hex salt. The envelope carries those two public keys in the clear, and open refuses a plaintext key that does not match them. A wrong passphrase and a tampered envelope both fail as `recovery-rejected`. The header version is in the clear. After a successful decrypt, a plaintext version that matches the header but not the expected version is `recovery-stale`. An attacker who does not have the passphrase does not learn that distinction.

Open then checks that the decrypted `PrincipalId` matches the associated data and the expected account, and runs the existing keyring import. `expectedRotationSeq` and `rotations` come from the trusted resolved chain, not from the store. A copy sealed immediately after rotation fails that import until the checkpoint includes the rotation. Once the checkpoint includes the rotation, open of that copy succeeds.

Every rotation reseals. `rotateAndReseal` / `rotate_and_reseal` writes the new version as a pending copy and leaves the current copy in place. Every `put`, `commit`, and `delete` is a signed compare-and-swap by the account's current chain-head key. The domain is `sociacl-store-write-v1`. The message is length-prefixed: that domain, the `PrincipalId`, the operation (`put`, `commit`, or `delete`), the decimal target sequence, the SHA-256 of the envelope (principal, decimal sequence, signing public key, encryption public key, and the lowercase hex of the envelope bytes), the decimal published head, the SHA-256 of the row this write replaces or the explicit token `none`, the class `none`, and the decimal per-principal write generation. The store reads the chain from a resolver the adapter injected when the store was built. Panopticon fills that resolver from the published Gun chain. The store verifies the signature against the head key that resolver reports, and it rejects the write when the predecessor hash is not the row it holds. A chain that does not resolve, or a signature that does not verify, is `store-rejected` and the store does not change. The store keeps a monotonic per-principal head floor: every head its resolver has reported, including a read or a rejected write, and every stored current sequence. A pending sequence is not part of the floor, so an abandoned rotation does not freeze a later write by the current key. The recovery store and the wrap store share one floor for that principal. A write whose resolved head is below that floor is `store-rejected` and changes nothing. The generation advances only on an accepted write. Emptying the slot leaves the generation and the floor in place, so a signature over an empty slot cannot be replayed after a delete. Session authentication is not this check. Adapters, Panopticon included, must verify before they write. Panopticon is a verifier and a witness. It is never the authority. `put` at the resolved head replaces the current copy and drops any pending copy. The envelope's signing public key must equal the resolved current key, and when the chain has a current epub the envelope's epub must equal it. A public-key mismatch is `store-rejected` and changes nothing. `put` at head + 1 is the only pending copy. Any other sequence is `store-rejected` and changes nothing. An equal-sequence put is a passphrase change at the current version, and it drops the pending copy so the previous passphrase cannot be committed back. That put is accepted at the resolved head. A pending copy does not raise the floor. `commitRecoveryCopy` / `commit_recovery_copy` is signed by the key the store's resolver reports as current. An unsigned draft does not resolve, so commit is `store-rejected` and both copies stay. A pending copy at head + 1 is a rotation that is not on that chain: commit is `store-rejected` and the pending copy stays. A pending copy at the head is promoted only when its signing public key and epub equal the resolved current key and current epub. A pending copy at the head whose keys differ is a fork: commit is `store-rejected` and both copies stay. A pending copy at neither head nor head + 1 is `store-rejected` and both copies stay. A rejected commit leaves the pending copy in place. `deleteRecoveryCopy` / `delete_recovery_copy` removes the current copy or the pending copy at one sequence. It does not promote the other. A missing target is `store-rejected`. Promotion assigns the pending row onto the current row in place. Adapters, Panopticon included, must replace atomically and only forward: write the new row, then drop the old one. Promotion never leaves a window with zero copies, and a stored copy never moves to an older `rotationSeq`. An older envelope opened against the new version is `recovery-stale`. Re-sealing under a new passphrase leaves any keyring an attacker already copied intact. Rotating the account key is the remedy after a passphrase leak.

The serialized keyring has a fixed cap, `KEYRING_SERIAL_MAX`, 262144 bytes (256 KiB). The constant is unchanged. Each retired pair encodes as 138 bytes. Each prior base lane and each prior contact-lane secret encodes as 68 bytes. 1024 retired keys, 1024 prior base lanes, and 1024 prior contact-lane secrets are about 281237 bytes and do not fit. The byte cap rejects that encoding. The count rules stay `priorLanes.length == rotationSeq` and `priorContactSecrets.length == rotationSeq`. [SociACL#68](https://github.com/FyberLabs/SociACL/issues/68) still owns any further count limit. Seal checks the plaintext length before it encrypts. Open refuses a blob longer than `RECOVERY_ABSOLUTE_MAX` (262269) before it parses the header. That ceiling is `RECOVERY_ENVELOPE_MAX` (262205: the 33-byte header, a 12-byte nonce, the plaintext cap, and the 16-byte tag) plus the 64-byte salt ceiling. Salt length is not a term of `RECOVERY_ENVELOPE_MAX`. After the header parses, a ciphertext longer than the plaintext cap plus the 16-byte tag is `keyring-too-large` for a 16-byte salt and for a 64-byte salt.

Rust wipes the derived Argon2 key and the keyring plaintext with `zeroize`. The `argon2` crate's `zeroize` feature wipes that crate's working memory blocks, the 64 MiB blocks, not a separate password buffer. The string API collects NFC into a `Zeroizing` buffer and wipes it on success and on error. The caller's passphrase string and the scratch inside `unicode-normalization` are not wiped. TypeScript cannot wipe strings either. TypeScript fills its derived-key `Uint8Array`, its plaintext `Uint8Array`, and the string API's passphrase copy. The hash-wasm Argon2 linear memory is not wiped. Node's `Buffer.concat` AES intermediates are not wiped.

## Device delivery of a keyring

A new device receives the keyring through its own sealed wrap. The KDF and associated data use `sociacl-keyring-delivery-v1`. The signature uses `sociacl-keyring-delivery-sig-v1`. Those domains are separate from the genesis backup domains `sociacl-account-key-bind-v1` and `sociacl-account-key-wrap-sig-v1`. The transport public key still arrives out of band. The ciphertext goes to a `KeyWrapStore` keyed by `(principal, wrapId)`. The genesis backup and each device delivery share that store. A second device's wrap id is stored beside the first. The same wrap id replaces only that row. `get_wrap` / `get` takes the principal and the wrap id. `list_wraps` / `list` returns every wrap for the principal. The device inherits the one keypair and does not mint an identity or a contact-lane secret. The delivery wrap carries that secret, including at sequence 0. The genesis backup does not. The wrap is refused when the serialized keyring is over `KEYRING_SERIAL_MAX`, before seal, and when the blob is over `DELIVERY_BLOB_MAX` (262238: version byte, 65-byte point, 12-byte nonce, plaintext cap, and tag), before decrypt. The genesis backup cap stays 8192 bytes. The wrap store accepts a keyring-sized blob. Genesis seal and open still enforce 8192.

Open checks the current-key signature before it parses the plaintext. `recovery-stale` is returned only when the plaintext `rotationSeq` is older than the expected sequence and the signature also verifies under the key that was valid at that older sequence. That key is the current key of the rotation records whose own `seq` is less than or equal to the delivered sequence. Array position is not a sequence. Sequence 0 is the genesis principal. `recovery-stale` is not proof the delivery is genuine: a signature under a key the rotation was meant to cut off still returns `recovery-stale`, and no key material is accepted. A bad signature, a sequence that is not older, and a codec failure on this path are `wrap-rejected`. A forged wrap cannot choose among `recovery-stale`, `recovery-rejected`, and `wrap-rejected`. The transport scalar is wiped if key agreement throws, including on an attacker-chosen ephemeral point. Rust copies that scalar into a temporary P-256 secret that zeros on drop, and drops the secret as soon as the shared secret is derived. The caller's transport key stays. The transport public key must not be the principal, the genesis epub, the current pub, the current epub, or a retired epub. Opening a delivery blob with the genesis backup opener fails closed. TypeScript returns `wrap-rejected`. Rust returns `signature-rejected`, the result `open_account_backup` already uses when the current-key signature does not verify.

The wrap store holds at most 64 rows per principal, `MAX_WRAPS_PER_PRINCIPAL`. A new wrap id at that cap is `store-rejected`. Replacing an existing id does not count as a new row. Each row has a class, `genesis` or `delivery`. The same class and the same wrap id may replace that row. A different class on an existing wrap id is `store-rejected` and the old row stays, so a delivery cannot take the genesis backup's wrap id. The class is a field of the `sociacl-store-write-v1` signature. Openers ignore it. Every put and delete carries that signature by the current chain-head key the store's resolver reports. The message is the principal, the operation, the wrap id, the SHA-256 of the ciphertext bytes, the published head, the hash of the row being replaced or `none`, the class, and the write generation. That signature is separate from the wrap's own signature. The store reads the published chain itself and verifies the signature before it writes. The same head floor applies, shared with the recovery store for that principal. A write is `store-rejected` when its resolved head is below a head either store has already been shown, whether or not that head accepted a write. A retired key cannot fill the cap, delete a delivery row, or store a delivery signature under the genesis class. An unsigned row is `store-rejected` and does not count toward the cap. Session authentication is not this check. Adapters, Panopticon included, must verify before they write. `delete` / `delete_account_wrap` removes a delivery row under that same signature. The genesis backup can be replaced by another genesis row with the same wrap id, and it cannot be deleted. A rejected write, including a genesis delete and a class change, leaves the stored rows and the write generation unchanged. The TypeScript memory store copies a row on put, get, and list.

## Epoch manifest

Those devices share the account key, so two of them can each mint a different key for epoch `e+1` and publish ciphertext and wraps under the same epoch number. The epoch number alone does not say which key is current. A field-wise merge can keep one item body and a wrap for the other key.

The owner device publishes an `EpochManifest`, signed with the account SEA key. Devices check that signature with the account `pub` they already hold. The manifest is a self-wrap in the author's one lane, or it sits inside the encrypted item. It is not an owner pub on a visible grant row. It is not a grant. Publishing it does not mint.

`revisionId` is the hash of the canonical manifest body: object, epoch, previous epoch, device id, key commitment, `settleWindowMs`, and `aclSnapshot`. It is not a hash of the device id alone. `aclSnapshot` is the SHA-256 of one row per accessor: the accessor, that accessor's `grantRevision`, `stated`, `from`, `until`, the scope (`direct`, `same-group`, or `named-circle`), the set id, and `hamState`. There is no single cancel number across accessors. A replica that knows accessor A is cancelled at revision R ignores a snapshot that lists A as live, omits A, or cancels A below R. For a group or circle row, the same rule uses `MeshMembership.hamState` on that predicate and set. A lower `hamState` does not hide a removal this replica has already merged. The snapshot also names the object-to-set edge: predicate, set id, `stated`, and `ObjectSetName.hamState`. Member `hamState` does not stand in for that edge. A replica that has merged a newer object-set edge ignores a snapshot whose predicate, set, or `stated` disagrees, or whose `hamState` is lower, or that omits the edge. The manifest signature covers `revisionId`, length-prefixed domain `s3rch-epoch-manifest-sig-v1` plus that id. A signature over `keyCommitment` alone does not verify. A stated-1 entry whose `until` is at or before now does not settle. The buffer stays buffered. The owner publishes a new revision whose key was not wrapped to that accessor, and whose snapshot lists that accessor `stated: 0`. That replacement starts its own settle window. A finalization that names that snapshot is ignored too. The winner is recomputed over the finalizations that remain. An offline device that wrapped a reader before learning of the cancel cannot win once replicas have seen that cancel. A retry that mints a new key commitment gets a new `revisionId`. The device id is local to that enrollment. It is not a Gun device record, not a second SEA keypair, and not a grant. Enrollment still does not mint.

`settleWindowMs` is the owner-signed wait before readers switch to this candidate. The owner signs it in the manifest for one object. For a group or circle, the owner signs the same number in `GroupEpochConfig`, and every group-epoch manifest repeats the window of the greatest `configRevision` for that predicate and setId. A higher revision for another predicate or setId does not replace it. A lower `configRevision` is ignored. At the same revision, the smaller digest of the signed config wins. The signed bytes also include `owner`. `GroupSeeGraph.ownerOfSet` names the account that owns the set. The signature is checked with that account's enrolled pub. A missing owner, or an owner that is not `ownerOfSet`, fails closed. A signature under some other key does not verify. A manifest that repeats an older window is ignored. The config sits with the manifest, in the author lane or inside the encrypted item. It is not an owner pub on a visible grant row.

The bounds are fixed. The minimum is `SETTLE_WINDOW_MIN_MS`, 3600000 (1 hour). A shorter wait lets one replica switch keys before a competing finalization arrives over an ordinary delay. Re-convergence would still correct the winner, and readers would churn keys in the meantime. The maximum is `SETTLE_WINDOW_MAX_MS`, 259200000 (72 hours). A longer wait holds remaining readers on the previous key through a long weekend partition. Past three days the delay is an availability stall, not a race buffer. The default is `SETTLE_WINDOW_DEFAULT_MS`, 86400000 (24 hours). One day covers devices that publish a few hours apart, including a device offline overnight, and it stays under the maximum. The owner signs the default by writing that number. An omitted number is that same decimal in the canonical body. A signed value outside the bounds is ignored.

Two devices racing the same next epoch produce two revision ids, because the key commitments differ. Each manifest is append-only and content-addressed by `revisionId` (SHA-256 of the canonical body, lowercase hex). A body that does not hash to its `revisionId` is rejected. A merge cannot swap the key commitment.

Each owner device may publish an `EpochFinalization` for that object and epoch step. It names its candidate revision ids and the winner inside that list, which is the lexicographically smallest `revisionId` in the list. It chains to a parent finalization (`previousFinalizationId`, empty for the first). Each candidate id must resolve to a verified manifest with the same object, epoch, and previous epoch. An id that does not resolve, or that names another object or epoch, is not in the minimum. A finalization whose named `revisionId` is not that minimum is ignored. The owner signature covers `finalizationId`, using the length-prefixed domain `s3rch-epoch-finalization-sig-v1` and that id. `finalizationId` already covers the candidate list and `previousFinalizationId`. A signature over `revisionId` alone does not verify.

Replicas do not keep the first finalization they see. Each replica keeps every verified finalization for the same object, epoch, and parent, and recomputes the winner as the lexicographically smallest `finalizationId` in that set. Two replicas that have seen the same set compute the same winner, whichever message arrived first. When a smaller `finalizationId` arrives later, the replica adopts it and drops the previous winner. A finalization is on the current chain only when its `previousFinalizationId` is the winner of the previous epoch, or empty for the first epoch. Replacing the winner of an epoch takes every later finalization that names the displaced id, or names a descendant of that id, off the current chain. Replicas keep those finalizations. They are not the winner, and they do not extend the chain. The owner rebuilds outward. Each invalidated epoch, parent before child, gets a new finalization whose `previousFinalizationId` is the new parent winner and whose `revisionId` is a new manifest. That candidate starts its own settle window. Content bound to a displaced descendant is not current. The owner re-encrypts it under the rebuilt winner after that window and issues wraps for the new snapshot. Each remaining accessor gets a new signed payload whose `grantRevision` is greater than that accessor's previous record, and a status proof that names that new revision and `stated: 1`. The old payload stays at the lower revision. Readers stay on the last settled revision that still sits on the current chain.

Readers take the window from the winning manifest. New writes for the step become current only after that winning id has stayed the winner for the whole signed window (`now >= winnerSeenAt + settleWindowMs`). `winnerSeenAt` is the time this replica first saw that id. A new winner starts the window again, using the window signed on the new winner's manifest. While the window has not elapsed, readers keep the last settled key (`settledRevisionId`) and do not switch. When it elapses, `epochStepCurrent` switches them to the winner only when the winning snapshot still matches the ACL this replica has merged, and every stated-1 entry is still inside its window. The function takes that snapshot and the replica's ACL. An expired stated-1 entry, a higher `grantRevision` on the merged ACL whether that row is live or a cancel, an earlier `until` or a later `from` on that ACL, a membership removal the snapshot understates, or an object-set edge the snapshot understates, does not settle, and the buffer stays buffered until a replacement that excludes that accessor settles. During the window a presentation names `settledEpoch`, the epoch of the last settled key, not the pending candidate epoch.

The window never delays privilege-down. A `stated: 0` grant, a higher `grantRevision` cancel, and removal from a group apply when the replica sees them. A revoked reader is left out of every candidate epoch's wraps, including a candidate whose window is still running. See [Rotation on revoke](#rotation-on-revoke).

**Honest limit.** Agreement does not depend on arrival order, and a replica that later sees a smaller id re-converges instead of forking. The window only delays the key switch. It does not freeze the set, and it does not delay a cancel. A smaller `finalizationId` after the window still replaces the winner. Content encrypted under the displaced revision is not current. The owner re-encrypts those writes under the new winner and issues wraps that match the new snapshot. Readers keep bytes they already unwrapped and do not treat the displaced ciphertext as current. Bytes already unwrapped under the previous key stay readable, as in [Rotation on revoke](#rotation-on-revoke). Closing the set on a local clock would leave two replicas that missed different messages with different winners. Replicas that have not yet seen the same finalizations disagree until they do.

A member offline longer than the window still holds the last key they settled. A cancel they missed applies as soon as they see the higher `grantRevision`. It does not wait out the window. If they are still a member, their window starts when they first see the current winner. They keep the last settled key until that local window elapses, then switch. They do not skip the wait because other replicas already switched. A smaller `finalizationId` during their wait restarts it. If they were removed while offline, they receive no wrap for the pending candidate or for the key it settles to.

Every `WrappedKey` carries its `revisionId` inside the authenticated wrap. A cleartext epoch number is not enough to tell two keys for the same epoch apart. While a candidate is pending, readers still read ciphertext already written under the last settled revision. New writes stay in a buffer. They are not encrypted under the last settled key, and they are not encrypted under the pending candidate, because a later smaller `finalizationId` can replace that candidate. When the window elapses, the owner revalidates every stated-1 snapshot entry. An entry whose `until` is at or before now is expired, and that candidate does not receive the buffer, because the expired reader may already hold its wrap. The buffer is encrypted under a later winner whose snapshot excludes that accessor. Otherwise the buffer is encrypted under the winner that settled. Wraps follow that winner's per-accessor snapshot. If a smaller `finalizationId` later displaces that winner, the owner re-encrypts those writes under the new winner before they are current again. After each switch, readers reject further writes bound to a revision the recomputed winner has superseded, including when the epoch number matches. A device that lost adopts that settled result and does not keep publishing under the superseded revision. An offline device can still become the winner by publishing a smaller `finalizationId` that other replicas then see, and those replicas wait out the signed window before they switch. Expiry does not stop at settlement. `settledKeyOpen` reads the snapshot of `settledRevisionId` and the ACL this replica has merged. It is false when a stated-1 entry has `until` at or before now, or `from` after now. It is also false when that ACL has cancelled the recipient, raised `grantRevision`, moved `until` earlier, or moved `from` later, even while the settled snapshot still lists the recipient live. It is false while `seen` has a winner whose `revisionId` is not `settledRevisionId`, and while `now` is before `winnerSeenAt + settleWindowMs`. A pending successor, including a late smaller id still inside its window, does not leave the old key writable. New writes then stay buffered. They are not encrypted under that settled key. The owner publishes a new revision whose key was not wrapped to that accessor. Ciphertext already written under the old key stays, and readers keep bytes they already unwrapped.

How long an epoch lasts is still open. See [Open choices](#open-choices).

## First contact

A first introduction on the one lane carries the sender's SEA `epub` and SEA `pub`, and an account binding that is not a signature by that `pub`.

The binding is one of two checks. An enrollment lookup reads `VerifierEnrollmentState` for that account. The record holds `pub` and `epub`. Both must be the ones in the introduction. The introduction does not supply the record. Or the account identity signs the length-prefixed fields `s3rch-account-binding-v1`, the account, `pub`, and `epub`. The verification key is `identityPub` on the enrolled record, the account's one SEA `pub`. The introduction does not supply that key, and it is not a second keypair. A missing `identityPub` fails closed. The signed `pub` must equal `identityPub`, and the signed `epub` must equal the enrolled `epub`. A signature that omits the account, or concatenates `pub` and `epub` with no lengths, does not verify. A check that uses the introduced `pub` as the verification key fails closed. A missing `epub`, a missing binding, or an `epub` that was not the one enrolled or signed fails closed. `pub` alone can verify a self-signature and still leave the reader unable to wrap to the account that was claimed.

The introduction is not a grant. It does not open a second lane. It does not mint. Later wraps to that sender use the bound `epub`. `priv` and `epriv` still never go on Gun. First contact under the public policy also needs proof-of-work or a trusted stamp. See [Inbox write policy](#inbox-write-policy).

## Inbox write policy

The reader chooses who may append to their one lane. The hook is `filterInboxAppend` (`InboxWriteHook`). The default policy is `public-filtered`. Public stays the default. `named-writers` stays the allowlist.

| Policy | Who may append | First contact | Quotas |
| --- | --- | --- | --- |
| `public-filtered` (default) | Any principal | Proof-of-work against a verifier-issued nonce and difficulty, or a stamp signed by an issuer the verifier trusts, both bound to the row's `entryId`. First contact means the writer is absent from the verifier's `knownSenders`. A caller flag is not that record. A self-signature is not enough | `senderQuotas` is one counter per `AccessorId`, and `laneRemaining` is one shared capacity for the lane. The writer does not claim either. A sender at 0 does not change any other sender and does not change `laneRemaining`. Spending a sender's quota does not give that sender a private copy of the lane capacity |
| `named-writers` | Only principals listed on the hook | Unlisted first contact is refused before the row is a candidate grant | The same per-sender map and the same one lane capacity |

The user sets the policy. `filterInboxAppend` takes the row, the verifier's `VerifierAdmissionState`, and `WriterAppendAuth`. The writer id is not a bare argument. It is an `AuthenticatedWriterChannel`, or a signature over the length-prefixed fields `s3rch-writer-append-v1` and `row.entryId`, checked under the enrolled SEA pub for the named writer. The channel constructor is private. `openWithPossession` mints one only after a signature over the length-prefixed fields `s3rch-writer-channel-v1` and the writer id verifies under `writerPub`. The brand is the same private field and `WeakSet` as the presenter channel. `InboxEnvelope.writerSignature` covers those same bytes. That check runs against `VerifierEnrollmentState` before `knownSenders`, the allowlist, and the quotas. The claimed `writerPub` must be the enrolled SEA pub for that writer. A missing account or a different pub is `writer-auth` and does not spend another sender's counter. The stored public row still has no writer pub. The relay that accepts the append learns the writer id for that `entryId`. A peer that only replicates the stored row does not learn the writer, and that replica is not an admitted append. This verifier admits a row only by running `filterInboxAppend` and recording `entryId` in its local `admitted` set. A later replica whose ciphertext, commitment, wrap, or `laneId` does not hash to that `entryId` is not admitted, even when the id is already in the set. The auth and the evidence are presented at that check. They are not fields of the stored row, and the row carries no admission receipt. This spec does not define an unlinkable admission credential. The state holds the outstanding challenges (one entry per nonce), the trusted stamp issuers, the spent set, `knownSenders`, `senderQuotas`, and `laneRemaining`. Issuing a second challenge does not drop the first. Spending one nonce leaves the others outstanding. A writer-supplied token string, a self-chosen difficulty, a claimed remaining quota, or a first-contact flag is not evidence. A writer missing from `knownSenders` is first contact and needs a verified stamp or proof-of-work. Proof-of-work evidence names the outstanding nonce it answers. The work is SHA-256 over that nonce, the row's `entryId`, and the solution, with at least that challenge's number of leading zero bits. Only that nonce is spent. A solution that also meets another outstanding challenge does not spend the other nonce. A stamp is a signature by a trusted issuer over that same `entryId`. The named nonce or the stamp signature is spent on use. A repeat fails closed. The counter used is the `senderQuotas` entry for that authenticated writer. A known sender with no counter, or with remaining 0, is `sender-quota`, and `laneRemaining` stays. A sender absent from `knownSenders` is first contact. After their evidence verifies, their counter starts at the verifier's `firstContactRemaining`. The writer does not set that number. At 0 the result is `sender-quota` and the sender is not added. Above 0 the counter is created, then the accept drops it by one. `laneRemaining` at 0 is `reader-capacity`, and that sender's counter stays. On accept, that sender's remaining and `laneRemaining` each drop by one, and a new sender joins `knownSenders`. A relay may check that evidence, or that the body hashes to the entry key, without opening the grant. SociACL does not run the filter and does not store a spam score. The 64 KiB bound is the length of the canonical entry. The filter measures that length before it hashes the body. A field longer than uint32 is the same local `spam` drop. Oversized rows and rows over the lane capacity are still local drops. A commitment mismatch is `checkPresentedGrant`, not a score. A row the hook accepts is still not a grant. A hop, a hint, a wrap, or a stamp never mints. Being allowed to append does not confer `see`.

## Rotation on revoke

Revoke of an encrypted object always starts with privilege-down, then a new epoch. The owner chooses what happens to ciphertext that already exists. `RevokeCipherMode` records the choice. `rotateOnRevoke` names the operation. `crates/sociacl-encdisc` runs this check. A wrap from it is not a grant.

1. **Privilege-down, immediate for a current verifier.** `stated: 0` on the grant (or on the direct membership) and a `hamState` bump, same as `cancelSee`. On a private row the same deny is a new append whose signed `grantRevision` is greater and whose `stated` is 0. The settle window does not delay this step. The next Check after that verifier has merged the cancel denies. Do not cache an allow across that merge. Freshness for every other verifier is [Revocation freshness](#revocation-freshness).
2. **New epoch.** A new DEK, or a new group epoch key, wrapped only to the remaining readers. The revoked reader is left out of every candidate's wraps, including a candidate whose settle window has not elapsed. A candidate whose `aclSnapshot` still names that reader is ignored. Remaining readers still read ciphertext already written under the last settled key while the candidate is pending, and they switch reads once the signed window passes. They do not encrypt new writes under that last settled key, and they do not encrypt new writes under the pending candidate. New writes stay buffered until the winner settles, then they are encrypted under that settled key, unless a stated-1 recipient's `until` has passed. In that case the owner publishes a new key that was not wrapped to that accessor, and the buffer waits for that replacement. The epoch is the winning [epoch manifest](#epoch-manifest). A second key under the same epoch number does not become current.
3. **Ciphertext choice**, one of:

| Mode | What the owner does | What remaining readers do during the window | What a revoked reader can still read |
| --- | --- | --- | --- |
| `forward-only` | Leaves ciphertext already written under the last settled DEK. New writes stay buffered until the winner settles, then use that key | Keep reading old ciphertext with the last settled key. Do not append new ciphertext under that key or under a pending candidate. After the window, read the buffered writes under the settled key | Old ciphertext, if they already unwrapped the old DEK or saved the old bytes. Not the buffered writes, and not the settled key |
| `re-encrypt` | Rewrites existing ciphertext under the candidate DEK and bumps merge state so the new ciphertext wins | Keep the copy they already unwrapped under the last settled key until the window passes, then switch to the rewritten ciphertext. A peer that only has the rewritten soul opens it after they hold that settled key | A local copy, or plaintext they already unwrapped. The replaced soul no longer serves the old ciphertext to peers that merged the new record. They receive no wrap for the candidate |

A wrap for an older epoch does not mint a grant. Check denies the revoked accessor after step 1 even when they still hold the old DEK. The settle window does not keep that grant live.

**Honest limit, both modes.** Content the revoked party already unwrapped stays readable to them. `re-encrypt` replaces the soul's ciphertext. It does not erase a copy or a DEK they already hold, and the window does not postpone the deny while remaining readers finish the wait. `forward-only` does not pretend to hide the old epoch. A member who was offline for the whole window learns the cancel as soon as they see it, and learns the new key only if they are still a member, after their own observation of the winner has lasted the signed window.

Removing a reader is this revoke, including the owner's choice of mode. Whether adding a member, or a quiet boundary with no removal, also starts a new group epoch is open. See [Open choices](#open-choices).

## Revocation freshness

Privilege-down is immediate only for a current verifier, as in [Rotation on revoke](#rotation-on-revoke). A stale, partitioned, or offline verifier has not merged that cancel. Absence of a cancel in its copy is not proof the grant is live.

Destination re-check of an encrypted grant requires an owner-signed `EpochStatusProof` beside the Check zookie. The proof names the object, the epoch, the winning revision, the accessor, that accessor's `grantRevision`, and `stated`. The owner signs the length-prefixed encoding of those fields, the times, and the zookie. The destination checks that signature with the enrolled owner `pub` from the presentation, not from a field on the visible row. The grant, the proof, the zookie, and the epoch view name one object and one epoch. The proof's accessor is the grant's accessor. The zookie is the existing Check freshness token: object, object version, and snapshot hash. The verifier compares it to `SeeGraph.objectVersion(object)` and `SeeGraph.snapshotHash(object)` for that same object. A hash of a different object, or one hash for the whole graph, is not this check. A presenter-supplied version is not the trusted value. A zookie for an older object version, a version this graph has not merged, or a different snapshot hash fails closed. It is not a cached allow.

`maxAgeMs` is the age bound the owner signed. `policyMaxAgeMs` is the verifier's cap, passed into `checkPresentedGrant`. The bound that applies is the smaller of the two. `skewAllowanceMs` is the verifier's clock-skew allowance, also passed in, not a field the owner sets on the proof. A proof is fresh only when `signedAt <= now + skewAllowanceMs` and `now - signedAt` is within that smaller age bound. A proof dated further ahead than the allowance fails closed. A current verifier has merged the privilege-down, when there is one, and holds a proof inside that window. That verifier denies immediately when `stated` is 0 or the merged grant is cancelled. Do not cache an allow across that merge.

Every other verifier may rely on a proof only while it is inside max-age and the skew allowance. A missing proof, a proof older than max-age, a proof dated too far ahead, a proof for a superseded revision, or a zookie that does not match the graph fails closed. Revocation is immediate only for a current verifier. Otherwise it is bounded by max-age. A revoked reader cannot present a proof after that bound.

The proof is not a grant. It does not mint. It does not change hopcap 1.

## Group predicates

`same-group` and `named-circle` already exist on the core Check plane. This spec names them on the s3r.ch light contract. Hopcap stays 1. Edges stay jointly stated. There is no transitive inheritance, no nested group, and no friend-of-friend walk.

The object names one of `delegate`, `same-group`, or `named-circle`. The accessor does not pick a richer one. An object with no named predicate stays on today's `delegate` / `MeshSeeGrant` path.

Owner allow does not depend on that name. The owner sees their object.

Check then evaluates only the named predicate. Both edges in a group or circle check must be `stated: 1`.

| Predicate | Holds when |
| --- | --- |
| `owner` | The accessor is the object's owner. Unchanged. |
| `delegate` | An admitted signed mesh grant names this accessor on an admitted signed object, and `now` is in `[from, until)`. `IdentitySeeGrant` alone is unsigned data. |
| `same-group` | `ObjectSetName` names a group, stated 1. The accessor has a jointly stated direct `member-of` edge to that group (`MeshMembership`). |
| `named-circle` | `ObjectSetName` names a circle, stated 1. The accessor has a jointly stated direct `in-circle` edge to that circle. |

One-sided membership is stored and is not a grant. Cancels are a grow-only set of ids. Each id is the hash of the replica, a fresh nonce, and the ids already on the row, so two replicas cancelling from the same prior row do not collide. A live assent or object-set edge lists every known cancel. A cancel it does not list dominates, including one this replica had not seen. Each membership assent is signed by that party. An object-set row is signed by the object owner's enrolled key, which Check reads with `GroupSeeGraph.enrolledKey`. A cancel whose own signature verifies is kept even when another signature on that row does not. Merge stores a row under the key recomputed from the signed fields, not under the peer's map key. The set id is `<principal>/<name>`, and the name contains neither `/` nor `_`, so `aclKey` is the same key in the soul and in memory. A predictable id, or two ids that would share that key, is rejected. Check denies a returned membership whose set id or accessor is not the requested one, and an object-set row whose object is not the requested one. It fails closed when `ownerOfSet` is absent. At an equal hamState, a direct see grant keeps the cancellation, then the narrower window, then the smaller canonical bytes. A membership row stays bound to the set owner in its soul. An object-set row stays bound to the object owner in its soul. Replacing the object owner drops that edge, and Check denies an edge whose recorded owner is not the current one. A later name or assent, after those cancels are merged, can state the row again. `checkGroupSee` is that Check. Hop may factor an already-named direct membership. Hop alone never allows. A wrap never mints a membership.

The group epoch key opens group ciphertext. It does not replace the membership edge. Check reads the edge. The key opens bytes. The reference crate runs `checkGroupSee` on the plaintext edges. It does not read a wrapped key.

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

A per-contact inbox lane is indexed by its lane id hex alone. The index key is not either `PrincipalId` and not a `~pub` path. SociACL does not store that index. [SociACL#71](https://github.com/FyberLabs/SociACL/issues/71) is the Panopticon and Gun wiring, including write-spam limits.

Whether a private group's index is addressed by search tokens, and what those tokens leak to whoever serves the index, is not decided. See [Open choices](#open-choices). This spec does not define a token construction.

## Contract types

Copy or re-type [s3rch-check.d.ts](s3rch-check.d.ts). Do not `npm install sociacl`. Do not import `crates/sociacl-gun`.

| Type or function | Role |
| --- | --- |
| `AccountSeaKey` | One SEA keypair per account. Devices inherit it through enrollment. `priv` / `epriv` stay off Gun |
| `WrappedKey` | DEK or group key wrap. `revisionId` sits inside the authenticated payload |
| `GrantCommitment` | SHA-256 of a fresh blinding plus the canonical grant, including the item ciphertext digest. The blinding is not on the visible row. Not an owner SEA pub |
| `ItemContentAuth` | Owner signature over item id, epoch, version, plaintext digest, and `revisionId`. Signed before encryption. Inside the encrypted item |
| `SignedGrantPayload` | Grant bytes inside the ciphertext, including monotonic `grantRevision` and `itemCiphertextDigest`. The greatest revision wins. At the same revision, `stated: 0` wins before the payload digest. The verifier holds that record. A lower live row does not undo a cancel |
| `InboxEnvelope` | Optional writer-signed outer envelope for `named-writers`. Carries the full `InboxEntryBody`. The relay recomputes `entryId` |
| `GrantPresentation` | What the holder shows the destination. Not written to Gun. A proof alone grants nothing |
| `PresenterBinding` / `VerifierChallengeState` | Verifier-issued nonce, single use, with expiry and a verifier-chosen audience. The presenter does not supply the challenge store |
| `BlindedGrantRow` / `inboxEntryId` | One append-only lane entry. `entryId` hashes lane, ciphertext, commitment, and wrap. No owner field. No `hamState` on the entry |
| `AuthenticatedPresenterChannel` | Transport capability. Brand is an ECMAScript private field and a module `WeakSet`. `accessor` and `readerPub` are frozen and must match the grant |
| `checkPresentedGrant` | Commitment, graph owner, owner signature, presenter binding, verifier-held enrollment, `grantRevision`, winning snapshot, and replica ACL, fetched item digest, fresh status proof, then Check. A group grant runs `checkGroupSee` and still requires a live payload inside `[from, until)` |
| `RecipientInbox` | The one disclosed base lane for that account. Not a shared bucket. Not the contact-lane secret |
| `ContactLaneGrant` | The derived lane id, sealed to the sender's `currentEpub`. The recipient signature is inside the ciphertext. The outer envelope is the blob. Delivery only. Not a grant. Indexed by lane id hex alone |
| `DailyShardScan` | Whole-shard rescan with dedup. Not a per-device cursor. Not a second lane |
| `AuthorFastUnwrap` | Local author DEK bound to `revisionId`. Not a grant row. The epoch number is not enough |
| `FirstContactIntro` / `AccountKeyBinding` | Sender `pub` and `epub`, bound by enrollment or by the account identity. Enrollment stores `pub`, `epub`, and `identityPub`. The signature is checked under `identityPub`. Not a self-signature |
| `WriterAppendAuth` / `filterInboxAppend` | Who may append. Writer id comes from a branded channel or a signature, checked against verifier-held enrollment, before quotas. The accepting relay learns that writer. The stored row does not. Default `public-filtered` |
| `EpochManifest` / `epochRevisionId` | SHA-256 of the length-prefixed manifest body, including `settleWindowMs` and `aclSnapshot`. The signature covers `revisionId`. One row per accessor, including `from`, `until`, scope, and membership `hamState`, plus the object-set edge. A snapshot that misses a cancel, a membership removal, an object-set update, or a stated-1 row past `until`, does not settle |
| `GroupEpochConfig` | Owner-signed settle window for one group or circle, ordered by `configRevision`. `owner` is in the signed bytes and must equal `ownerOfSet`. A group epoch manifest repeats the winning window. Minimum 1 hour, maximum 72 hours, default 24 hours |
| `EpochFinalization` / `EpochReplicaView` | Candidates for one step. Smallest `finalizationId` seen wins. The signature covers `finalizationId`. A displaced parent drops descendants off the chain, and the owner rebuilds them outward. Readers keep the last settled key, at `settledEpoch`, until the signed window elapses, then switch. `epochStepCurrent` and `settledKeyOpen` take the replica's ACL. A higher revision, a cancel, or a tighter window closes the settled key for new writes. The window does not delay privilege-down |
| `GrantStorage` | `public-plain` or `private-row` (whether public-plain stays is open) |
| `MeshMembership` | Direct `same-group` or `named-circle` edge. Hopcap 1 |
| `ObjectSetName` | The group or circle an object names |
| `GroupSeeGraph` / `checkGroupSee` | Check for those two predicates |
| `CancelledGrant` / `RotationCancel` | Plaintext `stated: 0` and the bumped `hamState`, or a private-row payload with a greater `grantRevision` and a matching status proof |
| `RevokeCipherMode` | `forward-only` or `re-encrypt`. The owner chooses at revoke |
| `EpochRotation` / `rotateOnRevoke` | Privilege-down, new epoch, then the ciphertext mode |
| `EpochStatusProof` | Owner-signed epoch/status beside the zookie. Names the accessor and that accessor's `grantRevision`. Length-prefixed signature. Age bound plus the verifier's skew allowance |
| `ProtocolMigration` / `ReaderMigration` | Owner-only. Plaintext drops per reader after that reader's authenticated wrap receipt. The version gate alone does not drop it |
| `ContentIndexTier` | `public`, `private-group`, or `local`. SociACL does not store it |
| `EncryptedDiscoveryVector` | Conformance names below. `sociacl-encdisc` runs the canonical ids, the reader-wrap vector, blinded rows, commitment opening, author fast unwrap, presenter binding through `checkPresentedGrant`, inbox admission, epoch admission, `rotateOnRevoke`, and in-place migration. A shard-close watermark is not implemented |

`GunFeedNode` and `GunUserNode` are unchanged. Predicate and membership are ACL rows, not feed fields. The user node may carry the account SEA `pub` and `epub`. It does not carry `priv`, `epriv`, or a copy of a grant row's owner field.

## Migration

Applying a new protocol version encrypts existing shared items in place. It does not leave those items on the plaintext path and encrypt only later writes. Only the owner re-encrypts a shared item and issues the new wraps. A reader does not choose a replacement DEK, does not re-encrypt the shared soul, and does not issue wraps for other readers. The reference crate runs this migration. Opening a wrap or the migrated item is not a grant.

For each existing item that moves onto the version:

1. The object id and item soul stay. The owner generates a DEK and the ciphertext for the existing body. `version` on that ciphertext is `toVersion`. The plaintext body stays in place through this step.
2. The owner keeps that DEK for [author fast unwrap](#author-fast-unwrap).
3. The owner writes each current reader a `WrappedKey` and a `BlindedGrantRow` in that reader's one lane. The commitment hides the owner and covers the item ciphertext digest, as in [Hidden authorship](#hidden-authorship) and [Item content authenticity](#item-content-authenticity).
4. Each reader keeps the plaintext copy, and may keep reading it, until that reader has sent an authenticated receipt for their wrap. The receipt is a SEA signature over the length-prefixed fields `s3rch-wrap-receipt-v1`, object, accessor, decimal `toVersion`, `revisionId`, and `entryId`. A caller boolean is not that receipt. A concatenated string with no lengths does not verify. A reader version at or above `versionGate` does not by itself remove that copy. One reader's ack does not remove plaintext for anyone else.
5. The owner removes plaintext for a reader only after that reader's wrap receipt. While any current reader has not acknowledged, the plaintext soul stays. Readers who have already acknowledged read the published ciphertext with their wrap. The soul is not replaced out from under a reader who is still waiting.
6. When every current reader has acknowledged the wrap, the ciphertext replaces the body, merge state bumps so the ciphertext wins, and the old plaintext `MeshSeeGrant` is cancelled (`stated: 0` and a `hamState` bump). Check after that merge denies the clear row for a current verifier. The private row is the live grant for readers who can open it.
7. `ProtocolMigration` records `fromVersion`, `toVersion`, the object, the wraps the owner issued, `readers`, and `versionGate`. There is no single flag. Readers do not issue wraps and do not clear another reader's row.

A current reader is a live grant whose window has not ended. That includes a grant whose `from` is still ahead of `now`. An expired grant is not current. Each merged edge's soul is `grantSoul(owner, object, accessor)`. A different soul is rejected, and the cancellation is written back to that same soul.

The ciphertext's epoch and `revisionId` are the replica's current read key, and that key is open for a new write. A displaced revision, or a successor that can still replace the key, is rejected. Before receipts are applied, the owner compares the soul's current `hamState` and body to the prepared snapshot. A mismatch aborts. The owner prepares again from the current item. The row's wrap is the recorded `WrappedKey`, including the authenticated blob. Opening the item verifies the owner signature over the item-auth tuple. Holding the DEK does not make a different body authentic.

Items the owner keeps on the public plaintext path are not rewritten. Whether that path stays is open. See [Open choices](#open-choices).

**Honest limit.** Peers that already replicated the plaintext body or the plaintext grant keep that copy. In-place replacement updates the soul for peers that merge the new record. It does not claw back an old replica. A reader who has not acknowledged the wrap keeps the old copy and does not invent a second ciphertext to fill the gap.

## Conformance vectors

The names are `EncryptedDiscoveryVector` in [s3rch-check.d.ts](s3rch-check.d.ts). `crates/sociacl-encdisc` and the TypeScript contract both load `vectors/encrypted-discovery/canonical.json` for `inboxEntryId`, `epochRevisionId`, the item-auth bytes, and the account-binding bytes. They both load `vectors/encrypted-discovery/presentation.json` for the grant commitment, the grant payload digest, the presenter-binding bytes, the epoch-status bytes, and author fast unwrap. They both load `vectors/encrypted-discovery/inbox.json` for the whole-entry id, the writer-append bytes, the proof-of-work bytes, the stamp bytes, and the daily-shard dedup. They both load `vectors/encrypted-discovery/forbidden-names.json` for the closed name list. The reader wrap in `vectors/encrypted-discovery/wrap.json` is checked by the Rust crate. The TypeScript contract also checks the presenter-channel brand and the writer-channel brand. The Rust crate runs `filterInboxAppend`, epoch admission, `rotateOnRevoke`, and in-place migration. Both load `vectors/encrypted-discovery/migration.json` for the structural migration cases. Both load `vectors/encrypted-discovery/contact-lane.json` for the HKDF info, the swapped-party lane, and the contact-lane grant. A shard-close watermark is not in this slice. In every vector, a wrap, a hop, a hint, an introduction, a binding, an append, or a stamp never mints.

### Content authenticity

`content-auth-accept`. The plaintext digest matches the owner signature over (item id, epoch, version, plaintext digest, `revisionId`). The signature was produced before encryption and sits inside the encrypted item. The row commitment covers the ciphertext digest. The reader accepts the body as authentic. Accepting it is not a grant.

`author-fast-revision`. The author's local DEK is stored with a `revisionId`. A DEK whose `revisionId` is a displaced manifest of the same epoch does not unwrap the winning body. The epoch number alone does not pick the DEK.

`content-auth-reader-forge`. A reader who holds the item DEK writes a different plaintext at the item soul. The plaintext digest no longer matches the owner signature, and the commitment does not cover the new ciphertext. Other readers reject the body.

`content-auth-revision-relabel`. The plaintext digest is unchanged and `revisionId` is swapped for another revision. The signed tuple no longer matches. Readers reject the body.

`content-auth-owner-pub-hidden`. The visible row bytes do not contain the owner SEA pub. The signature stays inside the encrypted item.

`content-auth-sign-then-encrypt`. The signed tuple is the plaintext digest. The ciphertext is built after that signature exists. The signed tuple does not include the ciphertext digest. The visible row still has no owner pub.

`commitment-blinding`. The same grant bytes with two blindings produce two commitment hashes. An unsalted hash of the grant bytes does not match the row. The presentation carries the blinding and recomputes the row hash. The visible row does not contain the blinding or the owner.

### Inbox replacement

`inbox-content-address-distinct`. Two entries that differ in ciphertext, commitment, wrap, or `laneId` have two entry ids. Each id is the hash of that canonical entry.

`inbox-replace-rejected`. A put whose canonical entry does not hash to the entry id is rejected. A different body under an existing entry id does not replace the first entry.

`inbox-wrap-swap`. The ciphertext stays and the wrap changes. The entry id changes. The new put does not replace the first entry.

`inbox-stamp-mismatch`. `filterInboxAppend` is given the row and the verifier's admission state. The stamp signature is over some other entry id, or the issuer is not in the verifier's trusted set. The append is rejected.

`inbox-pow-verified`. The solution, with the nonce named in the evidence and this row's `entryId`, hashes under SHA-256 to a digest with at least that challenge's number of leading zero bits. The verifier spends that nonce, decrements that sender's `senderQuotas` entry, and decrements `laneRemaining`. The append is still not a grant.

`inbox-pow-nonce`. Two admission challenges are outstanding. The evidence names one nonce. Only that nonce is spent, even when the solution also has enough leading zero bits for the other challenge. An evidence nonce that is not outstanding fails closed.

`inbox-fabricated-quota`. The writer claims a remaining quota or a difficulty. Those claims are not fields the verifier reads. The verifier's `senderQuotas` entry for that writer and the issued difficulty decide. An exhausted counter or a digest that misses the issued difficulty rejects the append, and the writer's claim does not refill any counter.

`inbox-spent-challenge`. The same challenge nonce, or the same stamp signature, is presented again after the verifier recorded it spent. The second append is `replay` and fails closed.

`inbox-known-sender`. The caller omits admission. The writer is absent from `knownSenders`. The append still requires proof-of-work or a trusted stamp. A caller flag is not part of the input.

`inbox-sender-quota-map`. Sender A has remaining 0. Sender B has remaining above 0. A's append is `sender-quota`. B's counter and `laneRemaining` stay as they were.

`inbox-lane-capacity`. `laneRemaining` is 0 and the writer's own counter is above 0. The append is `reader-capacity`. That writer's counter stays.

`grant-revision-order`. A signed payload with `stated: 0` and `grantRevision` 2 is already open. A signed payload with `stated: 1` and `grantRevision` 1 arrives later. Both signatures match. The cancel stands.

`grant-revision-stale`. The verifier's record for this object and accessor is `grantRevision` 2 and `stated: 0`. The holder presents an older live row at revision 1 with a valid signature and a fresh proof. `checkPresentedGrant` fails closed. The holder does not supply the record.

`grant-item-digest`. The grant names an encrypted item. The destination passes `fetchedItemDigest`, the SHA-256 of the ciphertext it fetched. That digest differs from `SignedGrantPayload.itemCiphertextDigest`. `checkPresentedGrant` fails closed before the revision record changes. `SeeGraph.snapshotHash` is not this comparison.

`writer-auth-required`. The caller names an accessor that is already in `knownSenders` and passes no channel and no signature. The append is `writer-auth`. That sender's quota and `laneRemaining` stay as they were. The stored row still has no writer pub.

`writer-enrollment-pub`. The proof names a known writer and a signature that verifies under the proof's `writerPub`. That pub is not the pub in `VerifierEnrollmentState` for that writer. The append is `writer-auth`. Quotas and the allowlist are not consulted.

`public-append-relay-learns-writer`. The relay that accepts a `public-filtered` append learns the authenticated writer id for that `entryId`. The stored row bytes do not contain `writerPub`. A peer that only replicates the row does not learn the writer from the row.

`inbox-concurrent-challenges`. Two first-contact writers each hold a distinct outstanding nonce. One append spends its nonce. The other nonce stays outstanding and still verifies.

`presenter-brand-unforgeable`. A caller copies the brand off a genuine channel, builds a new object with the victim's accessor and pub, and offers it. The private field is absent and the object is not in the module `WeakSet`. The check fails closed.

`revoke-no-old-key-writes`. Privilege-down has landed and the candidate window is still running. A new write encrypted under the last settled key is not current. The write stays buffered until the winner settles. The revoked reader has no wrap for that settled key.

`grant-payload-mismatch`. `grantBytes` decode to `grantRevision` 1. The caller also sets `grantRevision` to 9. The check fails closed and does not update `VerifierGrantRevisionState`.

`grant-revision-tie`. Two owner devices sign payloads at `grantRevision` 4. One has `stated: 0`. The other has `stated: 1` and the smaller payload digest. The cancel is current. The live payload does not replace it.

`grant-revision-digest-tie`. Two live payloads at `grantRevision` 4. The smaller payload digest is the current one. A later arrival of that smaller digest replaces a stored larger digest. The larger digest does not replace the smaller one. A cancel at that revision still wins over either live payload.

`grant-empty-digest`. A verified status proof raises the record to `grantRevision` 5, `stated: 1`, with an empty payload digest. The first live payload at that revision is accepted and its digest is stored. The empty string does not reject that payload as a larger digest. A `stated: 0` payload at that same revision still replaces the live record.

`epoch-proof-matches-winner`. The verifier's read key is the settled revision. The holder presents a fresh owner-signed proof for a different revision. The check fails closed.

`epoch-buffer-until-settle`. A candidate is pending. A new write is buffered. A later smaller `finalizationId` replaces that candidate. The buffer is encrypted only under the winner that settles, not under the candidate that lost.

`epoch-stale-acl`. This replica has accessor A cancelled at revision 10 and accessor B cancelled at revision 2. An offline device finalizes a snapshot that lists A as live, omits B, or cancels B below 2. That finalization is ignored. A's cancel does not hide B's. The revoked readers cannot unwrap the writes that settle afterward.

`epoch-reencrypt-displaced`. The window elapsed and writes were encrypted under winner W. A smaller `finalizationId` arrives and replaces W. Those writes are not current. The owner re-encrypts them under the new winner and issues wraps that match the new snapshot. Each remaining accessor's new payload has a greater `grantRevision`, and a status proof names that revision. The old payload stays at the lower revision. Readers keep bytes they already unwrapped.

`epoch-object-set`. The object moved from set A to set B, and `ObjectSetName.hamState` increased. An offline device finalizes a snapshot whose member rows are current for set A and whose object-set edge still names A. `epochStepCurrent` is false. Members of A do not receive the new key.

`epoch-rebuild-descendants`. Epoch E+1 has finalized against parent P. A smaller finalization replaces P. The E+1 finalization that names P leaves the current chain. The owner publishes a new E+1 finalization whose `previousFinalizationId` is the new parent and whose `revisionId` is a new manifest. That candidate starts its own settle window. Readers stay on the last settled revision that still sits on the current chain.

`epoch-finalization-sig`. The owner signature covers `finalizationId`. A signature over `revisionId` alone does not verify. Changing `previousFinalizationId` or the candidate list changes `finalizationId`, so the old signature fails.

`epoch-expire-before-settle`. A stated-1 snapshot entry has `until` before the settle instant, and that reader already holds the candidate wrap. The candidate does not settle. The buffer stays buffered. The owner publishes a new revision whose key was not wrapped to that accessor.

`epoch-settle-needs-snapshot`. `epochStepCurrent` is given the winning snapshot and the ACL this replica has merged. A stated-1 entry past `until`, or a cancel in the replica ACL that the snapshot still lists as live, makes the function false. The buffer is not encrypted under that key.

`epoch-settled-read`. Epoch E+1 is inside its first settle window. `settledRevisionId` is the key from epoch E. A presentation whose grant and status proof name epoch E and that revision is accepted for the read-key check. A presentation that relabels the same ciphertext as epoch E+1 fails closed.

`epoch-stale-membership`. A group member was removed and `MeshMembership.hamState` moved to 4 with `stated: 0`. An offline device finalizes a snapshot that still lists that member `same-group` at `hamState` 2. The finalization is ignored. That member has no wrap for the writes that settle afterward.

`epoch-manifest-sig`. The owner signature covers `revisionId`. A signature over `keyCommitment` alone does not verify. Changing the object, the parent epoch, `settleWindowMs`, or `aclSnapshot` changes `revisionId`, so the old signature fails.

`inbox-envelope-body`. A `named-writers` envelope carries `InboxEntryBody`. The relay recomputes `inboxEntryId`. A body that does not hash to `entryId` is rejected even when the writer signature matches the claimed id.

`item-auth-canonical`. `ItemContentAuth` is a signature over the length-prefixed fields `s3rch-item-auth-v1`, object, epoch, version, SHA-256 of the raw plaintext, and `revisionId`. A different framing of the same values does not verify.

`status-policy-max-age`. The owner signed `maxAgeMs` far above the verifier's `policyMaxAgeMs`. The proof is older than the cap and inside the owner's bound. The check fails closed.

`status-binds-accessor`. The proof names a different accessor, or a lower `grantRevision` than a cancel this verifier holds for this accessor. The check fails closed. A verified proof with a higher `grantRevision`, or `stated: 0` at the same revision against a stored live row, updates the record.

`status-object-match`. The proof names a different object or epoch than the decoded grant, the zookie, or the epoch view. The check fails closed before a nonce is spent and before the revision record changes.

`status-signed-encoding`. The owner signature covers the length-prefixed fields `s3rch-epoch-status-v1`, object, decimal epoch, `revisionId`, accessor, decimal `grantRevision`, decimal `stated`, decimal `signedAt`, decimal `maxAgeMs`, and the zookie fields. A different framing of the same values does not verify.

`presented-group-check`. `PresentedGroup` is set. The graph is a `GroupSeeGraph`. After the binding, revision, and freshness checks, `checkGroupSee` runs. A group object with no group argument fails closed. An ordinary see grant omits the argument and runs `checkSee`.

`presented-group-cancel`. The opened payload has `stated: 0`, or `now` is outside `[from, until)`. `PresentedGroup` is set and `checkGroupSee` would allow because the membership edge is still stated 1. `checkPresentedGrant` returns `allowed: false`. The revision record may store that cancel. A live membership edge does not override the payload.

`migration-wrap-receipt`. A reader's version is at `versionGate` and that reader has not acknowledged the wrap. Plaintext for that reader stays.

`migration-per-reader`. One reader has a verified wrap receipt. Plaintext for that reader drops. Another current reader has no receipt. Their plaintext stays. The shared soul stays plaintext. The object id stays.

`migration-soul-replaces`. Every current reader has a verified receipt. The ciphertext replaces the body, the soul's merge state bumps, and each plaintext MeshSeeGrant is cancelled (stated 0 and a hamState bump). A reader below versionGate who has acknowledged is included. The gate is not the condition. The private row is the live grant. An opened wrap still does not grant.

`migration-no-widen`. A wrap, a reader, or a payload names an accessor the live plaintext grant does not name, or the payload window starts earlier or ends later than that grant. The migration is rejected. A cancelled grant is not revived.

`migration-privilege-down`. A reader already has stated 0 and a bumped hamState. That reader is not wrapped and does not have to acknowledge before other readers migrate. The cancel is not held for a receipt.

`migration-public-skipped`. The owner keeps the item on the public plaintext path. No ciphertext replaces the body and no wrap is issued. Whether that path stays is open.

`migration-reader-cannot-issue`. The caller is not the owner. The call is rejected. A reader does not re-encrypt the shared soul and does not issue wraps.

`migration-receipt-canonical`. The receipt is a signature over the length-prefixed fields s3rch-wrap-receipt-v1, object, accessor, decimal toVersion, revisionId, and entryId. A different framing of the same values does not verify.

`migration-historical-replica`. After the soul is replaced, a peer that already stored the plaintext body still has that copy. The replacement does not claw it back.

`epoch-late-manifest`. A replica's winner is one finalization. A later finalization with a smaller `finalizationId` arrives. The replica adopts it and keeps the last settled key. The step switches only after the new winner's signed `settleWindowMs` has passed.

`epoch-arrival-order`. Two replicas receive the same two finalizations in opposite orders. Both compute the same winner, the smaller `finalizationId`.

`epoch-settle-window`. The smallest finalization has been the winner for less than the owner-signed `settleWindowMs`. Readers still read with the last settled key. New writes stay buffered.

`epoch-settle-bounds`. A manifest signs a window below 3600000 or above 259200000. That manifest is ignored. A manifest that signs 86400000 is the default and stays in range.

`epoch-settle-pending-key`. A candidate has been the winner for less than its signed window. Readers read with `settledRevisionId` and buffer new writes. They do not encrypt those writes under the settled key or the pending candidate. After `winnerSeenAt + settleWindowMs` they encrypt the buffer under the winner and switch.

`epoch-settle-skips-revoke`. A candidate window is still running. A `stated: 0` payload with a higher `grantRevision` arrives. The cancel applies at once. The revoked reader has no wrap for that candidate.

`epoch-group-window`. `GroupEpochConfig` signs 7200000 at `configRevision` 2 for a set. A group-epoch manifest that repeats 7200000 uses that window. A manifest that signs a different in-range number is ignored. A config at `configRevision` 1 does not replace revision 2.

`epoch-group-owner`. `GroupEpochConfig.owner` is not `ownerOfSet` for that predicate and set, or the signature verifies under some other account. The config is ignored.

`epoch-candidate-scope`. A finalization for object A lists a `revisionId` that belongs to a verified manifest for object B. That id is not in the minimum. The finalization is ignored.

`presented-settlement-acl`. The settle timer has elapsed, and the winning snapshot still lists a recipient past `until`. `epochStepCurrent` is false. A status proof for the pending candidate fails closed. A proof for `settledRevisionId` is the read key.

`inbox-first-contact-quota`. A sender is absent from `knownSenders` and has no quota row. Their proof-of-work verifies. `firstContactRemaining` is 3. The append is accepted, the counter is created at 3 and then drops to 2, and the sender joins `knownSenders`. When `firstContactRemaining` is 0, the same evidence is `sender-quota` and the sender is not added.

`writer-append-canonical`. `WriterAppendProof` and `InboxEnvelope.writerSignature` cover the length-prefixed fields `s3rch-writer-append-v1` and `entryId`. A bare hex string does not verify.

`inbox-replicated-row`. A public row arrives by replication. Its bytes have no writer pub and no admission evidence. `entryId` is absent from this verifier's `admitted` set. The row is not an admitted append. It becomes one only when `filterInboxAppend` records that id.

`rotate-private-cancel`. A private-row revoke carries `RotationCancel` kind `private-row`: stated 0, a greater `grantRevision`, and a status proof for that revision. A plaintext `CancelledGrant` does not cancel that private row.

`id-sha256-canonical`. `inboxEntryId` and `epochRevisionId` are SHA-256 of the length-prefixed UTF-8 fields, written as lowercase hex. A hex encoding of the raw body is not the id.

`zookie-object-snapshot`. The zookie names one object. The verifier compares its snapshot hash to `SeeGraph.snapshotHash` of that same object. A hash of a different object, or one hash for the whole graph, fails closed.

### First contact

`intro-epub-required`. An introduction with `pub` and no `epub` fails closed.

`intro-binding-ok`. Enrollment for the account names this `pub` and `epub`, or the account identity signs that pair and the reader verifies it with the enrolled account key. The introduction is accepted as first contact. It is not a grant and it does not open a second lane.

`intro-binding-canonical`. The account signature covers the length-prefixed fields `s3rch-account-binding-v1`, account, `pub`, and `epub`. A signature that omits the account, or concatenates `pub` and `epub` with no lengths, does not verify.

`intro-binding-swap-epub`. The enrolled or signed `epub` differs from the introduction. The introduction fails closed.

`intro-enrolled-epub`. The enrollment binding is used. `VerifierEnrollmentState` for that account has no `epub`, or its `epub` is not the introduced one. The introduction fails closed. A record that holds only `pub` is not enough.

`intro-self-signature-rejected`. The introduced `pub` signs the account, `pub`, and `epub`. That signature is not an account binding. The introduction fails closed.

`intro-account-identity`. The binding is `account-signature`. The verifier has no `identityPub` for that account, or the check uses the introduced `pub` instead of `identityPub`. The introduction fails closed. A signed `pub` that differs from `identityPub` fails closed. There is still one SEA keypair.

`intro-not-a-grant`. A valid introduction does not set `allowed`.

### Presenter binding

`presenter-proof-alone`. A `GrantPresentation` with a matching commitment and a valid owner signature, and with no nonce signature and no transport-minted channel, fails closed. The proof does not grant.

`presenter-nonce-ok`. The verifier's outstanding nonce, not yet expired, is signed by the reader's SEA key and matches the enrolled pub for the named accessor. The nonce is spent. Check then runs. Check may still deny.

`presenter-binding-canonical`. The presenter signature covers the length-prefixed fields `s3rch-presenter-binding-v1`, the nonce, the commitment hash, and `audience`. A concatenated string with no lengths does not verify.

`presenter-audience`. The signature is valid for the outstanding nonce and the commitment, and its `audience` is not the audience on that challenge. `checkPresentedGrant` fails closed. The nonce stays outstanding.

`epoch-settled-expiry`. A revision has settled with a stated-1 recipient whose `until` is still ahead. When `until` passes, `settledKeyOpen` is false. New writes are buffered and are not encrypted under `settledRevisionId`. The owner publishes a replacement that does not wrap that accessor. Ciphertext already written under the old key stays.

`epoch-settled-cancel`. The same revision has settled with the recipient still inside the window. The replica then merges a cancel for that accessor. `settledKeyOpen` is false. New writes are not encrypted under that key.

`epoch-settled-pending`. A successor finalization is inside its settle window, and every recipient window on the settled snapshot is still open. `settledKeyOpen` is false. New writes stay buffered. They are not encrypted under `settledRevisionId`, including when a later smaller `finalizationId` has replaced the winner.

`epoch-live-revision-window`. The merged ACL has a higher live `grantRevision` whose `until` is earlier than the snapshot. `epochStepCurrent` is false, and `settledKeyOpen` is false. The snapshot's longer window is not used for new ciphertext.

`presented-enrollment`. The presentation's `seaPub` verifies the owner signature, and it is not the pub in `VerifierEnrollmentState` for that owner. `checkPresentedGrant` fails closed before a nonce is spent. The same failure applies when the binding pub is not the enrolled pub for the accessor.

`presented-graph-owner`. The signature verifies under `presentation.seaPub`, and that pub is the enrolled pub for `presentation.owner`. `graph.ownerOf(object)` is absent or names a different account. `checkPresentedGrant` fails closed before the signature is accepted, before a nonce is spent, and before the revision record changes. A reader signing as owner does not raise that record and does not refresh the status proof.

`presenter-bad-key`. The nonce signature verifies under a different key. The destination rejects it.

`presenter-spent-nonce`. The same nonce is presented again after it was spent. The second check fails closed.

`presenter-expired-challenge`. `now >= expiresAt` for the outstanding nonce. The check fails closed.

`presenter-forged-channel`. An object literal with `accessor` and `readerPub` is offered in place of `AuthenticatedPresenterChannel`. It is not an instance, and `hasTransportBrand()` is not true. The check fails closed.

`presenter-channel-wrong-principal`. The channel is a real transport instance, and its brand checks. Its `accessor` is a different principal, or its `readerPub` is not the enrolled pub for the grant's accessor. The check fails closed.

`presenter-binding-not-a-grant`. A valid binding with a Check deny stays a deny.

## Open choices

Not decided:

1. **Group epoch length.** How long an epoch lasts, and whether every membership change forces a new epoch. Removal of a reader still follows [Rotation on revoke](#rotation-on-revoke): privilege-down, a new DEK or epoch key for the remaining readers, and the owner's `forward-only` or `re-encrypt` choice.
2. **Public-content mode.** Whether plaintext `MeshSeeGrant` stays for public content, with private rows only when the item is encrypted. Migration skips items that stay on that path.
3. **Group search tokens.** Whether a private group's index is addressed by search tokens, and what those tokens leak to whoever serves the index. No token scheme is fixed here.

## What this does not do

- Change Check's allow rules for a hop or a hint
- Put SEA `priv` or `epriv` on Gun
- Put a passphrase or a recovery-copy plaintext on Gun
- Open an Argon2id recovery envelope below the floor or above the ceiling
- Decrypt a keyring or a recovery envelope before checking its length
- Let device delivery mint a second identity
- Impose a prior-lane maximum beyond `priorLanes.length == rotationSeq` and the 256 KiB serial cap (any further count stays with [SociACL#68](https://github.com/FyberLabs/SociACL/issues/68))
- Put the owner's SEA pub on a visible grant row
- Treat a wrap, a presentation, an inbox append, an introduction, a content signature, an epoch manifest, a presenter binding, a status proof, or a stamp as a grant
- Accept a presentation that does not bind the presenter to the reader's SEA key
- Treat a missing, expired, or future-dated epoch/status proof as a live grant
- Let a reader re-encrypt a shared item, or remove one reader's plaintext before that reader has acknowledged receipt of the wrap
- Use a per-device cursor, or one clock high-water mark, as the lane scan
- Add a second inbox lane, or a Gun device record, for a device id
- Derive a contact lane from the disclosed base `laneId`
- Index a contact lane under a `PrincipalId` or a `~pub` path
- Treat a contact-lane grant as a Check allow
- Open the first-contact public request channel ([SociACL#70](https://github.com/FyberLabs/SociACL/issues/70)) or wire the Panopticon and Gun lane-id index ([SociACL#71](https://github.com/FyberLabs/SociACL/issues/71))
- Treat a signature by the introduced SEA `pub` as the account binding
- Accept a writer-claimed quota, a self-chosen difficulty, a first-contact flag, or an unverified token as admission evidence
- Freeze an epoch winner on the first finalization a replica happened to see
- Delay privilege-down, or a higher `grantRevision` cancel, until an epoch settle window elapses
- Accept a settle window below 1 hour or above 72 hours
- Let one sender's quota counter stand in for every sender, or give each sender a private copy of the lane capacity
- Let a live private grant with a lower or equal signed `grantRevision` undo a cancel
- Let a smaller payload digest undo a cancel at the same revision
- Use one cancel number for every recipient
- Treat ciphertext bound to a displaced settled revision as current
- Accept a status proof for a different object, epoch, or accessor
- Treat an empty payload digest as the smallest digest
- Put the commitment blinding on the visible row, or use an unsalted hash of the grant bytes as the commitment
- Leave a descendant epoch current after its parent finalization is displaced
- Settle a candidate whose stated-1 recipient is past `until`
- Accept an epoch finalization signature that covers only `revisionId`
- Compare `SeeGraph.snapshotHash` to the item ciphertext digest
- Treat a caller-supplied `writerPub` as the enrolled key
- Require a pending epoch number on a presentation while the last settled key is still the read key
- Hide the authenticated writer from the relay that accepts the append
- Settle an epoch from the clock alone, without the winning snapshot and the replica's ACL
- Let a lower membership `hamState` hide a removal this replica has merged
- Accept an epoch manifest signature that covers only `keyCommitment`
- Accept an account binding that omits the account or drops the length prefixes on `pub` and `epub`
- Re-encrypt displaced content under the same `grantRevision`
- Trust a presenter-supplied pub as the enrolled key
- Check an account-signature under the introduced `pub`
- Leave the settled key writable while a successor finalization is still pending
- Open an author fast unwrap whose `revisionId` is not the manifest that DEK belongs to
- Accept a named owner that is not `graph.ownerOf` for that object
- Treat a live group or circle edge as an allow for a payload whose `stated` is 0 or whose window has passed
- Spend an unnamed proof-of-work nonce when several challenges are outstanding
- Settle a snapshot whose object-set edge is older than the one this replica has merged
- Accept a presenter binding that is not the length-prefixed domain
- Spend a presenter nonce when the signed audience is not the audience on that challenge
- Encrypt a new write under a settled key after a stated-1 recipient's `until` has passed
- Treat a pending candidate as the read key while `epochStepCurrent` is false
- Reject a verified first contact for lack of a preallocated quota row
- Accept a writer-append signature that is not the length-prefixed domain
- Treat a replicated public row as an admitted append
- Cancel a private row with only a plaintext `hamState` bump
- Let a candidate id from another object or epoch enter the finalization minimum
- Let an older `GroupEpochConfig` replace a higher `configRevision`
- Accept a `GroupEpochConfig` whose owner is not `ownerOfSet` for that set
- Treat an enrollment record that omits `epub` as enough to accept an introduction
- Keep encrypting new writes under a settled key after the replica ACL cancels that recipient or shortens that window
- Accept a presentation whose `grantRevision` is below the verifier's record
- Take a bare accessor as the writer for quotas or the allowlist
- Encrypt a post-revoke write under the last settled key
- Allow a reader to scan a shared bucket
- Claim private information retrieval or a zero-knowledge proof (future work only)
- Add an index, or a group search-token scheme, to SociACL
- Fork `items`, `users`, or the five-segment `grantSoul` path
- Edit FyberLabs/s3r.ch
