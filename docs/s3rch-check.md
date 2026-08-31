# Light Check consume contract (s3r.ch)

This is the artifact the s3r.ch Next app reimplements against.

**File:** [s3rch-check.d.ts](s3rch-check.d.ts)

The Next app runs Check **in the browser** on the Gun mesh. It does **not** import this Rust crate, NAPI, or WASM. Do not `npm install sociacl`. Copy the `.d.ts` or re-type the same names. WASM later is optional and is **not** the lab-feed path.

`crates/sociacl-gun` in this repo is the reference implementation. It is not a runtime they load.

## What they implement

`CHECK(see, object, accessor)` at `now`.

| Name | Meaning |
| --- | --- |
| `object` | `GunFeedNode` at `s3rch/items/<encodeKey(id)>`, or a Gun-native claim linked from `s3rch/users/{wallet}` |
| `accessor` | wallet / Gun peer (`s3rch/users/{wallet}`) |
| `see` | dest Check `read` |
| grant | jointly stated `IdentitySeeGrant`; hopcap **1** (no friend-of-friend) |
| revoke | immediate privilege-down on the dest object (`cancelSee`) |
| hint | `HandoffHint` — untrusted; never a grant |
| admit | dest re-authorizes **before** `put()` into `items` |

`s3rch/meta` is seed cache. It is not a Check object. A permalink / RSS3 / RSS / issuer URL is a `UrlLeaf`, not a node and not a grant.

Execute-without-read is existing `delegate` (`execute` without `read`). The `.d.ts` documents it. Lab-feed may omit it.

## Locked Gun paths (do not fork)

```
gun.get('s3rch').get('items').get(encodeKey(id))  → GunFeedNode
gun.get('s3rch').get('meta')                     → seed meta (not a Check object)
gun.get('s3rch').get('users').get(wallet)        → GunUserNode
```

`encodeKey`: `id.replace(/[.#$\[\]]/g, '_')`.

Claim object id is the claim id, linked from the user node. Do not invent `s3rch/users/{wallet}/claims/…`.

## Out of this contract

Anything not in [s3rch-check.d.ts](s3rch-check.d.ts) is **not** for the Next app: other SociACL verbs, C / Python bindings, and optional binary hint frames. The crate may implement those here. The browser path does not.

See [gun.md](gun.md) for the Rust adapter map.
