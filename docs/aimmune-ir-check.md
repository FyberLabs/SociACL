# Light Check consume contract (AImmune / IR)

This is the artifact the AImmune Next console (Brewnix/auto-defense) reimplements against. MockCheck-first in the browser.

**File:** [aimmune-ir-check.d.ts](aimmune-ir-check.d.ts)

The Next app runs Check **in the browser** on logical site objects. It does **not** import this Rust crate, NAPI, or WASM. Do not `npm install sociacl`. Copy the `.d.ts` or re-type the same names. Same consume rules as [s3rch-check.d.ts](s3rch-check.d.ts). WASM later is optional and is **not** the IR light path.

`crates/sociacl-core` in this repo is the primitive source of truth ([PR #11](https://github.com/FyberLabs/SociACL/pull/11) delegate, [PR #13](https://github.com/FyberLabs/SociACL/pull/13) / [s3rch-check.d.ts](s3rch-check.d.ts) light see, [verbs.md](verbs.md)). It is not a runtime they load.

The Brewnix object/mask table lives in [Brewnix/inference-iface `docs/sociacl-ir-binding-v0.md`](https://github.com/Brewnix/inference-iface/blob/main/docs/sociacl-ir-binding-v0.md). Do not fork those primitives here. This file is the TypeScript consume surface they copy.

## What they implement

`CHECK(action, object, accessor)` at `now` via `checkDelegate`.

| Name | Meaning |
| --- | --- |
| `object` | `site:{site_id}` (standing owner possession) or `site:{site_id}:ir` (IR keep-operating) |
| `accessor` | human / agent id. Not a machine site-token type |
| `see` | dest Check `read` (alias) |
| `action` | `read` / `write` / `execute` (`ActionMask`) |
| grant | jointly stated `DelegateGrant`; hopcap **1** (no friend-of-friend) |
| `until` | exclusive unix seconds; omit = open |
| revoke | immediate privilege-down (`cancelDelegate` / `undelegate`) |
| hint | `HandoffHint` — untrusted; never a grant (`acceptHint` never sets `allowed`) |
| apply | owner-only `applyDelegate` |
| refresh | `remintCapability` only if `checkDelegate` still allows |

`site:{site_id}:host` is later (when Host exists). Do not mint `site:{site_id}:incident:{incident_id}`. Hypermesh Checkout is not a consumer of these grants.

`write` without `execute` is annotate-only (Brewnix). Ticket resolve and grant mint need `execute` on `:ir`. `break_glass` approve is a Brewnix owner gate, not a SociACL verb. `fyber.privilege_grant/v0` body stays Brewnix. Zero-LLM contain / expiry never calls Check per event.

Later, on request: `:host` execute when Host exists. Not this cut.

## Locked site objects (do not fork)

```
site:{site_id}       standing owner possession
site:{site_id}:ir    IR keep-operating (tickets, non-break-glass mint)
site:{site_id}:host  later — not this cut
```

`site_id` is the same token as envelopes / grants / auditor scope.

CheckResult, AccessorId, and HandoffHint match [s3rch-check.d.ts](s3rch-check.d.ts). Copy or re-type. Do not add an npm package to share them.

The Rust crate in this repo remains the full plane. See [verbs.md](verbs.md) for that map.
