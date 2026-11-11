# Cross-network requests: security design

Status: design only for #48. No network bridge, server index, new grant format or
runtime implementation is introduced. Existing building blocks are
`typescript/ids/src/records.js` (current-key/history and signed requests),
`typescript/contract/presenter.ts` (nonce/audience binding),
`typescript/contract/epoch.ts` (freshness), and `typescript/src/request.js`
(destination-owner approval). Those functions do not currently implement the
cross-network envelope below.

## Identity and trust boundary

A URL and its source-network hints are untrusted transport. The destination
resolves the canonical destination network id and object locally; it never
accepts a source-supplied mapping to another object or authority. TLS authenticates
the endpoint, not the requester's SEA identity or right to access an object.

A person using the same SEA genesis principal in both networks proves control
with its current key, resolved through authenticated complete history. Rotation
changes a signing key, not the principal. Wallet and OIDC credentials remain
recovery/login links. Neither a wallet address, email match nor OAuth subject
links two principals automatically.

If the networks use distinct genesis principals, the design requires a separate
explicit binding signed by both current keys. It names both network ids, both
genesis principals, both current keys, destination audience, a one-time
challenge and expiry. This proves joint control only. It neither merges graph
nodes nor transfers ownership, memberships, grants or recovery authority. The
destination still grants to its chosen local principal. A single signature,
stale key history or an unsigned alias is insufficient. No transitive alias
chain is followed.

## Request and destination processing

A future versioned request envelope signs, in canonical length-prefixed order:
new domain, source network, destination network, destination audience, target
object, requester genesis principal, current key, requested scope, challenge,
issued-at and expiry. Domain and canonical bytes must be frozen with shared
Rust/TypeScript vectors before implementation. Do not reuse the existing local
request signature while omitting the network/audience fields.

1. Destination allocates an unpredictable 32-byte challenge bound to requester,
   audience, object and requested scope. Challenges expire after at most five
   minutes and are single-use at the destination's durable serialization point.
2. Destination checks bounded input, canonical ids, exact network/audience,
   issuance/expiry, current authenticated key history and the signature. A
   failed check creates no request, grant or trusted cache entry.
3. After verification, atomically consume the challenge and store an idempotent
   request id derived from the signed body. Duplicate delivery returns the
   existing outcome; concurrent attempts cannot create independent approvals.
4. The destination object owner approves using ordinary destination ACL writes.
   Source-network grants and claims of source approval are ignored. Read and
   post remain separate grants; a requested scope is not a granted scope.
5. The requester proves presenter possession to the destination verifier using
   a fresh verifier nonce and exact audience. Encrypted discovery additionally
   requires current revision/epoch status and a matching Check zookie. Missing
   or stale authority fails closed. Opening a link always re-checks.

Revocation remains on each destination ACL. Cancelling a source grant does not
silently mutate another network, and cancelling the destination grant takes
precedence over an old request or cached result. No request can Remint an ACL
that does not already name that destination principal. No step Elects.

## Abuse cases and limits

| Attempt | Required refusal/limit |
| --- | --- |
| Replay signed request into another network/object | Exact signed destination, audience, target and nonce binding |
| Reuse a consumed challenge or race two workers | Durable atomic consumption and idempotent request id |
| Substitute wallet/email or retired signing key | SEA genesis identity plus complete current-key resolution |
| Copy a source grant or add an intermediate friend | Destination Check only; hopcap remains 1 |
| Forge joint control from one key | Both independently verified current-key signatures |
| Make the destination fetch an attacker-controlled URL | Resolve local canonical network configuration; no request-driven server fetch |
| Flood requests | Destination quotas before expensive verification, bounded records, recipient mute/block; limits do not grant |
| Leak private target ids or source-network relationships | Explicit link disclosure; no global directory or public request-body index |

Network outages deny freshness-sensitive access; no fail-open fallback to the
source. This design provides no traffic-analysis anonymity or revocation of
plaintext already copied. Before implementation, shared negative vectors must
cover every row above, expiry boundaries, rotation between challenge and use,
concurrent consumption and destination cancellation after request approval.
