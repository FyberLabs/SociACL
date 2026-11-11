# Delegated agent credentials

This consume contract advances #156 and s3r.ch #277/#278. It adds no session
issuer, JWT, endpoint, or new object permission. The implementation is in
`typescript/ids/src/agent-delegation.js`. The declarations in
`docs/identity-consume/agent-delegation.d.ts` are generated standalone copies;
the identity consume manifest pins them and the shared vector bytes.
CI rebuilds and checks them with `scripts/identity-consume-contract.py`.

An owner's current SEA signing key signs a v1 delegation naming one distinct
agent SEA key, a canonical HTTPS origin as audience, a sorted unique list of
exact scopes, a 32-byte lowercase-hex nonce, issuance and exclusive expiry.
Scope names contain lowercase ASCII letters, digits, hyphens and colons. There
are no wildcards or implied parent scopes. At most 32 scopes and a 24-hour
maximum delegation lifetime are accepted. Issuers may impose shorter limits.
The nonce must be newly generated from a cryptographic RNG for each delegation.

`agentDelegationBytes` uses the shared little-endian UTF-8 length-prefix encoder:
domain, version, principal, agent, audience, scope count, each scope, nonce,
issuedAt, expiresAt. The ID is lowercase hex SHA-256 of those bytes, independent
of signature encoding. Revocation uses a separate domain with version,
principal, delegation ID and issuedAt. Both use the existing compact P-256
signature verification. All signed fields are bound; wallet and OIDC subjects
are not principals.

`verifyAgentDelegation` resolves the owner's current key using the existing
verified history and rejects retired signing keys. A key rotation invalidates
old delegations. It accepts only a live signature with the requested agent,
audience and a nonempty subset of delegated scopes. It returns the parsed
record and ID, not an allow answer for a forum or other object.

The caller must obtain a complete, fresh revocation snapshot from the owner's
authenticated storage, not a caller-selected Gun fragment or arbitrary empty
array. Missing, stale or unreadable storage denies before invoking this
function; do not translate such failures into an empty list. Every supplied
revocation must be well-formed and owner-signed; an invalid row denies.
Unrelated historical revocations are verified against the issuance-time key in
authenticated rotation history and retained without blocking new delegations.
A retired key can never revoke a current-key delegation through that historical
path. No historical timestamp is used to grant authority. A matching
revocation denies, with no later grant overriding the same ID. A newly issued
delegation needs a new nonce. Rotation also makes old delegation tokens unusable.

Before exchanging this record for a short-lived JWT, the identity issuer must
verify the agent's possession of its key with a fresh, single-use, audience-bound
challenge. It must bind principal, agent, delegation ID, exact audience and
scopes in the token, and cap token expiry at delegation expiry. Token consumers
must re-evaluate fresh delegation/revocation state and current Check permission;
a valid signature or tenant storage receipt alone grants no object access.
The principal's private key stays in browser or agent custody. This contract
neither enables chained delegation nor lets the agent sign as its principal.

The shared vector uses public test scalars 1 and 2. It is a wire/crypto fixture,
not a deployed identity. Runtime/browser integration belongs in scheduled CI.
