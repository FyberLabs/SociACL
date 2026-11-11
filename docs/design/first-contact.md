# First contact before a private lane exists

Status: design proposal for #70, not a deployed endpoint. The existing
`typescript/contract/contact-lane.ts` and `contact-lane-seal.ts` derive and seal a
recipient-approved private lane. `docs/encrypted-discovery.md` specifies that its
secret is distinct from the disclosed base inbox. A stranger cannot derive it.

The recipient may explicitly publish a separate, rotatable request descriptor:
an opaque random request-channel id, a dedicated encryption public key, expiry,
maximum ciphertext size and the storage service's admission policy. It contains
no base lane id or contact-lane secret. Publishing the descriptor associates that
channel with wherever it is advertised; it cannot promise to hide that public
association. The storage service sees channel ids, sizes, timing and network
addresses. It should not see sender/recipient SEA ids in the envelope metadata.

A sender creates an encrypted request to the descriptor key. Inside are sender
SEA principal, current-key signature, exact channel id, descriptor revision,
one-time request nonce, issued-at/expiry, an ephemeral reply key and a bounded
message. The signature binds every field, including reply key. Encryption is
not sender authentication. The recipient resolves authenticated current-key
history after decrypting and refuses malformed, stale or replayed requests.
No raw HTML or active content is rendered. This new envelope needs a reviewed
canonical domain, a vetted authenticated-encryption construction and shared
vectors before either client can use it; it must not be implemented by abusing
an existing grant or contact-lane domain.

Storage admits only bounded ciphertext with short retention. Apply per-channel,
per-source and global quotas before decryption/signature work, with optional
proof-of-work or another deployment-owned abuse control. Rate limits are service
policy, never an ACL grant. Readers can mute, block or rotate the descriptor;
old descriptor requests are rejected after expiry. Do not trial-decrypt a shared
global bucket. Retain dedup ids for the request lifetime and skew horizon. Use
an unpredictable reply capability with the same bounded lifetime; do not expose
a public sender-to-recipient index or reflect arbitrary replies to URLs.

Acceptance is an explicit recipient action. Only then derive a private lane and
return the existing signed `sociacl-contact-lane-grant-v1` sealed to the sender's
verified current key. Merely delivering, decrypting, reading or replying to a
request never grants a lane or item access. Verify the lane grant normally;
Check on each destination remains independent. Rejection/expiry returns no
private lane metadata. Private lane writes then follow #71's storage limits.

Before implementation: recipient opt-in/rotation lifecycle in Infra or the
owning storage repository; stable envelope bytes and Rust/TypeScript vectors;
quota and retention tests; forged sender/reply-key, wrong descriptor, replay,
stale-key and oversized-message refusals; and a client acceptance test proving
that a request never creates a lane grant by itself. No live fixture or tenant
is provisioned by this design.
