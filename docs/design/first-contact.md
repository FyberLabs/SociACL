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

## Signed inner request v1

The reference module `typescript/contract/first-contact.ts` and copied
`docs/first-contact.d.ts` implement the signed inner payload. This is a library
format, not a deployed channel or encrypted transport. #70 remains open for
confidential envelope interoperability, recipient descriptor provisioning,
durable replay admission, quotas and the client acceptance flow. #71 still owns
private-lane storage after acceptance.

Canonical signing fields are domain `sociacl-first-contact-request-v1`, decimal
version `1`, channelId, decimal descriptorRevision, sender, replyEpub, nonce,
decimal issuedAt, decimal expiresAt, and message. Every string uses the existing
little-endian 32-bit UTF-8 length prefix. The channel and nonce are each 32 random
bytes represented as 64 lowercase hex characters. The descriptor revision is a
positive safe integer. Times are safe, nonnegative UTC seconds, with issuance
inclusive and expiry exclusive. Negative zero, unpaired surrogates, extra fields
and getter properties are refused. The message is at most 4096 UTF-8 bytes and
otherwise preserved exactly, including normalization form and whitespace; render
it as inert text, never HTML. The recipient descriptor can impose a smaller
message cap and must explicitly set its maximum request lifetime. No library
default silently grants a long retention window.

The sender's current SEA signing key signs those bytes in the existing compact
P-256 format. The reply point is a dedicated ephemeral encryption key, not proof
of an account identity. The signature binds it along with the channel/revision;
reply destinations are never URLs. Request identifiers are SHA-256 of signing
bytes, excluding the signature encoding. The independently authenticated history
resolver must agree with the verified current sender key; omitted transport
history must not be replaced with an empty list. Retired keys fail closed.

Replay keys hash length-prefixed domain `sociacl-first-contact-replay-v1`, channel,
revision, sender and nonce. They deliberately exclude message, expiry and signature,
so changing or re-signing a request cannot reuse one nonce. Before displaying or
accepting a verified request, the recipient atomically reserves that key in its
durable store until the descriptor's exclusive expiry (`replayUntil`). Keeping
only the shorter request expiry could admit another signed use of the same nonce
with a later expiry. Descriptor policy, including expiry, is immutable within a
revision; changing it requires a new revision. A failed reservation, missing
store or failed commit does not admit the request. The verifier itself is pure
and does not claim to provide that persistence boundary. Descriptor rotation
rejects old revisions, and requests cannot outlive the descriptor.

The outer confidential envelope must hide the sender, reply point, signature,
message and nonce from storage. Do not publish this signed plaintext as a public
Gun row. The public descriptor and outer ciphertext address are the only public
routing material; neither contains a private lane id. Accepting the request is
still a separate explicit recipient operation that issues the existing lane grant.
The new verifier returns request metadata and replay identity only, with no ACL
answer, lane id, wrap or grant.

`vectors/first-contact/v1.json` pins canonical bytes, request ID and replay key.
PR CI signs with public test scalar 1 and checks tampering, key retirement,
missing history, descriptor binding, expiry, UTF-8 bounds and nonce reuse.
This is TypeScript library coverage; Rust parity and encrypted cross-client E2E
remain unfinished and must run in CI when implemented.
