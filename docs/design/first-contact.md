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
global bucket. Retain dedup ids through the descriptor expiry as specified below. Use
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
The Rust `sociacl-ids` first-contact module consumes the same canonical vector and
enforces the same descriptor, signature, history and replay-horizon boundaries.
Its parser accepts `serde_json::Value`; JSON decoding rejects unpaired surrogates
before parsing, and typed Rust strings cannot contain them. Both language suites
run in PR CI. This covers signed inner payload interoperability only; encrypted
cross-client E2E remains unfinished and must run in CI when implemented.

## Confidential envelope v1 reference

`typescript/contract/first-contact-seal.ts` supplies a bounded envelope, separate
from grant encryption. The binary layout is version byte `01`, a 65-byte
uncompressed ephemeral P-256 point, 12 random nonce bytes, AES-256-GCM ciphertext,
and a 16-byte tag, with an 8192-byte total cap. Each seal uses a fresh random
scalar and nonce. The trusted descriptor adds a dedicated `encryptionEpub`.
Never obtain that key or the descriptor policy from the received envelope.

Associated data is length-prefixed UTF-8: `sociacl-first-contact-seal-v1`, `1`,
channel ID, canonical decimal descriptor revision, recipient encryption SEA
point, ephemeral SEA point. HKDF-SHA256 takes the 32-byte ECDH x coordinate as
IKM, 32 zero salt bytes, that same associated data as info, and produces the
32-byte AES key. The plaintext is the canonical ten signing fields followed by
the compact signature as an eleventh length-prefixed field. Decoding must
round-trip exactly; noncanonical decimals, invalid UTF-8 and trailing data fail.
The public envelope contains no sender, reply key, signature or private lane.
Ciphertext length still exposes approximate message length; padding is not part
of this version.

Opening verifies the recipient key, authenticated encryption, canonical payload,
current sender signature/history and descriptor policy before returning verified
request metadata. Durable replay admission and explicit recipient acceptance
remain separate. Invalid ciphertext never yields a partially decoded request.
The TypeScript and Rust PR suites exercise randomization, tampering, destination
binding, wrong keys, bounds, expiry and forged inner signatures; the TypeScript
suite also checks missing history. CI exchanges freshly sealed ciphertext in both
directions and compares request identity, replay identity, retention and exact
message bytes. This reference alone must not be advertised as a deployed public
request channel; provisioning, replay persistence and explicit acceptance remain
required.

## Recipient replay journal and explicit acceptance

The browser `sociacl-ids/first-contact-store` adapter uses strict IndexedDB
readwrite transactions, resolving only after commit. Opt-in and rotation generate
new random channel IDs; the recipient advertises the returned descriptor over an
authenticated channel. Disable stops receipt and decisions immediately. Descriptor
policy is immutable within a revision. The store bounds descriptors to seven days
and retains at most 256 unexpired replay entries per recipient. Overflow refuses
new requests instead of evicting live replay protection. A backward clock fails.

The journal contains the encrypted request, its opaque request/replay IDs,
deadlines and decision, never plaintext messages. Duplicate reservations cannot
replace an envelope, extend its deadline or change its decision. Rejection and
acceptance retain the replay tombstone through descriptor expiry, even after the
shorter request expires. Missing storage is not implicitly bootstrapped. After
origin-data loss, explicit setup publishes a fresh channel instead of reopening an
old descriptor without its replay history. Origin compromise and externally
rolled-back browser profiles remain outside IndexedDB's durability guarantee.

`first-contact-inbox.ts` demonstrates the crypto/storage boundary: receive opens
and verifies a request, reserves it durably, then returns it for display. Explicit
acceptance loads the committed ciphertext, reauthenticates current sender history,
seals the existing private-lane grant and commits it to the outbox before returning
it for delivery. The grant targets the sender's authenticated current encryption
key, not an unchecked reply key. A lost response is reconciled from the committed
outbox. Accepted outbox entries survive request/descriptor expiry, disable and rotation
until the exact ciphertext is acknowledged after delivery. They count against
the quota and are never evicted to admit new requests. Callers must revalidate
current histories and recipient rotation sequence before retrying delivery. A rotated recipient
uses the existing regrant flow; an old outbox entry is not a fresh grant.

PR CI covers receipt-to-acceptance cryptography, competing transactions, aborts,
quotas, replay retention, disable/rotation and restart. The central scheduled
browser suite additionally exercises real Chromium connections and a process
restart. That suite is scheduled-only; adding its case does not claim it has run.
Authenticated descriptor publication and s3r.ch's user-facing flow remain required
before the public channel is complete.

The public descriptor can be signed with `first-contact-descriptor.ts`. Its
separate domain binds the expected owner, issuance time, channel, revision,
encryption key, expiry and both request limits. Verification requires the
independently expected owner, authenticated current-key history and a locally
maintained revision floor. Sign only the descriptor returned by committed opt-in;
never publish the private channel encryption scalar. A descriptor signature
proves authorship, not freshness: first discovery still needs authenticated
publication, and a known descriptor revision must not roll back. Old descriptors
stop working locally on disable/rotation even if a transport replays them.

## Sender observation continuity

`first-contact-discovery.ts` authenticates a public descriptor and commits its
revision and canonical intent digest through `sociacl-ids/first-contact-floor`.
The strict IndexedDB transaction serializes tabs, rejects lower revisions and
same-revision equivocation, persists a clock floor, and rechecks authentication
and expiry at commit completion. Re-signing identical bytes does not change the
intent digest. No plaintext request, contact lane or grant is stored here.

Bootstrap requires an independently authenticated exact descriptor anchor.
Reopening missing state fails; initialization is explicit and cannot repair an
existing conflicting floor. Clearing origin storage destroys continuity and
requires authenticated recovery. Origin storage is trusted; this adapter does
not defend against malicious same-origin code restoring an entire old database.

An observed floor is not proof that an untrusted directory returned the newest
descriptor, nor that the owner has not disabled a channel. Authenticated fresh
discovery and disable publication, s3r.ch transport/UI, bounded public-channel
storage, delivery reconciliation and service E2E remain separate requirements.
The existing scheduled Chromium case now covers competing descriptor observations
and process restart; ordinary PR CI uses an IndexedDB fixture for these contracts.

## Public-channel polling into the recipient journal

`pollFirstContact` is a headless/reference adapter using the Node crypto contract,
not a browser crypto implementation. It connects a provisioned Spanopticon ciphertext source to the
recipient-owned journal. It bounds the transport deadline and batch, snapshots
ciphertexts and verifies their digests before asynchronous admission, decrypts
and authenticates sender history, and reserves each replay key before returning
plaintext. Invalid signatures do not block other valid rows; duplicate requests
are skipped. Storage failures abort rather than pretending admission succeeded.
Authorization is rechecked after commit and before return; a disabled or changed
descriptor aborts the batch. Expired requests retain their committed replay keys.
The caller must independently authenticate history and supply the current clock.
No incoming request is automatically accepted and no outbox grant is delivered.
The adapter contract returns decoded `{id,ciphertext:Uint8Array}` rows and never
accepts a destination URL from storage. Product UI, discovery and grant delivery
remain separate integrations.
