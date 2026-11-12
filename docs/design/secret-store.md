# Secret, key and small-file store: phase-one protocol plan

Status: design work for #155. Shipped as library building blocks: canonical version
and audit transcripts, a passphrase-sealed local file with an atomic Unix file store,
authorized read composed with Check and epoch freshness, signed version history,
in-memory audit admission, and encrypted history and audit checkpoints (see the
status updates on #155, most recently PRs #178 to #180). Not shipped: a CLI,
credential helper, sync service, device-key adapters, agent broker and an audited
cryptographic implementation. The existing encrypted-discovery implementation is the
starting point, not proof that a new secret-store protocol is safe. The formal threat
model and cross-language vectors remain implementation prerequisites.

The multi-slot design that extends this plan (key slots, the portable file profile,
sharing, brokered agent use with a daily lease, storage, rotation and the build
slices) is in [secret-store-vault-design.md](secret-store-vault-design.md).

## Ownership and component boundary

Use a `sociacl-vault` library in this repository for the portable item/version,
wrap, authorization and conflict rules. A thin CLI can consume it. Visor owns its
user interaction and local execute/use/sign broker; it does not turn a decrypted
item into permission to execute a command or sign a wallet transaction. Mobile
and browser clients implement device-key adapters around the same protocol.
Storage peers retain ciphertext and authenticated metadata, never plaintext keys.

The account's stable SEA genesis principal owns the store. Current signing keys
are resolved from authenticated history. Wallet/OIDC credentials gate the
existing recovery flow; they are not owners, item encryption keys or substitutes
for proof of the SEA identity. A device enrollment must not widen account grants.
Per-device keys wrap local material; they must not masquerade as account principals.

## Item and version shape

Proposed first release limit: 1 MiB of plaintext per item, checked before
allocation/encryption and after authenticated opening. Treat this as a proposal,
not a selected deployment quota. Larger files belong in ordinary encrypted
storage, with a key/reference stored here. Encrypted metadata includes item name,
media type, labels and user notes. The visible transport envelope contains only
opaque item/version ids, size and the minimum key-wrap routing information
required by the existing grant model. Do not promise to hide recipient identities
if the selected wrap representation exposes them.

Each new immutable version has an unpredictable per-version data key and fresh
nonce. It binds item id, version id, parent version ids, owner principal, epoch
revision and ciphertext digest into authenticated data and an owner-signed
version statement. Use existing vetted encrypted-discovery primitives; exact
canonical ordering and domain separation must be frozen in vectors before code.
Do not encrypt different plaintext under a reused key/nonce. Do not put secret
names, plaintext digests of low-entropy secrets or raw credentials in public ids.

Read admission requires current Check and a fresh EpochStatusProof matching the
version and graph zookie, then the authenticated wrap and item signature checks.
A successful unwrap is insufficient. Offline reads need a bounded lease that
cannot outlive the configured freshness horizon; unavailable/stale authority
fails closed. An unlocked process can still copy plaintext: device keys and
revocation cannot undo that disclosure.

Concurrent children of one parent remain visible conflicts. Neither timestamp
nor lexicographic id silently chooses a winner. A merge is a new signed version
that explicitly names all resolved parents. A durable authenticated local head
prevents a malicious sync peer from rolling back a previously observed version;
a restored client needs independently authenticated freshness, not a server's
claim that an old ciphertext is latest. Retention must preserve unresolved
conflicts and cannot prune the only recovery copy. Version count/time defaults
remain a separate product choice.

## Share, revoke and device loss

Sharing adds wraps only for principals already allowed by current ACLs. Each
admitted membership change starts a new epoch under the selected group policy.
`rotate_on_revoke` validates removal, next-epoch manifest and remaining-reader
wraps; the storage transaction must persist the cancellation and new head
consistently. Sensitive items require new encrypted versions after removal;
forward-only mode must be explicit for other items. New members do not receive
historical epoch keys automatically. Every API exposes partial persistence as a
recoverable failure, not a successful revoke.

A lost device triggers its device-key revocation and rotation of material it
could open. Since today's account enrollment copies a SEA keypair, revoking only
a local device wrap cannot neutralize an already copied account signing key.
Account-key rotation and authenticated history/retention are therefore required
when that key may have escaped. The UI must not claim device-only revocation
solves account-key compromise. Existing recovery ciphertext stays recoverable;
only a newly created passphrase seal uses the current asynchronous strength rule.

## Local custody and recovery

The first portable backend can be a passphrase-sealed local file with Argon2id
and explicit file permissions, atomic replacement and crash-safe writes. This
is a weaker custody option than a verified hardware-backed device adapter; it
must not be advertised as hardware protected. Hardware/PRF adapters need
platform capability checks, explicit fallback UX and enrolled recovery before
activation. No server-side decryption or account-key escrow is introduced.

The store must reuse the authenticated recovery/wrap APIs and their per-principal
floor/generation transaction boundary in `hyperme-sh/acl-service#13`, including
exact read-back after a lost successful response and fresh signatures after a
competing write. Historical `FyberLabs/panopticon#554` is superseded. Ordinary
retries never lower rollback floors or restore tombstoned data.

## Audit, consumers and execution order

Audit records are encrypted to the owner/authorized auditors and signed. They
bind opaque item id, actor, device, operation, outcome and predecessor digest;
no plaintext secret or secret name is logged. An append-only chain detects
modification of an observed prefix but cannot prove an untrusted server supplied
the latest head or that every read was logged. Do not claim completeness without
an independent freshness/checkpoint mechanism.

Implement in this order: reviewed threat model and canonical vectors; local core
and file backend; CLI get/put/share/revoke/version operations; safe child env
injection and credential helpers; untrusted sync with conflicts; browser device
adapter; mobile adapters; trustee recovery and SSH signing. Each adds its own
unit/contract suite and CI-owned runtime adapter. No fake hardware assurance or
manual shared-resource acceptance is substituted for the platform work. The
independent audit and GA decision remain open.
