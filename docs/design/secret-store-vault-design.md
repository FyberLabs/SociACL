# Secret store: multi-slot vault design

Status: design for #155, extending the phase-one pieces in
[secret-store.md](secret-store.md). It records decisions and a build order. None of
the slots, file profile, broker, lease or sync described here is implemented yet,
and nothing here has had an independent security review.

## Decisions

| Question | Decision |
| --- | --- |
| Daily key slot | A passkey with the WebAuthn PRF extension (or a native device key). A recovery-key slot is mandatory. Login is never a key. |
| File format | A strict JWE profile (RFC 7516, General JSON Serialization). |
| Agent access in v1 | Brokered use only. Agents receive no plaintext. Plaintext release is revisited after the broker has handled real cases. |
| Unattended agents | A renewable lease: default and maximum 24 hours, renewed every 2 minutes with a 5 minute token and a 5 minute grace window. Extension needs the human again. |
| Managed-host broker | Ships in v1, off by default, with a per-lease opt-in. |
| Standing subset | Optional, opt-in per item, audited, rotated on revoke. |
| Storage | One shared Spanopticon storage space for Spanopticon and s3r.ch users, for now. |
| Identity | The SEA key is the account identity. Wallet and OIDC credentials are linked credentials for login and recovery. |

## 1. Current state and gaps

| Piece | Where | Today |
| --- | --- | --- |
| Design set | `docs/design/secret-store*.md` | Phase-one plan, signing format, local custody, threat model. |
| Sealed file v1 | `crates/sociacl-encdisc/src/vault_local.rs` | Magic `SAVFILE1`. One passphrase slot: Argon2id (64 MiB, 3 passes, 4 lanes) then XChaCha20-Poly1305 around a fresh 32-byte data key. 1 MiB item and 16 KiB metadata caps. Rust only. |
| Signed versions and audit | `vault_format.rs`, `vault_history.rs`, `vault_journal.rs`, `vault_audit.rs`, `typescript/contract/vault-format.ts` | Canonical transcripts in both languages, a version graph that keeps concurrent heads, encrypted history and audit checkpoints, in-memory audit admission. |
| Authorized read | `vault_read.rs` | Signed version, Check, fresh epoch proof and custody open, with a commit callback before plaintext returns. |
| File store | `vault_file.rs` | Private Unix directory, compare-and-swap writes, exact retry. No Windows. Needs an independently held head. |
| Item wraps | `wrap.rs`, `typescript/ids/src/reader-wrap.js` | Item key wrapped to a reader's SEA `epub` or a group epoch key. A wrap is not a grant. Raw wraps carry target and object labels. |
| Revoke and rotate | `rotation.rs`, `epoch.rs` | New epoch, wraps for remaining readers, re-encryption of sensitive items. |
| Account recovery | `recovery.rs`, `docs/recovery-flow.md` | Passphrase-sealed copy of the account keyring. |
| Agent delegation | `docs/agent-delegation/README.md` | Owner-signed record: one agent key, one HTTPS audience, up to 32 exact scopes of at most 64 characters, 24 hour maximum, revocation records. |

Gaps against the goals:

- One slot only. No file format holds a passkey, recovery-key, trustee or grantee slot.
- `SAVFILE1` has no browser opener. The TypeScript contract covers transcripts only, and XChaCha20 is not in WebCrypto.
- No sync, no protected head floor, no vault storage namespace. The in-memory version graph refuses additions at 256 entries until an authenticated checkpoint design exists.
- Wrap routing is not confidential yet, and the wrap store caps rows per principal (`MAX_WRAPS_PER_PRINCIPAL`, 64).
- No broker, no vault-audience token and no key binding on agent tokens.
- The existing rule of no server-side decryption and no account-key escrow rules out any design where a server releases a key after login.

## 2. Threat model

| Adversary | Holds | Result |
| --- | --- | --- |
| Stolen file | Container bytes | Passkey and recovery-key slots hold 256-bit secrets, so there is no offline guess path. A passphrase slot is guessable, so it is optional and gated by the strength check. Visible: sizes, slot count and kinds, random ids. |
| Compromised storage or Spanopticon | All ciphertext; can replay, fork, withhold, delete | No plaintext or keys. Rollback is caught only by the independently held head floor. Deletion is an availability loss, so backups matter. |
| Stolen session (Keycloak, SIWE cookie, access token) | Calls storage and token endpoints as the user | Can fetch ciphertext and slot blobs but cannot open them. Cannot mint an agent token without an owner-signed delegation. Writes need an account-key signature. |
| Malicious or prompt-injected agent | A scoped, short-lived token | Cannot see secrets in brokered mode. Can ask the broker to use a secret, so use is limited by destination, method, rate and value policy, and audited. |
| Operator or insider | Database, logs, deploy rights | No decryption path. Code delivery is the exposure: altered browser code could capture keys. Mitigate with CLI and native clients, signed builds with provenance, and channel-tag releases. A managed-host broker during a lease is a second exposure (section 6). |
| Revoked grantee | Old plaintext and wraps | Later versions are closed by epoch rotation. Copies already taken cannot be recalled. |
| Compromised device with the vault open | Memory, files | Out of scope, as in the threat model. Serving mode bounds the window with idle and maximum open time. |

## 3. Key hierarchy and slots

```text
slot secrets --wrap--> vault key (VK, random 256-bit, one per vault)
VK --wraps--> item version key (DEK, fresh random per version, owner copy)
DEK --encrypts--> item ciphertext
DEK --also wrapped to--> grantee epub, or group epoch key (shared items only)
```

- Per-vault key: serves the owner's devices and recovery. Adding a device rewrites only the keybag.
- Per-item keys for sharing: Check, epochs and revoke already work per object. A team vault is an item group that uses the existing group epoch key.
- Do not use the shared SEA `epub` as an owner slot. Enrollment copies the account keypair to each device, so that slot cannot be revoked per device. Use per-device keys, and keep SEA wraps for grantees.

### The daily slot

| Option | Verdict | Reason |
| --- | --- | --- |
| Key derived from an OIDC login | No | The IdP holds the password and mints every token, so anything derived from them is known to it. |
| Key derived from a wallet signature | Optional legacy slot only | ECDSA determinism is a convention (RFC 6979). ERC-1271 and smart-wallet signatures are contract or passkey based and are not a stable secret. Assumption: wallets were not tested. |
| Device key escrowed behind login | No | A server that releases the key after login can decrypt. That contradicts the no-escrow rule. |
| WebAuthn PRF passkey | Decided: daily slot for browser and mobile | Secret stays in the authenticator, needs user verification, syncs through the platform manager. Support varies by browser, OS and manager (third-party snapshots, August 2026). Per-origin `rp.id`. A synced passkey can be deleted, so a second slot is mandatory. |
| Native device key (Secure Enclave, Android Keystore, TPM) | Daily slot for CLI, phone and host | Non-exportable, one slot per device, enrolled through an already open slot. Cannot be backed up, so it never stands alone. |
| Recovery key (random 256 bits, shown once) | Mandatory | Same pattern as the s3r.ch paper key. Works offline. Losing it and every passkey makes the vault unrecoverable by design. |
| Passphrase (Argon2id) | Optional | Reuses the `SAVFILE1` parameters and the strength gate. The only slot an attacker with the file can attack offline. |

Optional multifactor decryption: an AND slot (the slot key is derived from two secrets) or a Shamir k-of-n slot where each share is wrapped to a different slot. Both need an audited library. The trustee form fits the existing `trustee` predicate.

## 4. Portable file format

| Candidate | Verdict |
| --- | --- |
| age | Poor fit. The scrypt stanza must be the only stanza, so a passphrase slot cannot sit beside other slots. Recipients are X25519 while SEA keys and passkeys are P-256. No authenticated metadata. |
| HPKE (RFC 9180) | Good primitive, not a file format. Would still need slot framing. Assumption: no WebCrypto support, so browsers need a library. |
| JWE General JSON (RFC 7516) | Decided. Multiple recipients, a protected header and external associated data are in the standard. ECDH-ES+A256KW and A256GCM run on WebCrypto, and `wrap.rs` and `reader-wrap.js` already use P-256 key agreement and AES-GCM. |
| COSE_Encrypt (RFC 9052) | Binary alternative if size matters. |
| KeePass KDBX4 | Model for composite keys and Argon2. No recipient list, no sharing. |
| `SAVFILE1` | Stays readable. Re-sealed to v2 on next write. |

Profile ("vault container v2", working name):

- Keybag: a JWE whose content key is the vault key. Recipients are the slots. `kid` is a random per-slot id, never a principal or object name.
- Item version: a JWE with a fresh content key (the DEK). Recipients are an `A256KW` entry under the vault key and, for shared items, `ECDH-ES+A256KW` entries to grantee `epub`s or the group epoch key. `enc` is `A256GCM`.
- The protected header carries the profile id and version, vault id, item id, version id, epoch and algorithm set id. The signed version manifest digest is external associated data, so a ciphertext cannot be moved to another version.
- Algorithm allowlist per profile version. Reject `alg` none, `zip`, `jku`, `jwk`, `x5u`, unknown critical headers, and unprotected headers that matter.
- Passphrase and PRF slots use Argon2id and HKDF with fixed parameter-set ids (never attacker-chosen values), carried as protected extension parameters, because PBES2 in JWE is PBKDF2 only.
- Shippable form: one JSON file holding the keybag, encrypted history and audit checkpoint, and item JWEs. Item caps stay at 1 MiB and 16 KiB.

Why the file is safe on untrusted storage: every secret-bearing field is authenticated encryption under a random key, slot secrets are high-entropy except the optional passphrase, headers are authenticated, versions are owner-signed and bound to ciphertext digests, and nothing in the file lets a server choose between versions. A replay of an older valid file is caught by the head floor (section 8), not by the file. Visible to the storage party: sizes, timing, slot count and algorithm kinds. Names, labels, owner, parents and epoch state stay encrypted, as in `secret-store-format.md`.

## 5. Sharing through SociACL

1. Grant: the owner states an edge on the item object (`delegate` with an action mask and optional `until`, or `same-group`). Check, not the wrap, is the permission.
2. Wrap: only for accessors the grant already names. The DEK is wrapped to the grantee `epub`, or the item joins a group whose epoch key is wrapped to members.
3. Read: the reader presents the grant. The destination runs Check, fresh epoch proof and signed-version admission (`read_authorized_local_vault`), then opens the wrap.
4. Revoke: privilege-down is immediate in Check. `rotate_on_revoke` starts a new epoch with wraps for the remaining readers, and sensitive items get a new version with a fresh DEK.

| Question | Decision |
| --- | --- |
| Per-item or per-vault keys for sharing | Per item, or per group epoch. |
| Read versus use | Read gets a wrap. Use gets no wrap: the grantee asks a broker that holds the wrap, mapped to the `execute` action. Revoking a use-only grantee is then complete because they never held a key. The mapping is a convention that needs documenting. |
| Rekey cost | Batch through group epoch keys, because wrap rows per principal are capped. |
| Wrap visibility | Opaque, capability-addressed `kid`. Raw `WrappedKey` labels are not published. |
| Copies already taken | The UI says revoke cannot recall plaintext already read. |

## 6. Agent access while serving

Serving means a human has opened the vault on a client or local broker (the Visor daemon or a CLI serve command). Decrypted keys live in that process only, with an idle timeout and a hard maximum. A server never decrypts by default.

### Tokens

| Property | Design |
| --- | --- |
| `iss`, `aud` | Issuer origin, and the exact vault broker audience. |
| `sub`, `agent` | Principal SEA key and agent SEA key. The agent never signs as its principal. |
| `delegationId`, `scopes` | Coarse scopes such as `vault:use` and `vault:list`. Scopes are capped at 32 entries of 64 characters, so a 64-hex item id cannot be a scope. Per-secret decisions come from Check on the item. |
| `exp` | Token at most 300 seconds. Interactive delegation 1 to 4 hours (policy choice). Lease 24 hours. |
| `jti` | Single use at exchange, logged on use. |
| `cnf` | Hash of the agent public key (RFC 7800), with DPoP proofs (RFC 9449) per request. The agent already holds a P-256 key. Today only the exchange step proves possession. |
| Signing | ES256 with a published key for the broker audience. HS256 with a shared secret is acceptable only inside one service. |

### Brokered use and plaintext

In v1 the broker performs the use: HTTP header injection, a git credential helper, an ssh-agent signer, child-process environment injection, wallet signing. Plaintext never enters model context, logs or transcripts. Child-process environment injection still places plaintext in that process, so it is limited and audited. Use policy limits hosts, methods, rate and value. Plaintext release to agents is deferred (slice H).

Controls: per-use audit with the existing `use` and `read` operations (an allowed entry records Check authorization, not delivery, and a log cannot prove completeness); a kill switch in four steps: seal the vault, publish a signed delegation revocation, drop the agent's ACL edge, and as a last resort rotate the SEA key, which invalidates every delegation.

### Unattended lease

Live, always-running agents keep working after the user disconnects, for a bounded time.

1. Open: while the user's session is live, the user opens a lease for one named agent. The owner signs it with the SEA key: agent, audience, granted items, maximum duration (default and cap 24 hours), renewal interval and grace window.
2. Hand over only what is granted: the broker makes a per-lease key pair in memory and wraps the current key of each granted item to it. When the user session ends, the broker drops the vault key and every other item key and keeps only the lease key and those wraps.
3. Renew: the agent renews with a fresh challenge signed by its own key plus a DPoP proof, and gets a token of at most 300 seconds bound to that key. Each renewal re-checks the delegation, revocations and Check on every granted item. A renewal never moves the hard expiry.
4. Extend: only the human, through a new signed lease while a session is live.

Timing (decided): renew every 2 minutes, 5 minute token, 5 minute grace after the last token expires. Keys drop within about 10 minutes of silence. The 24 hour cap equals the delegation contract maximum.

| The lease ends when | Detected by | Effect |
| --- | --- | --- |
| Renewals missed past grace | Broker timer | Keys dropped, calls refused |
| Hard expiry | Signed expiry in the lease record | Keys dropped, calls refused |
| User revoke | Signed delegation revocation plus an explicit seal | Immediate if the broker is reachable, otherwise at the next renewal or when grace passes |
| SociACL grant change | Check on every renewal and use; `rotate_on_revoke` on revoke | That item is refused at the next use. The lease ends if no item remains |

Versions of a granted item created after the user disconnects are not readable on the lease until the human reopens (assumption).

### Where the broker runs

| Placement | Holds keys | Risk |
| --- | --- | --- |
| User device (Visor daemon or CLI) | The user's machine | Best custody. A sleeping or offline device ends the agent's access, and the agent needs a reachable path. Device compromise exposes the granted items for the lease. |
| Host the user controls | A machine the user administers, enrolled with its own device key | Stays up, custody stays with the user. Host compromise exposes the granted items, and the user carries operations work. |
| Managed host | Operator-run memory | Always on. Unwrapped item keys sit where the operator, a compromised host or an insider can reach them for the lease. This weakens the no-server-side-decryption rule. |

Default: the user device or a host the user controls. The managed-host option ships in v1, off by default, as an explicit per-lease opt-in with its own consent text and an audit flag. On a managed host the broker holds only the granted item keys, never the vault key, and the shortest lease that fits. A hosted bot already running on managed infrastructure has its broker there, so it is the managed-host case.

### Standing subset (optional)

A chosen subset of items is wrapped to a host key (held in Key Vault or the host's own device key) so an agent can always reach those items with no live session. It is a normal SociACL grant to a host principal, so Check applies. Opt-in per item and never per vault; every use audited; removal runs `rotate_on_revoke` so later versions use a fresh key (versions the host already opened stay exposed). It has no time bound, so whoever can reach that key can read those items at any time. It suits scoped credentials such as one API key with its own limits.

## 7. Backup, restore and recovery

- Backup is copying the container. Add an export action and an optional scheduled copy to storage. A restore drill runs in the nightly batch.
- A restored copy has no head floor. Treat it as possibly stale until freshness is re-established from an owner-signed head checkpoint kept by an independent store. The existing witness checkpoints cover management policy snapshots, not vault heads, so a vault head checkpoint is new work (assumption).
- Lost passkey: open with the recovery-key slot, enroll a new passkey, remove the old slot.
- Lost every slot: only trustee shares, if configured, can help. Otherwise the vault is unrecoverable by design, and onboarding says so before the first secret is saved.
- Lost device with a device slot: remove the slot. If its vault key may have escaped, rotate the vault key and re-encrypt sensitive items, because an old file copy still opens with the old key.
- Account identity recovery stays separate (`recovery.rs`, keyring store). OIDC or SIWE only gates the fetch of that ciphertext.

## 8. Storage placement and sync

| Location | Limit found | Use |
| --- | --- | --- |
| s3r.ch record store (`lib/record-store.ts`) | 8 MiB per record, names of 1 to 128 characters, namespaces `cache`, `recovery`, `fixtures`, `media`, conditional writes by revision | Head and keybag records. A `vault` namespace is missing. |
| s3r.ch object store | 64 MiB per object, 256 MiB per tenant, addressed by SHA-256 | Immutable item version ciphertext. |
| Spanopticon tenant storage | Same adapters. The service-side record limit was not read (assumption) | Decided home: one shared space for Spanopticon and s3r.ch users. |
| acl-service Postgres | Wrap and recovery ciphertext per principal, up to 64 rows | Slot and wrap metadata SociACL already owns. |
| Vault item | 1 MiB item, 16 KiB metadata, 256-entry history | Every item fits any of the above. |

The s3r.ch record store is itself an adapter over Spanopticon (or optionally Azure Blob), so one storage contract serves both user groups. What is missing is a vault namespace, the head floor and conflict storage, not capacity.

Sync: write immutable objects, then compare-and-swap the head with the previous revision. If the swap fails, fetch the head: a descendant fast-forwards; anything else keeps both heads (as `VaultVersionHistory` does) and a merge is a new signed version naming its parents. On read, check the fetched head against the locally retained floor first. Raising the 256-entry cap needs an authenticated checkpoint design.

## 9. Rotation and crypto agility

| What rotates | How | Cost |
| --- | --- | --- |
| Slot added or removed | Rewrap the vault key in the keybag | One small record |
| Item key | Fresh DEK on every version (already true) | None extra |
| Vault key | New VK, rewrap owner DEK copies, re-encrypt sensitive items | Linear in items |
| Reader set | `rotate_on_revoke`: new epoch and wraps | Per shared item or group |
| Account key | Existing keyring rotation; invalidates all delegations | Wraps move to the new `epub` |
| Passkey | Enroll a new credential, drop the old slot | One record |

- Every slot and item carries an algorithm set id inside the authenticated header. Each profile version has an allowlist, and the retained head stores a minimum profile version so an attacker cannot downgrade.
- KDF costs stay fixed per set id (ceiling equals floor today). A cost increase is a new set id and a re-wrap on next open.
- A post-quantum or hybrid slot kind can be added without changing the item format. Not proposed now.
- `SAVFILE1` stays readable and a reseal tool upgrades it. Rust and TypeScript share vectors under `vectors/vault/`.

## 10. Vertical slices

Proposed order, all in v1 after the spine slices at the front of that queue. Slice G is optional and slice H is deferred. Each slice ends with a done check of contract tests plus a scoped CI smoke. Real-browser, real-time and TEST-storage runs belong to the nightly batch.

### A. Own vault with a multi-slot file (v1)

Outcome: a user creates a vault with a passkey (or device key) slot and a recovery-key slot, saves and reads items in the container v2 file from the CLI and a browser panel, and existing v1 files still import.

- [ ] Data: container v2 schema (profile id, algorithm allowlist, slot record, keybag, item version layout), carrying over the 1 MiB item and 16 KiB metadata caps and adding a slot-count cap.
- [ ] Data: shared vectors under `vectors/vault/` for seal, open, tamper, slot add and remove, downgrade, unknown algorithm and v1 import.
- [ ] Crypto core (Rust): keybag and item seal and open, strict header validation, Argon2id and HKDF parameter-set ids.
- [ ] Crypto core (TypeScript): the same on WebCrypto, checked against the same vectors.
- [ ] Slot kinds: PRF passkey, native device key, recovery key, optional passphrase (reusing the existing strength gate).
- [ ] SAVFILE1 reader and a reseal tool.
- [ ] SociACL checks: compose the signed-manifest digest as external associated data and route reads through `read_authorized_local_vault`.
- [ ] CLI: create, open, put, get, export, slot add and remove.
- [ ] Browser panel in s3r.ch: open a file with the passkey, show the recovery key once.
- [ ] Docs: update the secret-store design set.
- [ ] Done check: contract tests on the shared Rust and TypeScript vectors, plus a scoped CI smoke that runs a CLI round trip with a software PRF stub. Real browser PRF runs only in the nightly batch.

### B. Sync to shared Spanopticon storage (v1)

Outcome: the same vault opens on two devices through the shared Spanopticon storage space, with conflicts kept visible and rollback caught.

- [ ] Storage: a `vault` namespace in the record store for the head and keybag (conditional writes by revision), and immutable objects for item versions.
- [ ] Storage: a durable, independently held head floor on each client.
- [ ] Data: an authenticated checkpoint design that lifts the 256-entry version history cap.
- [ ] Crypto core: signed head record and merge versions that name all parents.
- [ ] Service and API: record-store permissions for the vault namespace on the shared space, and size checks against the 8 MiB record limit.
- [ ] SociACL checks: owner-signed writes, so a session alone cannot replace the head.
- [ ] CLI and UI: sync, status and conflict display.
- [ ] Done check: contract tests for compare-and-swap, conflict heads, rollback and stale head, plus a CI smoke against an in-process storage fake. Real TEST storage runs in the nightly batch.

### C. Backup and recovery (v1)

Outcome: a user exports and restores a vault, a restored copy is flagged stale until its freshness is re-established, and a lost passkey is recovered with the recovery key.

- [ ] Data: owner-signed head checkpoint record.
- [ ] Storage: an independent checkpoint store and the durable wrap and recovery APIs from acl-service#13 (prerequisite).
- [ ] Crypto core: recovery-key rotation and vault-key rotation (rewrap, re-encrypt sensitive items).
- [ ] Service and API: checkpoint publish and fetch.
- [ ] SociACL checks: login gates the fetch of slot and recovery ciphertext and never acts as a key.
- [ ] CLI and UI: export, restore with a staleness warning, lost-passkey flow, scheduled copy.
- [ ] Done check: contract tests that an old backup is flagged stale, the recovery key opens, and rotation removes the old slot, plus a CI smoke restoring from a fixture. The restore drill runs in the nightly batch.

### D. Share and revoke (v1)

Outcome: an owner shares an item with another SociACL principal or group and revokes it, with new versions closed to the revoked reader.

- [ ] Data: capability-addressed recipient ids and confidential wrap manifests (no raw target or object labels in sync bytes).
- [ ] Crypto core: grantee slots (P-256 key agreement plus key wrap) and group epoch key wraps.
- [ ] Service and API: wrap storage that stays under the per-principal row cap by using group epoch keys.
- [ ] SociACL checks: grant edges, the named-set rule, fresh epoch proof on read, and `rotate_on_revoke` wired to vault versions with re-encryption of sensitive items.
- [ ] Docs: state that revoke cannot recall plaintext already read.
- [ ] CLI and UI: share, list grants, revoke.
- [ ] Done check: contract tests that a revoked reader fails on the next version, a stale epoch fails closed and an unauthorized wrap is refused, plus a scoped CI smoke with two test principals.

### E. Brokered agent use and unattended lease (v1)

Outcome: an agent uses a secret through a broker without seeing it, and a live agent keeps working for up to 24 hours after the user disconnects on a renewable lease.

- [ ] Data: lease record built on the delegation record (agent, audience, granted items, duration up to 24 hours, renewal interval, grace) and the vault-audience token claims (`sub`, `agent`, `delegationId`, `scopes`, `jti`, `cnf`).
- [ ] Storage: lease state held in broker memory only, and an append-only audit stream for use and read operations.
- [ ] Crypto core: per-lease key pair, wraps of only the granted item keys, zeroization when the lease ends.
- [ ] Service and API: ES256 token issuer with a published key for the vault audience, renewal with a single-use challenge and DPoP proof, token life of 5 minutes.
- [ ] SociACL checks: Check on the item for every use and every renewal, delegation and revocation re-check, and a documented mapping of use onto the `execute` action.
- [ ] Broker: serving mode in the Visor broker with idle and maximum open time, HTTP header injection, git credential helper, use policy (hosts, methods, rate, value), kill switch.
- [ ] Lease timing: renew every 2 minutes, 5 minute token, 5 minute grace, 24 hour cap, extension only through a new human-signed lease.
- [ ] Broker placement: user device or user-controlled host by default, and a managed-host option that ships off by default with a per-lease opt-in, consent text and audit flag.
- [ ] CLI and UI: open, list, seal and revoke leases, and the managed-host consent step.
- [ ] Done check: contract tests with a fake time source (scope narrowing, expired or revoked delegation, replayed `jti`, key mismatch, secret absent from logs, missed renewals past grace drop the keys, hard expiry ends the lease, revoke and grant change end it, renewal cannot move expiry, extension needs a new signed lease, managed-host use refused without opt-in), plus a CI smoke against a fake upstream. Real-time runs only in the nightly batch.

### F. Optional multifactor decryption (later v1)

Outcome: a vault can require two secrets (AND slot) or k of n trustees (threshold slot) to open.

- [ ] Data: AND-slot and threshold-slot records.
- [ ] Crypto core: derivation from two slot secrets and Shamir sharing of the vault key, each share wrapped to a separate slot, using an audited library.
- [ ] SociACL checks: trustee principals use the existing `trustee` predicate.
- [ ] CLI and UI: guided setup.
- [ ] Done check: contract tests that any k of n opens and k minus one fails, plus a scoped CI smoke of guided setup.

### G. Standing subset (optional, late v1)

Outcome: a user opts in specific items so an agent can always reach them with no live session.

- [ ] Data: per-item opt-in flag in the encrypted item metadata.
- [ ] Crypto core: wrap of the item key to a host or Key Vault key as a normal grantee.
- [ ] Service and API: host key enrollment and audit on every use.
- [ ] SociACL checks: grant to a host principal, `rotate_on_revoke` on removal so later versions use a fresh key.
- [ ] Broker: serve flagged items to the named agent with no session.
- [ ] CLI and UI: a short named list of standing items.
- [ ] Done check: contract tests that only flagged items are wrapped, revoke gives a fresh key and the old wrap fails on the new version, each use writes an audit entry and an unflagged item is refused, plus a CI smoke with a test host key.

### H. Plaintext release (deferred)

Outcome: decided after the broker has handled real cases. Agents get no plaintext in v1.

- [ ] Revisit after slice E has run on real cases, then design a read action with per-use approval and a temporary private mount.
- [ ] Done check when scheduled: contract tests that approval is required and files are cleaned up on stop and revoke, plus a scoped CI smoke.

## 11. Assumptions and limits

- PRF support figures come from third-party snapshots dated August 2026, not first-party tests.
- Wallet signature behavior is reasoned from the specifications, not tested.
- The service-side Spanopticon record limit was not read.
- Whether HPKE exists in WebCrypto was not checked.
- The `execute` as use mapping, the 1 to 4 hour interactive delegation length, the per-lease key design and the vault head checkpoint are proposals.
- Later versions of a granted item are not readable on a lease after the user disconnects.
- Nothing here has had an independent security review.
