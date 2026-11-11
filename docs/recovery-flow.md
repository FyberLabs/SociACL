# Reusable lost-device recovery flow

SociACL is a general library. This contract is not owned by s3r.ch, Visor, or any
particular UI. `prepareRecoveryRotation` is exported from
`typescript/contract/recovery.ts`; the reference lifecycle is
`typescript/contract/recovery-flow.ts`. CLI, browser, desktop and other callers
can present their own explicit choice of a new recovery passphrase.

1. Restore using `openRecoveryCopy` with the expected principal, minimum sequence
   and authenticated history/context. Opening an old backup does not apply
   today's strength rules. An error named `recovery-stale` is not an authenticated
   delivery; do not substitute its contents for a successfully opened keyring.
2. Ask for a new passphrase. Pass its bytes explicitly as `newPassphrase` to
   `prepareRecoveryRotation`, together with the recovered keyring, device list,
   lost device, authenticated history/context, store and rotation-key generator.
   There is no implicit fallback to the old passphrase. The byte API snapshots
   exactly those bytes before awaiting the strength checker and KDF; it does not
   trim or normalize. Callers choosing the string API can explicitly encode
   first with `encodePassphrase`, whose existing NFC rule is documented.
3. Await preparation. Existing canonical rotation/history validation and the
   asynchronous seal-strength checker run before a flow is returned. The result
   is `prepared`, not persisted, published or authenticated by a UI flag. The
   old recovery copy stays untouched. Internal passphrase, salt and nonce byte
   copies are wiped after preparation; caller buffers remain caller-owned.
4. Call `persist()` before publishing the rotation. The exact prepared ciphertext
   is put as pending with a fresh compare-and-swap signature. Failure leaves the
   same flow retryable, without generating another rotation or rerunning the KDF.
   Every retry reads current authority, predecessor and generation. If another
   pending copy replaced the captured predecessor, return `recovery-conflict`;
   do not silently overwrite a competing rotation. An unrelated generation
   change can be retried with a new signature.
5. Publish the rotation through the existing authenticated history/attestation
   protocol. The flow does not publish, attest, create a session or mint grants.
   Once the store's independent resolver observes the exact new key, epub and
   sequence, `commit()` promotes exactly this pending copy. An unpublished or
   different head fails closed.

The states are `prepared`, `pending`, `committed`, and `cancelled`. A lost put or
commit response is reconciled by exact ciphertext and public-field read-back;
a successful read-back avoids an unnecessary second write. This is the storage
adapter's persistence contract, not proof of durability against a malicious
server. The adapter must still verify canonical store-write signatures and
preserve its floor/generation transaction boundary. The existing store interface
is synchronous; this controller does not invent a network protocol or relax
that interface for remote implementations.

An AbortSignal is checked before preparation, after asynchronous sealing and
before mutations. It cannot interrupt the KDF itself, but abort during that work
causes rejection before persistence. `cancel()` blocks future operations on this
flow. Neither cancellation method deletes a durable pending/current backup,
lowers a floor or reverses a published rotation. If publication may have happened,
resume through authenticated history and storage reconciliation. Cancelling an
already committed flow leaves it committed. Keep secret-bearing flow objects
in local custody; only ciphertext goes to storage.

Coverage in `typescript/tests/test_recovery.ts` includes old-backup restoration,
authenticated new-key publication, exact decomposed/whitespace passphrase bytes,
mutation of the caller buffer while strength checking is asynchronous, failures
before persistence, lost successful put/commit responses, competing pending
writes, fresh-generation retry, weak new-passphrase refusal and cancellation.
Existing legacy-strength and stale/forged-delivery tests remain in the same
unit/contract suite. Applications need no special tenant or live fixture to use
this library contract. Deployment acceptance remains in the owning nightly CI.
