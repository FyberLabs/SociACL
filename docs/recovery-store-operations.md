# Recovery store trust and restoration

The recovery and wrap stores hold ciphertext. They do not establish account
identity. This guide describes the reference stores and requirements for a
production adapter; it does not claim that Panopticon implements persistence or
an operator restore endpoint.

## Resolver boundary

The injected resolver must run `resolveCurrentKey` / `resolve_current_key` over
an authenticated account-history snapshot with the required links, revocations,
genesis-epub bindings, pinned witness keys, and policy. Return its accepted
current key, current epub, and rotation chain. Propagate a failed resolution as
a rejection. Do not manufacture a resolved account from caller fields, a session
identity, an unsigned Gun field, or an index's claim that history is complete.
A resolver must also enforce the application's freshness and completeness
requirements; signature verification alone cannot detect omitted history.

The TypeScript structural result type and Rust `PublishedChain` interface are
trust boundaries, not proofs that the callback performed these checks. The
memory stores trust the injected resolver. Production adapter enforcement is
still tracked in #68 F14; durable state is F16. Both stores for a principal must
share the same monotonic floor. A resolver read, including one during a rejected
write, can raise that floor.

## Unknown genesis encryption key

At the resolved head, a recovery put requires the envelope's signing public key
to equal the authenticated current signing key. It compares the envelope epub
with `currentEpub` only when that value is known. At genesis without a witnessed
genesis-epub binding, `currentEpub` is null: the store can accept an arbitrary epub
label signed by the current signing key. The label is covered by the full
envelope hash in the store-write signature, but that does not prove possession
of the corresponding encryption secret or bind that key to the account.

This is ciphertext storage acceptance, not a successful recovery, a verified
epub, or permission to encrypt new content to that key. Callers must not use a
stored envelope label to fill in an unknown resolver epub. New content seals
still require the witnessed binding or an accepted rotation. Opening recovery
must authenticate and decode the ciphertext and validate the restored keyring
against the resolved account state; do not mark a backup usable merely because
a put succeeded. The same unknown-epub limitation applies to a historical v2
head that has no authenticated encryption-key binding.

## Restoring a store without lowering its floor

There is no supported online floor reset or operator override that lowers an
existing principal's floor. A stale resolver response is a reason to recover
missing history, not to construct a fresh `HeadFloor` to make a write pass.

1. Pause writes for the principal across both stores and all replicas. Keep the
   existing rows, current and pending slots, generation counters, and shared
   floor; preserve an authenticated snapshot for diagnosis.
2. Repair the resolver's source and resolve the full authenticated history. A
   fork, missing history, or head below the saved floor keeps writes paused.
   Do not accept a self-declared sequence or an unsigned draft to raise a head.
3. Restore the latest trusted state of both stores together. Preserve generation
   counters even for deleted rows and empty slots, and preserve the greatest
   floor previously observed by either store. An old backup alone is not proof
   of the latest generation or floor: reconcile with authoritative durable
   state before resuming. Never roll back generations to make old signatures
   usable again.
4. Under the adapter's single-writer boundary, restore rows and generations and
   initialize the shared floor to at least the saved floor, the resolved head,
   and every stored current recovery sequence. Pending copies do not raise the
   floor. Resume only after verifying that both stores use that same state.
5. Clients re-read the predecessor row and write generation, then sign a fresh
   operation. A `store-rejected` response is not permission to replay the old
   signature or clear the floor.

If the saved floor was poisoned by an unauthenticated resolver, repair the trust
boundary first. If no authenticated history reaches that floor, or the latest
floor/generations cannot be recovered, these APIs provide no safe in-place reset.
Keep the affected identity blocked; use an explicitly reviewed migration to a
new identity if recovery is impossible. That migration does not automatically
transfer grants. The in-memory stores have no durable restore API; implementing
these atomic restoration steps for a production adapter remains F16.
