/** Product-independent lost-device recovery preparation and retry lifecycle. */
import { rotateKeyring, type AccountKeyring, type KeyringRotation, type RotationMint } from './account-keyring.ts';
import { ARGON2ID_LIMITS } from './keyring-limits.ts';
import { sealRecoveryCopyWith, signRecoveryOp, type RecoveryCopyStore, type RecoveryEnvelope } from './recovery-seal.ts';
import { recoveryEnvelopeHash, REPLACED_NONE } from './store-write.ts';
import type { ResolutionContext } from '../ids/src/index.js';

export type RecoveryRotationState = 'prepared' | 'pending' | 'committed' | 'cancelled';
export type RecoveryRotationFlow = {
  readonly rotation: KeyringRotation;
  readonly state: RecoveryRotationState;
  /** Returns a defensive ciphertext copy, never a passphrase. */
  envelope(): RecoveryEnvelope;
  /** Persist before publishing the rotation. Retries re-read and re-sign. */
  persist(): void;
  /** After authenticated publication, promote exactly this pending copy. */
  commit(): void;
  /** Stop this flow; never delete persisted copies or undo a published rotation. */
  cancel(): void;
};

const copy = (e: RecoveryEnvelope): RecoveryEnvelope => ({ ...e, bytes: new Uint8Array(e.bytes) });
const hash = (e: RecoveryEnvelope | undefined): string => e ? recoveryEnvelopeHash(e) : REPLACED_NONE;
const same = (a: RecoveryEnvelope | undefined, b: RecoveryEnvelope): boolean => !!a &&
  a.principal === b.principal && a.rotationSeq === b.rotationSeq &&
  a.signingPub === b.signingPub && a.epub === b.epub && hash(a) === hash(b);

/**
 * Pass an already authenticated recovered keyring (openRecoveryCopy verifies
 * historical backups without applying today's seal-strength rule). Explicitly
 * choose newPassphrase; its bytes are copied before the asynchronous checker.
 * Preparation performs no recovery put, commit, delete, or chain publication.
 */
export async function prepareRecoveryRotation(options: {
  recovered: AccountKeyring;
  newPassphrase: Uint8Array;
  trusted: readonly string[];
  lost: string;
  rotations: readonly unknown[];
  context: ResolutionContext;
  store: RecoveryCopyStore;
  mint: () => RotationMint;
  handle?: string;
  signal?: AbortSignal;
}): Promise<RecoveryRotationFlow> {
  const { recovered, store, signal } = options;
  signal?.throwIfAborted();
  const passphrase = new Uint8Array(options.newPassphrase);
  let predecessor: string;
  const salt = new Uint8Array(ARGON2ID_LIMITS.saltLength.floor);
  const nonce = new Uint8Array(12);
  let rotation: KeyringRotation;
  let sealed: RecoveryEnvelope;
  try {
    predecessor = hash(store.pending(recovered.principal));
    crypto.getRandomValues(salt); crypto.getRandomValues(nonce);
    rotation = rotateKeyring(recovered, options.trusted, options.lost,
      options.rotations, options.context, options.mint);
    // Existing sealing constructs the canonical CAS signature. Stage only the
    // ciphertext here: persistence below re-reads all inputs and signs afresh.
    const staging = new Proxy(store, {
      get(target, property) {
        if (property === 'put') return () => { signal?.throwIfAborted(); };
        const value = Reflect.get(target, property, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    sealed = await sealRecoveryCopyWith(rotation.keyring, passphrase, salt, nonce,
      recovered.currentPriv(), staging, options.handle);
    signal?.throwIfAborted();
  } finally {
    passphrase.fill(0); salt.fill(0); nonce.fill(0);
  }
  let state: RecoveryRotationState = 'prepared';
  const committed = () => state === 'committed';
  const active = () => {
    signal?.throwIfAborted();
    if (state === 'cancelled') throw new Error('recovery-cancelled');
  };
  const reconcile = () => {
    const account = store.publishedAccount(sealed.principal);
    if (same(store.current(sealed.principal), sealed) &&
        account.currentKey === sealed.signingPub && account.currentEpub === sealed.epub &&
        account.rotations.length === sealed.rotationSeq) {
      state = 'committed'; return true;
    }
    if (same(store.pending(sealed.principal), sealed) &&
        ((account.currentKey === recovered.pub && account.rotations.length === recovered.rotationSeq) ||
         (account.currentKey === sealed.signingPub && account.currentEpub === sealed.epub &&
          account.rotations.length === sealed.rotationSeq))) {
      state = 'pending'; return true;
    }
    return false;
  };
  return {
    rotation,
    get state() { return state; },
    envelope: () => copy(sealed),
    persist() {
      active();
      if (reconcile()) return;
      const account = store.publishedAccount(recovered.principal);
      if (account.currentKey !== recovered.pub || account.rotations.length !== recovered.rotationSeq ||
          hash(store.pending(recovered.principal)) !== predecessor) throw new Error('recovery-conflict');
      const signature = signRecoveryOp(store, recovered.currentPriv(), sealed.principal, 'put',
        sealed.rotationSeq, hash(sealed), predecessor);
      active();
      try { store.put(copy(sealed), signature); }
      catch (error) { if (!reconcile()) throw error; return; }
      if (!reconcile()) throw new Error('recovery-persistence-unconfirmed');
    },
    commit() {
      active();
      reconcile();
      if (state === 'committed') return;
      const account = store.publishedAccount(sealed.principal);
      if (state !== 'pending' || !same(store.pending(sealed.principal), sealed) ||
          account.currentKey !== sealed.signingPub || account.currentEpub !== sealed.epub ||
          account.rotations.length !== sealed.rotationSeq) throw new Error('recovery-conflict');
      const signature = signRecoveryOp(store, rotation.keyring.currentPriv(), sealed.principal, 'commit',
        sealed.rotationSeq, hash(sealed), hash(store.current(sealed.principal)));
      active();
      try { store.commit(sealed.principal, signature); }
      catch (error) { reconcile(); if (!committed()) throw error; return; }
      reconcile();
      if (!committed()) throw new Error('recovery-persistence-unconfirmed');
    },
    cancel() { if (state !== 'committed') state = 'cancelled'; },
  };
}
