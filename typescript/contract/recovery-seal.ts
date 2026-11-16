/**
 * Recovery-copy cryptography. Not a package export. Caller-chosen salt and
 * nonce are wrapped for tests in typescript/tests/support/recovery-deterministic.ts.
 *
 * Argon2id runs in hash-wasm. That build has no pthreads. Lanes for p=4 are
 * the serial loop in its Argon2 implementation, which is the same module a
 * browser loads.
 */
import { createCipheriv, createDecipheriv } from "node:crypto";
import { parsePrincipalId, type PrincipalId, type ResolutionContext } from "../ids/src/index.js";
import { AccountKeyring } from "./account-keyring.ts";
import { canonicalDecimal } from "./canonical.ts";
import { decodeKeyring, encodeKeyring } from "./keyring-codec.ts";
import {
  ARGON2ID_LIMITS,
  KEYRING_SERIAL_MAX,
  RECOVERY_ABSOLUTE_MAX,
  RECOVERY_NONCE_LEN,
} from "./keyring-limits.ts";
import { checkRecoveryPassphrase } from "./passphrase-strength.ts";
import {passphraseRejected,deriveKey,parseHeader,writeHeader,recoveryAad,headerRotationSeq} from "./recovery-wire.ts";
export {encodePassphrase,DOMAIN_RECOVERY} from "./recovery-wire.ts";
import {
  HeadFloor,
  nextStoreGeneration,
  recoveryEnvelopeHash,
  REPLACED_NONE,
  signStoreWrite,
  STORE_CLASS_NONE,
  verifyStoreWrite,
  type StoreWriteAccount,
} from "./store-write.ts";


export type RecoveryEnvelope = {
  readonly principal: PrincipalId;
  readonly rotationSeq: number;
  readonly signingPub: PrincipalId;
  readonly epub: PrincipalId;
  readonly bytes: Uint8Array;
};

/** Ciphertext adapter. Not an authority, and not Gun.
 *
 * The store reads the published chain from `publishedAccount`. The writer
 * does not pass one. Every put, commit, and delete carries a compare-and-swap
 * signature by the head key that resolver reports. Adapters, Panopticon
 * included, must verify that signature before they write. Session
 * authentication is not this check. Panopticon reads the published Gun chain.
 * It is a verifier and a witness. It is never the authority.
 *
 * A put at the resolved head replaces the current copy and drops any pending
 * copy. A put at head + 1 is the only pending copy. Any other sequence is
 * `store-rejected` and changes nothing. A rejected commit leaves both copies
 * where they were.
 */
export interface RecoveryCopyStore {
  readonly isAuthority: false;
  readonly seesPlaintext: false;
  readonly seesPassphrase: false;
  publishedAccount(principal: PrincipalId): StoreWriteAccount;
  writeGeneration(principal: PrincipalId): number;
  put(envelope: RecoveryEnvelope, signature: string): void;
  get(principal: PrincipalId, rotationSeq: number): RecoveryEnvelope | undefined;
  current(principal: PrincipalId): RecoveryEnvelope | undefined;
  pending(principal: PrincipalId): RecoveryEnvelope | undefined;
  commit(principal: PrincipalId, signature: string): void;
  delete(principal: PrincipalId, rotationSeq: number, signature: string): void;
}

type RecoverySlot = { current?: RecoveryEnvelope; pending?: RecoveryEnvelope };

export class MemoryRecoveryStore implements RecoveryCopyStore {
  readonly isAuthority = false as const;
  readonly seesPlaintext = false as const;
  readonly seesPassphrase = false as const;
  /** Current copy per principal, plus at most one pending copy at head + 1. */
  readonly #slots = new Map<string, RecoverySlot>();
  readonly #floor: HeadFloor;
  readonly #generation = new Map<string, number>();
  readonly #chain: (principal: PrincipalId) => StoreWriteAccount;

  /** Share this floor with the wrap store for the same principals. */
  constructor(chain: (principal: PrincipalId) => StoreWriteAccount, floor: HeadFloor) {
    if (!(floor instanceof HeadFloor)) throw new Error("store-rejected");
    this.#chain = chain;
    this.#floor = floor;
  }

  publishedAccount(principal: PrincipalId): StoreWriteAccount {
    const account = this.#chain(principal);
    this.#floor.observe(principal, account.rotations.length);
    return account;
  }

  writeGeneration(principal: PrincipalId): number {
    return this.#generation.get(principal) ?? 0;
  }

  put(envelope: RecoveryEnvelope, signature: string): void {
    if (envelope.bytes.length === 0 || envelope.bytes.length > RECOVERY_ABSOLUTE_MAX) throw new Error("store-rejected");
    if (headerRotationSeq(envelope.bytes) !== envelope.rotationSeq) throw new Error("store-rejected");
    const account = this.#account(envelope.principal);
    const head = account.rotations.length;
    const slot = this.#slots.get(envelope.principal);
    if (slot?.current && slot.current.rotationSeq > head) throw new Error("store-rejected");
    const atHead = envelope.rotationSeq === head;
    const atNext = envelope.rotationSeq === head + 1;
    if (!atHead && !atNext) throw new Error("store-rejected");
    const replaced = predecessor(atHead ? slot?.current : slot?.pending);
    const hash = recoveryEnvelopeHash(envelope);
    const generation = this.writeGeneration(envelope.principal);
    const nextGeneration = nextStoreGeneration(generation);
    verifyStoreWrite(
      envelope.principal,
      "put",
      canonicalDecimal(envelope.rotationSeq),
      hash,
      canonicalDecimal(head),
      replaced,
      STORE_CLASS_NONE,
      canonicalDecimal(generation),
      signature,
      account,
    );
    const copy = copyEnvelope(envelope);
    if (atHead) {
      if (copy.signingPub !== account.currentKey || (account.currentEpub !== null && copy.epub !== account.currentEpub)) {
        throw new Error("store-rejected");
      }
      this.#slots.set(envelope.principal, { current: copy });
      this.#bump(envelope.principal, head, nextGeneration);
      return;
    }
    this.#slots.set(envelope.principal, { current: slot?.current, pending: copy });
    this.#bump(envelope.principal, head, nextGeneration);
  }

  get(principal: PrincipalId, rotationSeq: number): RecoveryEnvelope | undefined {
    const slot = this.#slots.get(principal);
    if (!slot) return undefined;
    if (slot.current?.rotationSeq === rotationSeq) return copyEnvelope(slot.current);
    if (slot.pending?.rotationSeq === rotationSeq) return copyEnvelope(slot.pending);
    return undefined;
  }

  current(principal: PrincipalId): RecoveryEnvelope | undefined {
    const current = this.#slots.get(principal)?.current;
    return current ? copyEnvelope(current) : undefined;
  }

  pending(principal: PrincipalId): RecoveryEnvelope | undefined {
    const pending = this.#slots.get(principal)?.pending;
    return pending ? copyEnvelope(pending) : undefined;
  }

  commit(principal: PrincipalId, signature: string): void {
    const account = this.#account(principal);
    const slot = this.#slots.get(principal);
    const pending = slot?.pending;
    if (!slot || !pending) throw new Error("store-rejected");
    const head = account.rotations.length;
    const hash = recoveryEnvelopeHash(pending);
    const generation = this.writeGeneration(principal);
    const nextGeneration = nextStoreGeneration(generation);
    verifyStoreWrite(
      principal,
      "commit",
      canonicalDecimal(head),
      hash,
      canonicalDecimal(head),
      predecessor(slot.current),
      STORE_CLASS_NONE,
      canonicalDecimal(generation),
      signature,
      account,
    );
    const pubsMatch =
      pending.rotationSeq === head &&
      account.currentEpub !== null &&
      pending.signingPub === account.currentKey &&
      pending.epub === account.currentEpub;
    if (!pubsMatch) throw new Error("store-rejected");
    slot.current = pending;
    slot.pending = undefined;
    this.#bump(principal, head, nextGeneration);
  }

  delete(principal: PrincipalId, rotationSeq: number, signature: string): void {
    const account = this.#account(principal);
    const head = account.rotations.length;
    const slot = this.#slots.get(principal);
    const stored =
      slot?.current?.rotationSeq === rotationSeq
        ? slot.current
        : slot?.pending?.rotationSeq === rotationSeq
          ? slot.pending
          : undefined;
    if (!slot || !stored) throw new Error("store-rejected");
    const hash = recoveryEnvelopeHash(stored);
    const generation = this.writeGeneration(principal);
    const nextGeneration = nextStoreGeneration(generation);
    verifyStoreWrite(
      principal,
      "delete",
      canonicalDecimal(rotationSeq),
      hash,
      canonicalDecimal(head),
      hash,
      STORE_CLASS_NONE,
      canonicalDecimal(generation),
      signature,
      account,
    );
    if (slot.current?.rotationSeq === rotationSeq) slot.current = undefined;
    if (slot.pending?.rotationSeq === rotationSeq) slot.pending = undefined;
    if (!slot.current && !slot.pending) this.#slots.delete(principal);
    this.#bump(principal, head, nextGeneration);
  }

  #account(principal: PrincipalId): StoreWriteAccount {
    try {
      return this.publishedAccount(principal);
    } catch (error) {
      if (error instanceof Error && error.message === "store-rejected") throw error;
      throw new Error("store-rejected");
    }
  }

  #bump(principal: string, head: number, nextGeneration: number): void {
    this.#floor.raise(principal, head);
    const current = this.#slots.get(principal)?.current;
    if (current) this.#floor.raise(principal, current.rotationSeq);
    this.#generation.set(principal, nextGeneration);
  }
}

function predecessor(row: RecoveryEnvelope | undefined): string {
  return row ? recoveryEnvelopeHash(row) : REPLACED_NONE;
}

export function signRecoveryOp(
  store: RecoveryCopyStore,
  signerPriv: string,
  principal: PrincipalId,
  operation: string,
  target: number,
  envelopeHash: string,
  replaced: string,
): string {
  const account = store.publishedAccount(principal);
  return signStoreWrite(
    signerPriv,
    principal,
    operation,
    canonicalDecimal(target),
    envelopeHash,
    canonicalDecimal(account.rotations.length),
    replaced,
    STORE_CLASS_NONE,
    canonicalDecimal(store.writeGeneration(principal)),
  );
}

function copyEnvelope(envelope: RecoveryEnvelope): RecoveryEnvelope {
  return {
    principal: envelope.principal,
    rotationSeq: envelope.rotationSeq,
    signingPub: envelope.signingPub,
    epub: envelope.epub,
    bytes: new Uint8Array(envelope.bytes),
  };
}

/** Caller-chosen salt and nonce. Tests use this through the support wrapper. */
export async function sealRecoveryCopyWith(
  keyring: AccountKeyring,
  passphrase: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  signerPriv: string,
  store: RecoveryCopyStore,
  handle?: string,
): Promise<RecoveryEnvelope> {
  if (keyring.priorLanes().length !== keyring.rotationSeq) throw new Error("bad-lane");
  if (passphraseRejected(passphrase)) throw new Error("recovery-params");
  if (
    salt.length < ARGON2ID_LIMITS.saltLength.floor ||
    salt.length > ARGON2ID_LIMITS.saltLength.ceiling ||
    nonce.length !== RECOVERY_NONCE_LEN
  ) {
    throw new Error("recovery-params");
  }
  // The async strength gate and KDF must consume the same bytes even if the
  // caller mutates its buffer while the estimator is loading.
  const checkedPassphrase = new Uint8Array(passphrase);
  let plain: Uint8Array | undefined;
  let key: Uint8Array | undefined;
  try {
    await checkRecoveryPassphrase(checkedPassphrase, keyring.principal, handle);
    plain = encodeKeyring(keyring);
    key = await deriveKey(
      checkedPassphrase,
      salt,
      ARGON2ID_LIMITS.memoryKiB.floor,
      ARGON2ID_LIMITS.iterations.floor,
      ARGON2ID_LIMITS.parallelism.floor,
      ARGON2ID_LIMITS.hashLength.floor,
    );
    const aad = recoveryAad(
      keyring.principal,
      keyring.rotationSeq,
      keyring.pub,
      keyring.epub,
      ARGON2ID_LIMITS.memoryKiB.floor,
      ARGON2ID_LIMITS.iterations.floor,
      ARGON2ID_LIMITS.parallelism.floor,
      ARGON2ID_LIMITS.hashLength.floor,
      ARGON2ID_LIMITS.version.floor,
      salt,
    );
    const ciphertext = aesEncrypt(key, nonce, aad, plain);
    const header = writeHeader(
      ARGON2ID_LIMITS.version.floor,
      ARGON2ID_LIMITS.memoryKiB.floor,
      ARGON2ID_LIMITS.iterations.floor,
      ARGON2ID_LIMITS.parallelism.floor,
      ARGON2ID_LIMITS.hashLength.floor,
      salt,
      keyring.rotationSeq,
    );
    const bytes = new Uint8Array(header.length + nonce.length + ciphertext.length);
    bytes.set(header, 0);
    bytes.set(nonce, header.length);
    bytes.set(ciphertext, header.length + nonce.length);
    if (bytes.length > RECOVERY_ABSOLUTE_MAX) throw new Error("keyring-too-large");
    const envelope: RecoveryEnvelope = {
      principal: keyring.principal,
      rotationSeq: keyring.rotationSeq,
      signingPub: keyring.pub,
      epub: keyring.epub,
      bytes,
    };
    const account = store.publishedAccount(envelope.principal);
    const replaced =
      envelope.rotationSeq === account.rotations.length
        ? predecessor(store.current(envelope.principal))
        : predecessor(store.pending(envelope.principal));
    const signature = signRecoveryOp(
      store,
      signerPriv,
      envelope.principal,
      "put",
      envelope.rotationSeq,
      recoveryEnvelopeHash(envelope),
      replaced,
    );
    store.put(envelope, signature);
    return envelope;
  } finally {
    checkedPassphrase.fill(0);
    plain?.fill(0);
    key?.fill(0);
  }
}

export async function openRecoveryCopy(
  passphrase: Uint8Array,
  envelope: RecoveryEnvelope,
  expected: PrincipalId,
  expectedRotationSeq: number,
  rotations: readonly unknown[],
  context: ResolutionContext,
): Promise<AccountKeyring> {
  if (envelope.bytes.length > RECOVERY_ABSOLUTE_MAX) throw new Error("keyring-too-large");
  const header = parseHeader(envelope.bytes);
  if (passphraseRejected(passphrase)) throw new Error("recovery-params");
  if (envelope.principal !== expected || header.rotationSeq !== envelope.rotationSeq) throw new Error("recovery-rejected");
  if (!Number.isSafeInteger(header.rotationSeq)) throw new Error("recovery-rejected");
  const key = await deriveKey(passphrase, header.salt, header.memoryKiB, header.iterations, header.parallelism, header.hashLength);
  let plain: Uint8Array | undefined;
  try {
    const aad = recoveryAad(
      expected,
      header.rotationSeq,
      envelope.signingPub,
      envelope.epub,
      header.memoryKiB,
      header.iterations,
      header.parallelism,
      header.hashLength,
      header.version,
      header.salt,
    );
    try {
      plain = aesDecrypt(key, header.nonce, aad, header.ciphertext);
    } catch {
      throw new Error("recovery-rejected");
    }
    if (plain.length > KEYRING_SERIAL_MAX) throw new Error("keyring-too-large");
    const fields = decodeKeyring(plain);
    const parsed = parsePrincipalId(fields.principal);
    if (!parsed.ok || parsed.value !== fields.principal || parsed.value !== expected) throw new Error("recovery-rejected");
    if (fields.rotationSeq !== header.rotationSeq || fields.pub !== envelope.signingPub || fields.epub !== envelope.epub) {
      throw new Error("recovery-rejected");
    }
    if (fields.rotationSeq !== expectedRotationSeq) throw new Error("recovery-stale");
    return AccountKeyring.import(
      fields.principal,
      fields.genesisEpub,
      fields.pub,
      fields.priv,
      fields.epub,
      fields.epriv,
      fields.retired,
      fields.laneId,
      fields.contentEpoch,
      fields.rotationSeq,
      rotations,
      context,
      fields.priorLanes,
      fields.contactLaneSecret,
      fields.priorContactSecrets,
    );
  } finally {
    key.fill(0);
    plain?.fill(0);
    header.salt.fill(0);
  }
}

function aesEncrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plain: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  return new Uint8Array(Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
}

function aesDecrypt(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, body: Uint8Array): Uint8Array {
  const tag = body.subarray(body.length - 16);
  const data = body.subarray(0, body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
}
