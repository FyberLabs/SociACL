import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { argon2id } from "hash-wasm";
import { MemoryKeyWrapStore, deleteAccountWrap, importGenesis, openAccountBackup, parseWrapObject, sealAccountBackup, type EncryptedAccountWrap } from "../contract/account-key.ts";
import { AccountKeyring } from "../contract/account-keyring.ts";
import {
  backupAad,
  backupKdf,
  backupSignatureMessage,
  bytesToHex,
  hexToBytes,
  seaPoint,
  sharedX,
  unb64,
  uncompressedFromSea,
} from "../contract/account-key-seal.ts";
import * as delivery from "../contract/delivery.ts";
import { createCipheriv } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import {
  ARGON2ID_LIMITS,
  DELIVERY_BLOB_MAX,
  KEYRING_SERIAL_MAX,
  MAX_WRAPS_PER_PRINCIPAL,
  RECOVERY_ABSOLUTE_MAX,
  RECOVERY_ENVELOPE_MAX,
} from "../contract/keyring-limits.ts";
import * as recovery from "../contract/recovery.ts";
import { canonicalDecimal, lengthPrefixed } from "../contract/canonical.ts";
import { deriveContactLane } from "../contract/contact-lane.ts";
import { decodeKeyring, DOMAIN_KEYRING_PLAIN } from "../contract/keyring-codec.ts";
import { checkRecoveryPassphrase, RecoveryWeakPassphraseError } from "../contract/passphrase-strength.ts";
import { encodePassphrase, MemoryRecoveryStore, openRecoveryCopy, signRecoveryOp, type RecoveryEnvelope } from "../contract/recovery-seal.ts";
import { DOMAIN_STORE_WRITE, HeadFloor, recoveryEnvelopeHash, REPLACED_NONE, signStoreWrite, storeWriteMessage, STORE_CLASS_DELIVERY, STORE_CLASS_GENESIS, verifyStoreWrite, wrapCiphertextHash } from "../contract/store-write.ts";
import { deliverKeyringWith, sealRecoveryCopyWith } from "./support/recovery-deterministic.ts";
import {
  historyState,
  mintObjectId,
  parsePrincipalId,
  resolveCurrentKey,
  type Jwks,
  type PrincipalId,
  type ResolutionContext,
} from "../ids/src/index.js";

function mintedWrap(principal: PrincipalId, n: number) {
  const bytes = new Uint8Array(16);
  new DataView(bytes.buffer).setUint32(12, n);
  const minted = mintObjectId("wrap", principal, () => bytes);
  if (!minted.ok) throw new Error(minted.reason);
  return parseWrapObject(minted.value);
}

const recoveryVector = JSON.parse(readFileSync(new URL("../../vectors/encrypted-discovery/recovery-copy.json", import.meta.url), "utf8")) as {
  domain: string;
  keyringDomain: string;
  bindDomain: string;
  sigDomain: string;
  limits: {
    version: { floor: number; ceiling: number };
    memoryKiB: { floor: number; ceiling: number };
    iterations: { floor: number; ceiling: number };
    parallelism: { floor: number; ceiling: number };
    hashLength: { floor: number; ceiling: number };
    saltLength: { floor: number; ceiling: number };
    keyringSerialMax: number;
    deliveryBlobMax: number;
    recoveryEnvelopeMax: number;
    recoveryAbsoluteMax: number;
    wrapsPerPrincipal: number;
  };
  unicodeVersion: string;
  passphraseRejects: { name: string; passphrase: string; error: string }[];
  passphraseStrength: {
    error: string;
    enforcedAt: string;
    open: string;
    minVisibleCodePoints: number;
    minScore: number;
    parity: string;
    cases: {
      name: string;
      passphrase: string;
      result: string;
      score?: number;
      warning?: string;
      handle?: string;
    }[];
  };
  retention: { downgrade: string; sameSeq: string; higherSeq: string; commitUnverified: string };
  storeWrite: {
    domain: string;
    operations: string[];
    pending: string;
    equalSeqClearsPending: boolean;
    commitKey: string;
    fork: string;
    unpublished: string;
    chain: string;
    rejectedCommit: string;
    sample: {
      principal: string;
      signingPub: string;
      epub: string;
      seq: number;
      bytesHex: string;
      envelopeHash: string;
      wrapId: string;
      wrapCiphertextHex: string;
      wrapCiphertextHash: string;
      messages: Record<
        string,
        {
          operation: string;
          target: string;
          envelopeHash: string;
          head: string;
          replaced: string;
          class: string;
          generation: string;
          messageHex: string;
        }
      >;
    };
  };
  unicodeRuntime: { minimum: string; probe: string; error: string };
  passphraseUtf8: string;
  wrongPassphraseUtf8: string;
  saltHex: string;
  nonceHex: string;
  normalization: { nfc: string; nfd: string; saltHex: string; derivedKeyHex: string };
  envelopeHex: string;
  rejects: RejectRow[];
  delivery: {
    transportScalarHex: string;
    transportPub: string;
    ephemeralScalarHex: string;
    nonceHex: string;
    wrapId: string;
    ciphertextHex: string;
    signature: string;
  };
};

type RejectRow = {
  name: string;
  error: string;
  memoryKiB?: number;
  iterations?: number;
  parallelism?: number;
  hashLength?: number;
  version?: number;
  saltHex?: string;
  envelopeBytes?: number;
  ciphertextBytes?: number;
  blobBytes?: number;
};

const ring = JSON.parse(readFileSync(new URL("../../vectors/encrypted-discovery/account-keyring.json", import.meta.url), "utf8")) as {
  genesis: {
    laneId: string;
    contactLaneSecret: string;
    signingPub: string;
    signingPriv: string;
    epub: string;
    epriv: string;
    principal: string;
  };
  mint: { signingPub: string; signingPriv: string; epub: string; epriv: string; laneId: string; contactLaneSecret: string };
  trusted: string[];
  lost: string;
  genesisBinding: unknown;
  witnessed: {
    rotationName: string;
    genesisScalar: number;
    genesisEpubScalar: number;
    currentScalar: number;
    epubScalar: number;
    laneId: string;
    contentEpoch: number;
    rotationSeq: number;
  };
  importPriorLanes: { rule: string; rotationSeq: number; priorLane: string; missingError: string };
  witnessContact: { secret: string; prior: string[] };
};

const records = JSON.parse(readFileSync(new URL("../../vectors/ids/records.json", import.meta.url), "utf8")) as {
  accept: { name: string; input: unknown }[];
  context: {
    jwks: Jwks;
    pinnedIss: string[];
    now: number;
    links: [string, unknown][];
    policy: { allowedDomains: string[]; allowedUris: string[]; allowedChainIds: string[] };
    authenticatedAccounts: string[];
    genesis: string;
  };
};

const SMALL_ARGON2ID = "bb0cc80a3e671149526915418c6eefe761bb19d5d2d567a017703e0cea6ab05c";

function principalOf(): PrincipalId {
  const parsed = parsePrincipalId(ring.genesis.principal);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value;
}

function genesisKeyring(): AccountKeyring {
  return AccountKeyring.fromGenesis(
    importGenesis(ring.genesis.laneId, ring.genesis.signingPub, ring.genesis.signingPriv, ring.genesis.epub, ring.genesis.epriv),
    ring.genesis.contactLaneSecret,
  );
}

function witnessedContext(): ResolutionContext {
  const links = new Map(records.context.links);
  const history = (principal: PrincipalId, at: number, until: number) =>
    records.context.authenticatedAccounts.includes(principal)
      ? { ok: true as const, value: historyState(principal, [], at, until) }
      : { ok: false as const, reason: "missing-history" as const };
  return {
    jwks: records.context.jwks,
    links,
    revocations: [],
    now: records.context.now,
    policy: records.context.policy,
    pinnedIss: new Set(records.context.pinnedIss),
    history,
    genesisEpubBindings: [ring.genesisBinding],
  } as ResolutionContext;
}

function vectorMint() {
  return {
    signingPub: ring.mint.signingPub,
    signingPriv: ring.mint.signingPriv,
    epub: ring.mint.epub,
    epriv: ring.mint.epriv,
    laneId: ring.mint.laneId,
    contactLaneSecret: ring.mint.contactLaneSecret,
  };
}

async function errorMessage(run: () => unknown): Promise<string> {
  try {
    await run();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected throw");
}

function craft(row: RejectRow, ciphertextLen: number, principal: PrincipalId): RecoveryEnvelope {
  const limits = recoveryVector.limits;
  const version = row.version ?? limits.version.floor;
  const memoryKiB = row.memoryKiB ?? limits.memoryKiB.floor;
  const iterations = row.iterations ?? limits.iterations.floor;
  const parallelism = row.parallelism ?? limits.parallelism.floor;
  const hashLength = row.hashLength ?? limits.hashLength.floor;
  const salt = row.saltHex === undefined ? new Uint8Array(16).fill(0x11) : hexToBytes(row.saltHex);
  const header = new Uint8Array(33 + salt.length);
  const view = new DataView(header.buffer);
  header[0] = 1;
  view.setUint32(1, version, true);
  view.setUint32(5, memoryKiB, true);
  view.setUint32(9, iterations, true);
  view.setUint32(13, parallelism, true);
  view.setUint32(17, hashLength, true);
  view.setUint32(21, salt.length, true);
  header.set(salt, 33);
  const bytes = new Uint8Array(header.length + 12 + ciphertextLen);
  bytes.set(header, 0);
  return { principal, rotationSeq: 0, signingPub: principal, epub: genesisEpub(), bytes };
}

test("limits match the shared vector", () => {
  const limits = recoveryVector.limits;
  assert.equal(limits.version.floor, ARGON2ID_LIMITS.version.floor);
  assert.equal(limits.version.ceiling, ARGON2ID_LIMITS.version.ceiling);
  assert.equal(limits.memoryKiB.floor, ARGON2ID_LIMITS.memoryKiB.floor);
  assert.equal(limits.memoryKiB.ceiling, ARGON2ID_LIMITS.memoryKiB.ceiling);
  assert.equal(limits.iterations.floor, ARGON2ID_LIMITS.iterations.floor);
  assert.equal(limits.iterations.ceiling, ARGON2ID_LIMITS.iterations.ceiling);
  assert.equal(limits.parallelism.floor, ARGON2ID_LIMITS.parallelism.floor);
  assert.equal(limits.parallelism.ceiling, ARGON2ID_LIMITS.parallelism.ceiling);
  assert.equal(limits.hashLength.floor, ARGON2ID_LIMITS.hashLength.floor);
  assert.equal(limits.hashLength.ceiling, ARGON2ID_LIMITS.hashLength.ceiling);
  assert.equal(limits.saltLength.floor, ARGON2ID_LIMITS.saltLength.floor);
  assert.equal(limits.saltLength.ceiling, ARGON2ID_LIMITS.saltLength.ceiling);
  assert.equal(limits.keyringSerialMax, KEYRING_SERIAL_MAX);
  assert.equal(limits.deliveryBlobMax, DELIVERY_BLOB_MAX);
  assert.equal(limits.recoveryEnvelopeMax, RECOVERY_ENVELOPE_MAX);
  assert.equal(limits.recoveryAbsoluteMax, RECOVERY_ABSOLUTE_MAX);
  assert.equal(limits.wrapsPerPrincipal, MAX_WRAPS_PER_PRINCIPAL);
  assert.equal(recoveryVector.unicodeVersion, "16.0.0");
  assert.equal(RECOVERY_ABSOLUTE_MAX, RECOVERY_ENVELOPE_MAX + ARGON2ID_LIMITS.saltLength.ceiling);
  assert.equal(recoveryVector.storeWrite.domain, DOMAIN_STORE_WRITE);
  assert.deepEqual(recoveryVector.storeWrite.operations, ["put", "commit", "delete"]);
  assert.equal(recoveryVector.storeWrite.pending, "head-plus-one");
  assert.equal(recoveryVector.storeWrite.equalSeqClearsPending, true);
  assert.equal(recoveryVector.storeWrite.commitKey, "resolved-current-key");
  assert.equal(recoveryVector.storeWrite.chain, "store-resolver");
  assert.equal(recoveryVector.storeWrite.rejectedCommit, "pending-unchanged");
  assert.equal(recoveryVector.unicodeRuntime.minimum, "16.0.0");
  assert.equal(recoveryVector.unicodeRuntime.error, "unicode-version");
  assert.equal("\u{11382}\u{113C9}".normalize("NFC"), "\u{11383}");
  assert.equal(recoveryVector.domain, "sociacl-recovery-copy-v1");
  assert.equal(recoveryVector.keyringDomain, "sociacl-keyring-plain-v2");
  assert.equal(DOMAIN_KEYRING_PLAIN, "sociacl-keyring-plain-v2");
  assert.equal(recoveryVector.bindDomain, "sociacl-keyring-delivery-v1");
  assert.equal(recoveryVector.sigDomain, "sociacl-keyring-delivery-sig-v1");
  assert.equal(ARGON2ID_LIMITS.parallelism.floor, 4);
});

test("keyring plaintext v1 is refused", () => {
  assert.throws(
    () => decodeKeyring(lengthPrefixed(["sociacl-keyring-plain-v1"])),
    (error: unknown) => error instanceof Error && error.message === "recovery-rejected",
  );
});

test("passphrase strength matches the shared vector and stays off open", async () => {
  const gate = recoveryVector.passphraseStrength;
  assert.equal(gate.error, "recovery-weak-passphrase");
  assert.equal(gate.enforcedAt, "seal");
  assert.equal(gate.open, "unchecked");
  assert.equal(gate.parity, "advisory");
  assert.equal(gate.minVisibleCodePoints, 12);
  assert.equal(gate.minScore, 3);
  const principal = ring.genesis.principal;
  for (const row of gate.cases) {
    const bytes = new TextEncoder().encode(row.passphrase);
    if (row.result === "pass") {
      checkRecoveryPassphrase(bytes, principal, row.handle);
      continue;
    }
    let caught: unknown;
    try {
      checkRecoveryPassphrase(bytes, principal, row.handle);
    } catch (error) {
      caught = error;
    }
    assert.ok(caught instanceof RecoveryWeakPassphraseError, row.name);
    if (!(caught instanceof RecoveryWeakPassphraseError)) continue;
    assert.equal(caught.message, "recovery-weak-passphrase", row.name);
    assert.ok(caught.score < 3, row.name);
    assert.equal(caught.warning.includes(row.passphrase), false, row.name);
    assert.equal(caught.suggestions.some((item) => item.includes(row.passphrase)), false, row.name);
    if (row.score !== undefined) assert.equal(caught.score, row.score, row.name);
    if (row.warning !== undefined) {
      assert.equal(caught.warning, row.warning, row.name);
      assert.deepEqual(caught.suggestions, [], row.name);
    }
  }
  const keyring = genesisKeyring();
  const context = witnessedContext();
  const store = new MemoryRecoveryStore(watch([], context));
  const started = Date.now();
  await assert.rejects(
    () =>
      sealRecoveryCopyWith(
        keyring,
        new TextEncoder().encode("password"),
        new Uint8Array(16).fill(0x11),
        new Uint8Array(12).fill(0x22),
        keyring.currentPriv(),
        store,
      ),
    (error: unknown) => error instanceof RecoveryWeakPassphraseError,
  );
  assert.ok(Date.now() - started < 200);
  assert.equal(store.get(keyring.principal, 0), undefined);
  assert.equal(Buffer.from(encodePassphrase("\uFEFF")).toString("hex"), "efbbbf");
  assert.equal(Buffer.from(encodePassphrase("\u200B")).toString("hex"), "e2808b");
});

test("store-write bytes match the shared vector", () => {
  const sample = recoveryVector.storeWrite.sample;
  const hashed = recoveryEnvelopeHash({
    principal: asPrincipal(sample.principal),
    rotationSeq: sample.seq,
    signingPub: asPrincipal(sample.signingPub),
    epub: asPrincipal(sample.epub),
    bytes: hexToBytes(sample.bytesHex),
  });
  assert.equal(hashed, sample.envelopeHash);
  assert.equal(wrapCiphertextHash(sample.wrapCiphertextHex), sample.wrapCiphertextHash);
  for (const [name, row] of Object.entries(sample.messages)) {
    const message = storeWriteMessage(
      sample.principal,
      row.operation,
      row.target,
      row.envelopeHash,
      row.head,
      row.replaced,
      row.class,
      row.generation,
    );
    assert.equal(Buffer.from(message).toString("hex"), row.messageHex, name);
  }
});

test("hash-wasm runs p=4 in a serial lane loop", async () => {
  const source = readFileSync(new URL("../node_modules/hash-wasm/src/argon2.c", import.meta.url), "utf8");
  const script = readFileSync(new URL("../node_modules/hash-wasm/lib/argon2.ts", import.meta.url), "utf8");
  assert.equal(source.includes("pthread"), false);
  assert.match(source, /for \(uint32_t lane = 0; lane < parallelism; lane\+\+\)/);
  assert.match(script, /for \(let lane = 0; lane < parallelism; lane\+\+\)/);
  const hash = await argon2id({
    password: "password",
    salt: "somesalt",
    parallelism: 4,
    iterations: 3,
    memorySize: 32,
    hashLength: 32,
    outputType: "hex",
  });
  assert.equal(hash, SMALL_ARGON2ID);
});

test("parameter and size rejects happen before the kdf", async () => {
  const principal = principalOf();
  const context = witnessedContext();
  const started = Date.now();
  for (const row of recoveryVector.rejects) {
    if (row.blobBytes !== undefined) continue;
    const envelope =
      row.envelopeBytes !== undefined
        ? { principal, rotationSeq: 0, signingPub: principal, epub: genesisEpub(), bytes: new Uint8Array(row.envelopeBytes) }
        : craft(row, row.ciphertextBytes ?? 16, principal);
    const error = await errorMessage(() => openRecoveryCopy(new TextEncoder().encode("x"), envelope, principal, 0, [], context));
    assert.equal(error, row.error, row.name);
  }
  assert.ok(Date.now() - started < 200, "a reject row ran the KDF");
});

test("an empty or whitespace passphrase is recovery-params before the kdf", async () => {
  const principal = principalOf();
  const context = witnessedContext();
  const envelope = craft({ name: "empty", error: "recovery-params" }, 16, principal);
  const started = Date.now();
  const empty = await errorMessage(() => openRecoveryCopy(new Uint8Array(), envelope, principal, 0, [], context));
  const spaces = await errorMessage(() => openRecoveryCopy(new TextEncoder().encode(" \t\n"), envelope, principal, 0, [], context));
  assert.equal(empty, "recovery-params");
  assert.equal(spaces, "recovery-params");
  assert.throws(() => encodePassphrase(""), (error: unknown) => error instanceof Error && error.message === "recovery-params");
  assert.throws(() => encodePassphrase(" \t\n"), (error: unknown) => error instanceof Error && error.message === "recovery-params");
  for (const row of recoveryVector.passphraseRejects) {
    assert.throws(
      () => encodePassphrase(row.passphrase),
      (error: unknown) => error instanceof Error && error.message === row.error,
      row.name,
    );
    const bytes = new TextEncoder().encode(row.passphrase);
    const envelope = craft({ name: row.name, error: row.error }, 16, principal);
    assert.equal(
      await errorMessage(() => openRecoveryCopy(bytes, envelope, principal, 0, [], context)),
      "recovery-params",
      row.name,
    );
  }
  assert.equal(Buffer.from(encodePassphrase("\uFEFF")).toString("hex"), "efbbbf");
  assert.equal(encodePassphrase(" café")[0], 0x20);
  assert.ok(Date.now() - started < 200);
});

test("recovery copy matches the shared vector and stays off gun", { timeout: 180_000 }, async () => {
  const keyring = genesisKeyring();
  const context = witnessedContext();
  const store = new MemoryRecoveryStore(watch([], context));
  const passphrase = new TextEncoder().encode(recoveryVector.passphraseUtf8);
  const envelope = await sealRecoveryCopyWith(
    keyring,
    passphrase,
    hexToBytes(recoveryVector.saltHex),
    hexToBytes(recoveryVector.nonceHex),
    keyring.currentPriv(),
    store,
  );
  const hex = Buffer.from(envelope.bytes).toString("hex");
  assert.equal(hex, recoveryVector.envelopeHex);
  assert.ok(store.get(keyring.principal, 0));
  assert.equal(store.isAuthority, false);
  assert.equal(store.seesPlaintext, false);
  assert.equal(store.seesPassphrase, false);
  assert.equal("gun" in store, false);
  const opened = await openRecoveryCopy(passphrase, envelope, keyring.principal, 0, [], context);
  const openedString = await recovery.openRecoveryCopyFromString(recoveryVector.passphraseUtf8, envelope, keyring.principal, 0, [], context);
  assert.equal(openedString.currentPriv(), opened.currentPriv());
  assert.equal(opened.principal, keyring.principal);
  assert.equal(opened.currentPriv(), keyring.currentPriv());
  assert.equal(opened.currentEpriv(), keyring.currentEpriv());
  assert.equal(opened.laneId(), keyring.laneId());
  assert.equal(opened.contactLaneSecret(), keyring.contactLaneSecret());
  const gun = opened.gunDocument();
  assert.equal(gun.includes(keyring.currentPriv()), false);
  assert.equal(gun.includes(keyring.currentEpriv()), false);
  assert.equal(gun.includes(keyring.laneId()), false);
  assert.equal(hex.includes(keyring.currentPriv()), false);
  assert.equal(hex.includes(keyring.laneId()), false);
  assert.equal(hex.includes(keyring.contactLaneSecret()), false);
  assert.equal(gun.includes(keyring.contactLaneSecret()), false);
  const wrong = await errorMessage(() =>
    openRecoveryCopy(new TextEncoder().encode(recoveryVector.wrongPassphraseUtf8), envelope, keyring.principal, 0, [], context),
  );
  const tampered: RecoveryEnvelope = {
    principal: envelope.principal,
    rotationSeq: envelope.rotationSeq,
    signingPub: envelope.signingPub,
    epub: envelope.epub,
    bytes: new Uint8Array(envelope.bytes),
  };
  const last = tampered.bytes.length - 1;
  tampered.bytes[last] = (tampered.bytes[last] ?? 0) ^ 0x01;
  const tamper = await errorMessage(() => openRecoveryCopy(passphrase, tampered, keyring.principal, 0, [], context));
  assert.equal(wrong, tamper);
  assert.equal(
    await errorMessage(() => openRecoveryCopy(new TextEncoder().encode("password"), envelope, keyring.principal, 0, [], context)),
    "recovery-rejected",
  );
  assert.equal(wrong, "recovery-rejected");
  const stale = await errorMessage(() => openRecoveryCopy(passphrase, envelope, keyring.principal, 1, [], context));
  assert.equal(stale, "recovery-stale");
});

test("rotation reseals a new version and writes only the adapter", { timeout: 180_000 }, async () => {
  const keyring = genesisKeyring();
  const context = witnessedContext();
  const store = new MemoryRecoveryStore(watch([], context));
  const passphrase = new TextEncoder().encode(recoveryVector.passphraseUtf8);
  putRecovery(
    store,
    {
      principal: keyring.principal,
      rotationSeq: 0,
      signingPub: keyring.pub,
      epub: keyring.epub,
      bytes: hexToBytes(recoveryVector.envelopeHex),
    },
    keyring.currentPriv(),
  );
  assert.ok(store.get(keyring.principal, 0));
  const { rotation, envelope } = await recovery.rotateAndReseal(
    keyring,
    ring.trusted,
    ring.lost,
    [],
    context,
    passphrase,
    store,
    vectorMint,
  );
  assert.equal(rotation.keyring.rotationSeq, 1);
  assert.equal(envelope.rotationSeq, 1);
  assert.ok(store.get(keyring.principal, 1));
  assert.ok(store.get(keyring.principal, 0));
  assert.equal(
    messageSync(() => recovery.commitRecoveryCopy(keyring.principal, keyring.currentPriv(), store)),
    recoveryVector.retention.commitUnverified,
  );
  assert.ok(store.get(keyring.principal, 1));
  assert.ok(store.get(keyring.principal, 0));
  const hex = Buffer.from(envelope.bytes).toString("hex");
  assert.equal(hex.includes(rotation.keyring.currentPriv()), false);
  assert.equal(hex.includes(rotation.keyring.currentEpriv()), false);
  assert.equal(hex.includes(rotation.keyring.laneId()), false);
  assert.equal(rotation.keyring.gunDocument().includes(rotation.keyring.currentPriv()), false);
  const old: RecoveryEnvelope = {
    principal: keyring.principal,
    rotationSeq: 0,
    signingPub: keyring.pub,
    epub: keyring.epub,
    bytes: hexToBytes(recoveryVector.envelopeHex),
  };
  const stale = await errorMessage(() => openRecoveryCopy(passphrase, old, keyring.principal, 1, [], context));
  assert.equal(stale, "recovery-stale");
  const imported = await errorMessage(() => openRecoveryCopy(passphrase, envelope, keyring.principal, 1, [], context));
  assert.equal(imported, "pub-mismatch");
});

test("delivered keyring matches the shared vector and does not mint", async () => {
  const keyring = genesisKeyring();
  const context = witnessedContext();
  const store = new MemoryKeyWrapStore(watch([], context));
  const wrap = deliverKeyringWith(
    keyring,
    recoveryVector.delivery.transportPub,
    hexToBytes(recoveryVector.delivery.ephemeralScalarHex),
    hexToBytes(recoveryVector.delivery.nonceHex),
    parseWrapObject(recoveryVector.delivery.wrapId),
    [],
    context,
    store,
  );
  assert.equal(wrap.ciphertextHex, recoveryVector.delivery.ciphertextHex);
  assert.equal(wrap.signature, recoveryVector.delivery.signature);
  assert.equal(store.isAuthority, false);
  assert.equal(store.mintsGrant, false);
  assert.equal(wrap.ciphertextHex.includes(keyring.currentPriv()), false);
  assert.equal(wrap.ciphertextHex.includes(keyring.currentEpriv()), false);
  assert.equal(wrap.ciphertextHex.includes(keyring.laneId()), false);
  assert.equal(wrap.ciphertextHex.includes(keyring.contactLaneSecret()), false);
  const opened = delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, wrap, keyring.principal, 0, [], context);
  assert.equal(opened.principal, keyring.principal);
  assert.equal(opened.pub, keyring.pub);
  assert.equal(opened.currentPriv(), keyring.currentPriv());
  assert.equal(opened.currentEpriv(), keyring.currentEpriv());
  assert.equal(opened.contactLaneSecret(), keyring.contactLaneSecret());
  assert.equal(opened.laneId(), keyring.laneId());
  assert.equal(
    deriveContactLane(opened.contactLaneSecret(), opened.principal, ring.mint.signingPub),
    deriveContactLane(keyring.contactLaneSecret(), keyring.principal, ring.mint.signingPub),
  );
  const stale = await errorMessage(() =>
    delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, wrap, keyring.principal, 1, [], context),
  );
  assert.equal(stale, "recovery-stale");
  const bad = { ...wrap, signature: `${wrap.signature.slice(0, -1)}${wrap.signature.endsWith("0") ? "1" : "0"}` };
  assert.equal(
    await errorMessage(() => delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, bad, keyring.principal, 1, [], context)),
    "wrap-rejected",
  );
  const forged = { ...wrap, signature: "00".repeat(64) };
  assert.equal(
    messageSync(() => delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, forged, keyring.principal, 2, [], context)),
    "wrap-rejected",
  );
  const garbage = forgedDelivery(keyring.principal, keyring.epub, new Uint8Array([1, 2, 3]), "00".repeat(64));
  assert.equal(
    messageSync(() => delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, garbage, keyring.principal, 2, [], context)),
    "wrap-rejected",
  );
  const seqField = new Uint8Array([1, 0, 0, 0, 0x32]);
  const atExpected = forgedDelivery(keyring.principal, keyring.epub, seqField, "00".repeat(64));
  assert.equal(
    messageSync(() => delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, atExpected, keyring.principal, 2, [], context)),
    "wrap-rejected",
  );
  const unsignedGarbage = forgedDelivery(keyring.principal, keyring.epub, new Uint8Array([1, 2, 3]), "00".repeat(64));
  const blob = hexToBytes(unsignedGarbage.ciphertextHex);
  const transportPub = seaPoint(hexToBytes(recoveryVector.delivery.transportScalarHex));
  const message = backupSignatureMessage(blob, transportPub, unsignedGarbage.wrapId, "sociacl-keyring-delivery-sig-v1");
  const signedGarbage = {
    ...unsignedGarbage,
    signature: bytesToHex(p256.sign(message, unb64(keyring.currentPriv()), { lowS: true, prehash: true })),
  };
  assert.equal(
    messageSync(() => delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, signedGarbage, keyring.principal, 0, [], context)),
    "wrap-rejected",
  );
  assert.equal(
    await errorMessage(() => delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, bad, keyring.principal, 0, [], context)),
    "wrap-rejected",
  );
  assert.equal(
    await errorMessage(() => openAccountBackup(recoveryVector.delivery.transportScalarHex, wrap, keyring.principal, [], context)),
    "wrap-rejected",
  );
  assert.equal(
    await errorMessage(() => delivery.openDeliveredKeyring(scalarHex(5), wrap, keyring.principal, 0, [], context)),
    "wrap-rejected",
  );
  assert.equal(
    await errorMessage(() =>
      delivery.openDeliveredKeyring(
        recoveryVector.delivery.transportScalarHex,
        { ...wrap, wrapId: parseWrapObject("wrap_p_60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299_00112233445566778899aabbccddee00") },
        keyring.principal,
        0,
        [],
        context,
      ),
    ),
    "wrap-rejected",
  );
  const other = parsePrincipalId(ring.mint.signingPub);
  if (!other.ok) throw new Error(other.reason);
  assert.equal(
    await errorMessage(() =>
      delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, { ...wrap, principal: other.value }, keyring.principal, 0, [], context),
    ),
    "wrap-rejected",
  );
  assert.equal(
    await errorMessage(() =>
      delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, { ...wrap, epub: ring.mint.epub }, keyring.principal, 0, [], context),
    ),
    "wrap-rejected",
  );
});

test("delivery oversize is rejected before decrypt", () => {
  const row = recoveryVector.rejects.find((item) => item.name === "delivery-above-cap");
  if (!row || row.blobBytes === undefined) throw new Error("missing delivery-above-cap");
  assert.equal(row.blobBytes, DELIVERY_BLOB_MAX + 1);
  const principal = principalOf();
  const wrap = {
    principal,
    wrapId: parseWrapObject(recoveryVector.delivery.wrapId),
    epub: ring.genesis.epub,
    class: "delivery" as const,
    ciphertextHex: "aa".repeat(row.blobBytes),
    signature: "ab".repeat(64),
  };
  const started = Date.now();
  assert.throws(
    () => delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, wrap, principal, 0, [], witnessedContext()),
    (error: unknown) => error instanceof Error && error.message === "keyring-too-large",
  );
  assert.ok(Date.now() - started < 200);
  assert.equal(row.error, "keyring-too-large");
});

test("deterministic helpers are not production exports", () => {
  assert.equal(Object.keys(recovery).includes("sealRecoveryCopyWith"), false);
  assert.equal(Object.keys(delivery).includes("deliverKeyringWith"), false);
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { exports: Record<string, string> };
  const exported = JSON.stringify(pkg.exports);
  assert.equal(exported.includes("recovery"), false);
  assert.equal(exported.includes("delivery"), false);
  assert.equal(exported.includes("keyring"), false);
  assert.equal(exported.includes("recovery-deterministic"), false);
});

function scalarHex(n: number): string {
  const bytes = new Uint8Array(32);
  bytes[31] = n & 0xff;
  return Buffer.from(bytes).toString("hex");
}

function scalarSea(n: number): { pub: string; priv: string } {
  const bytes = new Uint8Array(32);
  bytes[30] = (n >> 8) & 0xff;
  bytes[31] = n & 0xff;
  const pub = seaPoint(bytes);
  const priv = Buffer.from(bytes).toString("base64url");
  bytes.fill(0);
  return { pub, priv };
}

function genesisEpub(): PrincipalId {
  const parsed = parsePrincipalId(ring.genesis.epub);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value;
}

function priorLanes(count: number): string[] {
  const extras = ["11", "22", "33", "44"].map((byte) => byte.repeat(32));
  return [ring.importPriorLanes.priorLane, ...extras].slice(0, count);
}

function dummyEnvelope(
  principal: PrincipalId,
  rotationSeq: number,
  signingPub: PrincipalId,
  epub: PrincipalId,
): RecoveryEnvelope {
  const bytes = new Uint8Array(33 + 16 + 12 + 16);
  const view = new DataView(bytes.buffer);
  bytes[0] = 1;
  view.setUint32(1, 0x13, true);
  view.setUint32(5, 65536, true);
  view.setUint32(9, 3, true);
  view.setUint32(13, 4, true);
  view.setUint32(17, 32, true);
  view.setUint32(21, 16, true);
  view.setUint32(25, rotationSeq, true);
  bytes.fill(0x11, 33, 49);
  return { principal, rotationSeq, signingPub, epub, bytes };
}

function watch(rotations: readonly unknown[], context: ResolutionContext) {
  return (principal: PrincipalId) => {
    const resolved = resolveCurrentKey(principal, rotations, context);
    if (!resolved.ok) throw new Error("store-rejected");
    return resolved.value;
  };
}

function predecessor(row: RecoveryEnvelope | undefined): string {
  return row ? recoveryEnvelopeHash(row) : REPLACED_NONE;
}

function putRecovery(store: MemoryRecoveryStore, envelope: RecoveryEnvelope, signerPriv: string): void {
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
}

function asPrincipal(sea: string): PrincipalId {
  const parsed = parsePrincipalId(sea);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.value;
}

function putWrap(
  store: MemoryKeyWrapStore,
  principal: PrincipalId,
  wrapId: ReturnType<typeof parseWrapObject>,
  wrapClass: "genesis" | "delivery",
  ciphertextHex: string,
  signerPriv: string,
  context: ResolutionContext,
): void {
  const wrap = {
    principal,
    wrapId,
    epub: ring.genesis.epub,
    class: wrapClass,
    ciphertextHex,
    signature: "ab".repeat(64),
  };
  const hash = wrapCiphertextHash(ciphertextHex);
  const account = store.publishedAccount(principal);
  const existing = store.get(principal, wrapId);
  const signature = signStoreWrite(
    signerPriv,
    principal,
    "put",
    wrapId,
    hash,
    canonicalDecimal(account.rotations.length),
    existing ? wrapCiphertextHash(existing.ciphertextHex) : REPLACED_NONE,
    wrapClass === "genesis" ? STORE_CLASS_GENESIS : STORE_CLASS_DELIVERY,
    canonicalDecimal(store.writeGeneration(principal)),
  );
  store.put({ principal, wrapId, epub: ring.genesis.epub }, wrap, signature);
}

function mintPubs(): { signingPub: PrincipalId; epub: PrincipalId } {
  const signing = parsePrincipalId(ring.mint.signingPub);
  const epub = parsePrincipalId(ring.mint.epub);
  if (!signing.ok || !epub.ok) throw new Error("mint pubs");
  return { signingPub: signing.value, epub: epub.value };
}

test("the store copies envelopes and keeps only the latest", () => {
  const keyring = genesisKeyring();
  const principal = keyring.principal;
  const context = witnessedContext();
  const store = new MemoryRecoveryStore(watch([], context));
  const older = dummyEnvelope(principal, 0, keyring.pub, keyring.epub);
  const original = new Uint8Array(older.bytes);
  putRecovery(store, older, keyring.currentPriv());
  older.bytes[40] = (older.bytes[40] ?? 0) ^ 0x01;
  const stored = store.get(principal, 0);
  if (!stored) throw new Error("missing copy");
  assert.deepEqual(stored.bytes, original);
  stored.bytes[40] = (stored.bytes[40] ?? 0) ^ 0xff;
  const again = store.get(principal, 0);
  if (!again) throw new Error("missing copy");
  assert.deepEqual(again.bytes, original);
  assert.throws(
    () => store.put(older, "00"),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  assert.deepEqual(store.get(principal, 0)?.bytes, original);
  const resealed = dummyEnvelope(principal, 0, keyring.pub, keyring.epub);
  resealed.bytes[40] = (resealed.bytes[40] ?? 0) ^ 0x11;
  putRecovery(store, resealed, keyring.currentPriv());
  assert.equal(store.get(principal, 0)?.bytes[40], resealed.bytes[40]);
  assert.equal(store.pending(principal), undefined);
  assert.equal(recoveryVector.retention.sameSeq, "replace-clears-pending");
  const pending = mintPubs();
  putRecovery(store, dummyEnvelope(principal, 1, pending.signingPub, pending.epub), keyring.currentPriv());
  assert.ok(store.get(principal, 0));
  assert.ok(store.get(principal, 1));
  putRecovery(store, resealed, keyring.currentPriv());
  assert.equal(store.get(principal, 0)?.bytes[40], resealed.bytes[40]);
  assert.equal(store.pending(principal), undefined);
  assert.throws(
    () => putRecovery(store, dummyEnvelope(principal, 99, keyring.pub, keyring.epub), keyring.currentPriv()),
    (error: unknown) => error instanceof Error && error.message === recoveryVector.retention.downgrade,
  );
  assert.equal(store.get(principal, 99), undefined);
  putRecovery(store, dummyEnvelope(principal, 1, pending.signingPub, pending.epub), keyring.currentPriv());
  assert.ok(store.pending(principal));
  const high = new MemoryRecoveryStore(watch([], context));
  assert.throws(
    () => putRecovery(high, dummyEnvelope(principal, 2, keyring.pub, keyring.epub), keyring.currentPriv()),
    (error: unknown) => error instanceof Error && error.message === recoveryVector.retention.downgrade,
  );
  assert.equal(high.get(principal, 2), undefined);
  assert.equal(recoveryVector.retention.higherSeq, "pending-only-head-plus-one");
  const gap = new MemoryRecoveryStore(watch([], context));
  putRecovery(gap, dummyEnvelope(principal, 0, keyring.pub, keyring.epub), keyring.currentPriv());
  assert.throws(
    () => putRecovery(gap, dummyEnvelope(principal, 2, keyring.pub, keyring.epub), keyring.currentPriv()),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  putRecovery(gap, dummyEnvelope(principal, 1, pending.signingPub, pending.epub), keyring.currentPriv());
  assert.ok(gap.get(principal, 0));
  assert.ok(gap.get(principal, 1));
  assert.equal(gap.get(principal, 2), undefined);
});

test("composed and decomposed passphrases derive the same key", async () => {
  const nfc = encodePassphrase(recoveryVector.normalization.nfc);
  const nfd = encodePassphrase(recoveryVector.normalization.nfd);
  assert.deepEqual(nfc, nfd);
  assert.equal(Buffer.from(nfc).toString("hex"), "636166c3a9");
  const hash = await argon2id({
    password: nfc,
    salt: hexToBytes(recoveryVector.normalization.saltHex),
    parallelism: 4,
    iterations: 3,
    memorySize: 65536,
    hashLength: 32,
    outputType: "hex",
  });
  assert.equal(hash, recoveryVector.normalization.derivedKeyHex);
});

test("a cross-principal envelope is recovery-rejected", async () => {
  const principal = principalOf();
  const other = parsePrincipalId(ring.mint.signingPub);
  if (!other.ok) throw new Error(other.reason);
  const context = witnessedContext();
  const envelope: RecoveryEnvelope = {
    principal,
    rotationSeq: 0,
    signingPub: principal,
    epub: genesisEpub(),
    bytes: hexToBytes(recoveryVector.envelopeHex),
  };
  const started = Date.now();
  const swapped = await errorMessage(() => openRecoveryCopy(new TextEncoder().encode("x"), envelope, other.value, 0, [], context));
  assert.equal(swapped, "recovery-rejected");
  assert.ok(Date.now() - started < 200);
  const both: RecoveryEnvelope = { ...envelope, principal: other.value, bytes: new Uint8Array(envelope.bytes) };
  const ad = await errorMessage(() =>
    openRecoveryCopy(new TextEncoder().encode(recoveryVector.passphraseUtf8), both, other.value, 0, [], context),
  );
  assert.equal(ad, "recovery-rejected");
});

test("a recovery copy opens after rotation against its chain", { timeout: 180_000 }, async () => {
  const rotation = records.accept.find((item) => item.name === ring.witnessed.rotationName);
  if (!rotation) throw new Error("missing rotation");
  const genesis = scalarSea(ring.witnessed.genesisScalar);
  const genesisEpub = scalarSea(ring.witnessed.genesisEpubScalar);
  const current = scalarSea(ring.witnessed.currentScalar);
  const epub = scalarSea(ring.witnessed.epubScalar);
  const context = witnessedContext();
  const keyring = AccountKeyring.import(
    genesis.pub,
    genesisEpub.pub,
    current.pub,
    current.priv,
    epub.pub,
    epub.priv,
    [{ epub: genesisEpub.pub, epriv: genesisEpub.priv }],
    ring.witnessed.laneId,
    ring.witnessed.contentEpoch,
    ring.witnessed.rotationSeq,
    [rotation.input],
    context,
    priorLanes(ring.witnessed.rotationSeq),
    ring.witnessContact.secret,
    ring.witnessContact.prior,
  );
  const store = new MemoryRecoveryStore(watch([rotation.input], context));
  const envelope = await recovery.sealRecoveryCopyFromString(
    keyring,
    recoveryVector.passphraseUtf8,
    store,
  );
  const opened = await recovery.openRecoveryCopyFromString(
    recoveryVector.passphraseUtf8,
    envelope,
    keyring.principal,
    1,
    [rotation.input],
    context,
  );
  assert.equal(opened.rotationSeq, 1);
  assert.equal(opened.currentPriv(), keyring.currentPriv());
  const unsigned = await errorMessage(() =>
    openRecoveryCopy(new TextEncoder().encode(recoveryVector.passphraseUtf8), envelope, keyring.principal, 1, [], context),
  );
  assert.equal(unsigned, "pub-mismatch");
  const genesisPoint = asPrincipal(genesis.pub);
  const genesisEncryption = asPrincipal(genesisEpub.pub);
  const currentPoint = asPrincipal(current.pub);
  const currentEncryption = asPrincipal(epub.pub);
  const published = { rotations: [] as unknown[] };
  const forward = new MemoryRecoveryStore((principal) => {
    const resolved = resolveCurrentKey(principal, published.rotations, context);
    if (!resolved.ok) throw new Error("store-rejected");
    return resolved.value;
  });
  putRecovery(forward, dummyEnvelope(keyring.principal, 0, genesisPoint, genesisEncryption), genesis.priv);
  putRecovery(forward, dummyEnvelope(keyring.principal, 1, currentPoint, currentEncryption), genesis.priv);
  published.rotations = [rotation.input];
  recovery.commitRecoveryCopy(keyring.principal, current.priv, forward);
  assert.equal(forward.get(keyring.principal, 0), undefined);
  assert.ok(forward.get(keyring.principal, 1));
  assert.equal(
    messageSync(() => recovery.commitRecoveryCopy(keyring.principal, current.priv, forward)),
    "store-rejected",
  );
  assert.ok(forward.get(keyring.principal, 1));
  assert.throws(
    () => putRecovery(forward, dummyEnvelope(keyring.principal, 0, genesisPoint, genesisEncryption), genesis.priv),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  const stuck = new MemoryRecoveryStore(watch([], context));
  putRecovery(stuck, dummyEnvelope(keyring.principal, 0, genesisPoint, genesisEncryption), genesis.priv);
  putRecovery(stuck, dummyEnvelope(keyring.principal, 1, currentPoint, currentEncryption), genesis.priv);
  assert.equal(
    messageSync(() => recovery.commitRecoveryCopy(keyring.principal, genesis.priv, stuck)),
    recoveryVector.retention.commitUnverified,
  );
  assert.ok(stuck.get(keyring.principal, 0));
  assert.ok(stuck.get(keyring.principal, 1));
  const forkChain = { rotations: [] as unknown[] };
  const fork = new MemoryRecoveryStore((principal) => {
    const resolved = resolveCurrentKey(principal, forkChain.rotations, context);
    if (!resolved.ok) throw new Error("store-rejected");
    return resolved.value;
  });
  const minted = mintPubs();
  putRecovery(fork, dummyEnvelope(keyring.principal, 0, genesisPoint, genesisEncryption), genesis.priv);
  putRecovery(fork, dummyEnvelope(keyring.principal, 1, minted.signingPub, minted.epub), genesis.priv);
  forkChain.rotations = [rotation.input];
  assert.equal(
    messageSync(() => recovery.commitRecoveryCopy(keyring.principal, current.priv, fork)),
    recoveryVector.storeWrite.fork,
  );
  assert.ok(fork.get(keyring.principal, 0));
  assert.ok(fork.get(keyring.principal, 1));
  recovery.deleteRecoveryCopy(keyring.principal, 1, genesis.priv, stuck);
  assert.ok(stuck.get(keyring.principal, 0));
  assert.equal(stuck.get(keyring.principal, 1), undefined);
});

test("two devices and the genesis backup share the store", () => {
  const keyring = genesisKeyring();
  const context = witnessedContext();
  const store = new MemoryKeyWrapStore(watch([], context));
  const account = importGenesis(
    ring.genesis.laneId,
    ring.genesis.signingPub,
    ring.genesis.signingPriv,
    ring.genesis.epub,
    ring.genesis.epriv,
  );
  const genesisId = parseWrapObject("wrap_p_60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299_00112233445566778899aabbccddee01");
  const firstId = parseWrapObject(recoveryVector.delivery.wrapId);
  const secondId = parseWrapObject("wrap_p_60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299_00112233445566778899aabbccddee02");
  const genesis = sealAccountBackup(account, recoveryVector.delivery.transportPub, genesisId, store, [], context);
  const first = deliverKeyringWith(
    keyring,
    recoveryVector.delivery.transportPub,
    hexToBytes(recoveryVector.delivery.ephemeralScalarHex),
    hexToBytes(recoveryVector.delivery.nonceHex),
    firstId,
    [],
    context,
    store,
  );
  const secondPub = scalarSea(4).pub;
  const second = deliverKeyringWith(
    keyring,
    secondPub,
    hexToBytes(scalarHex(7)),
    new Uint8Array([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b]),
    secondId,
    [],
    context,
    store,
  );
  assert.equal(store.list(keyring.principal).length, 3);
  assert.equal(store.get(keyring.principal, genesisId)?.ciphertextHex, genesis.ciphertextHex);
  assert.equal(store.get(keyring.principal, firstId)?.ciphertextHex, first.ciphertextHex);
  const replacement = deliverKeyringWith(
    keyring,
    secondPub,
    hexToBytes(scalarHex(7)),
    new Uint8Array([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b]),
    secondId,
    [],
    context,
    store,
  );
  assert.notEqual(replacement.ciphertextHex, second.ciphertextHex);
  assert.equal(store.list(keyring.principal).length, 3);
  assert.equal(store.get(keyring.principal, firstId)?.ciphertextHex, first.ciphertextHex);
  assert.equal(store.get(keyring.principal, secondId)?.ciphertextHex, replacement.ciphertextHex);
  assert.throws(
    () =>
      deliverKeyringWith(
        keyring,
        secondPub,
        hexToBytes(scalarHex(7)),
        new Uint8Array([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b]),
        genesisId,
        [],
        context,
        store,
      ),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  assert.equal(store.get(keyring.principal, genesisId)?.ciphertextHex, genesis.ciphertextHex);
  assert.equal(store.list(keyring.principal).length, 3);
});

test("wrap rows are capped and a class sticks to its id", () => {
  const principal = principalOf();
  const context = witnessedContext();
  const store = new MemoryKeyWrapStore(watch([], context));
  const signer = ring.genesis.signingPriv;
  const ids: ReturnType<typeof parseWrapObject>[] = [];
  for (let n = 0; n < MAX_WRAPS_PER_PRINCIPAL; n += 1) {
    const wrapId = mintedWrap(principal, n);
    ids.push(wrapId);
    putWrap(store, principal, wrapId, n === 0 ? "genesis" : "delivery", n.toString(16).padStart(2, "0"), signer, context);
  }
  const extra = mintedWrap(principal, 80);
  assert.throws(
    () => putWrap(store, principal, extra, "delivery", "bb", signer, context),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  assert.throws(
    () =>
      store.put(
        { principal, wrapId: extra, epub: ring.genesis.epub },
        { principal, wrapId: extra, epub: ring.genesis.epub, class: "delivery", ciphertextHex: "ee", signature: "ab".repeat(64) },
        "00",
      ),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  const first = ids[0];
  const delivery = ids[1];
  if (!first || !delivery) throw new Error("missing wrap");
  assert.throws(
    () => putWrap(store, principal, first, "delivery", "cc", signer, context),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  const viewed = store.get(principal, first);
  if (!viewed) throw new Error("missing genesis wrap");
  (viewed as { class: string }).class = "delivery";
  assert.equal(store.get(principal, first)?.class, "genesis");
  const listed = store.list(principal);
  const listedGenesis = listed.find((row) => row.wrapId === first);
  if (!listedGenesis) throw new Error("missing listed genesis wrap");
  (listedGenesis as { class: string }).class = "delivery";
  assert.equal(store.get(principal, first)?.class, "genesis");
  assert.throws(
    () => deleteAccountWrap(principal, first, signer, store),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  assert.equal(store.get(principal, first)?.ciphertextHex, "00");
  deleteAccountWrap(principal, delivery, signer, store);
  assert.equal(store.get(principal, delivery), undefined);
  putWrap(store, principal, extra, "delivery", "bb", signer, context);
  assert.equal(store.list(principal).length, MAX_WRAPS_PER_PRINCIPAL);
});

test("a rotated delivery needs its chain and a stale seq wins", () => {
  const rotation = records.accept.find((item) => item.name === ring.witnessed.rotationName);
  if (!rotation) throw new Error("missing rotation");
  const genesis = scalarSea(ring.witnessed.genesisScalar);
  const genesisEpub = scalarSea(ring.witnessed.genesisEpubScalar);
  const current = scalarSea(ring.witnessed.currentScalar);
  const epub = scalarSea(ring.witnessed.epubScalar);
  const context = witnessedContext();
  const keyring = AccountKeyring.import(
    genesis.pub,
    genesisEpub.pub,
    current.pub,
    current.priv,
    epub.pub,
    epub.priv,
    [{ epub: genesisEpub.pub, epriv: genesisEpub.priv }],
    ring.witnessed.laneId,
    ring.witnessed.contentEpoch,
    ring.witnessed.rotationSeq,
    [rotation.input],
    context,
    priorLanes(ring.witnessed.rotationSeq),
    ring.witnessContact.secret,
    ring.witnessContact.prior,
  );
  const store = new MemoryKeyWrapStore(watch([rotation.input], context));
  const transport = scalarSea(4);
  const wrap = deliverKeyringWith(
    keyring,
    transport.pub,
    hexToBytes(scalarHex(7)),
    new Uint8Array(12).fill(9),
    parseWrapObject("wrap_p_60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299_00112233445566778899aabbccddee03"),
    [rotation.input],
    context,
    store,
  );
  const opened = delivery.openDeliveredKeyring(scalarHex(4), wrap, keyring.principal, 1, [rotation.input], context);
  assert.equal(opened.rotationSeq, 1);
  assert.equal(
    messageSync(() => delivery.openDeliveredKeyring(scalarHex(4), wrap, keyring.principal, 1, [], context)),
    "wrap-rejected",
  );
  assert.equal(
    messageSync(() => delivery.openDeliveredKeyring(scalarHex(4), wrap, keyring.principal, 0, [], context)),
    "wrap-rejected",
  );
  assert.equal(
    messageSync(() => delivery.openDeliveredKeyring(scalarHex(4), wrap, keyring.principal, 2, [rotation.input], context)),
    "recovery-stale",
  );
  assert.equal(
    messageSync(() =>
      delivery.openDeliveredKeyring(
        scalarHex(4),
        wrap,
        keyring.principal,
        2,
        [{ kind: "nope", seq: 0 }, rotation.input],
        context,
      ),
    ),
    "recovery-stale",
  );
  const zero = { ...wrap, signature: "00".repeat(64) };
  assert.equal(
    messageSync(() => delivery.openDeliveredKeyring(scalarHex(4), zero, keyring.principal, 2, [rotation.input], context)),
    "wrap-rejected",
  );
});

function forgedDelivery(principal: PrincipalId, epub: string, plain: Uint8Array, signature: string): EncryptedAccountWrap {
  const transport = hexToBytes(recoveryVector.delivery.transportScalarHex);
  const ephemeral = hexToBytes(scalarHex(7));
  const nonce = new Uint8Array(12).fill(9);
  const transportPub = seaPoint(transport);
  const point = p256.getPublicKey(ephemeral, false);
  const ephemeralPub = seaPoint(ephemeral);
  const shared = sharedX(ephemeral, uncompressedFromSea(transportPub));
  const wrapId = parseWrapObject("wrap_p_60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299_00112233445566778899aabbccddee09");
  const key = backupKdf(shared, principal, wrapId, transportPub, ephemeralPub, "sociacl-keyring-delivery-v1");
  shared.fill(0);
  const aad = backupAad(principal, wrapId, transportPub, ephemeralPub, "sociacl-keyring-delivery-v1");
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = new Uint8Array(Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
  key.fill(0);
  transport.fill(0);
  ephemeral.fill(0);
  const blob = new Uint8Array(1 + point.length + nonce.length + ciphertext.length);
  blob[0] = 1;
  blob.set(point, 1);
  blob.set(nonce, 1 + point.length);
  blob.set(ciphertext, 1 + point.length + nonce.length);
  return { principal, wrapId, epub, class: "delivery", ciphertextHex: bytesToHex(blob), signature };
}

function messageSync(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected throw");
}

type ProbeRotation = { nextKey: string; nextEpub: string };

function probeChain(): ProbeRotation[] {
  const item = records.accept.find((row) => row.name === "probe-v3-then-v3");
  if (!item || !Array.isArray(item.input)) throw new Error("probe-v3-then-v3");
  return item.input as ProbeRotation[];
}

function probeContext(): ResolutionContext {
  const links = new Map(records.context.links);
  const history = (principal: PrincipalId, at: number, until: number) =>
    records.context.authenticatedAccounts.includes(principal)
      ? { ok: true as const, value: historyState(principal, [], at, until) }
      : { ok: false as const, reason: "missing-history" as const };
  return {
    jwks: records.context.jwks,
    links,
    revocations: [],
    now: records.context.now,
    policy: records.context.policy,
    pinnedIss: new Set(records.context.pinnedIss),
    history,
    genesisEpubBindings: [],
  } as ResolutionContext;
}

function resolver(published: { rotations: readonly unknown[] }, context: ResolutionContext) {
  return (principal: PrincipalId) => {
    const resolved = resolveCurrentKey(principal, published.rotations, context);
    if (!resolved.ok) throw new Error("store-rejected");
    return resolved.value;
  };
}

test("retired keys cannot write and replays do not restore", () => {
  const chain = probeChain();
  const context = probeContext();
  const k0 = scalarSea(1);
  const k1 = scalarSea(2);
  const k2 = scalarSea(3);
  const e1 = scalarSea(6);
  const e2 = scalarSea(7);
  assert.equal(k0.pub, records.context.genesis);
  assert.equal(k1.pub, chain[0]?.nextKey);
  assert.equal(e1.pub, chain[0]?.nextEpub);
  assert.equal(k2.pub, chain[1]?.nextKey);
  assert.equal(e2.pub, chain[1]?.nextEpub);
  const principal = asPrincipal(k0.pub);
  const k0p = asPrincipal(k0.pub);
  const k1p = asPrincipal(k1.pub);
  const k2p = asPrincipal(k2.pub);
  const e1p = asPrincipal(e1.pub);
  const e2p = asPrincipal(e2.pub);

  const honest = new MemoryRecoveryStore(watch(chain, context));
  const current = dummyEnvelope(principal, 2, k2p, e2p);
  assert.equal(messageSync(() => putRecovery(honest, current, k0.priv)), "store-rejected");
  putRecovery(honest, current, k2.priv);
  assert.equal(
    messageSync(() => recovery.deleteRecoveryCopy(principal, 2, k0.priv, honest)),
    "store-rejected",
  );
  assert.equal(
    messageSync(() => recovery.deleteRecoveryCopy(principal, 2, k1.priv, honest)),
    "store-rejected",
  );
  assert.deepEqual(honest.get(principal, 2)?.bytes, current.bytes);
  assert.equal(
    messageSync(() => putRecovery(honest, dummyEnvelope(principal, 0, k0p, k0p), k0.priv)),
    "store-rejected",
  );
  assert.deepEqual(honest.get(principal, 2)?.bytes, current.bytes);

  const published = { rotations: chain.slice() as unknown[] };
  const floored = new MemoryRecoveryStore(resolver(published, context));
  putRecovery(floored, current, k2.priv);
  const generation = floored.writeGeneration(principal);
  const hash = recoveryEnvelopeHash(current);
  published.rotations = [];
  const short = resolveCurrentKey(principal, [], context);
  if (!short.ok) throw new Error(short.reason);
  const staleDelete = signStoreWrite(
    k0.priv,
    principal,
    "delete",
    "2",
    hash,
    "0",
    hash,
    "none",
    canonicalDecimal(generation),
  );
  verifyStoreWrite(principal, "delete", "2", hash, "0", hash, "none", canonicalDecimal(generation), staleDelete, short.value);
  assert.equal(messageSync(() => floored.delete(principal, 2, staleDelete)), "store-rejected");
  assert.ok(floored.get(principal, 2));

  const mid = { rotations: [chain[0]] as unknown[] };
  const between = new MemoryRecoveryStore(resolver(mid, context));
  const kept = dummyEnvelope(principal, 1, k1p, e1p);
  putRecovery(between, kept, k1.priv);
  const waiting = dummyEnvelope(principal, 2, k2p, e2p);
  waiting.bytes[40] = 0x21;
  putRecovery(between, waiting, k1.priv);
  mid.rotations = chain.slice();
  const stolen = dummyEnvelope(principal, 1, k1p, e1p);
  stolen.bytes[40] = 0x99;
  assert.equal(messageSync(() => putRecovery(between, stolen, k1.priv)), "store-rejected");
  assert.deepEqual(between.get(principal, 1)?.bytes, kept.bytes);
  assert.equal(between.get(principal, 2)?.bytes[40], 0x21);

  const early = new MemoryRecoveryStore(watch(chain.slice(0, 1), context));
  putRecovery(early, kept, k1.priv);
  putRecovery(early, waiting, k1.priv);
  const earlyAccount = early.publishedAccount(principal);
  const earlySig = signStoreWrite(
    k1.priv,
    principal,
    "put",
    "1",
    recoveryEnvelopeHash(stolen),
    "1",
    recoveryEnvelopeHash(kept),
    "none",
    canonicalDecimal(early.writeGeneration(principal)),
  );
  verifyStoreWrite(
    principal,
    "put",
    "1",
    recoveryEnvelopeHash(stolen),
    "1",
    recoveryEnvelopeHash(kept),
    "none",
    canonicalDecimal(early.writeGeneration(principal)),
    earlySig,
    earlyAccount,
  );
  early.put(stolen, earlySig);
  assert.deepEqual(early.get(principal, 1)?.bytes, stolen.bytes);
  assert.equal(early.get(principal, 2), undefined);

  const live = new MemoryRecoveryStore(watch(chain, context));
  const first = dummyEnvelope(principal, 2, k2p, e2p);
  first.bytes[40] = 0x11;
  const sig1 = signRecoveryOp(live, k2.priv, principal, "put", 2, recoveryEnvelopeHash(first), REPLACED_NONE);
  live.put(first, sig1);
  const second = dummyEnvelope(principal, 2, k2p, e2p);
  second.bytes[40] = 0x22;
  putRecovery(live, second, k2.priv);
  assert.equal(messageSync(() => live.put(first, sig1)), "store-rejected");
  assert.equal(live.get(principal, 2)?.bytes[40], 0x22);
  recovery.deleteRecoveryCopy(principal, 2, k2.priv, live);
  assert.equal(live.get(principal, 2), undefined);
  assert.equal(messageSync(() => live.put(first, sig1)), "store-rejected");
  assert.equal(live.get(principal, 2), undefined);

  const stage = { rotations: [] as unknown[] };
  const pendingStore = new MemoryRecoveryStore(resolver(stage, context));
  putRecovery(pendingStore, dummyEnvelope(principal, 0, k0p, k0p), k0.priv);
  const capturedEnv = dummyEnvelope(principal, 1, k1p, e1p);
  capturedEnv.bytes[40] = 0x44;
  const captured = signRecoveryOp(
    pendingStore,
    k0.priv,
    principal,
    "put",
    1,
    recoveryEnvelopeHash(capturedEnv),
    predecessor(pendingStore.pending(principal)),
  );
  pendingStore.put(capturedEnv, captured);
  stage.rotations = [chain[0]];
  const reseal = dummyEnvelope(principal, 1, k1p, e1p);
  reseal.bytes[40] = 0x55;
  putRecovery(pendingStore, reseal, k1.priv);
  assert.equal(pendingStore.get(principal, 0), undefined);
  assert.equal(pendingStore.get(principal, 1)?.bytes[40], 0x55);
  assert.equal(messageSync(() => pendingStore.put(capturedEnv, captured)), "store-rejected");
  assert.equal(
    messageSync(() => recovery.commitRecoveryCopy(principal, k1.priv, pendingStore)),
    "store-rejected",
  );
  assert.equal(pendingStore.get(principal, 1)?.bytes[40], 0x55);

  const lag = { rotations: [] as unknown[] };
  const rejectedCommit = new MemoryRecoveryStore(resolver(lag, context));
  const genesisRow = dummyEnvelope(principal, 0, k0p, k0p);
  putRecovery(rejectedCommit, genesisRow, k0.priv);
  const oldPending = dummyEnvelope(principal, 1, k1p, e1p);
  oldPending.bytes[40] = 0x66;
  putRecovery(rejectedCommit, oldPending, k0.priv);
  lag.rotations = chain.slice();
  assert.equal(
    messageSync(() => recovery.commitRecoveryCopy(principal, k2.priv, rejectedCommit)),
    "store-rejected",
  );
  assert.deepEqual(rejectedCommit.get(principal, 0)?.bytes, genesisRow.bytes);
  assert.equal(rejectedCommit.get(principal, 1)?.bytes[40], 0x66);
  const recovered = dummyEnvelope(principal, 2, k2p, e2p);
  recovered.bytes[40] = 0x77;
  putRecovery(rejectedCommit, recovered, k2.priv);
  assert.equal(rejectedCommit.get(principal, 2)?.bytes[40], 0x77);
  assert.equal(rejectedCommit.get(principal, 1), undefined);
  assert.equal(rejectedCommit.get(principal, 0), undefined);
});

test("an abandoned pending copy does not freeze recovery writes", () => {
  const keyring = genesisKeyring();
  const context = witnessedContext();
  const signing = keyring.pub;
  const encryption = keyring.epub;
  const store = new MemoryRecoveryStore(watch([], context));
  const current = dummyEnvelope(keyring.principal, 0, signing, encryption);
  putRecovery(store, current, keyring.currentPriv());
  const pending = dummyEnvelope(keyring.principal, 1, signing, encryption);
  pending.bytes[40] = 0x21;
  putRecovery(store, pending, keyring.currentPriv());
  recovery.deleteRecoveryCopy(keyring.principal, 1, keyring.currentPriv(), store);
  assert.deepEqual(store.get(keyring.principal, 0)?.bytes, current.bytes);
  assert.equal(store.get(keyring.principal, 1), undefined);
  const replaced = dummyEnvelope(keyring.principal, 1, signing, encryption);
  replaced.bytes[40] = 0x22;
  putRecovery(store, replaced, keyring.currentPriv());
  assert.equal(store.get(keyring.principal, 1)?.bytes[40], 0x22);
  const passphraseChange = dummyEnvelope(keyring.principal, 0, signing, encryption);
  passphraseChange.bytes[40] = 0x33;
  putRecovery(store, passphraseChange, keyring.currentPriv());
  assert.equal(store.get(keyring.principal, 0)?.bytes[40], 0x33);
  assert.equal(store.get(keyring.principal, 1), undefined);
});

test("a resolved head raises the shared floor", () => {
  const chain = probeChain();
  const context = probeContext();
  const k0 = scalarSea(1);
  const principal = asPrincipal(k0.pub);
  const k2 = asPrincipal(scalarSea(3).pub);
  const e2 = asPrincipal(scalarSea(7).pub);
  const published = { rotations: chain.slice() as unknown[] };
  const floor = new HeadFloor();
  const recoveryStore = new MemoryRecoveryStore(resolver(published, context), floor);
  const envelope = dummyEnvelope(principal, 2, k2, e2);
  const bogus = signStoreWrite(
    k0.priv,
    principal,
    "put",
    "2",
    recoveryEnvelopeHash(envelope),
    "2",
    REPLACED_NONE,
    "none",
    "0",
  );
  assert.equal(messageSync(() => recoveryStore.put(envelope, bogus)), "store-rejected");
  assert.equal(recoveryStore.writeGeneration(principal), 0);
  assert.equal(recoveryStore.get(principal, 2), undefined);
  published.rotations = [];
  assert.equal(
    messageSync(() => putRecovery(recoveryStore, dummyEnvelope(principal, 0, principal, principal), k0.priv)),
    "store-rejected",
  );
  assert.equal(recoveryStore.writeGeneration(principal), 0);

  const wraps = new MemoryKeyWrapStore(watch([], context), floor);
  const wrapId = parseWrapObject("wrap_p_60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299_00112233445566778899aabbccddee11");
  const wrap = {
    principal,
    wrapId,
    epub: ring.genesis.epub,
    class: "delivery" as const,
    ciphertextHex: "aa",
    signature: "ab".repeat(64),
  };
  const staleSignature = signStoreWrite(
    k0.priv,
    principal,
    "put",
    wrapId,
    wrapCiphertextHash("aa"),
    "0",
    REPLACED_NONE,
    STORE_CLASS_DELIVERY,
    "0",
  );
  assert.equal(
    messageSync(() => wraps.put({ principal, wrapId, epub: wrap.epub }, wrap, staleSignature)),
    "store-rejected",
  );
  assert.equal(wraps.list(principal).length, 0);
  assert.equal(wraps.writeGeneration(principal), 0);

  const shared = new HeadFloor();
  const wrapSeen = new MemoryKeyWrapStore(watch(chain, context), shared);
  wrapSeen.publishedAccount(principal);
  assert.equal(wrapSeen.writeGeneration(principal), 0);
  const recoveryStale = new MemoryRecoveryStore(watch([], context), shared);
  assert.equal(
    messageSync(() => putRecovery(recoveryStale, dummyEnvelope(principal, 0, principal, principal), k0.priv)),
    "store-rejected",
  );
  assert.equal(recoveryStale.get(principal, 0), undefined);
  assert.equal(recoveryStale.writeGeneration(principal), 0);
});

test("a retired key cannot fill or relabel wraps", () => {
  const chain = probeChain();
  const context = probeContext();
  const k0 = scalarSea(1);
  const k2 = scalarSea(3);
  const principal = asPrincipal(k0.pub);
  const store = new MemoryKeyWrapStore(watch(chain, context));
  for (let n = 0; n < MAX_WRAPS_PER_PRINCIPAL; n += 1) {
    const wrapId = mintedWrap(principal, n);
    assert.equal(
      messageSync(() => putWrap(store, principal, wrapId, "delivery", n.toString(16).padStart(2, "0"), k0.priv, context)),
      "store-rejected",
    );
  }
  assert.equal(store.list(principal).length, 0);
  const wrapId = parseWrapObject("wrap_p_60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299_00112233445566778899aabbccddee11");
  putWrap(store, principal, wrapId, "delivery", "aa", k2.priv, context);
  assert.equal(store.list(principal).length, 1);
  assert.equal(
    messageSync(() => deleteAccountWrap(principal, wrapId, k0.priv, store)),
    "store-rejected",
  );
  assert.equal(store.get(principal, wrapId)?.ciphertextHex, "aa");

  const labeled = new MemoryKeyWrapStore(watch(chain, context));
  const hash = wrapCiphertextHash("aa");
  const signature = signStoreWrite(
    k2.priv,
    principal,
    "put",
    wrapId,
    hash,
    "2",
    REPLACED_NONE,
    STORE_CLASS_DELIVERY,
    "0",
  );
  const deliveryRow = {
    principal,
    wrapId,
    epub: ring.genesis.epub,
    class: "delivery" as const,
    ciphertextHex: "aa",
    signature: "ab".repeat(64),
  };
  assert.equal(
    messageSync(() =>
      labeled.put(
        { principal, wrapId, epub: ring.genesis.epub },
        { ...deliveryRow, class: "genesis" },
        signature,
      ),
    ),
    "store-rejected",
  );
  assert.equal(labeled.get(principal, wrapId), undefined);
  labeled.put({ principal, wrapId, epub: ring.genesis.epub }, deliveryRow, signature);
  assert.equal(labeled.get(principal, wrapId)?.class, "delivery");
  deleteAccountWrap(principal, wrapId, k2.priv, labeled);
  assert.equal(labeled.get(principal, wrapId), undefined);
});
