import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { argon2id } from "hash-wasm";
import { MemoryKeyWrapStore, importGenesis, openAccountBackup, parseWrapObject, sealAccountBackup, type EncryptedAccountWrap } from "../contract/account-key.ts";
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
import { encodePassphrase, MemoryRecoveryStore, openRecoveryCopy, type RecoveryEnvelope } from "../contract/recovery-seal.ts";
import { deliverKeyringWith, sealRecoveryCopyWith } from "./support/recovery-deterministic.ts";
import {
  historyState,
  parsePrincipalId,
  type Jwks,
  type PrincipalId,
  type ResolutionContext,
} from "../ids/src/index.js";

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
  retention: { downgrade: string; sameSeq: string; higherSeq: string; commitUnverified: string };
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
    signingPub: string;
    signingPriv: string;
    epub: string;
    epriv: string;
    principal: string;
  };
  mint: { signingPub: string; signingPriv: string; epub: string; epriv: string; laneId: string };
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
  return { principal, rotationSeq: 0, bytes };
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
  assert.equal(recoveryVector.domain, "sociacl-recovery-copy-v1");
  assert.equal(recoveryVector.keyringDomain, "sociacl-keyring-plain-v1");
  assert.equal(recoveryVector.bindDomain, "sociacl-keyring-delivery-v1");
  assert.equal(recoveryVector.sigDomain, "sociacl-keyring-delivery-sig-v1");
  assert.equal(ARGON2ID_LIMITS.parallelism.floor, 4);
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
        ? { principal, rotationSeq: 0, bytes: new Uint8Array(row.envelopeBytes) }
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
  const store = new MemoryRecoveryStore();
  const passphrase = new TextEncoder().encode(recoveryVector.passphraseUtf8);
  const envelope = await sealRecoveryCopyWith(keyring, passphrase, hexToBytes(recoveryVector.saltHex), hexToBytes(recoveryVector.nonceHex), store);
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
  const gun = opened.gunDocument();
  assert.equal(gun.includes(keyring.currentPriv()), false);
  assert.equal(gun.includes(keyring.currentEpriv()), false);
  assert.equal(gun.includes(keyring.laneId()), false);
  assert.equal(hex.includes(keyring.currentPriv()), false);
  assert.equal(hex.includes(keyring.laneId()), false);
  const wrong = await errorMessage(() =>
    openRecoveryCopy(new TextEncoder().encode(recoveryVector.wrongPassphraseUtf8), envelope, keyring.principal, 0, [], context),
  );
  const tampered: RecoveryEnvelope = {
    principal: envelope.principal,
    rotationSeq: envelope.rotationSeq,
    bytes: new Uint8Array(envelope.bytes),
  };
  const last = tampered.bytes.length - 1;
  tampered.bytes[last] = (tampered.bytes[last] ?? 0) ^ 0x01;
  const tamper = await errorMessage(() => openRecoveryCopy(passphrase, tampered, keyring.principal, 0, [], context));
  assert.equal(wrong, tamper);
  assert.equal(wrong, "recovery-rejected");
  const stale = await errorMessage(() => openRecoveryCopy(passphrase, envelope, keyring.principal, 1, [], context));
  assert.equal(stale, "recovery-stale");
});

test("rotation reseals a new version and writes only the adapter", { timeout: 180_000 }, async () => {
  const keyring = genesisKeyring();
  const context = witnessedContext();
  const store = new MemoryRecoveryStore();
  const passphrase = new TextEncoder().encode(recoveryVector.passphraseUtf8);
  store.put({ principal: keyring.principal, rotationSeq: 0, bytes: hexToBytes(recoveryVector.envelopeHex) });
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
    messageSync(() => recovery.commitRecoveryCopy(keyring.principal, [], context, store)),
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
  const store = new MemoryKeyWrapStore();
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
  const opened = delivery.openDeliveredKeyring(recoveryVector.delivery.transportScalarHex, wrap, keyring.principal, 0, [], context);
  assert.equal(opened.principal, keyring.principal);
  assert.equal(opened.pub, keyring.pub);
  assert.equal(opened.currentPriv(), keyring.currentPriv());
  assert.equal(opened.currentEpriv(), keyring.currentEpriv());
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
        { ...wrap, wrapId: parseWrapObject("wrap_00112233445566778899aabbccddee00") },
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

function dummyEnvelope(principal: PrincipalId, rotationSeq: number): RecoveryEnvelope {
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
  return { principal, rotationSeq, bytes };
}

test("the store copies envelopes and keeps only the latest", () => {
  const principal = principalOf();
  const store = new MemoryRecoveryStore();
  const older = dummyEnvelope(principal, 0);
  const original = new Uint8Array(older.bytes);
  store.put(older);
  older.bytes[40] = (older.bytes[40] ?? 0) ^ 0x01;
  const stored = store.get(principal, 0);
  if (!stored) throw new Error("missing copy");
  assert.deepEqual(stored.bytes, original);
  stored.bytes[40] = (stored.bytes[40] ?? 0) ^ 0xff;
  const again = store.get(principal, 0);
  if (!again) throw new Error("missing copy");
  assert.deepEqual(again.bytes, original);
  store.put(dummyEnvelope(principal, 1));
  assert.ok(store.get(principal, 0));
  assert.ok(store.get(principal, 1));
  const resealed = dummyEnvelope(principal, 0);
  resealed.bytes[40] = (resealed.bytes[40] ?? 0) ^ 0x11;
  store.put(resealed);
  assert.equal(store.get(principal, 0)?.bytes[40], resealed.bytes[40]);
  assert.ok(store.get(principal, 1));
  const high = new MemoryRecoveryStore();
  high.put(dummyEnvelope(principal, 2));
  assert.throws(
    () => high.put(dummyEnvelope(principal, 0)),
    (error: unknown) => error instanceof Error && error.message === recoveryVector.retention.downgrade,
  );
  assert.ok(high.get(principal, 2));
  assert.equal(high.get(principal, 0), undefined);
  const gap = new MemoryRecoveryStore();
  gap.put(dummyEnvelope(principal, 0));
  gap.put(dummyEnvelope(principal, 2));
  assert.throws(
    () => gap.put(dummyEnvelope(principal, 1)),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  assert.ok(gap.get(principal, 0));
  assert.ok(gap.get(principal, 2));
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
  );
  const store = new MemoryRecoveryStore();
  const envelope = await recovery.sealRecoveryCopyFromString(keyring, recoveryVector.passphraseUtf8, store);
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
  const forward = new MemoryRecoveryStore();
  forward.put(dummyEnvelope(keyring.principal, 0));
  forward.put(dummyEnvelope(keyring.principal, 1));
  recovery.commitRecoveryCopy(keyring.principal, [rotation.input], context, forward);
  assert.equal(forward.get(keyring.principal, 0), undefined);
  assert.ok(forward.get(keyring.principal, 1));
  assert.equal(
    messageSync(() => recovery.commitRecoveryCopy(keyring.principal, [rotation.input], context, forward)),
    "store-rejected",
  );
  assert.ok(forward.get(keyring.principal, 1));
  assert.throws(
    () => forward.put(dummyEnvelope(keyring.principal, 0)),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  const stuck = new MemoryRecoveryStore();
  stuck.put(dummyEnvelope(keyring.principal, 0));
  stuck.put(dummyEnvelope(keyring.principal, 1));
  assert.equal(
    messageSync(() => recovery.commitRecoveryCopy(keyring.principal, [], context, stuck)),
    recoveryVector.retention.commitUnverified,
  );
  assert.ok(stuck.get(keyring.principal, 0));
  assert.ok(stuck.get(keyring.principal, 1));
});

test("two devices and the genesis backup share the store", () => {
  const keyring = genesisKeyring();
  const context = witnessedContext();
  const store = new MemoryKeyWrapStore();
  const account = importGenesis(
    ring.genesis.laneId,
    ring.genesis.signingPub,
    ring.genesis.signingPriv,
    ring.genesis.epub,
    ring.genesis.epriv,
  );
  const genesisId = parseWrapObject("wrap_00112233445566778899aabbccddee01");
  const firstId = parseWrapObject(recoveryVector.delivery.wrapId);
  const secondId = parseWrapObject("wrap_00112233445566778899aabbccddee02");
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
  const store = new MemoryKeyWrapStore();
  const ids: ReturnType<typeof parseWrapObject>[] = [];
  for (let n = 0; n < MAX_WRAPS_PER_PRINCIPAL; n += 1) {
    const wrapId = parseWrapObject(`wrap_${n.toString(16).padStart(32, "0")}`);
    ids.push(wrapId);
    store.put(
      { principal, wrapId, epub: ring.genesis.epub },
      { principal, wrapId, epub: ring.genesis.epub, class: "delivery", ciphertextHex: "aa", signature: "ab".repeat(64) },
    );
  }
  const extra = parseWrapObject(`wrap_${(80).toString(16).padStart(32, "0")}`);
  assert.throws(
    () =>
      store.put(
        { principal, wrapId: extra, epub: ring.genesis.epub },
        { principal, wrapId: extra, epub: ring.genesis.epub, class: "delivery", ciphertextHex: "bb", signature: "ab".repeat(64) },
      ),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  const first = ids[0];
  if (!first) throw new Error("missing wrap");
  store.put(
    { principal, wrapId: first, epub: ring.genesis.epub },
    { principal, wrapId: first, epub: ring.genesis.epub, class: "delivery", ciphertextHex: "cc", signature: "ab".repeat(64) },
  );
  assert.equal(store.get(principal, first)?.ciphertextHex, "cc");
  assert.throws(
    () =>
      store.put(
        { principal, wrapId: first, epub: ring.genesis.epub },
        { principal, wrapId: first, epub: ring.genesis.epub, class: "genesis", ciphertextHex: "dd", signature: "ab".repeat(64) },
      ),
    (error: unknown) => error instanceof Error && error.message === "store-rejected",
  );
  assert.equal(store.get(principal, first)?.ciphertextHex, "cc");
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
  );
  const store = new MemoryKeyWrapStore();
  const transport = scalarSea(4);
  const wrap = deliverKeyringWith(
    keyring,
    transport.pub,
    hexToBytes(scalarHex(7)),
    new Uint8Array(12).fill(9),
    parseWrapObject("wrap_00112233445566778899aabbccddee03"),
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
  const wrapId = parseWrapObject("wrap_00112233445566778899aabbccddee09");
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
