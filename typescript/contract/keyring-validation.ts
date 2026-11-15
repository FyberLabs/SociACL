/** Canonical keyring validation shared by Node and browser imports. No RNG,
 * backups, storage or Node crypto is reachable from this module. */
import { p256 } from '@noble/curves/nist.js';
import { parsePrincipalId, resolveCurrentKey, type PrincipalId, type ResolutionContext } from '../ids/src/index.js';
import { b64, unb64 } from '../ids/src/util.js';
import { KEYRING_HISTORY_MAX } from './keyring-limits.ts';
import type { KeyringFields, KeyringSource } from './keyring-codec.ts';

export function validateKeyringFields(fields: KeyringFields): KeyringFields {
  const { principal: principalText, genesisEpub: genesisEpubText, pub: currentPubText,
    priv: currentPriv, epub: currentEpubText, epriv: currentEpriv, retired,
    laneId, priorLanes, contactLaneSecret, priorContactSecrets, contentEpoch, rotationSeq } = fields;
  const parsed = parsePrincipalId(principalText);
  if (!parsed.ok || parsed.value !== principalText) throw Error('keyring-rejected');
  const principal = parsed.value;
  requireBoundedRotationSeq(rotationSeq);
  requireHistoryCounts(priorLanes.length, priorContactSecrets.length);
  if (retired.length > 1024) throw new Error("too-many-keys");
  if (!Number.isSafeInteger(contentEpoch) || contentEpoch < 0) throw new Error("content-epoch");
  requireLaneSet(laneId, priorLanes);
  requireContactSet(contactLaneSecret, priorContactSecrets, laneId, priorLanes);
  const genesisEpub = encryptionPoint(genesisEpubText, null);
  if (genesisEpub === principal) throw new Error("epub-mismatch");
  const currentPub = signingPoint(currentPubText, currentPriv);
  const currentEpub = encryptionPoint(currentEpubText, currentEpriv);
  if (currentEpub === currentPub || currentEpub === principal) throw new Error("epub-mismatch");
  if (currentPub !== principal && currentEpub === genesisEpub) throw new Error("epub-mismatch");
  const retiredKeys: { epub: PrincipalId; epriv: string }[] = [];
  const seen = new Set<string>([currentEpub]);
  for (const row of retired) {
    const point = encryptionPoint(row.epub, row.epriv);
    // The genesis epub is retired once the signing key moves. It is not a second current epub.
    if (seen.has(point) || point === currentPub || point === principal) throw new Error("epub-reuse");
    seen.add(point);
    retiredKeys.push({ epub: point, epriv: row.epriv });
  }
  if (currentPub !== principal && !retiredKeys.some((row) => row.epub === genesisEpub)) {
    throw new Error("epub-mismatch");
  }
  if (priorLanes.length !== rotationSeq) throw Error('bad-lane');
  if (priorContactSecrets.length !== rotationSeq) throw Error('keyring-rejected');
  return { principal, genesisEpub, pub: currentPub, priv: currentPriv, epub: currentEpub,
    epriv: currentEpriv, retired: retiredKeys, laneId, priorLanes: [...priorLanes],
    contactLaneSecret, priorContactSecrets: [...priorContactSecrets], contentEpoch, rotationSeq };
}

export function confirmKeyring(keyring: KeyringSource, rotations: readonly unknown[], context: ResolutionContext): PrincipalId {
    const resolved = resolveCurrentKey(keyring.principal, rotations, context);
    if (!resolved.ok) throw new Error(resolved.reason);
    if (resolved.value.currentKey !== keyring.pub) throw new Error("pub-mismatch");
    if (resolved.value.currentEpub == null) throw new Error("epub-unknown");
    if (resolved.value.currentEpub !== keyring.epub) throw new Error("epub-mismatch");
    if (resolved.value.bindingEpub != null && resolved.value.bindingEpub !== keyring.genesisEpub) {
      throw new Error("epub-mismatch");
    }
    if (resolved.value.rotations.length !== keyring.rotationSeq) throw new Error("rotation-rejected");
    if (keyring.contentEpoch < resolved.value.rotations.length) throw new Error("content-epoch");
    for (const row of resolved.value.rotations) {
      if (row.nextEpub && row.nextEpub !== keyring.epub && !keyring.retired().some((retired) => retired.epub === row.nextEpub)) {
        throw new Error("epub-mismatch");
      }
    }
    if (keyring.retired().length > 1024) throw new Error("too-many-keys");
    return resolved.value.currentEpub;
}

export function requireLaneSet(laneId: string, priorLanes: readonly string[]): void {
  if (!/^[0-9a-f]{64}$/u.test(laneId)) throw new Error("bad-lane");
  const seen = new Set<string>([laneId]);
  for (const prior of priorLanes) {
    if (!/^[0-9a-f]{64}$/u.test(prior) || seen.has(prior)) throw new Error("bad-lane");
    seen.add(prior);
  }
}

export function requireContactSet(
  secret: string,
  prior: readonly string[],
  laneId: string,
  priorLanes: readonly string[],
): void {
  const disclosed = new Set<string>([laneId, ...priorLanes]);
  if (!/^[0-9a-f]{64}$/u.test(secret) || disclosed.has(secret)) throw new Error("bad-lane");
  const seen = new Set<string>([secret]);
  for (const held of prior) {
    if (!/^[0-9a-f]{64}$/u.test(held) || seen.has(held) || disclosed.has(held)) {
      throw new Error("bad-lane");
    }
    seen.add(held);
  }
}

export function requireBoundedRotationSeq(rotationSeq: number): void {
  if (!Number.isSafeInteger(rotationSeq) || rotationSeq < 0) throw new Error("keyring-rejected");
  if (rotationSeq > KEYRING_HISTORY_MAX) throw new Error("keyring-too-large");
}

export function requireHistoryCounts(lanes: number, contacts: number): void {
  if (lanes > KEYRING_HISTORY_MAX || contacts > KEYRING_HISTORY_MAX) throw new Error("keyring-too-large");
}

function scalarPoint(secret: string): string {
  if (typeof secret !== 'string' || secret.length !== 43) throw Error('base64url');
  const bytes = unb64(secret);
  try {
    if (bytes.length !== 32) throw Error('base64url');
    const point = p256.getPublicKey(bytes, false);
    return b64(point.subarray(1, 33)) + '.' + b64(point.subarray(33));
  } finally { bytes.fill(0); }
}
export function signingPoint(pub: string, priv: string): PrincipalId {
  const parsed = parsePrincipalId(pub);
  if (!parsed.ok || parsed.value !== pub || scalarPoint(priv) !== pub) throw Error('pub-mismatch');
  return parsed.value;
}
export function encryptionPoint(pub: string, priv: string | null): PrincipalId {
  const parsed = parsePrincipalId(pub);
  if (!parsed.ok || parsed.value !== pub) throw Error('epub-mismatch');
  if (priv !== null && scalarPoint(priv) !== pub) throw Error('epub-mismatch');
  return parsed.value;
}
