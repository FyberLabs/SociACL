/** Shared rotation preparation over canonical keyring fields; no Node dependency. */
import { signingPoint,encryptionPoint,validateKeyringFields,confirmKeyring } from './keyring-validation.ts';
import { KEYRING_HISTORY_MAX } from './keyring-limits.ts';
import { parsePrincipalId,parseEip55,resolveCurrentKey,checkRotationDraft,type PrincipalId,type ResolutionContext } from '../ids/src/index.js';
import type {KeyringSource,KeyringFields} from './keyring-codec.ts';

export type RotationMint = {
  readonly signingPub: string;
  readonly signingPriv: string;
  readonly epub: string;
  readonly epriv: string;
  readonly laneId: string;
  readonly contactLaneSecret?: string;
};

export type RotationDraft = {
  readonly v: 1;
  readonly kind: "rotate";
  readonly principal: PrincipalId;
  readonly seq: number;
  readonly prevKey: PrincipalId;
  readonly nextKey: PrincipalId;
  readonly nextEpub: PrincipalId;
  readonly version: 3;
};

export function prepareKeyringRotationFields(keyring:KeyringSource,trusted:readonly string[],lost:string,
  rotations:readonly unknown[],context:ResolutionContext,mint:()=>RotationMint,
  freshContactSecret:(banned:readonly string[])=>string):{fields:KeyringFields;draft:RotationDraft} {
  if (trusted.length === 0 || !trusted.includes(lost)) throw new Error("lost-device");
  const seen = new Set<string>();
  for (const localId of trusted) {
    if (seen.has(localId)) throw new Error("duplicate-device");
    seen.add(localId);
    requireDevice(localId);
  }
  if (keyring.rotationSeq >= KEYRING_HISTORY_MAX) throw new Error("keyring-too-large");
  const minted = mint();
  const contactLaneSecret = minted.contactLaneSecret ?? freshContactSecret([
    minted.laneId,
    keyring.laneId(),
    ...keyring.priorLanes(),
    keyring.contactLaneSecret(),
    ...keyring.priorContactSecrets(),
  ]);
  const nextPub = signingPoint(minted.signingPub, minted.signingPriv);
  const nextEpub = encryptionPoint(minted.epub, minted.epriv);
  if (nextEpub === nextPub || holdsPoint(keyring, nextEpub) || holdsPoint(keyring, nextPub)) {
    throw new Error("epub-reuse");
  }
  if (
    reusesLane(keyring, minted.laneId) ||
    reusesContactSecret(keyring, contactLaneSecret) ||
    reusesContactSecret(keyring, minted.laneId) ||
    disclosedLane(contactLaneSecret, minted.laneId, keyring)
  ) {
    throw new Error("bad-lane");
  }
  confirmKeyring(keyring, rotations, context);
  const resolved = resolveCurrentKey(keyring.principal, rotations, context);
  if (!resolved.ok) throw new Error(resolved.reason);
  const historical = new Set<string>([keyring.principal, keyring.pub]);
  for (const row of resolved.value.rotations) {
    historical.add(row.prevKey);
    historical.add(row.nextKey);
  }
  if (historical.has(nextPub) || nextPub === resolved.value.bindingEpub || nextEpub === resolved.value.bindingEpub) {
    throw new Error("epub-reuse");
  }
  if (keyring.retired().length >= 1024) throw new Error("too-many-keys");
  const retired = [...keyring.retired(), { epub: keyring.epub, epriv: keyring.currentEpriv() }];
  const seq = keyring.rotationSeq + 1;
  const epoch = keyring.contentEpoch + 1;
  if (!Number.isSafeInteger(seq)) throw new Error("rotation-rejected");
  if (!Number.isSafeInteger(epoch)) throw new Error("content-epoch");
  const fields = validateKeyringFields({principal:keyring.principal,genesisEpub:keyring.genesisEpub,
    pub:nextPub,priv:minted.signingPriv,epub:nextEpub,epriv:minted.epriv,retired,
    laneId:minted.laneId,priorLanes:[...keyring.priorLanes(),keyring.laneId()],contactLaneSecret,
    priorContactSecrets:[...keyring.priorContactSecrets(),keyring.contactLaneSecret()],contentEpoch:epoch,rotationSeq:seq});
  const draft: RotationDraft = {
    v: 1,
    kind: "rotate",
    principal: fields.principal as PrincipalId,
    seq,
    prevKey: keyring.pub as PrincipalId,
    nextKey: nextPub,
    nextEpub,
    version: 3,
  };
  const published = checkRotationDraft(
    {
      v: 1,
      kind: "rotate",
      principal: draft.principal,
      seq: draft.seq,
      prevKey: draft.prevKey,
      nextKey: draft.nextKey,
      nextEpub: draft.nextEpub,
      retainedLinks: [],
    },
    [],
    keyring.principal,
    rotations,
    context,
  );
  if (!published.ok) throw new Error(published.reason);
  return { fields, draft };
}

function reusesLane(keyring: KeyringSource, laneId: string): boolean {
  return !/^[0-9a-f]{64}$/u.test(laneId) || laneId === keyring.laneId() || keyring.priorLanes().includes(laneId);
}

function reusesContactSecret(keyring: KeyringSource, secret: string): boolean {
  return !/^[0-9a-f]{64}$/u.test(secret) || secret === keyring.contactLaneSecret() || keyring.priorContactSecrets().includes(secret);
}

function disclosedLane(secret: string, laneId: string, keyring: KeyringSource): boolean {
  return secret === laneId || secret === keyring.laneId() || keyring.priorLanes().includes(secret);
}

function holdsPoint(keyring: KeyringSource, point: PrincipalId): boolean {
  return (
    point === keyring.principal ||
    point === keyring.genesisEpub ||
    point === keyring.pub ||
    point === keyring.epub ||
    keyring.retired().some((row) => row.epub === point)
  );
}

function requireDevice(localId: string): void {
  if (localId.length === 0) throw new Error("empty-device");
  if (parsePrincipalId(localId).ok || parseEip55(localId).ok) throw new Error("device-id");
}

