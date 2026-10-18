/**
 * Deterministic account-key wrappers for tests.
 * Not imported by typescript/src and not listed in the package exports.
 * The production module does not re-export these and does not consult NODE_TEST_CONTEXT.
 */
import type { ObjectId, ResolutionContext } from "../../ids/src/index.js";
import { encryptAccountBackup, hexToBytes, wrapContent } from "../../contract/account-key-seal.ts";
import type { EncryptedAccountWrap, GenesisAccount, KeyWrapStore } from "../../contract/account-key.ts";
import { AccountKeyring } from "../../contract/account-keyring.ts";
import { sealReaderWrap } from "../../contract/content-wrap.ts";

export function sealAccountBackupWith(
  account: GenesisAccount,
  transportPub: string,
  ephemeralScalarHex: string,
  nonceHex: string,
  wrapId: ObjectId,
  rotations: readonly unknown[],
  context: ResolutionContext,
  store: KeyWrapStore,
): EncryptedAccountWrap {
  return encryptAccountBackup(
    account,
    transportPub,
    hexToBytes(ephemeralScalarHex),
    hexToBytes(nonceHex),
    wrapId,
    rotations,
    context,
    store,
  );
}

export function contentWrapHexWith(
  account: GenesisAccount,
  dekHex: string,
  ephemeralScalarHex: string,
  nonceHex: string,
  epoch: number,
  objectId: string,
  revisionId: string,
): string {
  return wrapContent(account, dekHex, ephemeralScalarHex, nonceHex, epoch, objectId, revisionId);
}

/**
 * Deterministic reader wrap for conformance tests.
 * Production `sealContent` draws the ephemeral and nonce itself and does not
 * export this helper.
 */
export function sealContentWith(
  keyring: AccountKeyring,
  dekHex: string,
  objectId: string,
  revisionId: string,
  rotations: readonly unknown[],
  context: ResolutionContext,
  gunUserEpub: string | null,
  ephemeral: Uint8Array,
  nonce: Uint8Array,
): { epoch: number; targetId: string; wrappedKey: string } {
  const witnessed = keyring.confirm(rotations, context);
  void gunUserEpub;
  return {
    epoch: keyring.contentEpoch,
    targetId: witnessed,
    wrappedKey: sealReaderWrap(witnessed, dekHex, keyring.contentEpoch, objectId, revisionId, ephemeral, nonce),
  };
}
