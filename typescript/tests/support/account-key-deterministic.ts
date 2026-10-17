/**
 * Deterministic account-key wrappers for tests.
 * Not imported by typescript/src and not listed in the package exports.
 * The production module does not re-export these and does not consult NODE_TEST_CONTEXT.
 */
import type { ObjectId, ResolutionContext } from "../../ids/src/index.js";
import { encryptAccountBackup, hexToBytes, wrapContent } from "../../contract/account-key-seal.ts";
import type { EncryptedAccountWrap, GenesisAccount, KeyWrapStore } from "../../contract/account-key.ts";

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
