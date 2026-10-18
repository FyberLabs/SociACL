/**
 * Deterministic reader wrap for conformance tests.
 * Production `sealContent` draws the ephemeral and nonce itself and does not
 * export this helper.
 */
import { AccountKeyring } from "../../contract/account-keyring.ts";
import { sealReaderWrap } from "../../contract/content-wrap.ts";
import type { ResolutionContext } from "../../ids/src/index.js";

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
