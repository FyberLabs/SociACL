/** Public deterministic test scalars. Codec view only: not an authenticated account. */
import { p256 } from "@noble/curves/nist.js";
import type { AccountKeyring } from "../../contract/account-keyring.ts";
import type { PrincipalId } from "../../ids/src/index.js";

export function capacityKeyring(count = 1024): AccountKeyring {
  const pair = (n: number) => {
    const scalar = new Uint8Array(32);
    new DataView(scalar.buffer).setUint32(28, n);
    const point = p256.getPublicKey(scalar, false);
    return {
      pub: (Buffer.from(point.subarray(1, 33)).toString("base64url") + "." + Buffer.from(point.subarray(33)).toString("base64url")) as PrincipalId,
      priv: Buffer.from(scalar).toString("base64url"),
    };
  };
  const genesis = pair(1), genesisEncryption = pair(2);
  const current = pair(count + 3), encryption = pair(count + 4);
  const hex = (n: number) => n.toString(16).padStart(64, "0");
  const retired = Array.from({ length: count }, (_, i) => {
    const key = pair(i + 2);
    return { epub: key.pub, epriv: key.priv };
  });
  // Encoding consumes this public view. It does not perform chain authentication.
  return {
    principal: genesis.pub, genesisEpub: genesisEncryption.pub,
    pub: current.pub, epub: encryption.pub,
    currentPriv: () => current.priv, currentEpriv: () => encryption.priv,
    retired: () => retired, laneId: () => hex(0),
    priorLanes: () => Array.from({ length: count }, (_, i) => hex(i + 1)),
    contactLaneSecret: () => hex(2 * count + 1),
    priorContactSecrets: () => Array.from({ length: count }, (_, i) => hex(count + i + 1)),
    contentEpoch: Number.MAX_SAFE_INTEGER, rotationSeq: count,
  } as unknown as AccountKeyring;
}
