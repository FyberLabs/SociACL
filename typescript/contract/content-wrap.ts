/**
 * Reader wrap for an item DEK. Same bytes as Rust `wrap_item_dek_to_readers`:
 * version, ephemeral point, nonce, then AES-GCM. The KDF is
 * `s3rch-sea-secret-v1` over the shared x coordinate. Epoch, epub, object,
 * and revision sit in the authenticated plaintext under `s3rch-wrapped-key-v1`.
 */
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { parseObjectId } from "../ids/src/index.js";
import {
  bytesToHex,
  decodeLengthPrefixed,
  hexToBytes,
  seaPoint,
  sharedX,
  unb64,
  uncompressedFromSea,
} from "./account-key-seal.ts";
import { canonicalDecimal, lengthPrefixed } from "./canonical.ts";

const DOMAIN_WRAPPED_KEY = "s3rch-wrapped-key-v1";
const DOMAIN_SEA_SECRET = "s3rch-sea-secret-v1";
const MAX_WRAP_HEX = 8192 * 2;

export function sealReaderWrap(
  epub: string,
  dekHex: string,
  epoch: number,
  objectId: string,
  revisionId: string,
  ephemeral: Uint8Array,
  nonce: Uint8Array,
): string {
  const parsed = parseObjectId(objectId);
  if (!parsed.ok) throw new Error(parsed.reason);
  if (!/^[0-9a-f]{64}$/u.test(revisionId)) throw new Error("bad-revision");
  const dek = hexToBytes(dekHex);
  if (dek.length !== 32 || ephemeral.length !== 32 || nonce.length !== 12) throw new Error("bad-key");
  const plain = lengthPrefixed([
    DOMAIN_WRAPPED_KEY,
    "item-dek",
    canonicalDecimal(epoch),
    "reader-epub",
    epub,
    parsed.value,
    "",
    revisionId,
    bytesToHex(dek),
  ]);
  dek.fill(0);
  const point = p256.getPublicKey(ephemeral, false);
  const ct = aesEncrypt(contentKdf(sharedX(ephemeral, uncompressedFromSea(epub))), nonce, plain);
  const blob = new Uint8Array(1 + point.length + nonce.length + ct.length);
  blob[0] = 1;
  blob.set(point, 1);
  blob.set(nonce, 1 + point.length);
  blob.set(ct, 1 + point.length + nonce.length);
  return bytesToHex(blob);
}

export function openReaderWrap(
  epriv: string,
  epub: string,
  wrappedHex: string,
  epoch: number,
  objectId: string,
  revisionId: string,
): string {
  const scalar = unb64(epriv);
  if (seaPoint(scalar) !== epub) {
    scalar.fill(0);
    throw new Error("wrap-rejected");
  }
  if (wrappedHex.length > MAX_WRAP_HEX || wrappedHex.length % 2 !== 0) throw new Error("wrap-rejected");
  const blob = hexToBytes(wrappedHex);
  if (blob[0] !== 1 || blob.length < 1 + 65 + 12 + 16) throw new Error("wrap-rejected");
  const ephemeral = blob.slice(1, 66);
  const nonce = blob.slice(66, 78);
  const plain = aesDecrypt(contentKdf(sharedX(scalar, ephemeral)), nonce, blob.slice(78));
  scalar.fill(0);
  const fields = decodeLengthPrefixed(plain);
  plain.fill(0);
  if (
    fields.length !== 9 ||
    fields[0] !== DOMAIN_WRAPPED_KEY ||
    fields[1] !== "item-dek" ||
    fields[2] !== canonicalDecimal(epoch) ||
    fields[3] !== "reader-epub" ||
    fields[4] !== epub ||
    fields[5] !== objectId ||
    fields[6] !== "" ||
    fields[7] !== revisionId ||
    !/^[0-9a-f]{64}$/u.test(fields[8] ?? "")
  ) {
    throw new Error("wrap-rejected");
  }
  const key = fields[8];
  if (key === undefined) throw new Error("wrap-rejected");
  return key;
}

function contentKdf(x: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(lengthPrefixed([DOMAIN_SEA_SECRET, bytesToHex(x)])).digest());
}

function aesEncrypt(key: Uint8Array, nonce: Uint8Array, plain: Uint8Array): Uint8Array {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(new Uint8Array());
  return new Uint8Array(Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]));
}

function aesDecrypt(key: Uint8Array, nonce: Uint8Array, body: Uint8Array): Uint8Array {
  const tag = body.slice(body.length - 16);
  const data = body.slice(0, body.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(new Uint8Array());
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
}
