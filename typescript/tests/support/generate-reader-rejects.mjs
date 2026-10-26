import { readFileSync, writeFileSync } from 'node:fs';
import { createCipheriv, createHash } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { lengthPrefixed } from '../../contract/canonical.ts';
import { sharedX, uncompressedFromSea } from '../../contract/account-key-seal.ts';
const path = new URL('../../../vectors/encrypted-discovery/account-key.json', import.meta.url);
const v = JSON.parse(readFileSync(path, 'utf8'));
const c = v.contentWrap;
const scalar = Buffer.from(c.ephemeralScalarHex, 'hex');
const nonce = Buffer.from(c.nonceHex, 'hex');
const key = createHash('sha256').update(lengthPrefixed([
  's3rch-sea-secret-v1', Buffer.from(sharedX(scalar, uncompressedFromSea(v.epub))).toString('hex'),
])).digest();
const seal = (revision) => {
  const plain = lengthPrefixed(['s3rch-wrapped-key-v1', 'item-dek', String(c.epoch), 'reader-epub', v.epub, c.objectId, '', revision, c.dekHex]);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.alloc(0));
  return Buffer.concat([Buffer.from([1]), p256.getPublicKey(scalar, false), nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString('hex');
};
v.contentWrapRejects = [
  ...['', 'a'.repeat(63), 'A'.repeat(64), 'g'.repeat(64)].map((revisionId, i) => ({ name: `revision-${i}`, revisionId, wrappedKey: seal(revisionId), error: 'wrap-rejected' })),
  ...['', 'zz', '0', '00'].map((wrappedKey, i) => ({ name: `blob-${i}`, revisionId: c.revisionId, wrappedKey, error: 'wrap-rejected' })),
];
writeFileSync(path, JSON.stringify(v, null, 2) + '\n');
