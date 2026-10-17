import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ok, fail, text, data, integer, unb64, hex, unhex, utf8, lengthPrefixed } from './util.js';
import { parsePrincipalId, parseEip55, parseOidcCredential, checksum } from './ids.js';
import { uniqueJson } from './json.js';
/** @import {PrincipalId, Eip55, Result, WalletLink, OidcLink, Rotate, Revoke, IdentityRecord, UnsignedRecord, Jwks, Siwe, ResolutionContext} from './types.js' */

/** @param {Record<string, unknown>} r @param {string[]} keys */
const only = (r, keys) => Object.keys(r).every(k => keys.includes(k));
/** @param {unknown} x @returns {Result<Siwe>} */
function siweData(x) {
  const d = data(x); if (!d.ok) return d;
  if (!only(d.value, ['message', 'signature'])) return fail('bad-record');
  const { message, signature } = d.value;
  // SIWE intentionally has LF separators, so do not run the scalar-id text guard.
  if (typeof message !== 'string' || typeof signature !== 'string') return fail('not-string');
  if (message.length > 8192) return fail('too-long');
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) return fail('unsupported-wallet');
  return ok(Object.freeze({ message, signature: /** @type {`0x${string}`} */ (signature) }));
}
/** @param {unknown} x @param {boolean} [unsigned] @returns {Result<IdentityRecord>} */
function record(x, unsigned = false) {
  const d = data(x); if (!d.ok) return d;
  const r = d.value;
  if (r.v !== 1 || !['wallet', 'oidc', 'rotate', 'revoke'].includes(/** @type {string} */ (r.kind))) return fail('bad-record');
  const principal = parsePrincipalId(r.principal); if (!principal.ok) return principal;
  if (!integer(r.issuedAt)) return fail('bad-record');
  const base = { v: /** @type {const} */ (1), principal: principal.value, issuedAt: /** @type {number} */ (r.issuedAt) };
  const common = ['v', 'kind', 'principal', 'issuedAt'];
  if (r.kind === 'wallet' || r.kind === 'oidc') {
    const nonce = text(r.nonce, 128); if (!nonce.ok) return nonce;
    if (!/^[A-Za-z0-9]{8,128}$/.test(nonce.value)) return fail('bad-record');
    const keySig = unsigned ? ok('') : text(r.keySig, 128); if (!keySig.ok) return keySig;
    if (r.kind === 'wallet') {
      if (!only(r, [...common, 'address', 'nonce', 'keySig', 'siwe'])) return fail('bad-record');
      const address = parseEip55(r.address); if (!address.ok) return address;
      const siwe = unsigned ? ok({ message: '', signature: /** @type {`0x${string}`} */ ('0x') }) : siweData(r.siwe); if (!siwe.ok) return siwe;
      return ok(Object.freeze({ ...base, kind: 'wallet', address: address.value, nonce: nonce.value, keySig: keySig.value, siwe: siwe.value }));
    }
    if (!only(r, [...common, 'cred', 'nonce', 'keySig', 'attest'])) return fail('bad-record');
    const cred = parseOidcCredential(r.cred); if (!cred.ok) return cred;
    const attest = unsigned ? ok('') : text(r.attest, 16384); if (!attest.ok) return attest;
    return ok(Object.freeze({ ...base, kind: 'oidc', cred: cred.value, nonce: nonce.value, keySig: keySig.value, attest: attest.value }));
  }
  if (r.kind === 'revoke') {
    if (!only(r, [...common, 'linkId', 'keySig'])) return fail('bad-record');
    const id = text(r.linkId, 64); if (!id.ok) return id;
    if (!/^[0-9a-f]{64}$/.test(id.value)) return fail('bad-record');
    const sig = unsigned ? ok('') : text(r.keySig, 128); if (!sig.ok) return sig;
    return ok(Object.freeze({ ...base, kind: 'revoke', linkId: id.value, keySig: sig.value }));
  }
  if (!only(r, [...common, 'seq', 'prevKey', 'nextKey', 'nextSig', 'authorizer', 'attest'])) return fail('bad-record');
  if (!integer(r.seq) || r.seq === 0) return fail('bad-sequence');
  const prev = parsePrincipalId(r.prevKey); if (!prev.ok) return prev;
  const next = parsePrincipalId(r.nextKey); if (!next.ok) return next;
  const sig = unsigned ? ok('') : text(r.nextSig, 128); if (!sig.ok) return sig;
  const attest = unsigned ? ok('') : text(r.attest, 16384); if (!attest.ok) return attest;
  const ad = unsigned ? data({ kind: 'oidc-fresh-login' }) : data(r.authorizer); if (!ad.ok) return ad;
  const a = ad.value;
  /** @type {Rotate['authorizer']} */ let authorizer;
  if (a.kind === 'oidc-fresh-login' && only(a, ['kind'])) authorizer = { kind: a.kind };
  else if (a.kind === 'wallet' && only(a, ['kind', 'link', 'siwe'])) {
    const link = text(a.link, 64); if (!link.ok) return link;
    if (!/^[0-9a-f]{64}$/.test(link.value)) return fail('bad-record');
    const siwe = siweData(a.siwe); if (!siwe.ok) return siwe;
    authorizer = { kind: a.kind, link: link.value, siwe: siwe.value };
  } else return fail('bad-record');
  return ok(Object.freeze({ ...base, kind: 'rotate', seq: /** @type {number} */ (r.seq), prevKey: prev.value, nextKey: next.value, nextSig: sig.value, attest: attest.value, authorizer: Object.freeze(authorizer) }));
}
/** @param {UnsignedRecord} r @returns {Result<Uint8Array>} */
export function signingBytes(r) {
  const p = record(r, true); if (!p.ok) return p;
  return ok(bytes(p.value));
}
/** @param {IdentityRecord} r */
function bytes(r) {
  const t = String(r.issuedAt);
  switch (r.kind) {
    case 'wallet': return lengthPrefixed(['sociacl-link-wallet-v1', r.principal, r.address, t, r.nonce]);
    case 'oidc': return lengthPrefixed(['sociacl-link-oidc-v1', r.principal, r.cred.iss, r.cred.tenant, r.cred.sub, t, r.nonce]);
    case 'rotate': return lengthPrefixed(['sociacl-rotate-v1', r.principal, String(r.seq), r.prevKey, r.nextKey, t]);
    case 'revoke': return lengthPrefixed(['sociacl-revoke-v1', r.principal, r.linkId, t]);
  }
}
/** @param {UnsignedRecord} r @returns {Result<string>} */
export function linkId(r) { const b = signingBytes(r); return b.ok ? ok(hex(sha256(b.value))) : b; }
/** @param {PrincipalId} p @param {string} sig @param {Uint8Array} message */
function keyVerify(p, sig, message) {
  try { return p256.verify(unb64(sig), message, new Uint8Array([4, ...unb64(p.slice(0, 43)), ...unb64(p.slice(44))]), { prehash: true, lowS: false, format: 'compact' }); }
  catch { return false; }
}
/** @param {number} issuedAt @param {number} now */
function time(issuedAt, now) { return !integer(now) ? fail('bad-record') : issuedAt > now ? fail('future-record') : ok(true); }
/** RFC3339 with an explicit offset; never accept JS date repair. @param {string} s */
function date(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.[0-9]+)?([Zz]|[+-]\d{2}:\d{2})$/.exec(s);
  if (!m) return NaN;
  const y = +m[1], month = +m[2], day = +m[3], hour = +m[4], minute = +m[5], sec = +m[6];
  const days = [31, y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || sec > 59) return NaN;
  const d = new Date(0); d.setUTCFullYear(y, month - 1, day); d.setUTCHours(hour, minute, sec, 0);
  let offset = 0;
  if (!/^[Zz]$/.test(m[8])) {
    const h = +m[8].slice(1, 3), min = +m[8].slice(4);
    if (h > 23 || min > 59) return NaN;
    offset = (h * 60 + min) * 60 * (m[8][0] === '+' ? 1 : -1);
  }
  return d.getTime() / 1000 + Number(m[7] ?? 0) - offset;
}
/** @param {string} s */
function uri(s) {
  if (!/^[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]+$/.test(s) || /%(?![0-9a-fA-F]{2})/.test(s) || /[<>"{}|\\^`]/.test(s)) return false;
  try { new URL(s); return true; } catch { return false; }
}
/** EIP-4361 statement binds the entire identity record, not an application session. @param {Siwe} proof @param {Eip55} address @param {Uint8Array} message @param {number} issuedAt @param {number} now @param {string} [nonce] */
function siweVerify(proof, address, message, issuedAt, now, nonce) {
  const lines = proof.message.split('\n');
  if (lines.length < 10 || !/^(?:[A-Za-z][A-Za-z0-9+.-]*:\/\/)?[^\s/?#]+ wants you to sign in with your Ethereum account:$/.test(lines[0]) || lines[1] !== address || lines[2] !== '' || lines[3] !== 'SociACL link: ' + hex(sha256(message)) || lines[4] !== '') return fail('bad-signature');
  if (!lines[5].startsWith('URI: ') || !uri(lines[5].slice(5)) || lines[6] !== 'Version: 1' || !/^Chain ID: [0-9]+$/.test(lines[7]) || !/^Nonce: [A-Za-z0-9]{8,128}$/.test(lines[8]) || (nonce !== undefined && lines[8] !== 'Nonce: ' + nonce) || !lines[9].startsWith('Issued At: ')) return fail('bad-signature');
  if (date(lines[9].slice(11)) !== issuedAt) return fail('bad-signature');
  let at = 10;
  if (lines[at]?.startsWith('Expiration Time: ')) {
    const expiry = date(lines[at++].slice(17));
    if (!Number.isFinite(expiry) || expiry <= issuedAt) return fail('bad-signature');
    if (now >= expiry) return fail('expired');
  }
  if (lines[at]?.startsWith('Not Before: ')) {
    const start = date(lines[at++].slice(12));
    if (!Number.isFinite(start) || start > issuedAt) return fail('bad-signature');
  }
  if (lines[at]?.startsWith('Request ID: ')) {
    if (!/^(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9a-fA-F]{2})*$/.test(lines[at++].slice(12))) return fail('bad-signature');
  }
  if (lines[at] === 'Resources:') {
    at++;
    while (at < lines.length && lines[at].startsWith('- ') && uri(lines[at].slice(2))) at++;
  }
  if (at !== lines.length) return fail('bad-signature');
  try {
    const sig = unhex(proof.signature.slice(2));
    const recovery = sig[64] >= 27 ? sig[64] - 27 : sig[64];
    if (recovery > 1) return fail('bad-signature');
    const encoded = utf8.encode(proof.message);
    const digest = keccak_256(new Uint8Array([...utf8.encode('\x19Ethereum Signed Message:\n' + encoded.length), ...encoded]));
    const recovered = secp256k1.recoverPublicKey(new Uint8Array([recovery, ...sig.slice(0, 64)]), digest, { prehash: false });
    const raw = secp256k1.Point.fromBytes(recovered).toBytes(false);
    return checksum('0x' + hex(keccak_256(raw.slice(1))).slice(-40)) === address ? ok(true) : fail('bad-signature');
  } catch { return fail('bad-signature'); }
}
/** @param {string} jws @param {Jwks} jwks @param {number} now @returns {Result<Record<string, unknown>>} */
function attestVerify(jws, jwks, now) {
  try {
    const parts = jws.split('.'); if (parts.length !== 3) return fail('bad-attestation');
    const decode = (/** @type {string} */ s) => uniqueJson(new TextDecoder('utf-8', { fatal: true }).decode(unb64(s)));
    const h = data(decode(parts[0])), c = data(decode(parts[1]));
    if (!h.ok || !c.ok || h.value.alg !== 'ES256' || typeof h.value.kid !== 'string' || !h.value.kid || !only(h.value, ['alg', 'kid', 'typ']) || (h.value.typ !== undefined && h.value.typ !== 'JWT')) return fail('bad-attestation');
    const keys = jwks.keys.filter(k => k.kid === h.value.kid);
    if (keys.length !== 1) return fail('bad-attestation');
    const k = keys[0];
    if (k.kty !== 'EC' || k.crv !== 'P-256' || (k.alg !== undefined && k.alg !== 'ES256') || (k.use !== undefined && k.use !== 'sig') || (k.key_ops !== undefined && (!k.key_ops.includes('verify') || k.key_ops.some(op => op !== 'verify')))) return fail('bad-attestation');
    const key = parsePrincipalId(k.x + '.' + k.y);
    if (!key.ok || !keyVerify(key.value, parts[2], utf8.encode(parts[0] + '.' + parts[1]))) return fail('bad-attestation');
    if (!integer(c.value.iat) || !integer(c.value.exp) || !integer(now) || /** @type {number} */ (c.value.exp) <= /** @type {number} */ (c.value.iat)) return fail('bad-attestation');
    if (/** @type {number} */ (c.value.iat) > now) return fail('future-record');
    if (/** @type {number} */ (c.value.exp) <= now) return fail('expired');
    return c;
  } catch { return fail('bad-attestation'); }
}
/** The optional currentKey must be resolved by the caller at issuedAt. @param {unknown} x @param {number} now @param {PrincipalId} [currentKey] @returns {Result<WalletLink>} */
export function verifyWalletLink(x, now, currentKey) {
  const p = record(x); if (!p.ok) return p; const r = p.value;
  if (r.kind !== 'wallet') return fail('bad-record');
  const t = time(r.issuedAt, now); if (!t.ok) return t;
  const b = bytes(r);
  if (!keyVerify(currentKey ?? r.principal, r.keySig, b)) return fail('bad-signature');
  const s = siweVerify(r.siwe, r.address, b, r.issuedAt, now, r.nonce); return s.ok ? ok(r) : s;
}
/** @param {unknown} x @param {Jwks} jwks @param {ReadonlySet<string>} pinnedIss @param {number} now @param {PrincipalId} [currentKey] @returns {Result<OidcLink>} */
export function verifyOidcLink(x, jwks, pinnedIss, now, currentKey) {
  const p = record(x); if (!p.ok) return p; const r = p.value;
  if (r.kind !== 'oidc') return fail('bad-record');
  const t = time(r.issuedAt, now); if (!t.ok) return t;
  if (!pinnedIss.has(r.cred.iss)) return fail('untrusted-issuer');
  if (!keyVerify(currentKey ?? r.principal, r.keySig, bytes(r))) return fail('bad-signature');
  const a = attestVerify(r.attest, jwks, now); if (!a.ok) return a;
  const c = a.value;
  if (!only(c, ['typ', 'iss', 'tenant', 'sub', 'principal', 'iat', 'exp', 'nonce']) || c.typ !== 'sociacl-oidc-attest-v1' || c.iss !== r.cred.iss || c.tenant !== r.cred.tenant || c.sub !== r.cred.sub || c.principal !== r.principal || c.iat !== r.issuedAt || c.nonce !== r.nonce) return fail('bad-attestation');
  return ok(r);
}
/** @param {unknown} x @param {PrincipalId} currentKey @param {number} now @returns {Result<Revoke>} */
export function verifyRevoke(x, currentKey, now) {
  const p = record(x); if (!p.ok) return p; const r = p.value;
  if (r.kind !== 'revoke') return fail('bad-record');
  const t = time(r.issuedAt, now); if (!t.ok) return t;
  return keyVerify(currentKey, r.keySig, bytes(r)) ? ok(r) : fail('bad-signature');
}
/** @param {unknown} x @param {PrincipalId} currentKey @param {ReadonlyMap<string, WalletLink>} links @param {Jwks} jwks @param {number} now @param {(principal: PrincipalId, at: number) => PrincipalId} [keyAt] @returns {Result<Rotate>} */
export function verifyRotate(x, currentKey, links, jwks, now, keyAt = p => p) {
  const p = record(x); if (!p.ok) return p; const r = p.value;
  if (r.kind !== 'rotate') return fail('bad-record');
  const t = time(r.issuedAt, now); if (!t.ok) return t;
  if (r.prevKey !== currentKey || r.nextKey === currentKey) return fail('bad-sequence');
  if (!keyVerify(r.nextKey, r.nextSig, bytes(r))) return fail('bad-signature');
  const a = attestVerify(r.attest, jwks, now); if (!a.ok) return a;
  const c = a.value;
  if (!only(c, ['typ', 'principal', 'nextKey', 'seq', 'iat', 'exp', 'auth']) || c.typ !== 'sociacl-rotate-attest-v1' || c.principal !== r.principal || c.nextKey !== r.nextKey || c.seq !== r.seq || c.iat !== r.issuedAt || c.auth !== r.authorizer.kind) return fail('bad-attestation');
  if (r.authorizer.kind === 'wallet') {
    const raw = links.get(r.authorizer.link); if (!raw) return fail('unknown-link');
    const l = verifyWalletLink(raw, raw.issuedAt, keyAt(raw.principal, raw.issuedAt)); if (!l.ok) return l;
    const id = linkId(l.value);
    if (!id.ok || id.value !== r.authorizer.link || l.value.principal !== r.principal || l.value.issuedAt > r.issuedAt) return fail('unknown-link');
    const s = siweVerify(r.authorizer.siwe, l.value.address, bytes(r), r.issuedAt, now); if (!s.ok) return s;
  }
  return ok(r);
}
/** Historical records are verified at their issuance; now bounds the history. Duplicate copies of one record are idempotent. @param {PrincipalId} genesis @param {readonly unknown[]} rotations @param {ResolutionContext} ctx @returns {Result<PrincipalId>} */
export function resolveCurrentKey(genesis, rotations, ctx) {
  if (!integer(ctx.now)) return fail('bad-record');
  /** @type {Rotate[]} */ const history = [];
  /** @type {Map<number, Rotate[]>} */ const groups = new Map();
  for (const raw of rotations) {
    const r = record(raw); if (!r.ok) return r;
    if (r.value.kind !== 'rotate' || r.value.principal !== genesis) return fail('bad-record');
    if (r.value.issuedAt > ctx.now) return fail('future-record');
    const list = groups.get(r.value.seq) ?? []; list.push(r.value); groups.set(r.value.seq, list);
  }
  /** @param {PrincipalId} principal @param {number} at */
  const keyAt = (principal, at) => principal === genesis ? history.filter(r => r.issuedAt < at).at(-1)?.nextKey ?? genesis : principal;
  let current = genesis, seq = 1, lastTime = -1;
  for (const [n, group] of [...groups].sort((a, b) => a[0] - b[0])) {
    if (n !== seq) return fail('bad-sequence');
    /** @type {Map<string, Rotate>} */ const valid = new Map();
    for (const raw of group) {
      if (raw.issuedAt <= lastTime) return fail('bad-sequence');
      const links = new Map(ctx.links);
      // Verify every revocation, and only apply those effective by this rotation.
      for (const rev of ctx.revocations ?? []) {
        const p = record(rev); if (!p.ok) return p;
        if (p.value.kind !== 'revoke' || p.value.principal !== genesis) return fail('bad-record');
        if (p.value.issuedAt > ctx.now) return fail('future-record');
        if (p.value.issuedAt > raw.issuedAt) continue;
        const v = verifyRevoke(p.value, keyAt(genesis, p.value.issuedAt), p.value.issuedAt); if (!v.ok) return v;
        const l = links.get(v.value.linkId);
        if (l && l.principal === genesis && v.value.issuedAt >= l.issuedAt) links.delete(v.value.linkId);
      }
      if (raw.authorizer.kind === 'wallet' && !links.has(raw.authorizer.link) && ctx.links.has(raw.authorizer.link)) return fail('revoked-link');
      // A newer valid link of this wallet to another principal removes its recovery authority.
      if (raw.authorizer.kind === 'wallet') {
        const own = links.get(raw.authorizer.link);
        if (own) for (const other of links.values()) {
          if (other.address !== own.address || other.issuedAt > raw.issuedAt) continue;
          const v = verifyWalletLink(other, other.issuedAt, keyAt(other.principal, other.issuedAt)); if (!v.ok) return v;
          if (other.principal !== genesis && other.issuedAt >= own.issuedAt) return fail('ambiguous-link');
        }
      }
      const r = verifyRotate(raw, current, links, ctx.jwks, raw.issuedAt, keyAt); if (!r.ok) return r;
      const id = linkId(r.value); if (!id.ok) return id; valid.set(id.value, r.value);
    }
    if (valid.size > 1) return fail('rotation-fork');
    const next = [...valid.values()][0]; current = next.nextKey; lastTime = next.issuedAt; history.push(next); seq++;
  }
  return ok(current);
}
/** Pick the newest verified wallet binding; equal-time cross-account bindings freeze lookup. Historical key resolution is the caller's authenticated context. @param {Eip55} address @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {number} now @param {(principal: PrincipalId, at: number) => PrincipalId} [keyAt] @returns {Result<WalletLink>} */
export function resolveWalletLink(address, links, revocations, now, keyAt = p => p) {
  /** @type {WalletLink[]} */ const valid = [];
  for (const raw of links) {
    const p = record(raw); if (!p.ok) return p;
    if (p.value.kind !== 'wallet') return fail('bad-record');
    const t = time(p.value.issuedAt, now); if (!t.ok) return t;
    const v = verifyWalletLink(p.value, p.value.issuedAt, keyAt(p.value.principal, p.value.issuedAt)); if (!v.ok) return v;
    if (v.value.address === address) valid.push(v.value);
  }
  // Never resurrect an older link when the newest link is revoked.
  valid.sort((a, b) => b.issuedAt - a.issuedAt);
  if (!valid.length) return fail('unknown-link');
  const newest = valid[0];
  if (valid.some(l => l.issuedAt === newest.issuedAt && l.principal !== newest.principal)) return fail('ambiguous-link');
  const id = linkId(newest); if (!id.ok) return id;
  for (const raw of revocations) {
    const p = record(raw); if (!p.ok) return p;
    if (p.value.kind !== 'revoke') return fail('bad-record');
    const t = time(p.value.issuedAt, now); if (!t.ok) return t;
    const v = verifyRevoke(p.value, keyAt(p.value.principal, p.value.issuedAt), p.value.issuedAt); if (!v.ok) return v;
    if (v.value.principal === newest.principal && v.value.linkId === id.value && v.value.issuedAt >= newest.issuedAt) return fail('revoked-link');
  }
  return ok(newest);
}
