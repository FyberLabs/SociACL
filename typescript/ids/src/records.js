import { webUri } from './uri.js';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ok, fail, text, data, integer, b64, unb64, hex, unhex, utf8, lp } from './util.js';
import { parsePrincipalId, parseObjectId, objectPrincipal, parseEip55, parseOidcCredential, checksum } from './ids.js';
import { uniqueJson } from './json.js';
/** @import {PrincipalId, Eip55, Result, WalletLink, OidcLink, Rotate, Revoke, GenesisEpub, IdentityRecord, UnsignedRecord, Jwks, Siwe, ResolutionContext, SiwePolicy, HistoryResolver, KeyState, Diagnostic, Resolution, ResolvedAccount, SignedAt, AclAttestation, SeeGrant} from './types.js' */

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
/** Each resolution list, link map, and revocation list stops at this length. Longer input is `too-long` and is not truncated. */
export const MAX_RESOLUTION_INPUT = 1024;
/** @param {unknown} list @returns {Result<readonly unknown[]>} */
function boundedList(list) {
  if (!Array.isArray(list)) return fail('bad-record');
  if (list.length > MAX_RESOLUTION_INPUT) return fail('too-long');
  return ok(list);
}
/** @param {ResolutionContext|undefined} ctx @returns {Result<true>} */
function boundedContext(ctx) {
  if (!ctx || typeof ctx.history !== 'function') return fail('missing-history');
  if (ctx.links instanceof Map && ctx.links.size > MAX_RESOLUTION_INPUT) return fail('too-long');
  if (ctx.revocations !== undefined && !Array.isArray(ctx.revocations)) return fail('bad-record');
  if ((ctx.revocations?.length ?? 0) > MAX_RESOLUTION_INPUT) return fail('too-long');
  if (ctx.genesisEpubBindings !== undefined && !Array.isArray(ctx.genesisEpubBindings)) return fail('bad-record');
  if ((ctx.genesisEpubBindings?.length ?? 0) > MAX_RESOLUTION_INPUT) return fail('too-long');
  return ok(true);
}
/** hex(sha256(length-prefixed sociacl-siwe-proof-v1, message, signature)).
 * @param {Siwe} proof */
function siweProofHash(proof) {
  return hex(sha256(lp(['sociacl-siwe-proof-v1', proof.message, proof.signature])));
}
/** Sorted unique 64-hex link ids, at most 1024. The same rule as a signed rotation.
 * @param {unknown} list @returns {Result<string[]>} */
function retainedIds(list) {
  /** @type {any[]} */ let retainedLinks;
  try {
    if (!Array.isArray(list)) return fail('bad-record');
    const d = /** @type {Record<string, PropertyDescriptor>} */ (/** @type {unknown} */ (Object.getOwnPropertyDescriptors(list))), length=d.length.value;
    if (!integer(length) || length > 1024) return fail('bad-record');
    retainedLinks = Array.from({length}, (_,i) => d[String(i)]?.value);
  } catch { return fail('bad-record'); }
  if (!retainedLinks.every((v,i) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) && (i === 0 || retainedLinks[i-1] < v))) return fail('bad-record');
  return ok(/** @type {string[]} */ (retainedLinks));
}
/** @param {unknown} x @param {boolean} [unsigned] @returns {Result<IdentityRecord>} */
function record(x, unsigned = false) {
  const d = data(x); if (!d.ok) return d;
  const r = d.value;
  if (r.v !== 1 || !['wallet', 'oidc', 'rotate', 'revoke', 'genesis-epub'].includes(/** @type {string} */ (r.kind))) return fail('bad-record');
  const principal = parsePrincipalId(r.principal); if (!principal.ok) return principal;
  if (!integer(r.issuedAt)) return fail('bad-record');
  const base = { v: /** @type {const} */ (1), principal: principal.value, issuedAt: /** @type {number} */ (r.issuedAt) };
  const common = ['v', 'kind', 'principal', 'issuedAt'];
  if (r.kind === 'genesis-epub') {
    if (!only(r, [...common, 'epub', 'keySig', 'attest'])) return fail('bad-record');
    const epub = parsePrincipalId(r.epub); if (!epub.ok) return epub;
    if (epub.value === principal.value) return fail('bad-record');
    const keySig = unsigned ? ok('') : text(r.keySig, 128); if (!keySig.ok) return keySig;
    const attest = unsigned ? ok('') : text(r.attest, 16384); if (!attest.ok) return attest;
    return ok(Object.freeze({ ...base, kind: 'genesis-epub', epub: epub.value, keySig: keySig.value, attest: attest.value }));
  }
  if (r.kind === 'wallet' || r.kind === 'oidc') {
    const nonce = text(r.nonce, 128); if (!nonce.ok) return nonce;
    if (!/^[A-Za-z0-9]{8,128}$/.test(nonce.value)) return fail('bad-record');
    const keySig = unsigned ? ok('') : text(r.keySig, 128); if (!keySig.ok) return keySig;
    if (r.kind === 'wallet') {
      if (!only(r, [...common, 'address', 'nonce', 'keySig', 'siwe', 'attest'])) return fail('bad-record');
      const address = parseEip55(r.address); if (!address.ok) return address;
      const siwe = unsigned ? ok({ message: '', signature: /** @type {`0x${string}`} */ ('0x') }) : siweData(r.siwe); if (!siwe.ok) return siwe;
      const attest = unsigned ? ok('') : text(r.attest, 16384); if (!attest.ok) return attest;
      return ok(Object.freeze({ ...base, attest: attest.value, kind: 'wallet', address: address.value, nonce: nonce.value, keySig: keySig.value, siwe: siwe.value }));
    }
    if (!only(r, [...common, 'cred', 'nonce', 'keySig', 'attest'])) return fail('bad-record');
    const cred = parseOidcCredential(r.cred); if (!cred.ok) return cred;
    const attest = unsigned ? ok('') : text(r.attest, 16384); if (!attest.ok) return attest;
    return ok(Object.freeze({ ...base, kind: 'oidc', cred: cred.value, nonce: nonce.value, keySig: keySig.value, attest: attest.value }));
  }
  if (r.kind === 'revoke') {
    if (!only(r, [...common, 'linkId', 'keySig', 'attest'])) return fail('bad-record');
    const id = text(r.linkId, 64); if (!id.ok) return id;
    if (!/^[0-9a-f]{64}$/.test(id.value)) return fail('bad-record');
    const sig = unsigned ? ok('') : text(r.keySig, 128); if (!sig.ok) return sig;
    const attest = unsigned || !Object.hasOwn(r, 'attest') ? ok(undefined) : text(r.attest,16384);
    if (!attest.ok) return attest;
    return ok(Object.freeze({ ...base, ...(attest.value === undefined ? {} : {attest:attest.value}), kind: 'revoke', linkId: id.value, keySig: sig.value }));
  }
  const hasEpub = Object.hasOwn(r, 'nextEpub');
  if (!only(r, [...common, 'seq', 'prevKey', 'nextKey', ...(hasEpub ? ['nextEpub'] : []), 'nextSig', 'authorizer', 'attest', 'retainedLinks'])) return fail('bad-record');
  if (!integer(r.seq) || r.seq === 0) return fail('bad-sequence');
  const retained = retainedIds(r.retainedLinks); if (!retained.ok) return retained;
  const retainedLinks = retained.value;
  const prev = parsePrincipalId(r.prevKey); if (!prev.ok) return prev;
  const next = parsePrincipalId(r.nextKey); if (!next.ok) return next;
  const nextEpub = hasEpub ? parsePrincipalId(r.nextEpub) : undefined; if (nextEpub && !nextEpub.ok) return nextEpub;
  const sig = unsigned ? ok('') : text(r.nextSig, 128); if (!sig.ok) return sig;
  const attest = unsigned ? ok('') : text(r.attest, 16384); if (!attest.ok) return attest;
  const ad = data(r.authorizer); if (!ad.ok) return ad;
  const a = ad.value;
  /** @type {Rotate['authorizer']} */ let authorizer;
  if (!['wallet','oidc-fresh-login'].includes(/** @type {string} */ (a.kind)) || !only(a, a.kind === 'wallet' ? ['kind','link','siwe'] : ['kind','link'])) return fail('bad-record');
  const link = text(a.link,64); if (!link.ok) return link;
  if (!/^[0-9a-f]{64}$/.test(link.value)) return fail('bad-record');
  if (a.kind === 'oidc-fresh-login') authorizer = {kind:a.kind,link:link.value};
  else {
    const siwe = unsigned ? ok({message:'',signature:/** @type {`0x${string}`} */ ('0x')}) : siweData(a.siwe); if (!siwe.ok) return siwe;
    authorizer = {kind:'wallet',link:link.value,siwe:siwe.value};
  }
  return ok(Object.freeze({ ...base, retainedLinks: Object.freeze(retainedLinks), kind: 'rotate', seq: /** @type {number} */ (r.seq), prevKey: prev.value, nextKey: next.value, ...(nextEpub ? { nextEpub: nextEpub.value } : {}), nextSig: sig.value, attest: attest.value, authorizer: Object.freeze(authorizer) }));
}
/** Preserve an authenticated rotation's identity even when its unsigned SIWE proof is missing.
 * The replacement proof cannot verify; it only lets signature/witness checks run before failing.
 * @param {unknown} x @returns {Result<IdentityRecord>} */
function rotationCandidate(x) {
  const parsed=record(x); if (parsed.ok) return parsed;
  const d=data(x); if (!d.ok || d.value.kind !== 'rotate') return parsed;
  const a=data(d.value.authorizer); if (!a.ok || a.value.kind !== 'wallet') return parsed;
  const candidate=record({...d.value,authorizer:{...a.value,siwe:{message:'',signature:'0x'+'00'.repeat(65)}}});
  return candidate.ok ? candidate : parsed;
}
/** Presence of nextEpub is the v2/v3 discriminator on a parsed rotation.
 * @param {{nextEpub?: PrincipalId}} r
 * @returns {r is {nextEpub: PrincipalId}}
 */
function hasNextEpub(r) {
  return Object.hasOwn(r, 'nextEpub');
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
    case 'wallet': return lp(['sociacl-link-wallet-v1', r.principal, r.address, t, r.nonce]);
    case 'oidc': return lp(['sociacl-link-oidc-v1', r.principal, r.cred.iss, r.cred.tenant, r.cred.sub, t, r.nonce]);
    case 'rotate': return lp([hasNextEpub(r) ? 'sociacl-rotate-v3' : 'sociacl-rotate-v2', r.principal, String(r.seq), r.prevKey, r.nextKey, ...(hasNextEpub(r) ? [r.nextEpub] : []), t, r.authorizer.kind, r.authorizer.link, String(r.retainedLinks.length), ...r.retainedLinks]);
    case 'revoke': return lp(['sociacl-revoke-v1', r.principal, r.linkId, t]);
    case 'genesis-epub': return lp(['sociacl-genesis-epub-v1', r.principal, r.epub, t]);
  }
}
/** @param {UnsignedRecord} r @returns {Result<string>} */
export function linkId(r) { const b = signingBytes(r); return b.ok ? ok(hex(sha256(b.value))) : b; }
/** @param {PrincipalId} p @param {string} sig @param {Uint8Array} message */
function keyVerify(p, sig, message) {
  try { return p256.verify(unb64(sig), message, new Uint8Array([4, ...unb64(p.slice(0, 43)), ...unb64(p.slice(44))]), { prehash: true, lowS: false, format: 'compact' }); }
  catch { return false; }
}
/** @param {number} issuedAt @param {number} now @param {number} [skew] */
function time(issuedAt, now, skew = 0) { return !integer(now) || !integer(skew) || skew > 300 ? fail('bad-record') : issuedAt > now + skew ? fail('future-record') : ok(true); }
/** Request mode only. Historical proofs stay an upper bound.
 * @param {number} issuedAt @param {number} now @param {number} skew */
function requestTime(issuedAt, now, skew) {
  const t = time(issuedAt, now, skew); if (!t.ok) return t;
  return issuedAt < now - skew ? fail('expired') : ok(true);
}
/** Present-revocation horizon for an unattested request. Historical checks stay skew-free.
 * A sum past the safe-integer cap falls back to `now`, which is stricter.
 * Direct `verifyRevokeNow` does not use this.
 * @param {number} now @param {number} skew */
function presentHorizon(now, skew) {
  if (!integer(now) || !integer(skew)) return now;
  const horizon = now + skew;
  return integer(horizon) ? horizon : now;
}
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
/** EIP-4361 statement binds the entire identity record, not an application session. @param {Siwe} proof @param {Eip55} address @param {Uint8Array} message @param {number} issuedAt @param {number} now @param {SiwePolicy} policy @param {string} [nonce] */
function siweVerify(proof, address, message, issuedAt, now, policy, nonce) {
  const lines = proof.message.split('\n');
  if (lines.length < 10 || !/^(?:[A-Za-z][A-Za-z0-9+.-]*:\/\/)?[^\s/?#]+ wants you to sign in with your Ethereum account:$/.test(lines[0]) || lines[1] !== address || lines[2] !== '' || lines[3] !== 'SociACL link: ' + hex(sha256(message)) || lines[4] !== '') return fail('bad-signature');
  if (!lines[5].startsWith('URI: ') || !webUri(lines[5].slice(5)) || lines[6] !== 'Version: 1' || !/^Chain ID: [0-9]+$/.test(lines[7]) || !/^Nonce: [A-Za-z0-9]{8,128}$/.test(lines[8]) || (nonce !== undefined && lines[8] !== 'Nonce: ' + nonce) || !lines[9].startsWith('Issued At: ')) return fail('bad-signature');
  const domain = lines[0].slice(0, -' wants you to sign in with your Ethereum account:'.length);
  if (!webUri((domain.startsWith('https://') ? domain : 'https://' + domain) + '/')) return fail('bad-signature');
  if (!policy || !policy.allowedDomains.includes(domain) || !policy.allowedUris.includes(lines[5].slice(5)) || !policy.allowedChainIds.includes(lines[7].slice(10))) return fail('bad-signature');
  if (date(lines[9].slice(11)) !== issuedAt) return fail('bad-signature');
  let at = 10;
  if (lines[at]?.startsWith('Expiration Time: ')) {
    const expiry = date(lines[at++].slice(17));
    if (!Number.isFinite(expiry) || expiry <= issuedAt) return fail('bad-signature');
    if (now - (policy.clockSkewSeconds ?? 0) >= expiry) return fail('expired');
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
    while (at < lines.length && lines[at].startsWith('- ') && webUri(lines[at].slice(2))) at++;
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
/** @param {string} jws @param {Jwks} jwks @param {number} now @param {number} [skew] @returns {Result<Record<string, unknown>>} */
function attestVerify(jws, jwks, now, skew = 0) {
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
    if (/** @type {number} */ (c.value.exp) - /** @type {number} */ (c.value.iat) > 900) return fail('bad-attestation');
    if (/** @type {number} */ (c.value.iat) > now + skew) return fail('future-record');
    if (/** @type {number} */ (c.value.exp) <= now - skew) return fail('expired');
    return c;
  } catch { return fail('bad-attestation'); }
}
/** @param {WalletLink|OidcLink} r @param {KeyState} keyState @returns {Result<true>} */
function linkKey(r,keyState) {
  if (!keyState || !keyState.key || !keyState.currentKey || (keyState.retainedLinks !== null && !Array.isArray(keyState.retainedLinks))) return fail('missing-history');
  if (!keyVerify(keyState.key,r.keySig,bytes(r))) return fail('bad-signature');
  if (keyState.retainedLinks !== null && !keyState.retainedLinks.includes(hex(sha256(bytes(r))))) return fail('unretained-link');
  return ok(true);
}
/** Authenticate the independent witnesses before requesting untrusted-index principals' history.
 * @param {WalletLink} r @param {Jwks} jwks @param {SiwePolicy} policy @param {number} now @returns {Result<true>} */
function walletWitness(r,jwks,policy,now) {
  const t=time(r.issuedAt,now,policy.clockSkewSeconds??0); if (!t.ok) return t;
  const b=bytes(r), s=siweVerify(r.siwe,r.address,b,r.issuedAt,now,policy,r.nonce); if (!s.ok) return s;
  const a=attestVerify(r.attest,jwks,now,policy.clockSkewSeconds??0); if (!a.ok) return a;
  const c=a.value;
  return !only(c,['typ','principal','linkId','iat','exp']) || c.typ !== 'sociacl-wallet-attest-v1' || c.principal !== r.principal || c.linkId !== hex(sha256(b)) || c.iat !== r.issuedAt ? fail('bad-attestation') : ok(true);
}
/** @param {OidcLink} r @param {Jwks} jwks @param {ReadonlySet<string>} pinnedIss @param {number} now @param {number} [skew] @returns {Result<true>} */
function oidcWitness(r,jwks,pinnedIss,now,skew=0) {
  const t=time(r.issuedAt,now,skew); if (!t.ok) return t;
  if (!pinnedIss.has(r.cred.iss)) return fail('untrusted-issuer');
  const a=attestVerify(r.attest,jwks,now,skew); if (!a.ok) return a;
  const c=a.value;
  return !only(c,['typ','iss','tenant','sub','principal','iat','exp','nonce']) || c.typ !== 'sociacl-oidc-attest-v1' || c.iss !== r.cred.iss || c.tenant !== r.cred.tenant || c.sub !== r.cred.sub || c.principal !== r.principal || c.iat !== r.issuedAt || c.nonce !== r.nonce ? fail('bad-attestation') : ok(true);
}
/** @param {unknown} x @param {Jwks} jwks @param {SiwePolicy} policy @param {number} now @param {KeyState} keyState @returns {Result<WalletLink>} */
export function verifyWalletLink(x,jwks,policy,now,keyState) {
  const p=record(x); if (!p.ok) return p; const r=p.value;
  if (r.kind !== 'wallet') return fail('bad-record');
  const t=time(r.issuedAt,now,policy?.clockSkewSeconds??0); if (!t.ok) return t;
  const k=linkKey(r,keyState); if (!k.ok) return k;
  const w=walletWitness(r,jwks,policy,now); return w.ok ? ok(r) : w;
}
/** @param {unknown} x @param {Jwks} jwks @param {ReadonlySet<string>} pinnedIss @param {number} now @param {KeyState} keyState @param {number} [clockSkewSeconds] @returns {Result<OidcLink>} */
export function verifyOidcLink(x,jwks,pinnedIss,now,keyState,clockSkewSeconds=0) {
  const p=record(x); if (!p.ok) return p; const r=p.value;
  if (r.kind !== 'oidc') return fail('bad-record');
  const t=time(r.issuedAt,now,clockSkewSeconds); if (!t.ok) return t;
  if (!pinnedIss.has(r.cred.iss)) return fail('untrusted-issuer');
  const k=linkKey(r,keyState); if (!k.ok) return k;
  const w=oidcWitness(r,jwks,pinnedIss,now,clockSkewSeconds); return w.ok ? ok(r) : w;
}
/** Present-time authority only: currentKey must be the final authenticated current key.
 * This does not certify an issuance time or produce historical revocation evidence.
 * @param {unknown} x @param {PrincipalId} currentKey @param {number} now @returns {Result<Revoke>} */
export function verifyRevokeNow(x, currentKey, now) {
  const p = record(x); if (!p.ok) return p; const r = p.value;
  if (r.kind !== 'revoke') return fail('bad-record');
  const t = time(r.issuedAt, now); if (!t.ok) return t;
  if (!keyVerify(currentKey,r.keySig,bytes(r))) return fail('bad-signature');
  return ok(r);
}
/** Witness required, including when the signer is the current key.
 * @param {unknown} x @param {PrincipalId} currentKey @param {Jwks} jwks @param {number} now @returns {Result<Revoke>} */
export function verifyRevoke(x, currentKey, jwks, now) {
  const p = verifyRevokeNow(x, currentKey, now); if (!p.ok) return p;
  const r = p.value;
  if (r.attest === undefined) return fail('bad-attestation');
  const a=attestVerify(r.attest,jwks,now); if (!a.ok) return a;
  const c=a.value;
  if (!only(c,['typ','principal','recordId','iat','exp']) || c.typ!=='sociacl-revoke-attest-v1' || c.principal!==r.principal || c.recordId!==hex(sha256(bytes(r))) || c.iat!==r.issuedAt) return fail('bad-attestation');
  return ok(r);
}
/** Derive state ONLY from an authenticated successful resolution, complete through until.
 * @param {PrincipalId} genesis @param {readonly Rotate[]} history @param {number} at @param {number} until @returns {KeyState} */
export function historyState(genesis, history, at, until) {
  const past = history.filter(r => r.issuedAt <= until);
  const later = past.filter(r => r.issuedAt >= at);
  return { key: past.filter(r => r.issuedAt < at).at(-1)?.nextKey ?? genesis,
    currentKey: past.at(-1)?.nextKey ?? genesis,
    retainedLinks: later.length ? later[0].retainedLinks.filter(id => later.every(r => r.retainedLinks.includes(id))) : null };
}
/** @param {HistoryResolver} history @param {PrincipalId} principal @param {number} at @param {number} until @returns {Result<KeyState>} */
function state(history, principal, at, until) {
  if (typeof history !== 'function') return fail('missing-history');
  try { return history(principal, at, until); } catch { return fail('missing-history'); }
}
/** @param {WalletLink|OidcLink} r @param {ResolutionContext} ctx @param {number} until @returns {Result<WalletLink|OidcLink>} */
function historicalLink(r,ctx,until) {
  const t=time(r.issuedAt,until); if (!t.ok) return t;
  const witness=r.kind === 'wallet' ? walletWitness(r,ctx.jwks,ctx.policy,r.issuedAt) : oidcWitness(r,ctx.jwks,ctx.pinnedIss,r.issuedAt);
  if (!witness.ok) return witness;
  const h=state(ctx.history,r.principal,r.issuedAt,until); if (!h.ok) return h;
  const k=linkKey(r,h.value); return k.ok ? ok(r) : k;
}
/** @param {Diagnostic[]} ds @param {Diagnostic['source']} source @param {number} index @param {import('./types.js').Reason} reason */
function report(ds,source,index,reason) {
  if (!ds.some(d=>d.source===source && d.index===index && d.reason===reason)) ds.push({source,index,reason});
}
/** Revokes never choose a key/history from attacker-controlled fields.
 * `present` is an unwitnessed current-key revoke at `now`. An unattested
 * request passes `now + clockSkewSeconds` so a future offline revoke inside
 * that skew still applies. Witnessed checks pass the raw time and stay skew-free.
 * @param {WalletLink|OidcLink} link @param {readonly unknown[]} revocations @param {PrincipalId} currentKey @param {number} now @param {Jwks} jwks @param {Diagnostic[]} diagnostics @param {boolean} [present] */
function revokedAt(link,revocations,currentKey,now,jwks,diagnostics,present=false) {
  const id=hex(sha256(bytes(link))); let revoked=false;
  for (const [index,raw] of revocations.entries()) {
    const p=record(raw);
    if (!p.ok || p.value.kind !== 'revoke') { report(diagnostics,'revoke',index,p.ok?'bad-record':p.reason); continue; }
    const r=p.value,t=time(r.issuedAt,now);
    if (!t.ok) {report(diagnostics,'revoke',index,t.reason);continue;}
    if (r.principal !== link.principal || r.linkId !== id || r.issuedAt < link.issuedAt) continue;
    const v = present ? verifyRevokeNow(r,currentKey,now) : verifyRevoke(r,currentKey,jwks,r.issuedAt);
    if (!v.ok) report(diagnostics,'revoke',index,v.reason); else revoked=true;
  }
  return revoked;
}
/** An authenticated rotation cannot be discarded because its referenced evidence is unavailable.
 * @param {import('./types.js').Reason} reason */
function requiredHistoryFailure(reason) {
  return reason === 'rotation-fork' || reason === 'rotation-conflict' ? reason : 'missing-history';
}
/** @param {unknown} x @param {PrincipalId} currentKey @param {ResolutionContext} ctx @returns {Result<Rotate>} */
export function verifyRotate(x,currentKey,ctx) {return checkRotate(x,currentKey,ctx,[]);}
/** Local pre-attestation check for one v3 rotation request.
 * Covers: v3 (`nextEpub` required; v2 is `bad-record`); no `attest` field
 * (a present attestation is `bad-record` and is not returned); `|issuedAt-now|`
 * within `policy.clockSkewSeconds` (`future-record` or `expired`); `prevKey`
 * equal to the supplied current key and `nextKey` different from it;
 * `nextEpub` different from `nextKey` and `prevKey`; the next-key signature;
 * the authorizer (wallet SIWE, or OIDC with no active wallet); every
 * authorizer and retained link historically valid at `issuedAt`; witnessed
 * revocation of those links at `issuedAt` and at `now` (`rotation-conflict`);
 * and an unwitnessed current-key revoke of those links at `now`
 * (`revoked-link`, `verifyRevokeNow`).
 * Freshness and present revocation apply only to this unattested request.
 * Present revocation honors `policy.clockSkewSeconds`: an offline revoke
 * issued at or before `now + skew` removes the link. A revoke dated further
 * ahead is ignored. The same horizon applies to the active-wallet check:
 * a wallet linked after `issuedAt` but at or before `now + skew` still makes
 * OIDC recovery `wallet-required`. Historical witnessed checks stay
 * skew-free, and `verifyRevokeNow` itself stays skew-free.
 * Does not cover chain sequence, sibling forks, or epub reuse against
 * history or the genesis-epub binding. Panopticon MUST call
 * `checkRotationPublish` for those. This is the building block that
 * function uses when the candidate has no attestation (panopticon#499).
 * `verifyRotate` still requires an attestation and does not use this window.
 * @param {unknown} x @param {PrincipalId} currentKey @param {ResolutionContext} ctx @returns {Result<Rotate>} */
export function verifyRotationRequest(x, currentKey, ctx) {
  if (typeof ctx.history !== 'function') return fail('missing-history');
  const d = data(x); if (!d.ok) return d;
  if (d.value.kind !== 'rotate' || Object.hasOwn(d.value, 'attest') || !Object.hasOwn(d.value, 'nextEpub')) return fail('bad-record');
  const p = rotationCandidate({ ...d.value, attest: 'request' }); if (!p.ok) return p;
  if (p.value.kind !== 'rotate' || !hasNextEpub(p.value)) return fail('bad-record');
  const checked = checkRotateBody(/** @type {Rotate} */ (p.value), currentKey, ctx, [], false);
  if (!checked.ok) return checked;
  return ok(/** @type {Rotate} */ ({ ...checked.value, attest: '' }));
}
/** Exact Panopticon rotation claim, including auth, linkId, and retainedLinks.
 * @param {Rotate} r @param {Record<string, unknown>} c */
function rotationClaimsMatch(r, c) {
  const v3 = hasNextEpub(r);
  const v4 = v3 && r.authorizer.kind === 'wallet' && c.typ === 'sociacl-rotate-attest-v4';
  const attestKeys = ['typ','principal','nextKey','seq','iat','exp','auth','linkId','retainedLinks'];
  if (v3) attestKeys.push('nextEpub');
  if (v4) attestKeys.push('siweHash');
  const typ = !v3 ? 'sociacl-rotate-attest-v2' : v4 ? 'sociacl-rotate-attest-v4' : 'sociacl-rotate-attest-v3';
  if (!(only(c, attestKeys) && c.typ === typ && c.principal === r.principal && c.nextKey === r.nextKey && (!v3 || c.nextEpub === r.nextEpub) && c.seq === r.seq && c.iat === r.issuedAt && c.auth === r.authorizer.kind && c.linkId === r.authorizer.link && JSON.stringify(c.retainedLinks) === JSON.stringify(r.retainedLinks))) return false;
  return !v4 || c.siweHash === siweProofHash(r.authorizer.siwe);
}
/** @param {Rotate} r @param {PrincipalId} currentKey @param {ResolutionContext} ctx @param {Diagnostic[]} diagnostics @param {boolean} requireAttest @returns {Result<Rotate>} */
function checkRotateBody(r, currentKey, ctx, diagnostics, requireAttest) {
  const skew = ctx.policy.clockSkewSeconds ?? 0;
  const t = requireAttest ? time(r.issuedAt, ctx.now, skew) : requestTime(r.issuedAt, ctx.now, skew);
  if (!t.ok) return t;
  if (r.prevKey !== currentKey || r.nextKey === currentKey) return fail('bad-sequence');
  if (hasNextEpub(r) && (r.nextEpub === r.nextKey || r.nextEpub === r.prevKey)) return fail('bad-sequence');
  if (!keyVerify(r.nextKey,r.nextSig,bytes(r))) return fail('bad-signature');
  if (requireAttest) {
    // Historical records verify as of issuedAt. The upper bound against ctx.now is `time` above.
    const a=attestVerify(r.attest,ctx.jwks,r.issuedAt,ctx.policy.clockSkewSeconds??0); if (!a.ok) return a;
    if (!rotationClaimsMatch(r, a.value)) return fail('bad-attestation');
  }
  // Validate the authorizing credential and every retained ID against the pre-rotation state.
  /** @type {Map<string,WalletLink|OidcLink>} */ const checked=new Map();
  for (const id of new Set([r.authorizer.link,...r.retainedLinks])) {
    if (!ctx.links.has(id)) return fail('missing-history');
    const raw=record(ctx.links.get(id)); if (!raw.ok) return fail('missing-history');
    const l=raw.value;
    if (!['wallet','oidc'].includes(l.kind) || l.principal !== r.principal || hex(sha256(bytes(l))) !== id) return fail('missing-history');
    const v=historicalLink(/** @type {WalletLink|OidcLink} */ (l),ctx,r.issuedAt); if (!v.ok) return fail(requiredHistoryFailure(v.reason));
    if (revokedAt(v.value,ctx.revocations??[],currentKey,r.issuedAt,ctx.jwks,diagnostics)) return fail('rotation-conflict');
    if (!requireAttest && revokedAt(v.value,ctx.revocations??[],currentKey,ctx.now,ctx.jwks,diagnostics)) return fail('rotation-conflict');
    if (!requireAttest && revokedAt(v.value,ctx.revocations??[],currentKey,presentHorizon(ctx.now,skew),ctx.jwks,diagnostics,true)) return fail('revoked-link');
    checked.set(id,v.value);
  }
  const authorizer=/** @type {WalletLink|OidcLink} */ (checked.get(r.authorizer.link));
  if (r.authorizer.kind === 'wallet') {
    if (authorizer.kind !== 'wallet') return fail('missing-history');
    const s=siweVerify(r.authorizer.siwe,authorizer.address,bytes(r),r.issuedAt,ctx.now,ctx.policy); if (!s.ok) return fail('missing-history');
  } else {
    if (authorizer.kind !== 'oidc') return fail('missing-history');
    // OIDC recovery is restricted to accounts with no active wallet, including wallets the candidate drops.
    // An unattested request also counts a wallet linked after issuedAt, up to now+skew.
    const entries=[...ctx.links].sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
    /** @param {number} until @returns {Result<true>} */
    const walletAbsent = until => {
      for (const [index,[id,raw]] of entries.entries()) {
        const parsed=record(raw);
        if (!parsed.ok) {report(diagnostics,'link',index,parsed.reason);continue;}
        const l=parsed.value;
        if (l.kind !== 'wallet' || l.principal !== r.principal) continue;
        if (hex(sha256(bytes(l))) !== id) {report(diagnostics,'link',index,'unknown-link');continue;}
        const v=historicalLink(l,ctx,until);
        if (!v.ok) {
          report(diagnostics,'link',index,v.reason);
          if (v.reason==='missing-history'||v.reason==='rotation-fork'||v.reason==='rotation-conflict') return v;
          continue;
        }
        if (!revokedAt(v.value,ctx.revocations??[],currentKey,until,ctx.jwks,diagnostics)) return fail('wallet-required');
      }
      return ok(true);
    };
    const absent = walletAbsent(r.issuedAt); if (!absent.ok) return absent;
    if (!requireAttest) {
      const present = walletAbsent(presentHorizon(ctx.now, skew)); if (!present.ok) return present;
    }
  }
  return ok(r);
}
/** @param {unknown} x @param {PrincipalId} currentKey @param {ResolutionContext} ctx @param {Diagnostic[]} diagnostics @returns {Result<Rotate>} */
function checkRotate(x,currentKey,ctx,diagnostics) {
  if (typeof ctx.history !== 'function') return fail('missing-history');
  const p=rotationCandidate(x); if (!p.ok) return p; const r=p.value;
  if (r.kind !== 'rotate') return fail('bad-record');
  return checkRotateBody(/** @type {Rotate} */ (r), currentKey, ctx, diagnostics, true);
}
/** Witnessed genesis-epub records. A missing list is empty. Gun user.epub is not read.
 * @param {ResolutionContext} ctx @returns {Result<readonly unknown[]>} */
function genesisBindings(ctx) {
  if (!Object.hasOwn(ctx, 'genesisEpubBindings') || ctx.genesisEpubBindings == null) return ok([]);
  if (!Array.isArray(ctx.genesisEpubBindings)) return fail('bad-record');
  return ok(ctx.genesisEpubBindings);
}
/** @param {unknown} raw @param {PrincipalId} genesis @param {ResolutionContext} ctx @returns {Result<GenesisEpub>} */
function verifyGenesisEpub(raw, genesis, ctx) {
  const p = record(raw); if (!p.ok) return p;
  if (p.value.kind !== 'genesis-epub') return fail('bad-record');
  const b = p.value;
  if (b.principal !== genesis) return fail('bad-record');
  const skew = ctx.policy.clockSkewSeconds ?? 0;
  const t = time(b.issuedAt, ctx.now, skew); if (!t.ok) return t;
  if (!keyVerify(genesis, b.keySig, bytes(b))) return fail('bad-signature');
  const a = attestVerify(b.attest, ctx.jwks, b.issuedAt, skew); if (!a.ok) return a;
  const c = a.value;
  if (!only(c, ['typ', 'principal', 'epub', 'iat', 'exp']) || c.typ !== 'sociacl-genesis-epub-attest-v1' || c.principal !== b.principal || c.epub !== b.epub || c.iat !== b.issuedAt) return fail('bad-attestation');
  return ok(b);
}
/** Pre-attestation check for a genesis-epub binding. Shape, epub canonical and
 * distinct from the genesis pub, genesis-key signature, and
 * `|issuedAt - now| <= policy.clockSkewSeconds` (`future-record` or `expired`).
 * A present `attest` is `bad-record`. Does not check that no rotation exists;
 * Panopticon does that, then attests (panopticon#499).
 * @param {unknown} x @param {PrincipalId} genesis @param {number} now @param {SiwePolicy} policy @returns {Result<GenesisEpub>} */
export function verifyGenesisEpubRequest(x, genesis, now, policy) {
  const g = parsePrincipalId(genesis); if (!g.ok) return g;
  const d = data(x); if (!d.ok) return d;
  if (d.value.kind !== 'genesis-epub' || Object.hasOwn(d.value, 'attest')) return fail('bad-record');
  const p = record({ ...d.value, attest: 'request' }); if (!p.ok) return p;
  if (p.value.kind !== 'genesis-epub') return fail('bad-record');
  const b = p.value;
  if (b.principal !== g.value) return fail('bad-record');
  const skew = policy?.clockSkewSeconds ?? 0;
  const t = requestTime(b.issuedAt, now, skew); if (!t.ok) return t;
  if (!keyVerify(g.value, b.keySig, bytes(b))) return fail('bad-signature');
  return ok(/** @type {GenesisEpub} */ ({ ...b, attest: '' }));
}
/** nextEpub is a fresh point, and a later signing key is not an earlier epub.
 * `bindingEpub` is the in-force witnessed genesis epub, or null.
 * @param {Rotate} raw @param {PrincipalId} genesis @param {readonly Rotate[]} history @param {PrincipalId|null} bindingEpub */
function reusesEpub(raw, genesis, history, bindingEpub) {
  if (history.some(h => h.nextEpub === raw.nextKey)) return true;
  if (bindingEpub && raw.nextKey === bindingEpub) return true;
  if (!hasNextEpub(raw)) return false;
  const epub = raw.nextEpub;
  return epub === raw.nextKey || epub === genesis || epub === bindingEpub || history.some(h => h.nextKey === epub || h.prevKey === epub || h.nextEpub === epub);
}
/** A sibling counts only when its next-key signature and Panopticon attestation both verify.
 * @param {unknown} raw @param {ResolutionContext} ctx @returns {Rotate|null} */
function authenticatedSibling(raw, ctx) {
  const parsed = rotationCandidate(raw);
  if (!parsed.ok || parsed.value.kind !== 'rotate') return null;
  const row = /** @type {Rotate} */ (parsed.value);
  if (!keyVerify(row.nextKey, row.nextSig, bytes(row))) return null;
  const a = attestVerify(row.attest, ctx.jwks, row.issuedAt, ctx.policy.clockSkewSeconds ?? 0);
  if (!a.ok) return null;
  if (!rotationClaimsMatch(row, a.value)) return null;
  return row;
}
/** Structural draft the keyring builder checks before a signature exists.
 * @param {unknown} x @returns {Result<Rotate>} */
function draftRotation(x) {
  const d = data(x); if (!d.ok) return d;
  const r = d.value;
  if (r.v !== 1 || r.kind !== 'rotate') return fail('bad-record');
  if (Object.hasOwn(r, 'nextSig') || Object.hasOwn(r, 'authorizer') || Object.hasOwn(r, 'attest')) return fail('bad-record');
  if (!only(r, ['v', 'kind', 'principal', 'seq', 'prevKey', 'nextKey', 'nextEpub', 'retainedLinks', 'issuedAt'])) return fail('bad-record');
  const principal = parsePrincipalId(r.principal); if (!principal.ok) return principal;
  if (!integer(r.seq) || r.seq === 0) return fail('bad-sequence');
  const prev = parsePrincipalId(r.prevKey); if (!prev.ok) return prev;
  const next = parsePrincipalId(r.nextKey); if (!next.ok) return next;
  const epub = parsePrincipalId(r.nextEpub); if (!epub.ok) return epub;
  const retained = retainedIds(r.retainedLinks); if (!retained.ok) return retained;
  const issuedAt = Object.hasOwn(r, 'issuedAt') ? r.issuedAt : undefined;
  if (issuedAt !== undefined && !integer(issuedAt)) return fail('bad-record');
  return ok(/** @type {Rotate} */ ({
    v: 1, kind: 'rotate', principal: principal.value, seq: /** @type {number} */ (r.seq),
    prevKey: prev.value, nextKey: next.value, nextEpub: epub.value, retainedLinks: retained.value,
    issuedAt: /** @type {number} */ (issuedAt ?? 0), nextSig: '', authorizer: { kind: 'oidc-fresh-login', link: '0'.repeat(64) }, attest: '',
  }));
}
/** A draft has no signing-byte id. The same transition is the same keys, epub, and retained set.
 * @param {Rotate} raw @param {Rotate} other */
function sameDraft(raw, other) {
  return hasNextEpub(other) && other.principal === raw.principal && other.seq === raw.seq && other.prevKey === raw.prevKey && other.nextKey === raw.nextKey && other.nextEpub === raw.nextEpub && JSON.stringify(other.retainedLinks) === JSON.stringify(raw.retainedLinks) && (raw.issuedAt === 0 || other.issuedAt === raw.issuedAt);
}
/** @param {PrincipalId} genesis @param {readonly unknown[]} priorRecords @param {ResolutionContext} ctx @returns {Result<{genesis: PrincipalId, history: readonly Rotate[], bindingEpub: PrincipalId|null}>} */
function loadChain(genesis, priorRecords, ctx) {
  const g = parsePrincipalId(genesis); if (!g.ok) return g;
  const resolved = resolveCurrentKey(g.value, priorRecords, ctx);
  if (!resolved.ok) return fail(resolved.reason);
  return ok({ genesis: g.value, history: resolved.value.rotations, bindingEpub: resolved.value.bindingEpub });
}
/** Sequence, sibling, and epub-reuse tail shared by publish and draft checks.
 * @param {Rotate} raw @param {readonly unknown[]} siblings @param {PrincipalId} genesis @param {readonly Rotate[]} history @param {PrincipalId|null} bindingEpub @param {ResolutionContext} ctx @param {boolean} draft @returns {Result<Rotate>} */
function publishTail(raw, siblings, genesis, history, bindingEpub, ctx, draft) {
  const id = draft ? '' : hex(sha256(bytes(raw)));
  for (const sibling of siblings) {
    const other = authenticatedSibling(sibling, ctx);
    if (!other || other.principal !== raw.principal || other.seq !== raw.seq) continue;
    if (draft) {
      if (!sameDraft(raw, other)) return fail('rotation-fork');
      continue;
    }
    if (!hasNextEpub(other) || hex(sha256(bytes(other))) !== id) return fail('rotation-fork');
  }
  const seq = history.length + 1;
  const current = history.length ? history[history.length - 1].nextKey : genesis;
  const lastTime = history.length ? history[history.length - 1].issuedAt : -1;
  const timed = !draft || raw.issuedAt !== 0;
  if (raw.seq !== seq || (timed && raw.issuedAt <= lastTime) || raw.prevKey !== current || raw.nextKey === genesis || history.some(r => r.nextKey === raw.nextKey) || reusesEpub(raw, genesis, history, bindingEpub)) return fail('bad-sequence');
  return ok(raw);
}
/** Structural draft the keyring builder checks before a signature exists.
 * An unsigned draft has no `nextSig`, `authorizer`, `attest`, or required
 * `issuedAt`. `retainedLinks` uses the signed-record rule. An identical
 * attested sibling of the same transition is a retry and is not a fork.
 * `checkRotationPublish` rejects this shape with `bad-record`. Only
 * `rotateKeyring` / `rotate_keyring` calls this.
 * @param {unknown} candidate @param {readonly unknown[]} siblings @param {PrincipalId} genesis @param {readonly unknown[]} priorRecords @param {ResolutionContext} ctx @returns {Result<Rotate>} */
export function checkRotationDraft(candidate, siblings, genesis, priorRecords, ctx) {
  const chain = loadChain(genesis, priorRecords, ctx); if (!chain.ok) return chain;
  const structural = draftRotation(candidate); if (!structural.ok) return structural;
  if (structural.value.principal !== chain.value.genesis) return fail('bad-record');
  return publishTail(structural.value, siblings, chain.value.genesis, chain.value.history, chain.value.bindingEpub, ctx, true);
}
/** Client publish check and Panopticon attest check. Same rules.
 * Refuses v2 and an unsigned draft (`bad-record`). Draft validation is
 * `checkRotationDraft`, and only the keyring builder calls it.
 * An authenticated sibling with a different signing-byte id at the same
 * (principal, seq) is `rotation-fork`. An identical attested sibling is a
 * retry and is not a fork. Junk and unattested siblings are skipped. Priors
 * are the records `resolveCurrentKey` accepts, not raw JSON.
 * A signed candidate with no attestation is checked by `verifyRotationRequest`
 * (its local checks only). Freshness and present revocation apply only to
 * that unattested request. An attested candidate uses the historical checks:
 * `issuedAt` is an upper bound, and revocation is the witnessed check at
 * `issuedAt`. Chain sequence, sibling forks, and epub reuse are applied
 * here, after that call. Panopticon MUST call this function before
 * attesting. It attests at most one genesis-epub binding per principal, only
 * before the first rotation, and that limit is global across instances and
 * signing keys (panopticon#499).
 * Does not replace verifyRotate. Historical v2 records still verify there.
 * @param {unknown} candidate @param {readonly unknown[]} siblings @param {PrincipalId} genesis @param {readonly unknown[]} priorRecords @param {ResolutionContext} ctx @returns {Result<Rotate>} */
export function checkRotationPublish(candidate, siblings, genesis, priorRecords, ctx) {
  const described = data(candidate);
  const signedRequest = described.ok && described.value.kind === 'rotate' && !Object.hasOwn(described.value, 'attest') && (Object.hasOwn(described.value, 'nextSig') || Object.hasOwn(described.value, 'authorizer'));
  const parsed = rotationCandidate(candidate);
  if (!signedRequest && (!parsed.ok || parsed.value.kind !== 'rotate')) return fail('bad-record');
  const chain = loadChain(genesis, priorRecords, ctx); if (!chain.ok) return chain;
  const history = chain.value.history;
  const current = history.length ? history[history.length - 1].nextKey : chain.value.genesis;
  const checked = signedRequest ? verifyRotationRequest(candidate, current, ctx) : checkRotate(candidate, current, ctx, []);
  if (!checked.ok) return checked;
  const raw = checked.value;
  if (!hasNextEpub(raw) || raw.principal !== chain.value.genesis) return fail('bad-record');
  return publishTail(raw, siblings, chain.value.genesis, history, chain.value.bindingEpub, ctx, false);
}
/** Copies share signing-byte identity: any fully verified copy satisfies that rotation ID.
 * Unauthenticated junk is diagnostic; unresolved authenticated evidence fails closed.
 * @param {PrincipalId} genesis @param {readonly unknown[]} rotations @param {ResolutionContext} ctx @returns {Resolution<ResolvedAccount>} */
export function resolveCurrentKey(genesis, rotations, ctx) {
  /** @type {Diagnostic[]} */ const diagnostics = [];
  const rotationsList = boundedList(rotations);
  if (!rotationsList.ok) return { ...rotationsList, diagnostics };
  const bounded = boundedContext(ctx);
  if (!bounded.ok) return { ...bounded, diagnostics };
  if (!integer(ctx.now)) return { ...fail('missing-history'), diagnostics };
  const g = parsePrincipalId(genesis); if (!g.ok) return { ...g, diagnostics };
  const listed = genesisBindings(ctx); if (!listed.ok) return { ...listed, diagnostics };
  /** @type {{row: GenesisEpub, index: number}[]} */
  let pending = [];
  listed.value.forEach((raw, index) => {
    const v = verifyGenesisEpub(raw, g.value, ctx);
    if (!v.ok) { diagnostics.push({ source: 'genesis-epub', index, reason: v.reason }); return; }
    const id = hex(sha256(bytes(v.value)));
    if (pending.some(b => hex(sha256(bytes(b.row))) === id)) return;
    pending.push({ row: v.value, index });
  });
  /** Bindings issued at or after the first accepted rotation are not a fork.
   * @type {{row: GenesisEpub, index: number}|null} */
  let binding = null;
  /** @type {Rotate[]} */ const history = [];
  /** @type {Map<number, {r:Rotate,index:number}[]>} */ const groups = new Map();
  for (const [index,raw] of rotations.entries()) {
    const p = rotationCandidate(raw);
    const reason = !p.ok ? p.reason : p.value.kind !== 'rotate' || p.value.principal !== genesis ? 'bad-record' : p.value.issuedAt > ctx.now ? 'future-record' : null;
    if (reason) { diagnostics.push({source:'rotation',index,reason}); continue; }
    const r = /** @type {Rotate} */ (/** @type {{ok:true,value:IdentityRecord}} */ (p).value);
    const list = groups.get(r.seq) ?? []; list.push({r,index}); groups.set(r.seq,list);
  }
  let current = genesis, currentEpub = /** @type {PrincipalId|null} */ (null), seq = 1, lastTime = -1;
  for (const [n,group] of [...groups].sort((a,b) => a[0]-b[0])) {
    /** @type {Map<string,Rotate>} */ const valid = new Map();
    /** @type {Map<string,import('./types.js').Reason>} */ const unresolved = new Map();
    for (const {r:raw,index} of group) {
      /** @type {ResolutionContext} */ const candidate = { ...ctx, now:raw.issuedAt,
        history:(p,at,until) => p === genesis ? ok(historyState(genesis,history,at,until)) : state(ctx.history,p,at,until) };
      /** @type {Result<Rotate>} */ let result;
      const earlyEpubs = history.length
        ? (binding && binding.row.issuedAt < history[0].issuedAt ? [binding.row.epub] : [])
        : pending.filter(b => b.row.issuedAt < raw.issuedAt).map(b => b.row.epub);
      const reused = reusesEpub(raw, genesis, history, null) || earlyEpubs.some(epub => reusesEpub(raw, genesis, history, epub));
      if (n !== seq || raw.issuedAt <= lastTime || raw.nextKey === genesis || history.some(r => r.nextKey === raw.nextKey) || reused) result = fail('bad-sequence');
      else {
        result = checkRotate(raw,current,candidate,diagnostics);
        // A witnessed OIDC rotation contradicted by an active wallet cannot be skipped.
        if (!result.ok && result.reason === 'wallet-required') result = fail('rotation-conflict');
        if (result.ok && raw.authorizer.kind === 'wallet') {
          const own = record(ctx.links.get(raw.authorizer.link));
          if (!own.ok || own.value.kind !== 'wallet') result = fail('missing-history');
          else {
            const lookup = resolveWalletLink(own.value.address, [...ctx.links].sort((a,b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0).map(e => e[1]), ctx.revocations ?? [], candidate);
            for (const d of lookup.diagnostics) report(diagnostics,d.source,d.index,d.reason);
            if (!lookup.ok) result = fail(['missing-history','rotation-fork','rotation-conflict'].includes(lookup.reason) ? lookup.reason : 'rotation-conflict');
            else if (hex(sha256(bytes(lookup.value))) !== raw.authorizer.link) result = fail('rotation-conflict');
          }
        }
      }
      const id=hex(sha256(bytes(raw)));
      if (!result.ok) {
        diagnostics.push({source:'rotation',index,reason:result.reason});
        if (['missing-history','rotation-fork','rotation-conflict'].includes(result.reason) && !unresolved.has(id)) unresolved.set(id,result.reason);
      } else valid.set(id,result.value);
    }
    // A damaged proof copy must not veto a verified copy of the same signed transition.
    // A different authenticated ID still requires evidence, even if another ID verifies.
    for (const [id,reason] of unresolved) if (!valid.has(id)) return {...fail(reason),diagnostics};
    if (valid.size > 1) return { ...fail('rotation-fork'), diagnostics };
    const next = [...valid.values()][0];
    if (next) {
      if (history.length === 0) {
        const early = pending.filter(b => b.row.issuedAt < next.issuedAt);
        for (const late of pending) if (late.row.issuedAt >= next.issuedAt) diagnostics.push({ source: 'genesis-epub', index: late.index, reason: 'bad-sequence' });
        if (early.length > 1) {
          diagnostics.push({ source: 'genesis-epub', index: early[1].index, reason: 'rotation-fork' });
          return { ...fail('rotation-fork'), diagnostics };
        }
        binding = early[0] ?? null;
        pending = [];
      }
      current=next.nextKey; currentEpub=hasNextEpub(next) ? next.nextEpub : null; lastTime=next.issuedAt; history.push(next); seq++;
    }
  }
  if (!history.length && pending.length > 1) {
    diagnostics.push({ source: 'genesis-epub', index: pending[1].index, reason: 'rotation-fork' });
    return { ...fail('rotation-fork'), diagnostics };
  }
  if (!history.length) binding = pending[0] ?? null;
  const bindingEpub = binding ? binding.row.epub : null;
  if (!history.length) currentEpub = bindingEpub;
  return { ...ok({currentKey:current,currentEpub,bindingEpub,rotations:history}), diagnostics };
}
/** Equal-time distinct links are ambiguous even for the same principal. No resurrection after revocation.
 * @param {Eip55} address @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {ResolutionContext} ctx @returns {Resolution<WalletLink>} */
export function resolveWalletLink(address, links, revocations, ctx) {
  return resolveWallet(address, links, revocations, ctx, false);
}
/** Present lookup using the final authenticated current key; never use for as-of queries.
 * @param {Eip55} address @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {ResolutionContext} ctx @returns {Resolution<WalletLink>} */
export function resolveWalletLinkNow(address, links, revocations, ctx) {
  return resolveWallet(address, links, revocations, ctx, true);
}
/** Present OIDC eligibility. Matches issuer, tenant, and subject. Same envelope as the wallet lookup.
 * @param {unknown} cred @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {ResolutionContext} ctx @returns {Resolution<OidcLink>} */
export function resolveOidcLinkNow(cred, links, revocations, ctx) {
  const parsed = parseOidcCredential(cred);
  if (!parsed.ok) return { ...parsed, diagnostics: [] };
  return resolveOidc(parsed.value, links, revocations, ctx);
}
/** @param {import('./types.js').OidcCredential} cred @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {ResolutionContext} ctx @returns {Resolution<OidcLink>} */
function resolveOidc(cred, links, revocations, ctx) {
  /** @type {Diagnostic[]} */ const diagnostics = [];
  const listed = boundedList(links);
  if (!listed.ok) return { ...listed, diagnostics };
  const revokedList = boundedList(revocations ?? []);
  if (!revokedList.ok) return { ...revokedList, diagnostics };
  const bounded = boundedContext(ctx);
  if (!bounded.ok) return { ...bounded, diagnostics };
  if (!integer(ctx.now)) return { ...fail('missing-history'), diagnostics };
  /** @type {Map<string, OidcLink>} */ const valid = new Map();
  for (const [index, raw] of links.entries()) {
    const p = record(raw);
    if (!p.ok) { report(diagnostics, 'link', index, p.reason); continue; }
    if (p.value.kind !== 'oidc' || p.value.cred.iss !== cred.iss || p.value.cred.tenant !== cred.tenant || p.value.cred.sub !== cred.sub) continue;
    const v = historicalLink(p.value, ctx, ctx.now);
    if (!v.ok) { report(diagnostics, 'link', index, v.reason); if (v.reason === 'missing-history' || v.reason === 'rotation-fork' || v.reason === 'rotation-conflict') return { ...v, diagnostics }; continue; }
    valid.set(hex(sha256(bytes(v.value))), /** @type {OidcLink} */ (v.value));
  }
  const sorted = [...valid].sort((a, b) => b[1].issuedAt - a[1].issuedAt || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  if (!sorted.length) return { ...fail('unknown-link'), diagnostics };
  const newest = sorted[0][1];
  if (sorted.length > 1 && sorted[1][1].issuedAt === newest.issuedAt) return { ...fail('ambiguous-link'), diagnostics };
  const h = state(ctx.history, newest.principal, newest.issuedAt, ctx.now);
  if (!h.ok) return { ...h, diagnostics };
  const revoked = revokedAt(newest, revocations, h.value.currentKey, ctx.now, ctx.jwks, diagnostics, true);
  return { ...(revoked ? fail('revoked-link') : ok(newest)), diagnostics };
}
/** Authenticate candidate link ids and drop those revoked under the final current key.
 * Does not issue an attestation. Missing history fails the call.
 * @param {readonly unknown[]} candidates @param {ResolutionContext} ctx @returns {Result<string[]>} */
export function prepareRetainedLinksNow(candidates, ctx) {
  const listed = boundedList(candidates);
  if (!listed.ok) return listed;
  const bounded = boundedContext(ctx);
  if (!bounded.ok) return bounded;
  if (!integer(ctx.now)) return fail('missing-history');
  /** @type {string[]} */ const retained = [];
  for (const id of listed.value) {
    if (typeof id !== 'string') return fail('bad-record');
    const link = ctx.links.get(id);
    if (!link || typeof link !== 'object') return fail('missing-history');
    const row = /** @type {WalletLink|OidcLink} */ (link);
    const looked = state(ctx.history, row.principal, row.issuedAt, ctx.now);
    if (!looked.ok) return looked;
    const proof = row.kind === 'wallet'
      ? verifyWalletLink(link, ctx.jwks, ctx.policy, row.issuedAt, looked.value)
      : verifyOidcLink(link, ctx.jwks, ctx.pinnedIss, row.issuedAt, looked.value);
    if (!proof.ok) return proof;
    const computed = linkId(proof.value);
    if (!computed.ok || computed.value !== id) return fail('missing-history');
    const revoked = (ctx.revocations ?? []).some(raw => {
      const r = verifyRevokeNow(raw, looked.value.currentKey, ctx.now);
      return r.ok && r.value.principal === proof.value.principal && r.value.linkId === id && r.value.issuedAt >= proof.value.issuedAt;
    });
    if (!revoked) retained.push(id);
  }
  return ok(retained.sort());
}
/** Group untrusted link copies by signing-byte id and keep one that verifies.
 * A tampered sibling does not drop that id. An id whose copies all fail closed
 * on missing history still fails the call. Other failures omit the id.
 * @param {readonly unknown[]} copies @param {ResolutionContext} ctx @returns {Result<Map<string, WalletLink|OidcLink>>} */
export function verifyingLinkMap(copies, ctx) {
  const listed = boundedList(copies);
  if (!listed.ok) return listed;
  const bounded = boundedContext(ctx);
  if (!bounded.ok) return bounded;
  if (!integer(ctx.now)) return fail('missing-history');
  /** @type {Map<string, unknown[]>} */ const groups = new Map();
  for (const raw of listed.value) {
    const p = record(raw);
    if (!p.ok || (p.value.kind !== 'wallet' && p.value.kind !== 'oidc')) continue;
    const id = hex(sha256(bytes(p.value)));
    const list = groups.get(id) ?? [];
    list.push(raw);
    groups.set(id, list);
  }
  /** @type {Map<string, WalletLink|OidcLink>} */ const kept = new Map();
  for (const [id, list] of groups) {
    /** @type {import('./types.js').Reason|null} */ let fatal = null;
    /** @type {WalletLink|OidcLink|null} */ let winner = null;
    for (const raw of list) {
      const p = record(raw);
      if (!p.ok || (p.value.kind !== 'wallet' && p.value.kind !== 'oidc')) continue;
      const v = historicalLink(/** @type {WalletLink|OidcLink} */ (p.value), ctx, ctx.now);
      if (v.ok) { winner = /** @type {WalletLink|OidcLink} */ (v.value); break; }
      if (!fatal && (v.reason === 'missing-history' || v.reason === 'rotation-fork' || v.reason === 'rotation-conflict')) fatal = v.reason;
    }
    if (winner) kept.set(id, winner);
    else if (fatal) return fail(fatal);
  }
  return ok(kept);
}
/** The public entry point fixes the revocation mode; history resolution always uses witnessed revokes.
 * @param {Eip55} address @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {ResolutionContext} ctx @param {boolean} present @returns {Resolution<WalletLink>} */
function resolveWallet(address, links, revocations, ctx, present) {
  /** @type {Diagnostic[]} */ const diagnostics = [];
  const listed = boundedList(links);
  if (!listed.ok) return { ...listed, diagnostics };
  const revokedList = boundedList(revocations ?? []);
  if (!revokedList.ok) return { ...revokedList, diagnostics };
  const bounded = boundedContext(ctx);
  if (!bounded.ok) return { ...bounded, diagnostics };
  if (!integer(ctx.now)) return { ...fail('missing-history'), diagnostics };
  /** @type {Map<string,WalletLink>} */ const valid = new Map();
  for (const [index,raw] of links.entries()) {
    const p=record(raw);
    if (!p.ok) {report(diagnostics,'link',index,p.reason);continue;}
    if (p.value.kind !== 'wallet' || p.value.address !== address) continue;
    const v=historicalLink(p.value,ctx,ctx.now);
    if (!v.ok) {report(diagnostics,'link',index,v.reason);if (v.reason==='missing-history'||v.reason==='rotation-fork'||v.reason==='rotation-conflict') return {...v,diagnostics};continue;}
    valid.set(hex(sha256(bytes(v.value))),/** @type {WalletLink} */ (v.value));
  }
  const sorted=[...valid].sort((a,b) => b[1].issuedAt-a[1].issuedAt || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  if (!sorted.length) return { ...fail('unknown-link'), diagnostics };
  const [id,newest]=sorted[0];
  if (sorted.length > 1 && sorted[1][1].issuedAt === newest.issuedAt) return { ...fail('ambiguous-link'), diagnostics };
  const h=state(ctx.history,newest.principal,newest.issuedAt,ctx.now);
  if (!h.ok) return {...h,diagnostics};
  const revoked=revokedAt(newest,revocations,h.value.currentKey,ctx.now,ctx.jwks,diagnostics,present);
  return { ...(revoked ? fail('revoked-link') : ok(newest)), diagnostics };
}
/** SEA P-256 ECDSA over SHA-256. Raw r||s, base64url. High-S and low-S both verify.
 * @param {PrincipalId} key @param {string} sig @param {Uint8Array} bytes @returns {Result<true>} */
export function verifyKeySignature(key, sig, bytes) {
  const p = parsePrincipalId(key); if (!p.ok) return p;
  const s = text(sig, 128); if (!s.ok) return s;
  if (!(bytes instanceof Uint8Array)) return fail('bad-signature');
  return keyVerify(p.value, s.value, bytes) ? ok(true) : fail('bad-signature');
}
/** Sign ids bytes with a 32-byte SEA scalar. `expectedKey` is the resolver's current key.
 * The working copy of the scalar is wiped. A bad scalar or a different public key is `bad-key`.
 * The result is raw r||s, base64url, the encoding verifyKeySignature accepts.
 * @param {Uint8Array} scalar @param {Uint8Array} bytes @param {PrincipalId} expectedKey @returns {Result<string>} */
export function signWithKeyring(scalar, bytes, expectedKey) {
  const key = parsePrincipalId(expectedKey);
  if (!key.ok || !(scalar instanceof Uint8Array) || scalar.length !== 32 || !(bytes instanceof Uint8Array)) return fail('bad-key');
  const held = new Uint8Array(scalar);
  try {
    const pub = p256.getPublicKey(held, false);
    const derived = parsePrincipalId(b64(pub.subarray(1, 33)) + '.' + b64(pub.subarray(33)));
    if (!derived.ok || derived.value !== key.value) return fail('bad-key');
    return ok(b64(p256.sign(bytes, held, { prehash: true, lowS: false, format: 'compact' })));
  } catch { return fail('bad-key'); }
  finally { held.fill(0); }
}
/** @param {Uint8Array} bytes */
function recordIdOf(bytes) { return hex(sha256(bytes)); }
/** sociacl-acl-attest-v1. Checked like attestVerify with now = issuedAt.
 * Nothing in this package issues the claim.
 * @param {string} jws @param {Jwks} jwks @param {number} issuedAt @param {Uint8Array} bytes @returns {Result<AclAttestation>} */
export function verifyAclAttestation(jws, jwks, issuedAt, bytes) {
  if (typeof jws !== 'string') return fail('not-string');
  if (jws.length > 16384) return fail('too-long');
  const token = text(jws, 16384); if (!token.ok) return token;
  if (!integer(issuedAt) || !(bytes instanceof Uint8Array)) return fail('bad-attestation');
  const a = attestVerify(token.value, jwks, issuedAt); if (!a.ok) return a;
  const c = a.value;
  if (!only(c, ['typ', 'principal', 'recordId', 'iat', 'exp']) || c.typ !== 'sociacl-acl-attest-v1' || c.iat !== issuedAt || c.recordId !== recordIdOf(bytes)) return fail('bad-attestation');
  const principal = parsePrincipalId(c.principal); if (!principal.ok) return fail('bad-attestation');
  return ok(Object.freeze({ typ: 'sociacl-acl-attest-v1', principal: principal.value, recordId: /** @type {string} */ (c.recordId), iat: issuedAt, exp: /** @type {number} */ (c.exp) }));
}
const SEE_DOMAIN = 'sociacl-see-grant-v2';
/** Signing bytes for one already-parsed see row. The domain and stated are inside the bytes.
 * @param {SeeGrant} grant */
export function seeGrantBytes(grant) {
  return lp([SEE_DOMAIN, grant.owner, grant.object, grant.accessor, String(grant.stated), String(grant.from), String(grant.until), String(grant.hamState), String(grant.issuedAt)]);
}
/** One snapshot of a see row. A getter or proxy is `bad-record`. `kind` is ignored.
 * @param {unknown} row @returns {Result<{ grant: SeeGrant, bytes: Uint8Array }>} */
export function parseSeeGrant(row) {
  const d = data(row); if (!d.ok) return d;
  const r = d.value;
  if (r.domain !== undefined && r.domain !== SEE_DOMAIN) return fail('legacy-row');
  if (!Object.hasOwn(r, 'sig')) return fail('legacy-row');
  const owner = parsePrincipalId(r.owner); if (!owner.ok) return owner;
  const object = parseObjectId(r.object); if (!object.ok) return object;
  const accessor = parsePrincipalId(r.accessor); if (!accessor.ok) return accessor;
  if (!Object.is(r.stated, 0) && !Object.is(r.stated, 1)) return fail('bad-record');
  const from = r.from, until = r.until, hamState = r.hamState, issuedAt = r.issuedAt;
  if (!integer(from) || !integer(until) || !integer(hamState) || !integer(issuedAt) || /** @type {number} */ (until) < /** @type {number} */ (from)) return fail('bad-record');
  const sig = text(r.sig, 128); if (!sig.ok) return sig;
  if (Object.hasOwn(r, 'attest')) {
    const attest = text(r.attest, 16384); if (!attest.ok) return attest;
  }
  /** @type {SeeGrant} */
  const grant = Object.freeze({
    owner: owner.value,
    object: object.value,
    accessor: accessor.value,
    stated: /** @type {0|1} */ (r.stated),
    from: /** @type {number} */ (r.from),
    until: /** @type {number} */ (r.until),
    hamState: /** @type {number} */ (r.hamState),
    issuedAt: /** @type {number} */ (r.issuedAt),
    sig: sig.value,
    ...(Object.hasOwn(r, 'attest') ? { attest: /** @type {string} */ (r.attest) } : {}),
  });
  return ok(Object.freeze({ grant, bytes: seeGrantBytes(grant) }));
}
/** @param {SeeGrant} grant @param {Uint8Array} bytes @param {ResolutionContext} ctx */
function seeWitness(grant, bytes, ctx) {
  if (grant.attest === undefined) return fail('unwitnessed-retired-key');
  const attest = verifyAclAttestation(grant.attest, ctx.jwks, grant.issuedAt, bytes);
  if (!attest.ok) return attest;
  if (attest.value.principal !== grant.owner) return fail('bad-attestation');
  return attest;
}
/** See-grant authority. Eligibility of a retired cancel is `stated === 0` on this parsed row.
 * There is no kind argument. A retired `stated === 1` row is refused even when witnessed.
 * @param {unknown} row @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @returns {Result<SignedAt & { grant: SeeGrant, bytes: Uint8Array }>} */
export function verifySeeGrant(row, rotations, ctx) {
  const parsed = parseSeeGrant(row); if (!parsed.ok) return parsed;
  const { grant, bytes } = parsed.value;
  if (!ctx || !Array.isArray(rotations)) return fail('missing-history');
  const account = resolveCurrentKey(grant.owner, rotations, ctx);
  if (!account.ok) return fail(account.reason);
  const skew = ctx.policy?.clockSkewSeconds ?? 0;
  const when = time(grant.issuedAt, ctx.now, skew); if (!when.ok) return when;
  const state = historyState(grant.owner, account.value.rotations, grant.issuedAt, ctx.now);
  if (state.key === account.value.currentKey) {
    if (!keyVerify(account.value.currentKey, grant.sig, bytes)) return fail('bad-signature');
    return ok(Object.freeze({ key: account.value.currentKey, mode: 'present', grant, bytes }));
  }
  if (grant.stated !== 0) {
    if (grant.attest !== undefined) {
      const seen = seeWitness(grant, bytes, ctx);
      if (!seen.ok) return seen;
    }
    return fail('unwitnessed-retired-key');
  }
  const seen = seeWitness(grant, bytes, ctx); if (!seen.ok) return seen;
  if (!keyVerify(state.key, grant.sig, bytes)) return fail('bad-signature');
  return ok(Object.freeze({ key: state.key, mode: 'witnessed', grant, bytes }));
}
/** Length-prefixed domain for postGrantBytes. */
export const POST_DOMAIN = 'sociacl-post-grant-v2';
/** Signing bytes for one already-parsed post row. The domain and stated are inside the bytes.
 * @param {SeeGrant} grant */
export function postGrantBytes(grant) {
  return lp([POST_DOMAIN, grant.owner, grant.object, grant.accessor, String(grant.stated), String(grant.from), String(grant.until), String(grant.hamState), String(grant.issuedAt)]);
}
/** One snapshot of a post row. Same fields as a see row. A getter or proxy is `bad-record`.
 * @param {unknown} row @returns {Result<{ grant: SeeGrant, bytes: Uint8Array }>} */
export function parsePostGrant(row) {
  const d = data(row); if (!d.ok) return d;
  const r = d.value;
  if (r.domain !== undefined && r.domain !== POST_DOMAIN) return fail('legacy-row');
  if (!Object.hasOwn(r, 'sig')) return fail('legacy-row');
  const owner = parsePrincipalId(r.owner); if (!owner.ok) return owner;
  const object = parseObjectId(r.object); if (!object.ok) return object;
  const accessor = parsePrincipalId(r.accessor); if (!accessor.ok) return accessor;
  if (!Object.is(r.stated, 0) && !Object.is(r.stated, 1)) return fail('bad-record');
  const from = r.from, until = r.until, hamState = r.hamState, issuedAt = r.issuedAt;
  if (!integer(from) || !integer(until) || !integer(hamState) || !integer(issuedAt) || /** @type {number} */ (until) < /** @type {number} */ (from)) return fail('bad-record');
  const sig = text(r.sig, 128); if (!sig.ok) return sig;
  if (Object.hasOwn(r, 'attest')) {
    const attest = text(r.attest, 16384); if (!attest.ok) return attest;
  }
  /** @type {SeeGrant} */
  const grant = Object.freeze({
    owner: owner.value,
    object: object.value,
    accessor: accessor.value,
    stated: /** @type {0|1} */ (r.stated),
    from: /** @type {number} */ (r.from),
    until: /** @type {number} */ (r.until),
    hamState: /** @type {number} */ (r.hamState),
    issuedAt: /** @type {number} */ (r.issuedAt),
    sig: sig.value,
    ...(Object.hasOwn(r, 'attest') ? { attest: /** @type {string} */ (r.attest) } : {}),
  });
  return ok(Object.freeze({ grant, bytes: postGrantBytes(grant) }));
}
/** Post-grant authority. A retired cancel is `stated === 0` on this parsed row.
 * A retired `stated === 1` row is refused even when witnessed.
 * @param {unknown} row @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @returns {Result<SignedAt & { grant: SeeGrant, bytes: Uint8Array }>} */
export function verifyPostGrant(row, rotations, ctx) {
  const parsed = parsePostGrant(row); if (!parsed.ok) return parsed;
  const { grant, bytes } = parsed.value;
  if (!ctx || !Array.isArray(rotations)) return fail('missing-history');
  const account = resolveCurrentKey(grant.owner, rotations, ctx);
  if (!account.ok) return fail(account.reason);
  const skew = ctx.policy?.clockSkewSeconds ?? 0;
  const when = time(grant.issuedAt, ctx.now, skew); if (!when.ok) return when;
  const state = historyState(grant.owner, account.value.rotations, grant.issuedAt, ctx.now);
  if (state.key === account.value.currentKey) {
    if (!keyVerify(account.value.currentKey, grant.sig, bytes)) return fail('bad-signature');
    return ok(Object.freeze({ key: account.value.currentKey, mode: 'present', grant, bytes }));
  }
  if (grant.stated !== 0) {
    if (grant.attest !== undefined) {
      const seen = seeWitness(grant, bytes, ctx);
      if (!seen.ok) return seen;
    }
    return fail('unwitnessed-retired-key');
  }
  const seen = seeWitness(grant, bytes, ctx); if (!seen.ok) return seen;
  if (!keyVerify(state.key, grant.sig, bytes)) return fail('bad-signature');
  return ok(Object.freeze({ key: state.key, mode: 'witnessed', grant, bytes }));
}
/** Present authority under the resolved current key.
 * Arbitrary bytes stay fail-closed on a retired key. A see cancel is
 * `verifySeeGrant`: the signed `stated` field is `0`.
 * Kind is not a parameter, and this function does not take an attestation.
 * @param {PrincipalId} principal @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @param {Uint8Array} bytes @param {string} sig @param {number} issuedAt
 * @returns {Result<SignedAt>} */
export function verifySignedAt(principal, rotations, ctx, bytes, sig, issuedAt) {
  const p = parsePrincipalId(principal); if (!p.ok) return p;
  if (!ctx || !Array.isArray(rotations)) return fail('missing-history');
  const account = resolveCurrentKey(p.value, rotations, ctx);
  if (!account.ok) return fail(account.reason);
  if (!integer(issuedAt)) return fail('bad-record');
  const skew = ctx.policy?.clockSkewSeconds ?? 0;
  const when = time(issuedAt, ctx.now, skew); if (!when.ok) return when;
  const state = historyState(p.value, account.value.rotations, issuedAt, ctx.now);
  if (state.key !== account.value.currentKey) return fail('unwitnessed-retired-key');
  const s = text(sig, 128);
  if (!(bytes instanceof Uint8Array) || !s.ok || !keyVerify(account.value.currentKey, s.value, bytes)) return fail('bad-signature');
  return ok(Object.freeze({ key: account.value.currentKey, mode: 'present' }));
}
/** Length-prefixed domain for requestId. The hash input is this domain, the requester, and the object. */
export const REQUEST_ID_DOMAIN = 'sociacl-request-id-v2';
/** Length-prefixed domain for an access request. */
export const REQUEST_DOMAIN = 'sociacl-access-request-v2';
const REQUEST_MESSAGE_MAX = 280;
const loneRequestSurrogate = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
/** @param {unknown} value @returns {Result<string>} */
function requestMessage(value) {
  if (typeof value !== 'string') return fail('not-string');
  if (loneRequestSurrogate.test(value)) return fail('unpaired-surrogate');
  if ([...value].length > REQUEST_MESSAGE_MAX) return fail('too-long');
  return ok(value);
}
/** Signing bytes for a request id. Scope, message, and status are not inputs.
 * @param {PrincipalId} requester @param {import('./types.js').ObjectId} object */
export function requestIdBytes(requester, object) {
  return lp([REQUEST_ID_DOMAIN, requester, object]);
}
/** `hex(sha256(requestIdBytes))` after both ids parse. A non-string is `not-string`.
 * @param {unknown} requester @param {unknown} object @returns {Result<string>} */
export function requestId(requester, object) {
  const who = parsePrincipalId(requester); if (!who.ok) return who;
  const id = parseObjectId(object); if (!id.ok) return id;
  return ok(hex(sha256(requestIdBytes(who.value, id.value))));
}
/** Signing bytes for one already-parsed access request.
 * @param {{ requestId: string, requester: PrincipalId, object: import('./types.js').ObjectId, scope: string, status: string, message: string, issuedAt: number }} request */
export function accessRequestBytes(request) {
  return lp([REQUEST_DOMAIN, request.requestId, request.requester, request.object, request.scope, request.status, request.message, String(request.issuedAt)]);
}
/** One snapshot of an access request. The request id is computed from the requester and object.
 * A wrong domain or a missing signature is `legacy-row`. An empty message is allowed.
 * @param {unknown} row @returns {Result<{ request: { requestId: string, requester: PrincipalId, object: import('./types.js').ObjectId, scope: 'read' | 'read+post', status: 'pending' | 'withdrawn', message: string, issuedAt: number, sig: string }, bytes: Uint8Array }>} */
export function parseAccessRequest(row) {
  const d = data(row); if (!d.ok) return d;
  const r = d.value;
  if (r.domain !== undefined && r.domain !== REQUEST_DOMAIN) return fail('legacy-row');
  if (!Object.hasOwn(r, 'sig')) return fail('legacy-row');
  const requester = parsePrincipalId(r.requester); if (!requester.ok) return requester;
  const object = parseObjectId(r.object); if (!object.ok) return object;
  const id = hex(sha256(requestIdBytes(requester.value, object.value)));
  if (typeof r.requestId !== 'string') return fail(r.requestId === undefined ? 'bad-record' : 'not-string');
  if (r.requestId !== id) return fail('bad-record');
  if (typeof r.scope !== 'string') return fail('not-string');
  if (r.scope !== 'read' && r.scope !== 'read+post') return fail('bad-record');
  if (typeof r.status !== 'string') return fail('not-string');
  if (r.status !== 'pending' && r.status !== 'withdrawn') return fail('bad-record');
  const message = requestMessage(r.message); if (!message.ok) return message;
  if (!integer(r.issuedAt)) return fail('bad-record');
  const sig = text(r.sig, 128); if (!sig.ok) return sig;
  const request = Object.freeze({
    requestId: id,
    requester: requester.value,
    object: object.value,
    scope: /** @type {'read' | 'read+post'} */ (r.scope),
    status: /** @type {'pending' | 'withdrawn'} */ (r.status),
    message: message.value,
    issuedAt: /** @type {number} */ (r.issuedAt),
    sig: sig.value,
  });
  return ok(Object.freeze({ request, bytes: accessRequestBytes(request) }));
}
/** Present authority for the requester. A retired key is refused. Kind is not a parameter.
 * @param {unknown} row @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @returns {Result<SignedAt & { request: { requestId: string, requester: PrincipalId, object: import('./types.js').ObjectId, scope: 'read' | 'read+post', status: 'pending' | 'withdrawn', message: string, issuedAt: number, sig: string }, bytes: Uint8Array }>} */
export function verifyAccessRequest(row, rotations, ctx) {
  const parsed = parseAccessRequest(row); if (!parsed.ok) return parsed;
  const signed = verifySignedAt(parsed.value.request.requester, rotations, ctx, parsed.value.bytes, parsed.value.request.sig, parsed.value.request.issuedAt);
  if (!signed.ok) return signed;
  return ok(Object.freeze({ ...signed.value, request: parsed.value.request, bytes: parsed.value.bytes }));
}
const OBJECT_DOMAIN = 'sociacl-object-v2';
/** Signing bytes for an object-owner record. The domain is inside the bytes.
 * @param {{ object: import('./types.js').ObjectId, owner: PrincipalId, issuedAt: number }} record */
export function objectRecordBytes(record) {
  return lp([OBJECT_DOMAIN, record.object, record.owner, String(record.issuedAt)]);
}
/** Snapshot one object-owner record. A missing signature is unsigned.
 * @param {unknown} row @returns {Result<{ record: import('./types.js').ObjectRecord, bytes: Uint8Array }>} */
export function parseObjectRecord(row) {
  const d = data(row); if (!d.ok) return d;
  const r = d.value;
  if (r.domain !== undefined && r.domain !== OBJECT_DOMAIN) return fail('bad-record');
  const object = parseObjectId(r.object); if (!object.ok) return object;
  const owner = parsePrincipalId(r.owner); if (!owner.ok) return owner;
  if (!integer(r.issuedAt)) return fail('bad-record');
  const creator = objectPrincipal(object.value);
  if (!creator.ok || creator.value !== owner.value) return fail('bad-record');
  if (!Object.hasOwn(r, 'sig')) return fail('bad-signature');
  const sig = text(r.sig, 128); if (!sig.ok) return sig;
  /** @type {import('./types.js').ObjectRecord} */
  const record = Object.freeze({
    object: object.value,
    owner: owner.value,
    issuedAt: /** @type {number} */ (r.issuedAt),
    sig: sig.value,
  });
  return ok(Object.freeze({ record, bytes: objectRecordBytes(record) }));
}
/** The owner signs `sociacl-object-v2`. A retired key is refused.
 * @param {unknown} row @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @returns {Result<SignedAt & { record: import('./types.js').ObjectRecord, bytes: Uint8Array }>} */
export function verifyObjectRecord(row, rotations, ctx) {
  const parsed = parseObjectRecord(row); if (!parsed.ok) return parsed;
  const signed = verifySignedAt(parsed.value.record.owner, rotations, ctx, parsed.value.bytes, parsed.value.record.sig, parsed.value.record.issuedAt);
  if (!signed.ok) return signed;
  return ok(Object.freeze({ ...signed.value, record: parsed.value.record, bytes: parsed.value.bytes }));
}
