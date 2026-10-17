import { webUri } from './uri.js';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ok, fail, text, data, integer, unb64, hex, unhex, utf8, lengthPrefixed } from './util.js';
import { parsePrincipalId, parseEip55, parseOidcCredential, checksum } from './ids.js';
import { uniqueJson } from './json.js';
/** @import {PrincipalId, Eip55, Result, WalletLink, OidcLink, Rotate, Revoke, IdentityRecord, UnsignedRecord, Jwks, Siwe, ResolutionContext, SiwePolicy, HistoryResolver, KeyState, Diagnostic, Resolution, ResolvedAccount} from './types.js' */

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
  /** @type {any[]} */ let retainedLinks;
  try {
    if (!Array.isArray(r.retainedLinks)) return fail('bad-record');
    const d = /** @type {Record<string, PropertyDescriptor>} */ (/** @type {unknown} */ (Object.getOwnPropertyDescriptors(r.retainedLinks))), length=d.length.value;
    if (!integer(length) || length > 1024) return fail('bad-record');
    retainedLinks = Array.from({length}, (_,i) => d[String(i)]?.value);
  } catch { return fail('bad-record'); }
  if (!retainedLinks.every((v,i) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) && (i === 0 || retainedLinks[i-1] < v))) return fail('bad-record');
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
    case 'wallet': return lengthPrefixed(['sociacl-link-wallet-v1', r.principal, r.address, t, r.nonce]);
    case 'oidc': return lengthPrefixed(['sociacl-link-oidc-v1', r.principal, r.cred.iss, r.cred.tenant, r.cred.sub, t, r.nonce]);
    case 'rotate': return lengthPrefixed([hasNextEpub(r) ? 'sociacl-rotate-v3' : 'sociacl-rotate-v2', r.principal, String(r.seq), r.prevKey, r.nextKey, ...(hasNextEpub(r) ? [r.nextEpub] : []), t, r.authorizer.kind, r.authorizer.link, String(r.retainedLinks.length), ...r.retainedLinks]);
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
/** @param {number} issuedAt @param {number} now @param {number} [skew] */
function time(issuedAt, now, skew = 0) { return !integer(now) || !integer(skew) || skew > 300 ? fail('bad-record') : issuedAt > now + skew ? fail('future-record') : ok(true); }
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
/** @param {unknown} x @param {PrincipalId} currentKey @param {ResolutionContext} ctx @param {Diagnostic[]} diagnostics @returns {Result<Rotate>} */
function checkRotate(x,currentKey,ctx,diagnostics) {
  if (typeof ctx.history !== 'function') return fail('missing-history');
  const p=rotationCandidate(x); if (!p.ok) return p; const r=p.value;
  if (r.kind !== 'rotate') return fail('bad-record');
  const t=time(r.issuedAt,ctx.now,ctx.policy.clockSkewSeconds??0); if (!t.ok) return t;
  if (r.prevKey !== currentKey || r.nextKey === currentKey) return fail('bad-sequence');
  if (hasNextEpub(r) && (r.nextEpub === r.nextKey || r.nextEpub === r.prevKey)) return fail('bad-sequence');
  if (!keyVerify(r.nextKey,r.nextSig,bytes(r))) return fail('bad-signature');
  const a=attestVerify(r.attest,ctx.jwks,ctx.now,ctx.policy.clockSkewSeconds??0); if (!a.ok) return a;
  const c=a.value;
  const attestKeys = ['typ','principal','nextKey','seq','iat','exp','auth','linkId','retainedLinks'];
  if (hasNextEpub(r)) attestKeys.push('nextEpub');
  if (!only(c,attestKeys) || c.typ !== (hasNextEpub(r) ? 'sociacl-rotate-attest-v3' : 'sociacl-rotate-attest-v2') || c.principal !== r.principal || c.nextKey !== r.nextKey || (hasNextEpub(r) && c.nextEpub !== r.nextEpub) || c.seq !== r.seq || c.iat !== r.issuedAt || c.auth !== r.authorizer.kind || c.linkId !== r.authorizer.link || JSON.stringify(c.retainedLinks) !== JSON.stringify(r.retainedLinks)) return fail('bad-attestation');
  // Validate the authorizing credential and every retained ID against the pre-rotation state.
  /** @type {Map<string,WalletLink|OidcLink>} */ const checked=new Map();
  for (const id of new Set([r.authorizer.link,...r.retainedLinks])) {
    if (!ctx.links.has(id)) return fail('missing-history');
    const raw=record(ctx.links.get(id)); if (!raw.ok) return fail('missing-history');
    const l=raw.value;
    if (!['wallet','oidc'].includes(l.kind) || l.principal !== r.principal || hex(sha256(bytes(l))) !== id) return fail('missing-history');
    const v=historicalLink(/** @type {WalletLink|OidcLink} */ (l),ctx,r.issuedAt); if (!v.ok) return fail(requiredHistoryFailure(v.reason));
    if (revokedAt(v.value,ctx.revocations??[],currentKey,r.issuedAt,ctx.jwks,diagnostics)) return fail('rotation-conflict');
    checked.set(id,v.value);
  }
  const authorizer=/** @type {WalletLink|OidcLink} */ (checked.get(r.authorizer.link));
  if (r.authorizer.kind === 'wallet') {
    if (authorizer.kind !== 'wallet') return fail('missing-history');
    const s=siweVerify(r.authorizer.siwe,authorizer.address,bytes(r),r.issuedAt,ctx.now,ctx.policy); if (!s.ok) return fail('missing-history');
  } else {
    if (authorizer.kind !== 'oidc') return fail('missing-history');
    // OIDC recovery is restricted to accounts with no active wallet, including wallets the candidate drops.
    const entries=[...ctx.links].sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:0);
    for (const [index,[id,raw]] of entries.entries()) {
      const parsed=record(raw);
      if (!parsed.ok) {report(diagnostics,'link',index,parsed.reason);continue;}
      const l=parsed.value;
      if (l.kind !== 'wallet' || l.principal !== r.principal) continue;
      if (hex(sha256(bytes(l))) !== id) {report(diagnostics,'link',index,'unknown-link');continue;}
      const v=historicalLink(l,ctx,r.issuedAt);
      if (!v.ok) {
        report(diagnostics,'link',index,v.reason);
        if (v.reason==='missing-history'||v.reason==='rotation-fork'||v.reason==='rotation-conflict') return v;
        continue;
      }
      if (!revokedAt(v.value,ctx.revocations??[],currentKey,r.issuedAt,ctx.jwks,diagnostics)) return fail('wallet-required');
    }
  }
  return ok(r);
}
/** nextEpub is a fresh point, and a later signing key is not an earlier epub.
 * @param {Rotate} raw @param {PrincipalId} genesis @param {readonly Rotate[]} history */
function reusesEpub(raw, genesis, history) {
  if (history.some(h => h.nextEpub === raw.nextKey)) return true;
  if (!hasNextEpub(raw)) return false;
  const epub = raw.nextEpub;
  return epub === raw.nextKey || epub === genesis || history.some(h => h.nextKey === epub || h.prevKey === epub || h.nextEpub === epub);
}
/** Copies share signing-byte identity: any fully verified copy satisfies that rotation ID.
 * Unauthenticated junk is diagnostic; unresolved authenticated evidence fails closed.
 * @param {PrincipalId} genesis @param {readonly unknown[]} rotations @param {ResolutionContext} ctx @returns {Resolution<ResolvedAccount>} */
export function resolveCurrentKey(genesis, rotations, ctx) {
  /** @type {Diagnostic[]} */ const diagnostics = [];
  if (!integer(ctx.now) || typeof ctx.history !== 'function') return { ...fail('missing-history'), diagnostics };
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
      if (n !== seq || raw.issuedAt <= lastTime || raw.nextKey === genesis || history.some(r => r.nextKey === raw.nextKey) || reusesEpub(raw, genesis, history)) result = fail('bad-sequence');
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
    if (next) { current=next.nextKey; currentEpub=hasNextEpub(next) ? next.nextEpub : null; lastTime=next.issuedAt; history.push(next); seq++; }
  }
  return { ...ok({currentKey:current,currentEpub,rotations:history}), diagnostics };
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
/** The public entry point fixes the revocation mode; history resolution always uses witnessed revokes.
 * @param {Eip55} address @param {readonly unknown[]} links @param {readonly unknown[]} revocations @param {ResolutionContext} ctx @param {boolean} present @returns {Resolution<WalletLink>} */
function resolveWallet(address, links, revocations, ctx, present) {
  /** @type {Diagnostic[]} */ const diagnostics = [];
  if (!integer(ctx.now) || typeof ctx.history !== 'function') return { ...fail('missing-history'), diagnostics };
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
/** @deprecated Use verifyWalletLink; this alias retains historical verification semantics. */
export const verifyWalletLinkAtKey = verifyWalletLink;
/** @deprecated Use verifyOidcLink; this alias retains historical verification semantics. */
export const verifyOidcLinkAtKey = verifyOidcLink;
/** @deprecated Use verifyRotate; this alias retains historical verification semantics. */
export const verifyRotateAtKey = verifyRotate;
/** @deprecated Use resolveWalletLink; this alias retains historical verification semantics. */
export const resolveWalletLinkAtKey = resolveWalletLink;
