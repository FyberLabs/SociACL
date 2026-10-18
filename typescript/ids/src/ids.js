import { publicHost, webUri } from './uri.js';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { ok, fail, text, data, b64, unb64, hex, unhex, utf8, lengthPrefixed } from './util.js';
/** @import {PrincipalId, PrincipalKey, Eip55, TenantId, OidcCredential, ObjectId, MintedObjectId, NetworkId, SourceKey, PathKey, Soul, Result, Collection, ParsedSoul, MembershipPredicate} from './types.js' */

/** @param {unknown} x @returns {Result<PrincipalId>} */
export function parsePrincipalId(x) {
  const t = text(x, 160); if (!t.ok) return t;
  const s = t.value;
  if (s.length !== 87) return fail('bad-length');
  if (!/^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/.test(s)) return fail('bad-alphabet');
  try {
    const bytes = new Uint8Array([4, ...unb64(s.slice(0, 43)), ...unb64(s.slice(44))]);
    p256.Point.fromBytes(bytes).assertValidity();
  } catch (e) { return fail(e instanceof Error && e.message.includes('noncanonical') ? 'non-canonical' : 'not-on-curve'); }
  return ok(/** @type {PrincipalId} */ (s));
}
/** @param {string} address */
export function checksum(address) {
  const lower = address.slice(2).toLowerCase();
  const hash = hex(keccak_256(utf8.encode(lower)));
  return '0x' + Array.from(lower, (c, i) => parseInt(hash[i], 16) >= 8 ? c.toUpperCase() : c).join('');
}
/** @param {unknown} x @returns {Result<Eip55>} */
export function parseEip55(x) {
  const t = text(x, 160); if (!t.ok) return t;
  if (!/^0x[0-9a-fA-F]{40}$/.test(t.value)) return fail('bad-alphabet');
  if (checksum(t.value) !== t.value) return fail('bad-checksum');
  return ok(/** @type {Eip55} */ (t.value));
}
/** UI edge only. @param {unknown} x @returns {Result<Eip55>} */
export function parseWalletInput(x) {
  const t = text(x, 160); if (!t.ok) return t;
  if (!/^0x[0-9a-fA-F]{40}$/.test(t.value)) return fail('bad-alphabet');
  const body = t.value.slice(2);
  return parseEip55(body === body.toLowerCase() || body === body.toUpperCase() ? checksum(t.value) : t.value);
}
/** @param {unknown} x @returns {Result<TenantId>} */
export function parseTenantId(x) {
  const t = text(x, 160); if (!t.ok) return t;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t.value)) return fail('bad-alphabet');
  if (t.value !== t.value.toLowerCase()) return fail('non-canonical');
  return ok(/** @type {TenantId} */ (t.value));
}
/** @param {unknown} x @returns {Result<OidcCredential>} */
export function parseOidcCredential(x) {
  const d = data(x); if (!d.ok) return d;
  if (Object.keys(d.value).some(k => !['iss', 'tenant', 'sub'].includes(k))) return fail('bad-record');
  const iss = text(d.value.iss, 2048); if (!iss.ok) return iss;
  const tenant = parseTenantId(d.value.tenant); if (!tenant.ok) return tenant;
  const sub = text(d.value.sub, 255); if (!sub.ok) return sub;
  if (!/^https:\/\/[\x21-\x7e]{1,2040}$/.test(iss.value) || !/^[\x21-\x7e]+$/.test(sub.value)) return fail('bad-alphabet');
  return ok(Object.freeze({ iss: iss.value, tenant: tenant.value, sub: sub.value }));
}
/** @param {unknown} x @returns {Result<ObjectId>} */
export function parseObjectId(x) {
  const t = text(x, 160); if (!t.ok) return t;
  const s = t.value;
  if (/^(claim|ext)_[0-9a-f]{64}$/.test(s)) return ok(/** @type {ObjectId} */ (s));
  const m = /^([a-z][a-z0-9]{1,15})_([0-9a-f]{32})$/.exec(s);
  if (m) return ['claim', 'ext', 'post', 'member', 'objset'].includes(m[1]) ? fail('reserved-kind') : ok(/** @type {ObjectId} */ (s));
  if (/^[a-z][a-z0-9]{1,15}_[0-9a-f]{32,64}$/i.test(s) && s !== s.toLowerCase()) return fail('non-canonical');
  const legacy = /^s3rch:(?:(?:room|chat|forum-msg):(0x[0-9a-fA-F]{40}):[0-9]{1,12}:[a-z0-9]{1,64}|(?:forum-group|bot):(0x[0-9a-fA-F]{40}):[a-z0-9]{1,64}|forum:(0x[0-9a-fA-F]{40}))$/.exec(s);
  if (!legacy) return fail('bad-alphabet');
  const w = parseEip55(legacy[1] ?? legacy[2] ?? legacy[3]); if (!w.ok) return w;
  return ok(/** @type {ObjectId} */ (s));
}
/** @param {unknown} x @returns {Result<NetworkId>} */
export function parseNetworkId(x) {
  const t = text(x, 2048); if (!t.ok) return t;
  const s = t.value;
  if (['atproto', 'farcaster', 'nostr', 'activitypub', 'rss'].includes(s)) return ok(/** @type {NetworkId} */ (s));
  const m = /^s3rch:https:\/\/([^/:;]+):([0-9]{1,5});key=([0-9a-f]{64})$/.exec(s);
  if (!m) return fail('unknown-network');
  if (!publicHost(m[1])) return fail('bad-host');
  if (+m[2] < 1 || +m[2] > 65535 || String(+m[2]) !== m[2]) return fail('bad-port');
  return ok(/** @type {NetworkId} */ (s));
}
/** RFC3986, uppercase hex. @param {string} s */
export const pct = (s) => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
/** @param {string} s */
function didWeb(s) {
  const [host, ...path] = s.slice(8).split(':');
  const m = /^([a-z0-9.-]+)(?:%3A([0-9]{1,5}))?$/.exec(host);
  return !!m && publicHost(m[1]) && (!m[2] || (+m[2] >= 1 && +m[2] <= 65535 && String(+m[2]) === m[2] && m[2] !== '443')) && path.every(p => /^(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+$/.test(p));
}
/** @param {unknown} x @returns {Result<SourceKey>} */
export function parseSourceKey(x) {
  const t = text(x, 8192); if (!t.ok) return t;
  if (!t.value.startsWith('sr1:')) return fail('bad-template');
  const parts = t.value.slice(4).split('/'); if (parts.length !== 4) return fail('bad-template');
  /** @type {string[]} */ const decoded = [];
  for (const part of parts.slice(0, 3)) {
    let s; try { s = decodeURIComponent(part); } catch { return fail('non-canonical'); }
    if (pct(s) !== part) return fail('non-canonical');
    const v = text(s, 2048); if (!v.ok) return v;
    decoded.push(s);
  }
  const [n, owner] = decoded;
  const network = parseNetworkId(n); if (!network.ok) return network;
  if (!['chat', 'forum', 'feed', 'stream', 'voice'].includes(parts[3])) return fail('bad-alphabet');
  if (n.startsWith('s3rch:')) { const p = parsePrincipalId(owner); if (!p.ok) return p; }
  else {
    let valid = false;
    if (n === 'atproto') valid = /^did:plc:[a-z2-7]{24}$/.test(owner) || (owner.startsWith('did:web:') && didWeb(owner));
    if (n === 'farcaster') valid = /^[1-9][0-9]{0,19}$/.test(owner) && BigInt(owner) <= (1n << 64n) - 1n;
    if (n === 'nostr') valid = /^[0-9a-f]{64}$/.test(owner);
    if (n === 'activitypub') valid = webUri(owner, false, true);
    if (n === 'rss') valid = webUri(owner, true, false);
    if (!valid) return fail('bad-alphabet');
  }
  return ok(/** @type {SourceKey} */ (t.value));
}
/** @param {PrincipalId} p @returns {PrincipalKey} */
export const formatPrincipalKey = p => /** @type {PrincipalKey} */ ('p_' + hex(new Uint8Array([...unb64(p.slice(0, 43)), ...unb64(p.slice(44))])));
/** @param {Eip55} w @returns {PathKey} */
export const formatWalletKey = w => /** @type {PathKey} */ ('w_' + w.slice(2).toLowerCase());
/** @param {string} tag @param {string} domain @param {string[]} fields @returns {PathKey} */
const hashKey = (tag, domain, fields) => /** @type {PathKey} */ (tag + hex(sha256(lengthPrefixed([domain, ...fields]))));
/** @param {OidcCredential} c */
export const formatOidcKey = c => hashKey('k_', 'sociacl-oidc-v1', [c.iss, c.tenant, c.sub]);
/** @param {NetworkId} n */
export const formatNetworkKey = n => hashKey('n_', 'sociacl-network-v1', [n]);
/** @param {SourceKey} s */
export const formatSourcePathKey = s => hashKey('s_', 'sociacl-source-v1', [s]);
/** @param {ObjectId} o @returns {PathKey} */
export const objectKey = o => /** @type {PathKey} */ (/** @type {unknown} */ (o));
/** @param {string[]} parts @param {number} count @returns {Soul} */
function soul(parts, count) {
  const s = parts.join('/');
  if (s.split('/').length !== count) throw Error('invalid soul segment count');
  return /** @type {Soul} */ (s);
}
/** @param {Collection} c @param {ObjectId} o */
export const objectSoul = (c, o) => {
  if (!['items', 'rooms', 'users-legacy'].includes(c)) throw Error('invalid collection');
  return soul(['s3rch', c, objectKey(o)], 3);
};
/** @param {PrincipalId} p @returns {Soul} */
export const userSoul = p => soul(['~' + p], 1);
/** @param {PrincipalId} p */
export const aclSoul = p => soul(['s3rch', 'acl', formatPrincipalKey(p)], 3);
/** @param {PrincipalId} owner @param {ObjectId} object @param {PrincipalId} accessor */
export const grantSoul = (owner, object, accessor) => soul(['s3rch', 'acl', formatPrincipalKey(owner), objectKey(object), formatPrincipalKey(accessor)], 5);
/** @param {PrincipalId} owner @param {ObjectId} object @param {PrincipalId} accessor */
export const postSoul = (owner, object, accessor) => soul(['s3rch', 'acl', formatPrincipalKey(owner), 'post', objectKey(object), formatPrincipalKey(accessor)], 6);
/** @param {PrincipalId} owner @param {MembershipPredicate} predicate @param {ObjectId} set @param {PrincipalId} accessor */
export function membershipSoul(owner, predicate, set, accessor) {
  if (predicate !== 'same-group' && predicate !== 'named-circle') throw Error('invalid membership predicate');
  return soul(['s3rch', 'acl', formatPrincipalKey(owner), 'member', predicate, objectKey(set), formatPrincipalKey(accessor)], 7);
}
/** @param {PrincipalId} owner @param {ObjectId} object */
export const objectSetSoul = (owner, object) => soul(['s3rch', 'acl', formatPrincipalKey(owner), 'objset', objectKey(object)], 5);
/** @param {unknown} x @returns {Result<PrincipalId>} */
function keyPrincipal(x) {
  const t = text(x, 160); if (!t.ok) return t;
  if (!/^p_[0-9a-f]{128}$/.test(t.value)) return fail('bad-alphabet');
  const bytes = unhex(t.value.slice(2));
  return parsePrincipalId(b64(bytes.slice(0, 32)) + '.' + b64(bytes.slice(32)));
}
/** @param {unknown} x @returns {Result<ParsedSoul>} */
export function parseSoul(x) {
  const t = text(x, 512); if (!t.ok) return t;
  if (t.value.startsWith('~')) {
    const p = parsePrincipalId(t.value.slice(1)); return p.ok ? ok({ template: 'user', ids: [p.value] }) : p;
  }
  const a = t.value.split('/');
  if (a[0] !== 's3rch') return fail('bad-template');
  if (a.length === 3 && ['items', 'rooms', 'users-legacy'].includes(a[1])) {
    const o = parseObjectId(a[2]); return o.ok ? ok({ template: 'object', ids: [a[1], o.value] }) : o;
  }
  if (a[1] === 'acl' && a.length === 5 && a[3] === 'objset') {
    const owner = keyPrincipal(a[2]); if (!owner.ok) return owner;
    const object = parseObjectId(a[4]); if (!object.ok) return object;
    return ok({ template: 'objset', ids: [owner.value, object.value] });
  }
  if (a[1] === 'acl' && a.length === 7 && a[3] === 'member') {
    if (a[4] !== 'same-group' && a[4] !== 'named-circle') return fail('bad-template');
    const owner = keyPrincipal(a[2]); if (!owner.ok) return owner;
    const set = parseObjectId(a[5]); if (!set.ok) return set;
    const accessor = keyPrincipal(a[6]); if (!accessor.ok) return accessor;
    return ok({ template: 'membership', ids: [owner.value, a[4], set.value, accessor.value] });
  }
  if (a[1] !== 'acl' || ![3, 5, 6].includes(a.length) || (a.length === 6 && a[3] !== 'post')) return fail('bad-template');
  const p = keyPrincipal(a[2]); if (!p.ok) return p;
  if (a.length === 3) return ok({ template: 'acl', ids: [p.value] });
  const o = parseObjectId(a[a.length - 2]); if (!o.ok) return o;
  const acc = keyPrincipal(a[a.length - 1]); if (!acc.ok) return acc;
  return ok({ template: a.length === 5 ? 'grant' : 'post', ids: [p.value, o.value, acc.value] });
}
/** @param {string} kind @param {(n: number) => Uint8Array} [rng] @returns {Result<MintedObjectId>} */
export function mintObjectId(kind, rng = n => crypto.getRandomValues(new Uint8Array(n))) {
  const k = text(kind, 16); if (!k.ok) return k;
  if (!/^[a-z][a-z0-9]{1,15}$/.test(k.value)) return fail('bad-alphabet');
  if (['claim', 'ext', 'post', 'member', 'objset'].includes(k.value)) return fail('reserved-kind');
  try {
    const bytes = rng(16);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 16) return fail('rng-failure');
    return ok(/** @type {MintedObjectId} */ (kind + '_' + hex(bytes)));
  } catch { return fail('rng-failure'); }
}
/** @param {string} claimText @returns {Result<ObjectId>} */
export function deriveClaimId(claimText) {
  const t = text(claimText, 2048); if (!t.ok) return t;
  return ok(/** @type {ObjectId} */ (/** @type {unknown} */ (hashKey('claim_', 'sociacl-claim-v1', [t.value]))));
}
/** @param {SourceKey} source @param {string} providerItemId @returns {Result<ObjectId>} */
export function deriveExternalId(source, providerItemId) {
  const t = text(providerItemId, 2048); if (!t.ok) return t;
  return ok(/** @type {ObjectId} */ (/** @type {unknown} */ (hashKey('ext_', 'sociacl-ext-v1', [source, t.value]))));
}

/** @param {unknown} x @returns {Result<PrincipalKey>} */
export function parsePrincipalKey(x) {
  const p = keyPrincipal(x); return p.ok ? ok(formatPrincipalKey(p.value)) : p;
}
/** @param {unknown} x @returns {Result<PathKey>} */
export function parsePathKey(x) {
  const t = text(x, 160); if (!t.ok) return t;
  if (t.value.startsWith('p_')) { const p = parsePrincipalKey(x); return p.ok ? ok(/** @type {PathKey} */ (/** @type {unknown} */ (p.value))) : p; }
  if (/^(?:w_[0-9a-f]{40}|[kns]_[0-9a-f]{64})$/.test(t.value)) return ok(/** @type {PathKey} */ (t.value));
  const o = parseObjectId(x); return o.ok ? ok(objectKey(o.value)) : o;
}
/** @param {Uint8Array} bytes @returns {Result<PrincipalId>} */
export function principalFromSec1(bytes) {
  try { const raw = p256.Point.fromBytes(bytes).toBytes(false); return parsePrincipalId(b64(raw.slice(1,33)) + '.' + b64(raw.slice(33))); }
  catch { return fail('not-on-curve'); }
}
