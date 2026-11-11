import { sha256 } from '@noble/hashes/sha2.js';
import { parsePrincipalId } from './ids.js';
import { verifySignedAt, resolveCurrentKey, historyState, verifyKeySignature } from './records.js';
import { data, integer, text, lp, hex, ok, fail } from './util.js';
/** @import {PrincipalId, Result, ResolutionContext} from './types.js' */
/** @typedef {Readonly<{v: 1, principal: PrincipalId, agent: PrincipalId, audience: string, scopes: readonly string[], nonce: string, issuedAt: number, expiresAt: number, sig: string}>} AgentDelegation */
/** @typedef {Readonly<{v: 1, principal: PrincipalId, delegationId: string, issuedAt: number, sig: string}>} AgentRevocation */
export const AGENT_DELEGATION_DOMAIN = 'sociacl-agent-delegation-v1';
export const AGENT_REVOCATION_DOMAIN = 'sociacl-agent-revocation-v1';
export const MAX_AGENT_DELEGATION_SECONDS = 86400;
/** Exact, sorted, unique scopes. No wildcard or implicit parent scope.
 * @param {unknown} input @returns {Result<readonly string[]>} */
function scopes(input) {
  try {
    if (!Array.isArray(input)) return fail('bad-record');
    const ds = /** @type {Record<string, PropertyDescriptor>} */ (/** @type {unknown} */ (Object.getOwnPropertyDescriptors(input))), n = ds.length.value;
    if (!integer(n) || n < 1 || n > 32 || Object.keys(ds).length !== n + 1) return fail('bad-record');
    const values = Array.from({ length: n }, (_, i) => ds[String(i)]?.value);
    if (!values.every((s, i) => typeof s === 'string' && /^[a-z][a-z0-9:-]{0,63}$/.test(s) && (!i || values[i - 1] < s))) return fail('bad-record');
    return ok(Object.freeze(values));
  } catch { return fail('bad-record'); }
}
/** @param {unknown} value */
function audience(value) {
  const t = text(value, 2048); if (!t.ok) return t;
  try { const u = new URL(t.value); return u.protocol === 'https:' && u.origin === t.value ? t : fail('bad-record'); }
  catch { return fail('bad-record'); }
}
/** Signing bytes for an already parsed delegation; all authority fields are bound.
 * @param {Omit<AgentDelegation, 'sig'>} r */
export function agentDelegationBytes(r) {
  return lp([AGENT_DELEGATION_DOMAIN, String(r.v), r.principal, r.agent, r.audience,
    String(r.scopes.length), ...r.scopes, r.nonce, String(r.issuedAt), String(r.expiresAt)]);
}
/** @param {unknown} input @returns {Result<{delegation: AgentDelegation, bytes: Uint8Array, id: string}>} */
export function parseAgentDelegation(input) {
  const d = data(input); if (!d.ok) return d;
  const r = d.value;
  if (Object.keys(r).sort().join() !== 'agent,audience,expiresAt,issuedAt,nonce,principal,scopes,sig,v' || r.v !== 1) return fail('bad-record');
  const principal = parsePrincipalId(r.principal), agent = parsePrincipalId(r.agent);
  if (!principal.ok) return principal; if (!agent.ok) return agent;
  if (principal.value === agent.value) return fail('bad-record');
  const aud = audience(r.audience), scope = scopes(r.scopes), sig = text(r.sig, 128);
  if (!aud.ok) return aud; if (!scope.ok) return scope; if (!sig.ok) return sig;
  if (typeof r.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(r.nonce) || !integer(r.issuedAt) || !integer(r.expiresAt)) return fail('bad-record');
  const issuedAt = /** @type {number} */ (r.issuedAt), expiresAt = /** @type {number} */ (r.expiresAt);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_AGENT_DELEGATION_SECONDS) return fail('bad-record');
  const delegation = Object.freeze({ v: /** @type {const} */ (1), principal: principal.value, agent: agent.value,
    audience: aud.value, scopes: scope.value, nonce: r.nonce, issuedAt, expiresAt, sig: sig.value });
  const bytes = agentDelegationBytes(delegation);
  return ok(Object.freeze({ delegation, bytes, id: hex(sha256(bytes)) }));
}
/** @param {Omit<AgentRevocation, 'sig'>} r */
export function agentRevocationBytes(r) {
  return lp([AGENT_REVOCATION_DOMAIN, String(r.v), r.principal, r.delegationId, String(r.issuedAt)]);
}
/** @param {unknown} input @returns {Result<{revocation: AgentRevocation, bytes: Uint8Array}>} */
export function parseAgentRevocation(input) {
  const d = data(input); if (!d.ok) return d;
  const r = d.value;
  if (Object.keys(r).sort().join() !== 'delegationId,issuedAt,principal,sig,v' || r.v !== 1 || !integer(r.issuedAt) ||
      typeof r.delegationId !== 'string' || !/^[0-9a-f]{64}$/.test(r.delegationId)) return fail('bad-record');
  const principal = parsePrincipalId(r.principal), sig = text(r.sig, 128);
  if (!principal.ok) return principal; if (!sig.ok) return sig;
  const revocation = Object.freeze({ v: /** @type {const} */ (1), principal: principal.value, delegationId: r.delegationId,
    issuedAt: /** @type {number} */ (r.issuedAt), sig: sig.value });
  return ok(Object.freeze({ revocation, bytes: agentRevocationBytes(revocation) }));
}
/** Verify present delegation authority against a complete, fresh owner revocation
 * snapshot. Missing/unreadable snapshots must not be replaced with []. Any bad
 * row denies. Rotation invalidates old-key delegations. This does not prove agent
 * possession, mint a JWT, or confer object access: the issuer must challenge the
 * agent key and services must still Check current object permissions. Re-evaluate
 * before token use; a cached JWT alone cannot establish non-revocation.
 * @param {unknown} input @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @param {{audience: string, agent: PrincipalId, scopes: readonly string[], revocations: readonly unknown[]}} request
 * @returns {Result<{delegation: AgentDelegation, id: string}>} */
export function verifyAgentDelegation(input, rotations, ctx, request) {
  const parsed = parseAgentDelegation(input); if (!parsed.ok) return parsed;
  if (!ctx || !integer(ctx.now) || !request) return fail('bad-record');
  const { delegation: r, bytes, id } = parsed.value;
  const wanted = scopes(request.scopes); if (!wanted.ok) return wanted;
  if (request.agent !== r.agent || request.audience !== r.audience || !wanted.value.every(s => r.scopes.includes(s))) return fail('bad-record');
  if (ctx.now < r.issuedAt) return fail('future-record');
  if (ctx.now >= r.expiresAt) return fail('expired');
  const verified = verifySignedAt(r.principal, rotations, ctx, bytes, r.sig, r.issuedAt);
  if (!verified.ok) return verified;
  if (!Array.isArray(request.revocations) || request.revocations.length > 1024) return fail('missing-history');
  for (const raw of request.revocations) {
    const p = parseAgentRevocation(raw); if (!p.ok) return p;
    const rev = p.value.revocation;
    if (rev.principal !== r.principal) return fail('owner-mismatch');
    if (rev.issuedAt > ctx.now) return fail('future-record');
    const proof = verifySignedAt(rev.principal, rotations, ctx, p.value.bytes, rev.sig, rev.issuedAt);
    if (!proof.ok) {
      // Retain authenticated historical cancellations without granting a retired
      // key authority over a new delegation. Only unrelated IDs take this path.
      if (proof.reason !== 'unwitnessed-retired-key' || rev.delegationId === id) return proof;
      const account = resolveCurrentKey(r.principal, rotations, ctx);
      if (!account.ok) return account;
      const historical = historyState(r.principal, account.value.rotations, rev.issuedAt, ctx.now);
      const signature = verifyKeySignature(historical.key, rev.sig, p.value.bytes);
      if (!signature.ok) return signature;
    }
    if (rev.delegationId === id) return fail('revoked-link');
  }
  return ok(Object.freeze({ delegation: r, id }));
}
