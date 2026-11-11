/** Signing bytes for an already parsed delegation; all authority fields are bound.
 * @param {Omit<AgentDelegation, 'sig'>} r */
export function agentDelegationBytes(r: Omit<AgentDelegation, "sig">): Uint8Array<ArrayBuffer>;
/** @param {unknown} input @returns {Result<{delegation: AgentDelegation, bytes: Uint8Array, id: string}>} */
export function parseAgentDelegation(input: unknown): Result<{
    delegation: AgentDelegation;
    bytes: Uint8Array;
    id: string;
}>;
/** @param {Omit<AgentRevocation, 'sig'>} r */
export function agentRevocationBytes(r: Omit<AgentRevocation, "sig">): Uint8Array<ArrayBuffer>;
/** @param {unknown} input @returns {Result<{revocation: AgentRevocation, bytes: Uint8Array}>} */
export function parseAgentRevocation(input: unknown): Result<{
    revocation: AgentRevocation;
    bytes: Uint8Array;
}>;
/** Verify present delegation authority against a complete, fresh owner revocation
 * snapshot. Missing/unreadable snapshots must not be replaced with []. Any bad
 * row denies. Rotation invalidates old-key delegations. This does not prove agent
 * possession, mint a JWT, or confer object access: the issuer must challenge the
 * agent key and services must still Check current object permissions. Re-evaluate
 * before token use; a cached JWT alone cannot establish non-revocation.
 * @param {unknown} input @param {readonly unknown[]} rotations @param {ResolutionContext} ctx
 * @param {{audience: string, agent: PrincipalId, scopes: readonly string[], revocations: readonly unknown[]}} request
 * @returns {Result<{delegation: AgentDelegation, id: string}>} */
export function verifyAgentDelegation(input: unknown, rotations: readonly unknown[], ctx: ResolutionContext, request: {
    audience: string;
    agent: PrincipalId;
    scopes: readonly string[];
    revocations: readonly unknown[];
}): Result<{
    delegation: AgentDelegation;
    id: string;
}>;
/** @import {PrincipalId, Result, ResolutionContext} from './types.js' */
/** @typedef {Readonly<{v: 1, principal: PrincipalId, agent: PrincipalId, audience: string, scopes: readonly string[], nonce: string, issuedAt: number, expiresAt: number, sig: string}>} AgentDelegation */
/** @typedef {Readonly<{v: 1, principal: PrincipalId, delegationId: string, issuedAt: number, sig: string}>} AgentRevocation */
export const AGENT_DELEGATION_DOMAIN: "sociacl-agent-delegation-v1";
export const AGENT_REVOCATION_DOMAIN: "sociacl-agent-revocation-v1";
export const MAX_AGENT_DELEGATION_SECONDS: 86400;
export type AgentDelegation = Readonly<{
    v: 1;
    principal: PrincipalId;
    agent: PrincipalId;
    audience: string;
    scopes: readonly string[];
    nonce: string;
    issuedAt: number;
    expiresAt: number;
    sig: string;
}>;
export type AgentRevocation = Readonly<{
    v: 1;
    principal: PrincipalId;
    delegationId: string;
    issuedAt: number;
    sig: string;
}>;
import type { Result } from './types.js';
import type { ResolutionContext } from './types.js';
import type { PrincipalId } from './types.js';
