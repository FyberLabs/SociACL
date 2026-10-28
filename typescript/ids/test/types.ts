import { grantSoul, membershipSoul, objectSetSoul, parsePrincipalId, parseObjectId, mintObjectId } from '../src/index.js';
// @ts-expect-error Unparsed strings cannot cross the core boundary.
grantSoul('a', 'b', 'c');
// @ts-expect-error Unparsed strings cannot cross the core boundary.
membershipSoul('a', 'same-group', 'b', 'c');
// @ts-expect-error Unparsed strings cannot cross the core boundary.
objectSetSoul('a', 'b', 'same-group', 'c');
const p = parsePrincipalId('untrusted');
const o = parseObjectId('untrusted');
if (p.ok && o.ok) {
  grantSoul(p.value, o.value, p.value);
  // @ts-expect-error Membership predicates are only same-group and named-circle.
  membershipSoul(p.value, 'nope', o.value, p.value);
  objectSetSoul(p.value, o.value, 'same-group', o.value);
  // @ts-expect-error Object-set predicates are only same-group and named-circle.
  objectSetSoul(p.value, o.value, 'nope', o.value);
}
const minted = p.ok ? mintObjectId('room', p.value) : p;
if (p.ok && minted.ok) grantSoul(p.value, minted.value, p.value);
import { verifyWalletLink, verifyRotate, resolveWalletLink, type ResolutionContext } from '../src/index.js';
declare const ctx: ResolutionContext;
// @ts-expect-error Wallet verification must receive an authenticated signing key.
verifyWalletLink({},ctx.jwks,ctx.policy,ctx.now);
// @ts-expect-error Resolution context must include an authenticated history resolver.
const missingHistory: ResolutionContext = {jwks:ctx.jwks,links:ctx.links,now:ctx.now,policy:ctx.policy};

import { verifyWitnessPolicyEnvelope, type WitnessPolicy } from '../src/index.js';
const policyResult = verifyWitnessPolicyEnvelope('{}', 'independently pinned root', 'deployment', 1700000000);
if (policyResult.ok) {
  const policy: WitnessPolicy = policyResult.value;
  // @ts-expect-error Authenticated output is immutable.
  policy.revision = 0;
}

import { advanceWitnessPolicy, type WitnessPolicyState } from '../src/index.js';
const transition = advanceWitnessPolicy('{}', null, '', 'deployment', 7, 1700000000);
if (transition.ok) {
  const saved: WitnessPolicyState = transition.value;
  // @ts-expect-error A consumer cannot erase retained removal history.
  saved.history[0].removed = false;
}
