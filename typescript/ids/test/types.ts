import { grantSoul, membershipSoul, objectSetSoul, parsePrincipalId, parseObjectId, mintObjectId } from '../src/index.js';
// @ts-expect-error Unparsed strings cannot cross the core boundary.
grantSoul('a', 'b', 'c');
// @ts-expect-error Unparsed strings cannot cross the core boundary.
membershipSoul('a', 'same-group', 'b', 'c');
// @ts-expect-error Unparsed strings cannot cross the core boundary.
objectSetSoul('a', 'b');
const p = parsePrincipalId('untrusted');
const o = parseObjectId('untrusted');
if (p.ok && o.ok) {
  grantSoul(p.value, o.value, p.value);
  // @ts-expect-error Membership predicates are only same-group and named-circle.
  membershipSoul(p.value, 'nope', o.value, p.value);
}
const minted = p.ok ? mintObjectId('room', p.value) : p;
if (p.ok && minted.ok) grantSoul(p.value, minted.value, p.value);
import { verifyWalletLink, verifyRotate, resolveWalletLink, type ResolutionContext } from '../src/index.js';
declare const ctx: ResolutionContext;
// @ts-expect-error Wallet verification must receive an authenticated signing key.
verifyWalletLink({},ctx.jwks,ctx.policy,ctx.now);
// @ts-expect-error Resolution context must include an authenticated history resolver.
const missingHistory: ResolutionContext = {jwks:ctx.jwks,links:ctx.links,now:ctx.now,policy:ctx.policy};
