import { grantSoul, parsePrincipalId, parseObjectId, mintObjectId } from '../src/index.js';
// @ts-expect-error Unparsed strings cannot cross the core boundary.
grantSoul('a', 'b', 'c');
const p = parsePrincipalId('untrusted');
const o = parseObjectId('untrusted');
if (p.ok && o.ok) grantSoul(p.value, o.value, p.value);
const minted = mintObjectId('room');
if (p.ok && minted.ok) grantSoul(p.value, minted.value, p.value);
import { verifyWalletLink, verifyRotate, resolveWalletLink, type ResolutionContext } from '../src/index.js';
declare const ctx: ResolutionContext;
// @ts-expect-error Wallet verification must receive an authenticated signing key.
verifyWalletLink({},ctx.jwks,ctx.policy,ctx.now);
// @ts-expect-error Resolution context must include an authenticated history resolver.
const missingHistory: ResolutionContext = {jwks:ctx.jwks,links:ctx.links,now:ctx.now,policy:ctx.policy};
