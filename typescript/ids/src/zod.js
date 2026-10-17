import { z } from 'zod';
import * as ids from './index.js';
/** @template T @param {(x: unknown) => import('./types.js').Result<T>} parse */
function schema(parse) {
  return z.unknown().transform((x, ctx) => {
    const r = parse(x);
    if (r.ok) return r.value;
    ctx.addIssue({ code: 'custom', message: r.reason });
    return z.NEVER;
  });
}
export const principalId = schema(ids.parsePrincipalId);
export const eip55 = schema(ids.parseEip55);
export const walletInput = schema(ids.parseWalletInput);
export const tenantId = schema(ids.parseTenantId);
export const oidcCredential = schema(ids.parseOidcCredential);
export const objectId = schema(ids.parseObjectId);
export const networkId = schema(ids.parseNetworkId);
export const sourceKey = schema(ids.parseSourceKey);
export const soul = schema(ids.parseSoul);
