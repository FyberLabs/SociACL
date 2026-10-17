import { grantSoul, parsePrincipalId, parseObjectId, mintObjectId } from '../src/index.js';
// @ts-expect-error Unparsed strings cannot cross the core boundary.
grantSoul('a', 'b', 'c');
const p = parsePrincipalId('untrusted');
const o = parseObjectId('untrusted');
if (p.ok && o.ok) grantSoul(p.value, o.value, p.value);
const minted = mintObjectId('room');
if (p.ok && minted.ok) grantSoul(p.value, minted.value, p.value);
