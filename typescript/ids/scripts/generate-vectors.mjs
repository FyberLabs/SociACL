// Regenerate only as a reviewed grammar/signing-domain change. Keys are public test fixtures.
import { mkdirSync, writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import * as ids from '../src/index.js';
import { b64, hex, utf8, checksum, pct } from './vector-util.mjs';
const val = r => { if (!r.ok) throw Error(r.reason); return r.value; };
const secret = n => { const b = new Uint8Array(32); b[31] = n; return b; };
const principal = n => { const b = p256.getPublicKey(secret(n), false); return val(ids.parsePrincipalId(b64(b.slice(1, 33)) + '.' + b64(b.slice(33)))); };
const p = principal(1), p2 = principal(2), p3 = principal(3);
const wallet = val(ids.parseWalletInput('0x' + hex(keccak_256(secp256k1.getPublicKey(secret(4), false).slice(1))).slice(-40)));
const tenant = val(ids.parseTenantId('01234567-89ab-cdef-0123-456789abcdef'));
const obj = val(ids.parseObjectId('room_' + '01'.repeat(16)));
const network = val(ids.parseNetworkId('s3rch:https://s3r.ch:443;key=' + '12'.repeat(32)));
const source = val(ids.parseSourceKey(`sr1:${pct(network)}/${pct(p)}/${obj}/chat`));
const cred = { iss: 'https://id.fyberlabs.com/realms/test', tenant, sub: 'Case-Sensitive/Subject' };
const at = 1700000000, now = at + 60;
const date = n => new Date(n * 1000).toISOString().replace('.000Z', 'Z');
const bytes = r => val(ids.signingBytes(r));
const keySig = (r, n = 1) => b64(p256.sign(bytes(r), secret(n), { lowS: false }));
const jwkPrincipal = principal(5);
const jwks = { keys: [{ kty: 'EC', crv: 'P-256', kid: 'fixture-1', x: jwkPrincipal.slice(0, 43), y: jwkPrincipal.slice(44), alg: 'ES256', use: 'sig', key_ops: ['verify'] }] };
const jwsRaw = (header, claims) => {
  const body = b64(utf8.encode(header)) + '.' + b64(utf8.encode(claims));
  return body + '.' + b64(p256.sign(utf8.encode(body), secret(5), { lowS: false }));
};
const jws = c => jwsRaw(JSON.stringify({ alg: 'ES256', kid: 'fixture-1', typ: 'JWT' }), JSON.stringify(c));
const signMessage = message => {
  const raw = utf8.encode(message);
  const digest = keccak_256(new Uint8Array([...utf8.encode('\x19Ethereum Signed Message:\n' + raw.length), ...raw]));
  const sig = secp256k1.sign(digest, secret(4), { prehash: false, format: 'recovered' });
  return { message, signature: '0x' + hex(new Uint8Array([...sig.slice(1), sig[0] + 27])) };
};
const siwe = (r, options = '') => signMessage(`s3r.ch wants you to sign in with your Ethereum account:\n${wallet}\n\nSociACL link: ${hex(sha256(bytes(r)))}\n\nURI: https://s3r.ch/identity/link\nVersion: 1\nChain ID: 1\nNonce: ${r.nonce ?? 'rotation1234'}\nIssued At: ${date(r.issuedAt)}${options}`);
function walletLink(principal = p, issuedAt = at, n = 1) {
  const r = { v: 1, kind: 'wallet', principal, address: wallet, issuedAt, nonce: 'fixtureNonce123' };
  return { ...r, keySig: keySig(r, n), siwe: siwe(r) };
}
const w = walletLink(), wid = val(ids.linkId(w));
const unsignedOidc = { v: 1, kind: 'oidc', principal: p, cred, issuedAt: at, nonce: 'fixtureNonce456' };
const oc = { typ: 'sociacl-oidc-attest-v1', ...cred, principal: p, iat: at, exp: at + 600, nonce: unsignedOidc.nonce };
const oidc = { ...unsignedOidc, keySig: keySig(unsignedOidc), attest: jws(oc) };
const rotation = (kind = 'wallet', next = p2, n = 2, seq = 1, prev = p, issuedAt = at + 30) => {
  const r = { v: 1, kind: 'rotate', principal: p, seq, prevKey: prev, nextKey: next, issuedAt };
  return { ...r, nextSig: keySig(r, n), authorizer: kind === 'wallet' ? { kind, link: wid, siwe: siwe(r) } : { kind }, attest: jws({ typ: 'sociacl-rotate-attest-v1', principal: p, nextKey: next, seq, iat: issuedAt, exp: issuedAt + 600, auth: kind }) };
};
const rot = rotation(), rotOidc = rotation('oidc-fresh-login'), fork = rotation('oidc-fresh-login', p3, 3);
const rev = { v: 1, kind: 'revoke', principal: p, linkId: wid, issuedAt: at + 20 }; rev.keySig = keySig(rev);
const rev2 = { ...rev, issuedAt: at + 50 }; rev2.keySig = keySig(rev2, 2);
const families = new Map();
const family = name => { if (!families.has(name)) families.set(name, { v: 1, family: name, accept: [], reject: [] }); return families.get(name); };
const accept = (f, name, input, canonical = input, extra = {}) => family(f).accept.push({ name, input, canonical, ...extra });
const reject = (f, name, input, reason, extra = {}) => family(f).reject.push({ name, input, reason, ...extra });
accept('principal', 'genesis-1', p, p, { pathKey: ids.formatPrincipalKey(p) });
accept('principal', 'genesis-2', p2, p2, { pathKey: ids.formatPrincipalKey(p2) });
for (const n of [86,88]) reject('principal', `length-${n}`, n === 86 ? p.slice(0, -1) : p + 'A', 'bad-length');
reject('principal', 'missing-dot', p.replace('.', 'A'), 'bad-alphabet');
reject('principal', 'two-dots', '.' + p.slice(1), 'bad-alphabet');
reject('principal', 'padding', '=' + p.slice(1), 'bad-alphabet');
reject('principal', 'last-bits', p.slice(0, -1) + 'B', 'non-canonical');
reject('principal', 'standard-plus', '+' + p.slice(1), 'bad-alphabet');
reject('principal', 'standard-slash', '/' + p.slice(1), 'bad-alphabet');
reject('principal', 'off-curve', 'A'.repeat(43) + '.' + 'A'.repeat(43), 'not-on-curve');
for (const [name, input, reason] of [
  ['gun-chain-1', "0xattacker.get('s3rch').get('users').get('0xvictim')", 'gun-chain'],
  ['gun-chain-2', "gun.get('s3rch').get('users').get('0xbob')", 'gun-chain'],
  ['gun-chain-space', "0xattacker.get ('s3rch')", 'gun-chain'],
  ['gun-chain-bracket', "0xattacker['get']('s3rch')", 'gun-chain'],
  ['gun-chain-double', 'attacker["get"]("s3rch")', 'gun-chain'],
  ['gun-chain-escape', 'x\\u002eget(', 'gun-chain'],
  ['nul', 'a\u0000b', 'control-char'], ['c1', '\u0085x', 'control-char'],
  ['bom', '\ufeffx', 'invisible-char'], ['zero-width', 'x\u200b', 'invisible-char'],
  ['line-separator', '\u2028', 'invisible-char'], ['unpaired', '\ud800', 'unpaired-surrogate'],
  ['leading-space', ' ' + p, 'whitespace'], ['trailing-tab', p + '\t', 'control-char'],
  ['nbsp', '\u00a0', 'bad-alphabet'], ['fullwidth-dot', 'room．alpha', 'bad-alphabet'],
  ['division-slash', 'room∕alpha', 'bad-alphabet'], ['fullwidth-slash', 'room／alpha', 'bad-alphabet'],
  ['cyrillic-hex', 'room_' + '0'.repeat(31) + 'а', 'bad-alphabet'],
]) reject('object', name, input, reason);
for (const input of ['room.alpha','room/alpha','room_alpha','room~1alpha','~0','%2F','a%2Eb','0xalice','doc','0xbob/x','0xalice/doc','0xbob','x']) reject('object', 'invalid-' + input, input, 'bad-alphabet');
for (const input of ['../meta','s3rch/meta','s3rch/acl/x','s3rch/users/0xbob']) reject('principal', 'path-' + input, input, 'bad-length');
for (const f of ['principal','wallet','tenant','object','network','source-key','soul']) for (const [name, input] of [['null',null],['number',42],['object',{ toString: 'no coercion' }],['array',[]],['boolean',true]]) reject(f,name,input,'not-string');
accept('wallet','checksum',wallet,wallet,{pathKey:ids.formatWalletKey(wallet)});
accept('wallet','ui-lower',wallet.toLowerCase(),wallet,{parser:'wallet-input',pathKey:ids.formatWalletKey(wallet)});
accept('wallet','ui-upper','0x'+wallet.slice(2).toUpperCase(),wallet,{parser:'wallet-input',pathKey:ids.formatWalletKey(wallet)});
reject('wallet','stored-lower',wallet.toLowerCase(),'bad-checksum');
reject('wallet','wrong-mixed', wallet.replace(/[a-f]/,c=>c.toUpperCase()),'bad-checksum');
reject('wallet','fullwidth-zero',wallet.replace('0x','０x'),'bad-alphabet');
accept('tenant','tenant',tenant); reject('tenant','uppercase',tenant.toUpperCase(),'non-canonical');
accept('oidc','tenant-scoped',cred,cred,{pathKey:ids.formatOidcKey(cred)});
accept('oidc','other-tenant',{...cred,tenant:'11234567-89ab-cdef-0123-456789abcdef'}, {...cred,tenant:'11234567-89ab-cdef-0123-456789abcdef'}, {pathKey:ids.formatOidcKey({...cred,tenant:val(ids.parseTenantId('11234567-89ab-cdef-0123-456789abcdef'))})});
reject('oidc','missing-tenant',{iss:cred.iss,sub:cred.sub},'not-string');
reject('oidc','subject-unicode',{...cred,sub:'é'},'bad-alphabet');
reject('oidc','issuer-http',{...cred,iss:'http://s3r.ch'},'bad-alphabet');
reject('oidc','extra-field',{...cred,alias:'wrong'},'bad-record');
accept('object','native',obj,obj,{pathKey:obj});
accept('object','claim', 'ens:alice.eth', val(ids.deriveClaimId('ens:alice.eth')), { operation:'claim', pathKey:val(ids.deriveClaimId('ens:alice.eth')) });
accept('object','external', {source,providerItemId:'rss3:act/1#x'}, val(ids.deriveExternalId(source,'rss3:act/1#x')), {operation:'external'});
for (const kind of ['room','chat','forum-msg','forum-group','bot','forum']) {
  const suffix = ['room','chat','forum-msg'].includes(kind) ? ':123456789012:abcd' : ['forum-group','bot'].includes(kind) ? ':abcd' : '';
  const legacy = `s3rch:${kind}:${wallet}${suffix}`; accept('object', 'legacy-'+kind,legacy,legacy,{pathKey:legacy});
}
reject('object','legacy-13-digit',`s3rch:room:${wallet}:1700000000000:abcd`,'bad-alphabet');
reject('object','uppercase-hex','room_'+'AB'.repeat(16),'non-canonical');
reject('object','reserved-kind','claim_'+'01'.repeat(16),'reserved-kind');
accept('object','deterministic-mint',{kind:'room',bytes:Array(16).fill(7)},'room_'+'07'.repeat(16),{operation:'mint'});
for (const n of ['atproto','farcaster','nostr','activitypub','rss',network]) accept('network',n,n,n,{pathKey:ids.formatNetworkKey(val(ids.parseNetworkId(n)))});
for (const [label,host] of [['ip','127.0.0.1'],['hex-ip','0x7f.0.0.1'],['private','box.local'],['uppercase','S3R.CH'],['trailing-dot','s3r.ch.']]) reject('network',label,`s3rch:https://${host}:443;key=${'12'.repeat(32)}`,'bad-host');
for (const port of ['0','65536','0443']) reject('network','port-'+port,network.replace(':443;',':'+port+';'),'bad-port');
accept('source-key','native-owner',source,source,{pathKey:ids.formatSourcePathKey(source)});
const refs = [ ['atproto','did:plc:'+'a'.repeat(24)],['atproto','did:web:s3r.ch:user:alice'],['farcaster','12345'],['nostr','ab'.repeat(32)],['activitypub','https://s3r.ch/users/alice'],['rss','https://s3r.ch'] ];
for (const [i,[n,owner]] of refs.entries()) { const s=`sr1:${pct(n)}/${pct(owner)}/${pct('feed/α#1')}/feed`; accept('source-key','protocol-'+i,s,s,{pathKey:ids.formatSourcePathKey(val(ids.parseSourceKey(s)))}); }
reject('source-key','wallet-owner',source.replace(p,wallet),'bad-length');
reject('source-key','over-encoding',source.replace('sr1:s','sr1:%73'),'non-canonical');
reject('source-key','lowercase-escape',source.replace('%3A','%3a'),'non-canonical');
reject('source-key','encoded-control','sr1:rss/https%3A%2F%2Fs3r.ch/a%00b/feed','control-char');
reject('source-key','too-long','x'.repeat(8193),'too-long');
for (const [name,s] of [['object',ids.objectSoul('items',obj)],['room',ids.objectSoul('rooms',obj)],['legacy-user',ids.objectSoul('users-legacy',obj)],['user',ids.userSoul(p)],['acl',ids.aclSoul(p)],['grant',ids.grantSoul(p,obj,p2)],['distinct-grant',ids.grantSoul(p2,obj,p)],['post',ids.postSoul(p,obj,p2)]]) accept('soul',name,s,val(ids.parseSoul(s)));
reject('soul','extra-segment',ids.grantSoul(p,obj,p2)+'/x','bad-template');
reject('soul','unknown-collection','s3rch/users/'+obj,'bad-template');
const signing = [w,oidc,rot,rev];
for (const r of signing) accept('signing-bytes',r.kind,r,hex(bytes(r)),{linkId:val(ids.linkId(r))});
const context = { jwks, pinnedIss:[cred.iss], now, genesis:p, currentKey:p, links:[[wid,w]] };
family('records').context = context;
for (const [name, operation, input, extra] of [ ['wallet','wallet-link',w,{}],['oidc','oidc-link',oidc,{}],['wallet-rotate','rotate',rot,{}],['oidc-rotate','rotate',rotOidc,{}],['revoke','revoke',rev,{}], ['resolve','resolve',[rot],{}],['duplicate-rotation','resolve',[rot,rot],{}],['reordered-history','resolve',[rotation('oidc-fresh-login',p3,3,2,p2,at+40),rot],{}], ['wallet-lookup','wallet-resolve',[w],{address:wallet}],['newest-wallet-wins','wallet-resolve',[w,walletLink(p2,at+10,2)],{address:wallet}],['historical-revoke','revoke',rev2,{currentKey:p2}] ]) {
  const canonical = operation==='resolve' ? name==='reordered-history'?p3:p2 : name==='newest-wallet-wins'?p2:p;
  accept('records',name,input,canonical,{operation,...extra});
}
const options = siwe(w,`\nExpiration Time: ${date(at+600)}\nNot Before: ${date(at)}\nRequest ID: request%3A123\nResources:\n- https://s3r.ch/resource`);
accept('records','siwe-optionals',{...w,siwe:options},p,{operation:'wallet-link'});
const bad = (name,input,reason,operation='wallet-link',extra={})=>reject('records',name,input,reason,{operation,...extra});
bad('link-object-principal',{...w,principal:{toString:p}},'not-string');
bad('rotate-object-principal',{...rot,principal:{toString:p}},'not-string','rotate');
bad('fork',[rot,fork],'rotation-fork','resolve');
bad('revoked-recovery',[rot],'revoked-link','resolve',{revocations:[rev]});
bad('newest-wallet-revoked',[w],'revoked-link','wallet-resolve',{address:wallet,revocations:[rev]});
bad('duplicate-wallet-tie',[w,walletLink(p2,at,2)],'ambiguous-link','wallet-resolve',{address:wallet});
bad('wrong-current-key',rot,'bad-sequence','rotate',{currentKey:p3});
bad('sequence-gap',[rotation('oidc-fresh-login',p2,2,2)],'bad-sequence','resolve');
bad('future-link',{...w,issuedAt:now+1},'future-record');
bad('unsafe-time',{...w,issuedAt:9007199254740992},'bad-record');
bad('bad-key-sig',{...w,keySig:b64(new Uint8Array(64))},'bad-signature');
bad('bad-siwe-sig',{...w,siwe:{...w.siwe,signature:'0x'+'00'.repeat(65)}},'bad-signature');
bad('contract-wallet',{...w,siwe:{...w.siwe,signature:'0x1234'}},'unsupported-wallet');
bad('changed-statement',{...w,siwe:signMessage(w.siwe.message.replace('SociACL link:','Not a link:'))},'bad-signature');
bad('changed-nonce',{...w,siwe:signMessage(w.siwe.message.replace(w.nonce,'unboundNonce'))},'bad-signature');
bad('expired-siwe',{...w,siwe:siwe(w,`\nExpiration Time: ${date(at+10)}`)},'expired');
bad('bad-date',{...w,siwe:signMessage(w.siwe.message.replace(date(at),'2023-02-30T00:00:00Z'))},'bad-signature');
bad('untrusted-issuer',oidc,'untrusted-issuer','oidc-link',{pinnedIss:[]});
bad('expired-jws',{...oidc,attest:jws({...oc,exp:at+1})},'expired','oidc-link');
bad('wrong-tenant',{...oidc,attest:jws({...oc,tenant:'11234567-89ab-cdef-0123-456789abcdef'})},'bad-attestation','oidc-link');
bad('duplicate-jws-member',{...oidc,attest:jwsRaw('{"alg":"none","alg":"ES256","kid":"fixture-1"}',JSON.stringify(oc))},'bad-attestation','oidc-link');
bad('untrusted-alg',{...oidc,attest:jwsRaw('{"alg":"HS256","kid":"fixture-1"}',JSON.stringify(oc))},'bad-attestation','oidc-link');
bad('duplicate-kid',oidc,'bad-attestation','oidc-link',{jwks:{keys:[...jwks.keys,...jwks.keys]}});
bad('no-attestation',{...rot,attest:''},'empty','rotate');
bad('revoke-wrong-key',{...rev,keySig:keySig(rev,2)},'bad-signature','revoke');
// Both P-256 S encodings must verify and retain the same record identity.
const flipS = (encoded, order) => {
  const raw = Uint8Array.from(Buffer.from(encoded, 'base64url'));
  const scalar = BigInt('0x' + hex(raw.slice(32)));
  raw.set(Buffer.from((order - scalar).toString(16).padStart(64, '0'), 'hex'), 32);
  return b64(raw);
};
const pOrder = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const opposite = {...w,keySig:flipS(w.keySig,pOrder)};
accept('records','p256-opposite-s',opposite,p,{operation:'wallet-link'});
accept('signing-bytes','signature-independent-id',opposite,hex(bytes(w)),{linkId:wid});
const sigRaw=Buffer.from(w.siwe.signature.slice(2),'hex');
const kOrder=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const highS=Buffer.from((kOrder-BigInt('0x'+sigRaw.subarray(32,64).toString('hex'))).toString(16).padStart(64,'0'),'hex');
highS.copy(sigRaw,32); sigRaw[64]=27+((sigRaw[64]-27)^1);
accept('records','siwe-high-s',{...w,siwe:{...w.siwe,signature:'0x'+sigRaw.toString('hex')}},p,{operation:'wallet-link'});
const afterRotation=walletLink(p,at+35,2);
accept('records','link-after-rotation',afterRotation,p,{operation:'wallet-link',currentKey:p2});
bad('genesis-cannot-sign-new-link',afterRotation,'bad-signature','wallet-link');
const historicalOidc={...unsignedOidc,issuedAt:at+35};
const historicProof={...historicalOidc,keySig:keySig(historicalOidc,2),attest:jws({...oc,iat:at+35})};
accept('records','oidc-after-rotation',historicProof,p,{operation:'oidc-link',currentKey:p2});
const otherWallet=walletLink(p2,at+10,2);const otherId=val(ids.linkId(otherWallet));
const otherRevoke={v:1,kind:'revoke',principal:p2,linkId:otherId,issuedAt:at+20};otherRevoke.keySig=keySig(otherRevoke,2);
bad('no-resurrection-after-revoke',[w,otherWallet],'revoked-link','wallet-resolve',{address:wallet,revocations:[otherRevoke]});
bad('new-wallet-owner-blocks-old-recovery',[rot],'ambiguous-link','resolve',{links:[[wid,w],[otherId,otherWallet]]});
const earlyRevoke={...rev,issuedAt:at-1};earlyRevoke.keySig=keySig(earlyRevoke);
accept('records','revoke-before-link-does-not-remove-link',[rot],p2,{operation:'resolve',revocations:[earlyRevoke]});
const sameSecond={...rev,issuedAt:rot.issuedAt};sameSecond.keySig=keySig(sameSecond);
bad('same-second-revoke-precedes-rotation',[rot],'revoked-link','resolve',{revocations:[sameSecond]});
const invalidLink={...w,keySig:b64(new Uint8Array(64))};
bad('unverified-wallet-map',rot,'bad-signature','rotate',{links:[[wid,invalidLink]]});
bad('wrong-link-map-key',rot,'unknown-link','rotate',{links:[['00'.repeat(32),w]]});
bad('extra-record-field',{...w,unexpected:true},'bad-record');
bad('fractional-issued-at',{...w,issuedAt:at+.5},'bad-record');
for (const [suffix,msg] of [ ['extra-lines',w.siwe.message+'\nunknown'],['duplicate-expiry',siwe(w,`\nExpiration Time: ${date(at+600)}\nExpiration Time: ${date(at+700)}`).message],['invalid-percent-uri',w.siwe.message.replace('/identity/link','/%xx')]]) bad('siwe-'+suffix,{...w,siwe:signMessage(msg)},'bad-signature');
const root = new URL('../../../vectors/ids/',import.meta.url); mkdirSync(root,{recursive:true});
for(const [name,value] of families) writeFileSync(new URL(name+'.json',root),JSON.stringify(value,null,2).replace(/"issuedAt": 1700000000,/g, '"issuedAt": 1700000000.0,')+'\n');
writeFileSync(new URL('test-keys.json',new URL('../test/',import.meta.url)),JSON.stringify({p,p2,p3,wallet,tenant,obj,network,source,secretScalars:[1,2,3,4,5]},null,2)+'\n');
console.log(`Wrote ${families.size} vector families`);
