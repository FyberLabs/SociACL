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
  return { ...r, keySig: keySig(r, n), siwe: siwe(r), attest:jws({typ:'sociacl-wallet-attest-v1',principal,linkId:val(ids.linkId(r)),iat:issuedAt,exp:issuedAt+600}) };
}
const w = walletLink(), wid = val(ids.linkId(w));
const unsignedOidc = { v: 1, kind: 'oidc', principal: p, cred, issuedAt: at, nonce: 'fixtureNonce456' };
const oc = { typ: 'sociacl-oidc-attest-v1', ...cred, principal: p, iat: at, exp: at + 600, nonce: unsignedOidc.nonce };
const oidc = { ...unsignedOidc, keySig: keySig(unsignedOidc), attest: jws(oc) };
const oid=val(ids.linkId(oidc));
const rotation = (kind = 'wallet', next = p2, n = 2, seq = 1, prev = p, issuedAt = at + 30, retainedLinks = kind==='wallet'?[wid]:[oid]) => {
  const r = { v: 1, kind: 'rotate', principal: p, seq, prevKey: prev, nextKey: next, issuedAt, retainedLinks, authorizer:{kind,link:kind==='wallet'?wid:oid} };
  return { ...r, nextSig: keySig(r, n), authorizer: kind === 'wallet' ? {...r.authorizer,siwe:siwe(r)} : r.authorizer, attest: jws({ typ: 'sociacl-rotate-attest-v2', principal: p, nextKey: next, seq, iat: issuedAt, exp: issuedAt + 600, auth: kind, linkId:r.authorizer.link, retainedLinks }) };
};
const rotationV3 = (kind = 'wallet', next = p2, n = 2, seq = 1, prev = p, issuedAt = at + 30, retainedLinks = kind==='wallet'?[wid]:[oid], nextEpub = principal(6)) => {
  const r = { v: 1, kind: 'rotate', principal: p, seq, prevKey: prev, nextKey: next, nextEpub, issuedAt, retainedLinks, authorizer:{kind,link:kind==='wallet'?wid:oid} };
  return { ...r, nextSig: keySig(r, n), authorizer: kind === 'wallet' ? {...r.authorizer,siwe:siwe(r)} : r.authorizer, attest: jws({ typ: 'sociacl-rotate-attest-v3', principal: p, nextKey: next, nextEpub, seq, iat: issuedAt, exp: issuedAt + 600, auth: kind, linkId:r.authorizer.link, retainedLinks }) };
};
const rot = rotation(), rotOidc = rotation('oidc-fresh-login'), fork = rotation('wallet', p3, 3);
const stampRevoke=r=>jws({typ:'sociacl-revoke-attest-v1',principal:r.principal,recordId:val(ids.linkId(r)),iat:r.issuedAt,exp:r.issuedAt+600});
const rev = { v: 1, kind: 'revoke', principal: p, linkId: wid, issuedAt: at + 20 }; rev.keySig = keySig(rev);rev.attest=stampRevoke(rev);
const rev2 = { ...rev, issuedAt: at + 50 }; rev2.keySig = keySig(rev2, 2);rev2.attest=stampRevoke(rev2);
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
  ['gun-chain-literal-escape', 'x\\u002eget(', 'gun-chain'],
  ['gun-chain-decoded-escape', 'x\u002eget(', 'gun-chain'],
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
for (const kind of ['room','chat','forum-msg','post','forum-group','bot','forum']) {
  const suffix = ['room','chat','forum-msg','post'].includes(kind) ? ':123456789012:abcd' : ['forum-group','bot'].includes(kind) ? ':abcd' : '';
  const legacy = `s3rch:${kind}:${wallet}${suffix}`; accept('object', 'legacy-'+kind,legacy,legacy,{pathKey:legacy});
}
reject('object','legacy-13-digit',`s3rch:room:${wallet}:1700000000000:abcd`,'bad-alphabet');
reject('object','legacy-post-13-digit',`s3rch:post:${wallet}:1700000000000:abcd`,'bad-alphabet');
reject('object','legacy-post-missing-tail',`s3rch:post:${wallet}:123456789012`,'bad-alphabet');
reject('object','legacy-post-uppercase-tail',`s3rch:post:${wallet}:123456789012:ABCD`,'bad-alphabet');
reject('object','legacy-post-extra',`s3rch:post:${wallet}:123456789012:abcd:extra`,'bad-alphabet');
reject('object','legacy-post-bad-checksum',`s3rch:post:${wallet.replace(/[a-f]/, c => c.toUpperCase())}:123456789012:abcd`,'bad-checksum');
reject('object','legacy-post-empty-ts',`s3rch:post:${wallet}::abcd`,'bad-alphabet');
reject('object','uppercase-hex','room_'+'AB'.repeat(16),'non-canonical');
reject('object','reserved-kind','claim_'+'01'.repeat(16),'reserved-kind');
for (const kind of ['post', 'member', 'objset']) reject('object', 'reserved-kind-' + kind, kind + '_' + '01'.repeat(16), 'reserved-kind');
reject('object','mint-kind-post',{kind:'post',bytes:Array(16).fill(1)},'reserved-kind',{operation:'mint'});
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
accept('soul','membership-7-segments',ids.membershipSoul(p,'same-group',obj,p2),val(ids.parseSoul(ids.membershipSoul(p,'same-group',obj,p2))));
accept('soul','objset-5-segments',ids.objectSetSoul(p,obj),val(ids.parseSoul(ids.objectSetSoul(p,obj))));
accept('soul','build-membership',[p,'same-group',obj,p2],ids.membershipSoul(p,'same-group',obj,p2),{operation:'build-membership'});
accept('soul','build-membership-named-circle',[p,'named-circle',obj,p2],ids.membershipSoul(p,'named-circle',obj,p2),{operation:'build-membership'});
accept('soul','build-objset',[p,obj],ids.objectSetSoul(p,obj),{operation:'build-objset'});
reject('soul','extra-segment',ids.grantSoul(p,obj,p2)+'/x','bad-template');
reject('soul','unknown-collection','s3rch/users/'+obj,'bad-template');
reject('soul','kind-post-reserved',`s3rch/acl/${ids.formatPrincipalKey(p)}/post_${'01'.repeat(16)}/${ids.formatPrincipalKey(p2)}`,'reserved-kind');
reject('soul','membership-bad-predicate',`s3rch/acl/${ids.formatPrincipalKey(p)}/member/nope/${obj}/${ids.formatPrincipalKey(p2)}`,'bad-template');
reject('soul','build-membership-bad-predicate',[p,'nope',obj,p2],'bad-template',{operation:'build-membership'});
const signing = [w,oidc,rot,rev];
for (const r of signing) accept('signing-bytes',r.kind,r,hex(bytes(r)),{linkId:val(ids.linkId(r))});
const context = { jwks, pinnedIss:[cred.iss], now, genesis:p, currentKey:p, links:[[wid,w],[oid,oidc]], policy:{allowedDomains:['s3r.ch'],allowedUris:['https://s3r.ch/identity/link'],allowedChainIds:['1']}, authenticatedAccounts:[p,p2,p3] };
family('records').context = context;
for (const [name, operation, input, extra] of [ ['wallet','wallet-link',w,{}],['oidc','oidc-link',oidc,{}],['wallet-rotate','rotate',rot,{}],['oidc-rotate','rotate',rotOidc,{links:[[oid,oidc]]}],['revoke','revoke',rev,{}], ['resolve','resolve',[rot],{}],['duplicate-rotation','resolve',[rot,rot],{}],['reordered-history','resolve',[rotation('wallet',p3,3,2,p2,at+40),rot],{}], ['wallet-lookup','wallet-resolve',[w],{address:wallet}],['newest-wallet-wins','wallet-resolve',[w,walletLink(p2,at+10,2)],{address:wallet}],['historical-revoke','revoke',rev2,{currentKey:p2}] ]) {
  const canonical = operation==='resolve' ? name==='reordered-history'?p3:p2 : name==='newest-wallet-wins'?p2:p;
  accept('records',name,input,canonical,{operation,...extra});
}
const options = siwe(w,`\nExpiration Time: ${date(at+600)}\nNot Before: ${date(at)}\nRequest ID: request%3A123\nResources:\n- https://s3r.ch/resource`);
accept('records','siwe-optionals',{...w,siwe:options},p,{operation:'wallet-link'});
const bad = (name,input,reason,operation='wallet-link',extra={})=>reject('records',name,input,reason,{operation,...extra});
bad('link-object-principal',{...w,principal:{toString:p}},'not-string');
bad('rotate-object-principal',{...rot,principal:{toString:p}},'not-string','rotate');
bad('fork',[rot,fork],'rotation-fork','resolve');
reject('records','revoked-recovery',[rot],'rotation-conflict',{operation:'resolve',diagnosticReasons:['rotation-conflict'],revocations:[rev]});
bad('newest-wallet-revoked',[w],'revoked-link','wallet-resolve',{address:wallet,revocations:[rev]});
bad('duplicate-wallet-tie',[w,walletLink(p2,at,2)],'ambiguous-link','wallet-resolve',{address:wallet});
bad('wrong-current-key',rot,'bad-sequence','rotate',{currentKey:p3});
accept('records','sequence-gap',[rotation('oidc-fresh-login',p2,2,2)],p,{operation:'resolve',diagnosticReasons:['bad-sequence'],...{}});
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
const otherRevoke={v:1,kind:'revoke',principal:p2,linkId:otherId,issuedAt:at+20};otherRevoke.keySig=keySig(otherRevoke,2);otherRevoke.attest=stampRevoke(otherRevoke);
bad('no-resurrection-after-revoke',[w,otherWallet],'revoked-link','wallet-resolve',{address:wallet,revocations:[otherRevoke]});
bad('new-wallet-owner-blocks-old-recovery',[rot],'rotation-conflict','resolve',{diagnosticReasons:['rotation-conflict'],links:[[wid,w],[otherId,otherWallet]]});
const earlyRevoke={...rev,issuedAt:at-1};earlyRevoke.keySig=keySig(earlyRevoke);earlyRevoke.attest=stampRevoke(earlyRevoke);
accept('records','revoke-before-link-does-not-remove-link',[rot],p2,{operation:'resolve',revocations:[earlyRevoke]});
const sameSecond={...rev,issuedAt:rot.issuedAt};sameSecond.keySig=keySig(sameSecond);sameSecond.attest=stampRevoke(sameSecond);
bad('same-second-revoke-precedes-rotation',[rot],'rotation-conflict','resolve',{diagnosticReasons:['rotation-conflict'],revocations:[sameSecond]});
const invalidLink={...w,keySig:b64(new Uint8Array(64))};
bad('unverified-wallet-map',rot,'missing-history','rotate',{links:[[wid,invalidLink]]});
bad('wrong-link-map-key',rot,'missing-history','rotate',{links:[['00'.repeat(32),w]]});
bad('extra-record-field',{...w,unexpected:true},'bad-record');
bad('fractional-issued-at',{...w,issuedAt:at+.5},'bad-record');
for (const [suffix,msg] of [ ['extra-lines',w.siwe.message+'\nunknown'],['duplicate-expiry',siwe(w,`\nExpiration Time: ${date(at+600)}\nExpiration Time: ${date(at+700)}`).message],['invalid-percent-uri',w.siwe.message.replace('/identity/link','/%xx')]]) bad('siwe-'+suffix,{...w,siwe:signMessage(msg)},'bad-signature');
reject('source-key','source-leading-nbsp','sr1:rss/https%3A%2F%2Fs3r.ch/%C2%A0feed/feed','bad-alphabet');
reject('source-key','source-trailing-em-space','sr1:rss/https%3A%2F%2Fs3r.ch/feed%E2%80%83/feed','bad-alphabet');
reject('object','claim-leading-nbsp','\u00a0ens:alice.eth','bad-alphabet',{operation:'claim'});

// Review regression corpus: expected outcomes are explicit, independent of either URL parser.
const hosts = [['s3r.ch',true],['sub.s3r.ch',true],['xn--ab--.com',false],['xn--bcher-kva.de',false],['a.xn--ab--',false],['S3R.CH',false],['s3r.ch.',false],['127.0.0.1',false],['0x7f.0.0.1',false],['box.local',false],['-a.com',false],['a-.com',false],['a..com',false],['a'.repeat(63)+'.com',true],['a'.repeat(64)+'.com',false]];
const paths = [['/u',true],['/',true],['/u#',false],['/u?#',false],['/u?q=x',false],['/^',false],['/%2F',true],['/%2f',false],['/%XX',false],['/../u',false],['/%2E/u',false],['/a/..',false],['/a:b@c',true],['/a%20b',true]];
for (const [hi,[host,hgood]] of hosts.entries()) {
  const n=`s3rch:https://${host}:443;key=${'12'.repeat(32)}`;
  (hgood?accept:reject)('network',`url-host-${hi}`,n,hgood?n:'bad-host');
  for (const [pi,[path,pgood]] of paths.entries()) {
    const owner='https://'+host+path, source=`sr1:activitypub/${pct(owner)}/feed/feed`;
    (hgood&&pgood?accept:reject)('source-key',`url-corpus-${hi}-${pi}`,source,hgood&&pgood?source:'bad-alphabet');
  }
}
for (const [i,[path,good]] of paths.entries()) {
  const uri='https://s3r.ch'+path;
  const proof={...w,siwe:signMessage(w.siwe.message.replace('https://s3r.ch/identity/link',uri))};
  (good?accept:reject)('records',`siwe-uri-corpus-${i}`,proof,good?p:'bad-signature',{operation:'wallet-link',policy:{...context.policy,allowedUris:[uri]}});
  const resource={...w,siwe:siwe(w,'\nResources:\n- '+uri)};
  (good?accept:reject)('records',`siwe-resource-corpus-${i}`,resource,good?p:'bad-signature',{operation:'wallet-link'});
}
for (const [name,policy] of [['domain',{...context.policy,allowedDomains:['evil.com']}],['uri',{...context.policy,allowedUris:['https://s3r.ch/other']}],['chain',{...context.policy,allowedChainIds:['137']}]] ) bad('wrong-siwe-'+name,w,'bad-signature','wallet-link',{policy});
bad('missing-wallet-attest',{...w,attest:''},'empty');
bad('wallet-attest-wrong-time',{...w,attest:jws({typ:'sociacl-wallet-attest-v1',principal:p,linkId:wid,iat:at+1,exp:at+601})},'bad-attestation');
bad('wallet-attest-wrong-id',{...w,attest:jws({typ:'sociacl-wallet-attest-v1',principal:p,linkId:'00'.repeat(32),iat:at,exp:at+600})},'bad-attestation');
bad('wallet-attest-too-long',{...w,attest:jws({typ:'sociacl-wallet-attest-v1',principal:p,linkId:wid,iat:at,exp:at+901})},'bad-attestation');
bad('rotation-retained-tampered',{...rot,retainedLinks:[]},'bad-signature','rotate');
const noRetain=rotation('oidc-fresh-login',p2,2,1,p,at+30,[]);
bad('rotation-attest-retained-mismatch',{...noRetain,attest:rotOidc.attest},'bad-attestation','rotate');
bad('duplicate-retained-ids',{...rot,retainedLinks:[wid,wid]},'bad-record','rotate');
const forgedBackdated=walletLink(p,at+10,1), forgedId=val(ids.linkId(forgedBackdated));
bad('retired-key-backdated-wallet',[forgedBackdated],'unknown-link','wallet-resolve',{address:wallet,histories:[[p,[rot]]],diagnosticReasons:['unretained-link']});
accept('records','retained-link-survives-rotation',[w],p,{operation:'wallet-resolve',address:wallet,histories:[[p,[rot]]]});
bad('dropped-link-after-recovery',[w],'unknown-link','wallet-resolve',{address:wallet,histories:[[p,[noRetain]]],diagnosticReasons:['unretained-link']});
accept('records','retired-key-backdated-revoke',[w],p,{operation:'wallet-resolve',address:wallet,histories:[[p,[rot]]],revocations:[rev],diagnosticReasons:['bad-signature']});
bad('active-key-revoke-after-rotation',[w],'revoked-link','wallet-resolve',{address:wallet,histories:[[p,[rot]]],revocations:[rev2]});
accept('records','skip-malformed-forged-rotations',[null,{...rot,nextSig:b64(new Uint8Array(64))},rot],p2,{operation:'resolve',diagnosticReasons:['bad-record','bad-signature']});
bad('forgery-does-not-hide-valid-fork',[{...rot,nextSig:b64(new Uint8Array(64))},rot,fork],'rotation-fork','resolve',{diagnosticReasons:['bad-signature']});
accept('records','skip-invalid-wallet-and-revoke',[null,invalidLink,w],p,{operation:'wallet-resolve',address:wallet,revocations:[null,{...rev,keySig:b64(new Uint8Array(64))}],diagnosticReasons:['bad-record','bad-signature','bad-record','bad-signature']});
const tieBase={v:1,kind:'wallet',principal:p,address:wallet,issuedAt:at,nonce:'otherNonce123'};
const tie={...tieBase,keySig:keySig(tieBase),siwe:siwe(tieBase),attest:jws({typ:'sociacl-wallet-attest-v1',principal:p,linkId:val(ids.linkId(tieBase)),iat:at,exp:at+600})};
for (const [i,ls] of [[w,tie],[tie,w]].entries()) bad('same-principal-tie-'+i,ls,'ambiguous-link','wallet-resolve',{address:wallet,revocations:[rev]});
accept('records','duplicate-wallet-idempotent',[w,w],p,{operation:'wallet-resolve',address:wallet});
bad('missing-history-context',[w],'missing-history','wallet-resolve',{address:wallet,missingHistory:true});
bad('missing-rotate-history',rot,'missing-history','rotate',{missingHistory:true});
const extOidcBase={...unsignedOidc,principal:p2};
const extOidc={...extOidcBase,keySig:keySig(extOidcBase,2),attest:jws({...oc,principal:p2})},extOid=val(ids.linkId(extOidc));
const extBase={v:1,kind:'rotate',principal:p2,seq:1,prevKey:p2,nextKey:p3,issuedAt:at+5,retainedLinks:[],authorizer:{kind:'oidc-fresh-login',link:extOid}};
const extRot={...extBase,nextSig:keySig(extBase,3),authorizer:extBase.authorizer,attest:jws({typ:'sociacl-rotate-attest-v2',principal:p2,nextKey:p3,seq:1,iat:at+5,exp:at+605,auth:'oidc-fresh-login',linkId:extBase.authorizer.link,retainedLinks:[]})};
accept('records','external-history-fixture-authenticates',[extRot],p3,{operation:'resolve',genesis:p2,links:[[extOid,extOidc]]});
const extLink=walletLink(p2,at+10,3),extId=val(ids.linkId(extLink));
bad('rotated-external-owner-blocks-recovery',[rot],'rotation-conflict','resolve',{links:[[wid,w],[extId,extLink]],histories:[[p2,[extRot]]],diagnosticReasons:['rotation-conflict']});
accept('records','invalid-map-entry-skipped',[rot],p2,{operation:'resolve',links:[[wid,w],['00'.repeat(32),null]],diagnosticReasons:['bad-record']});

accept('records','clock-skew-expiry',w,p,{operation:'wallet-link',now:at+630,policy:{...context.policy,clockSkewSeconds:60}});
accept('records','clock-skew-future',w,p,{operation:'wallet-link',now:at-30,policy:{...context.policy,clockSkewSeconds:60}});
bad('clock-skew-bounded',w,'bad-record','wallet-link',{policy:{...context.policy,clockSkewSeconds:301}});
bad('clock-skew-expiry-boundary',w,'expired','wallet-link',{now:at+660,policy:{...context.policy,clockSkewSeconds:60}});
accept('edges','principal-key',ids.formatPrincipalKey(p),ids.formatPrincipalKey(p),{operation:'principal-key'});
accept('edges','path-key',ids.formatWalletKey(wallet),ids.formatWalletKey(wallet),{operation:'path-key'});
accept('edges','sec1-compressed',hex(p256.getPublicKey(secret(1),true)),p,{operation:'sec1'});
accept('edges','sec1-uncompressed',hex(p256.getPublicKey(secret(1),false)),p,{operation:'sec1'});
reject('edges','path-key-invalid','p_00','bad-alphabet',{operation:'path-key'});
reject('edges','sec1-invalid','00','not-on-curve',{operation:'sec1'});
accept('edges','json-record',JSON.stringify(w),w,{operation:'json'});
reject('edges','json-duplicate-member','{"v":1,"v":2}','bad-record',{operation:'json'});
reject('edges','json-escaped-duplicate','{"a":1,"\\u0061":2}','bad-record',{operation:'json'});
reject('edges','json-overflow','1e999','bad-record',{operation:'json'});
reject('edges','json-surrogate','"\\ud800"','unpaired-surrogate',{operation:'json'});
accept('edges','json-depth-limit','['.repeat(16)+'0'+']'.repeat(16),JSON.parse('['.repeat(16)+'0'+']'.repeat(16)),{operation:'json'});
reject('edges','json-too-deep','['.repeat(17)+'0'+']'.repeat(17),'bad-record',{operation:'json'});
// Explicit caller context failures must not be mistaken for forged input.
bad('unavailable-foreign-history',[otherWallet],'missing-history','wallet-resolve',{address:wallet,authenticatedAccounts:[p],diagnosticReasons:['missing-history']});
bad('direct-wallet-unretained',w,'unretained-link','wallet-link',{directState:{key:p,currentKey:p2,retainedLinks:[]}});
bad('direct-oidc-unretained',oidc,'unretained-link','oidc-link',{directState:{key:p,currentKey:p2,retainedLinks:[]}});

// Round 2: indexed garbage cannot demand authentication context or freeze a valid account.
const p7=principal(7), zero=b64(new Uint8Array(64));
const poison={...w,principal:p7,keySig:zero};
const poisonId=val(ids.linkId(poison));
const otherAddress=val(ids.parseWalletInput('0x'+'12'.repeat(20)));
for (const [name,link,diags] of [
  ['foreign-principal',poison,['bad-signature']],
  ['different-address',{...poison,address:otherAddress},[]],
  ['bad-attestation',{...walletLink(p7,at+10,7),attest:w.attest},['bad-attestation']],
  ['bad-siwe',{...walletLink(p7,at+10,7),siwe:{...w.siwe,signature:'0x'+'00'.repeat(65)}},['bad-signature']],
]) {
  accept('records','poison-wallet-'+name,[w,link],p,{operation:'wallet-resolve',address:wallet,diagnosticReasons:diags});
  accept('records','poison-rotation-map-'+name,[rot],p2,{operation:'resolve',links:[[wid,w],[val(ids.linkId(link)),link]],diagnosticReasons:diags});
}
for (const [name,record,diags] of [
  ['foreign',{...rev,principal:p7,keySig:zero},[]],
  ['future',{...rev,principal:p7,keySig:zero,issuedAt:now+1},['future-record']],
  ['forged',{...rev,keySig:zero},['bad-signature']],
  ['other-id',{...rev,linkId:'00'.repeat(32),keySig:zero},[]],
]) {
  accept('records','poison-wallet-revoke-'+name,[w],p,{operation:'wallet-resolve',address:wallet,revocations:[record],diagnosticReasons:diags});
  accept('records','poison-rotation-revoke-'+name,[rot],p2,{operation:'resolve',revocations:[record],diagnosticReasons:diags});
}
bad('valid-relevant-unknown-account',[w,walletLink(p7,at+10,7)],'missing-history','wallet-resolve',{address:wallet,diagnosticReasons:['missing-history']});
bad('valid-relevant-forked-account',[w,otherWallet],'rotation-fork','wallet-resolve',{address:wallet,historyErrors:[[p2,'rotation-fork']],diagnosticReasons:['rotation-fork']});
accept('records','poison-fork-context-ignored',[w,{...w,principal:p2,keySig:zero}],p,{operation:'wallet-resolve',address:wallet,historyErrors:[[p2,'rotation-fork']],diagnosticReasons:['bad-signature']});
const oidcOnly={links:[[oid,oidc]]};
accept('records','oidc-only-recovery',[rotOidc],p2,{operation:'resolve',...oidcOnly});
bad('oidc-recovery-blocked-by-wallet',[rotOidc],'rotation-conflict','resolve',{diagnosticReasons:['rotation-conflict']});
bad('oidc-cannot-drop-active-wallet',[noRetain],'rotation-conflict','resolve',{diagnosticReasons:['rotation-conflict']});
bad('direct-oidc-requires-wallet',rotOidc,'wallet-required','rotate');
bad('oidc-missing-enrolled-link',[rotOidc],'missing-history','resolve',{links:[[wid,w]],diagnosticReasons:['missing-history']});
const revokedOidc={...rev,linkId:oid};revokedOidc.keySig=keySig(revokedOidc);revokedOidc.attest=stampRevoke(revokedOidc);
bad('oidc-revoked-enrolled-link',[rotOidc],'rotation-conflict','resolve',{...oidcOnly,revocations:[revokedOidc],diagnosticReasons:['rotation-conflict']});
accept('records','oidc-recovery-after-wallet-revoke',[rotOidc],p2,{operation:'resolve',revocations:[rev]});
const retainRevoked=rotation('oidc-fresh-login',p2,2,1,p,at+30,[wid,oid].sort());
bad('rotation-cannot-retain-revoked-wallet',[retainRevoked],'rotation-conflict','resolve',{revocations:[rev],diagnosticReasons:['rotation-conflict']});
bad('direct-rotation-cannot-retain-revoked-wallet',retainRevoked,'rotation-conflict','rotate',{revocations:[rev]});
const retainRevokedOidc=rotation('wallet',p2,2,1,p,at+30,[wid,oid].sort());
bad('rotation-cannot-retain-revoked-oidc',[retainRevokedOidc],'rotation-conflict','resolve',{revocations:[revokedOidc],diagnosticReasons:['rotation-conflict']});
bad('oidc-unretained-after-wallet-recovery',[rot,rotation('oidc-fresh-login',p3,3,2,p2,at+40)],'missing-history','resolve',{diagnosticReasons:['missing-history']});
bad('oidc-attestation-wrong-link',{...rotOidc,attest:jws({typ:'sociacl-rotate-attest-v2',principal:p,nextKey:p2,seq:1,iat:at+30,exp:at+630,auth:'oidc-fresh-login',linkId:wid,retainedLinks:rotOidc.retainedLinks})},'bad-attestation','rotate',oidcOnly);
bad('oidc-authorizer-tampered',{...rotOidc,authorizer:{kind:'oidc-fresh-login',link:wid}},'bad-signature','rotate');
const untrustedOidc={...oidc,attest:jws({...oc,iss:'https://other.s3r.ch'})};
bad('oidc-invalid-attestation',[rotOidc],'missing-history','resolve',{links:[[oid,untrustedOidc]],diagnosticReasons:['missing-history']});
bad('oidc-issuer-not-pinned',[rotOidc],'missing-history','resolve',{...oidcOnly,pinnedIss:[],diagnosticReasons:['missing-history']});
for (const [name,port,good] of [['nondefault','%3A8443',true],['padded','%3A0443',false],['default','%3A443',false],['lowercase-escape','%3a8443',false],['zero','%3A0',false]]) {
  const source=`sr1:atproto/${pct('did:web:s3r.ch'+port+':user:alice')}/feed/feed`;
  (good?accept:reject)('source-key','did-web-port-'+name,source,good?source:'bad-alphabet');
}

// A retained key cannot invalidate an already valid rotation by inventing an older revoke.
const lateRetiredRevoke={...rev,issuedAt:at+50};lateRetiredRevoke.keySig=keySig(lateRetiredRevoke);lateRetiredRevoke.attest=stampRevoke(lateRetiredRevoke);
const backdatedRevoke={...lateRetiredRevoke,issuedAt:at+20};backdatedRevoke.keySig=keySig(backdatedRevoke);
accept('records','backdated-revoke-cannot-rollback-rotation',[rot],p2,{operation:'resolve',revocations:[backdatedRevoke],diagnosticReasons:['future-record']});
accept('records','late-retired-revoke-cannot-block-earlier-rotation',[rot],p2,{operation:'resolve',revocations:[lateRetiredRevoke],diagnosticReasons:['future-record']});
accept('records','late-retired-revoke-cannot-remove-retained-link',[w],p,{operation:'wallet-resolve',address:wallet,histories:[[p,[rot]]],revocations:[lateRetiredRevoke],diagnosticReasons:['bad-signature']});
bad('revoke-missing-attestation',{...rev,attest:''},'empty','revoke');
bad('revoke-mismatched-time',backdatedRevoke,'bad-attestation','revoke');
bad('revoke-expired-attestation',{...rev,attest:jws({typ:'sociacl-revoke-attest-v1',principal:p,recordId:val(ids.linkId(rev)),iat:rev.issuedAt,exp:rev.issuedAt+1})},'expired','revoke');
bad('revoke-untrusted-attestation',{...rev,attest:rev.attest.slice(0,-86)+zero},'bad-attestation','revoke');
bad('rejected-retention-does-not-resurrect-wallet',[retainRevoked],'rotation-conflict','resolve-and-wallet',{address:wallet,revocations:[rev]});
accept('records','witnessed-backdating-does-not-change-account',[rot],p,{operation:'resolve-and-wallet',address:wallet,revocations:[backdatedRevoke]});
for (const [name,path] of [['escaped-unreserved','/%41'],['escaped-nul','/%00'],['escaped-linefeed','/%0A'],['escaped-delete','/%7F']]) {
  const source=`sr1:activitypub/${pct('https://s3r.ch'+path)}/feed/feed`;
  reject('source-key',name,source,'bad-alphabet');
}
for (const host of ['s3r.0x1','s3r.123a']) reject('network','alphabetic-tld-'+host,`s3rch:https://${host}:443;key=${'12'.repeat(32)}`,'bad-host');
// Round 3: authenticated rotation evidence must never silently restore a retired key.
const hostileBackdated={...rev,issuedAt:at+25};hostileBackdated.keySig=keySig(hostileBackdated);hostileBackdated.attest=stampRevoke(hostileBackdated);
bad('witness-equivocation-freezes-rotation',[rot],'rotation-conflict','resolve',{revocations:[hostileBackdated],diagnosticReasons:['rotation-conflict']});
bad('witness-equivocation-blocks-present-lookup',[rot],'rotation-conflict','resolve-and-wallet',{address:wallet,revocations:[hostileBackdated]});
for (const [name,link] of [
  ['missing',undefined],['key-signature',{...w,keySig:zero}],
  ['siwe',{...w,siwe:{...w.siwe,signature:'0x'+'00'.repeat(65)}}],
  ['attestation',{...w,attest:'broken'}],['malformed',null],
]) {
  bad('required-wallet-'+name,[rot],'missing-history','resolve',{links:link===undefined?[]:[[wid,link]],diagnosticReasons:['missing-history']});
  if(name==='siwe') bad('required-retained-wallet-siwe',[retainRevoked],'missing-history','resolve',{links:[[oid,oidc],[wid,link]],diagnosticReasons:['missing-history']});
  else bad('required-retained-oidc-'+name,[retainRevokedOidc],'missing-history','resolve',{links:link===undefined?[[wid,w]]:[[wid,w],[oid,name==='key-signature'?{...oidc,keySig:zero}:name==='attestation'?{...oidc,attest:'broken'}:null]],diagnosticReasons:['missing-history']});
}
bad('required-rotation-wallet-proof',[{...rot,authorizer:{...rot.authorizer,siwe:{...rot.authorizer.siwe,signature:'0x'+'00'.repeat(65)}}}],'missing-history','resolve',{diagnosticReasons:['missing-history']});
accept('records','unwitnessed-rotation-cannot-demand-missing-links',[{...rot,attest:'broken'}],p,{operation:'resolve',links:[],diagnosticReasons:['bad-attestation']});
accept('records','unsigned-rotation-cannot-demand-missing-links',[{...rot,nextSig:zero}],p,{operation:'resolve',links:[],diagnosticReasons:['bad-signature']});
bad('foreign-rotation-conflict-propagates',[w,otherWallet],'rotation-conflict','wallet-resolve',{address:wallet,historyErrors:[[p2,'rotation-conflict']],diagnosticReasons:['rotation-conflict']});
const secondRotation=rotation('wallet',p3,3,2,p2,at+55);
bad('second-rotation-conflict-does-not-return-previous-key',[rot,secondRotation],'rotation-conflict','resolve',{revocations:[rev2],diagnosticReasons:['future-record','rotation-conflict']});

// Present-only revocation: final current-key authority is distinct from witnessed history.
const offline = record => { const {attest,...rest}=record; return rest; };
const offlineRev=offline(rev), offlineRev2=offline(rev2);
accept('signing-bytes','offline-revoke-same-identity',offlineRev,hex(bytes(rev)),{linkId:val(ids.linkId(rev))});
accept('records','offline-current-key-revoke',offlineRev,p,{operation:'revoke-now',jwks:{keys:[]}});
accept('records','offline-current-key-oidc-revoke',offline(revokedOidc),p,{operation:'revoke-now'});
bad('offline-revoke-is-not-historical-proof',offlineRev,'bad-attestation','revoke');
bad('offline-revoke-blocks-present-wallet',[w],'revoked-link','wallet-resolve-now',{address:wallet,revocations:[offlineRev]});
accept('records','offline-revoke-ignored-at-historical-horizon',[w],p,{operation:'wallet-resolve',address:wallet,revocations:[offlineRev],diagnosticReasons:['bad-attestation']});
bad('offline-rotated-current-key-blocks-present-wallet',[w],'revoked-link','wallet-resolve-now',{address:wallet,histories:[[p,[rot]]],revocations:[offlineRev2]});
bad('offline-current-revoke-after-resolving-rotation',[rot],'revoked-link','resolve-and-wallet-now',{address:wallet,revocations:[offlineRev2]});
accept('records','offline-retired-revoke-cannot-rollback-rotation',[rot],p2,{operation:'resolve',revocations:[offlineRev],diagnosticReasons:['bad-attestation']});
accept('records','offline-retired-revoke-cannot-rewrite-rotation-proof',rot,p,{operation:'rotate',revocations:[offlineRev]});
accept('records','offline-retired-revoke-stops-at-retirement',[w],p,{operation:'wallet-resolve-now',address:wallet,histories:[[p,[rot]]],revocations:[offlineRev],diagnosticReasons:['bad-signature']});
accept('records','offline-retired-backdated-revoke-cannot-remove-wallet',[rot],p,{operation:'resolve-and-wallet-now',address:wallet,revocations:[offline(backdatedRevoke)]});
accept('records','offline-revoke-cannot-block-second-rotation',[rot,secondRotation],p3,{operation:'resolve',revocations:[offlineRev2],diagnosticReasons:['future-record','bad-attestation']});
accept('records','offline-revoke-stops-after-second-rotation',[rot,secondRotation],p,{operation:'resolve-and-wallet-now',address:wallet,revocations:[offlineRev2]});
bad('offline-revoke-does-not-erase-wallet-from-historical-oidc-recovery',[rotOidc],'rotation-conflict','resolve',{revocations:[offlineRev],diagnosticReasons:['bad-attestation','rotation-conflict']});
accept('records','offline-oidc-revoke-cannot-rewrite-oidc-rotation',[rotOidc],p2,{operation:'resolve',...oidcOnly,revocations:[offline(revokedOidc)],diagnosticReasons:['bad-attestation']});
bad('witness-conflict-still-freezes-present-lookup',[rot],'rotation-conflict','resolve-and-wallet-now',{address:wallet,revocations:[hostileBackdated]});
bad('missing-rotation-evidence-still-blocks-present-lookup',[rot],'missing-history','resolve-and-wallet-now',{address:wallet,links:[]});
bad('rotation-fork-still-blocks-present-lookup',[rot,fork],'rotation-fork','resolve-and-wallet-now',{address:wallet});
bad('present-lookup-needs-history',[w],'missing-history','wallet-resolve-now',{address:wallet,missingHistory:true});
for(const reason of ['missing-history','rotation-fork','rotation-conflict']) bad('present-relevant-history-'+reason,[w,otherWallet],reason,'wallet-resolve-now',{address:wallet,historyErrors:[[p2,reason]],diagnosticReasons:[reason]});
for(const [name,record,diags] of [
  ['foreign',{...offlineRev,principal:p7,keySig:zero},[]],
  ['future',{...offlineRev,issuedAt:now+1},['future-record']],
  ['forged',{...offlineRev,keySig:zero},['bad-signature']],
  ['other-id',{...offlineRev,linkId:'00'.repeat(32),keySig:zero},[]],
]) accept('records','present-skip-revoke-'+name,[w],p,{operation:'wallet-resolve-now',address:wallet,revocations:[record],diagnosticReasons:diags});
bad('present-revoked-newest-wallet-never-resurrects-old',[w,otherWallet],'revoked-link','wallet-resolve-now',{address:wallet,revocations:[offline(otherRevoke)]});
accept('records','present-revoke-before-link-does-not-remove-link',[w],p,{operation:'wallet-resolve-now',address:wallet,revocations:[offline(earlyRevoke)]});
for(const [name,patch] of [['principal',{principal:p2}],['target',{linkId:'00'.repeat(32)}],['time',{issuedAt:at+21}]]) bad('offline-revoke-binds-'+name,{...offlineRev,...patch},'bad-signature','revoke-now');
bad('offline-retired-key-is-not-current',offlineRev,'bad-signature','revoke-now',{currentKey:p2});
bad('offline-future-revoke', {...offlineRev,issuedAt:now+1},'future-record','revoke-now');
for(const [name,attest,reason] of [['null',null,'not-string'],['number',3,'not-string'],['empty','','empty']]) bad('offline-malformed-attest-'+name,{...offlineRev,attest},reason,'revoke-now');
accept('records','present-revoke-does-not-certify-witness',{...rev,attest:'broken'},p,{operation:'revoke-now'});
bad('historical-revoke-still-validates-witness',{...rev,attest:'broken'},'bad-attestation','revoke');
bad('present-witnessed-revoke-blocks-wallet',[w],'revoked-link','wallet-resolve-now',{address:wallet,revocations:[rev]});

// Round 4: unsigned proof fields cannot turn an authentic duplicate into an account freeze.
const damagedRotation = r => ({...r,authorizer:{...r.authorizer,siwe:{...r.authorizer.siwe,signature:'0x'+'00'.repeat(65)}}});
const damagedRot=damagedRotation(rot);
accept('signing-bytes','damaged-rotation-proof-same-id',damagedRot,hex(bytes(rot)),{linkId:val(ids.linkId(rot))});
for(const [order,copies] of [['valid-first',[rot,damagedRot]],['valid-last',[damagedRot,rot]]]) {
  accept('records','rotation-duplicate-proof-'+order,copies,p2,{operation:'resolve',diagnosticReasons:['missing-history']});
  accept('records','rotation-duplicate-present-lookup-'+order,copies,p,{operation:'resolve-and-wallet-now',address:wallet});
  bad('duplicate-proof-cannot-hide-valid-fork-'+order,[...copies,fork],'rotation-fork','resolve',{diagnosticReasons:['missing-history']});
  bad('duplicate-proof-cannot-hide-witness-conflict-'+order,copies,'rotation-conflict','resolve',{revocations:[rev],diagnosticReasons:['rotation-conflict','rotation-conflict']});
  bad('duplicate-proof-cannot-supply-missing-link-'+order,copies,'missing-history','resolve',{links:[],diagnosticReasons:['missing-history','missing-history']});
}
bad('no-verifying-copy-of-authenticated-rotation',[damagedRot,{...rot,nextSig:zero}],'missing-history','resolve',{diagnosticReasons:['missing-history','bad-signature']});
for(const [order,copies] of [['valid-first',[rot,damagedRotation(fork)]],['valid-last',[damagedRotation(fork),rot]]]) bad('distinct-authenticated-id-still-needs-proof-'+order,copies,'missing-history','resolve',{diagnosticReasons:['missing-history']});
accept('records','duplicate-proof-at-next-sequence',[rot,damagedRotation(secondRotation),secondRotation],p3,{operation:'resolve',diagnosticReasons:['missing-history']});
accept('records','duplicate-proof-plus-unattested-copy',[damagedRot,{...rot,attest:'broken'},rot],p2,{operation:'resolve',diagnosticReasons:['missing-history','bad-attestation']});
for(const [order,links] of [['valid-first',[w,invalidLink]],['valid-last',[invalidLink,w]]]) accept('records','wallet-list-keeps-verifying-copy-'+order,links,p,{operation:'wallet-resolve-now',address:wallet,diagnosticReasons:['bad-signature']});
for(const [name,siwe] of [['absent',undefined],['null',null],['short-signature',{...rot.authorizer.siwe,signature:'0x1234'}],['bad-message',{...rot.authorizer.siwe,message:42}],['extra-field',{...rot.authorizer.siwe,extra:true}]]) {
  const damaged={...rot,authorizer:{kind:'wallet',link:wid,...(siwe===undefined?{}:{siwe})}};
  bad('authenticated-rotation-proof-'+name,[damaged],'missing-history','resolve',{diagnosticReasons:['missing-history']});
  for(const [order,copies] of [['first',[damaged,rot]],['last',[rot,damaged]]]) accept('records','duplicate-malformed-proof-'+name+'-'+order,copies,p2,{operation:'resolve',diagnosticReasons:['missing-history']});
}
const noSiwe={...rot,authorizer:{kind:'wallet',link:wid}};
accept('records','missing-proof-without-valid-witness-cannot-freeze',[{...noSiwe,attest:'broken'}],p,{operation:'resolve',links:[],diagnosticReasons:['bad-attestation']});
accept('records','missing-proof-without-valid-new-key-signature-cannot-freeze',[{...noSiwe,nextSig:zero}],p,{operation:'resolve',links:[],diagnosticReasons:['bad-signature']});
bad('direct-rotation-proof-missing',noSiwe,'missing-history','rotate');
// Caller pre-attestation obligations: refuse a revoked authorizer; omit revoked retention.
for(const [name,revs,expected] of [
  ['wallet',[offlineRev],[oid]],['oidc',[offline(revokedOidc)],[wid]],
  ['both',[offlineRev,offline(revokedOidc)],[]],
  ['forged',[{...offlineRev,keySig:zero}],[wid,oid].sort()],
]) accept('records','retention-excludes-present-revoked-'+name,[wid,oid].sort(),expected,{operation:'prepare-retained-links-now',revocations:revs});
accept('records','retention-ignores-retired-key-offline-revoke',[wid],[wid],{operation:'prepare-retained-links-now',histories:[[p,[rot]]],revocations:[offlineRev]});
bad('retention-cannot-use-missing-history',[wid],'missing-history','prepare-retained-links-now',{missingHistory:true});
bad('panopticon-present-check-refuses-offline-revoked-wallet',[w],'revoked-link','wallet-resolve-now',{address:wallet,revocations:[offlineRev]});
accept('records','build-rotation-excluding-offline-revoked-oidc',[rot],p2,{operation:'resolve',revocations:[offline(revokedOidc)]});
bad('excluded-offline-revoked-oidc-remains-unusable',oidc,'unretained-link','oidc-link',{directState:{key:p,currentKey:p2,retainedLinks:[wid]}});

// Rotate v3: nextEpub is in the signed bytes and the attestation. v2 records above stay unchanged.
const epub = principal(6), epub2 = principal(8);
const rot3 = rotationV3();
accept('signing-bytes','rotate-v3',rot3,hex(bytes(rot3)),{linkId:val(ids.linkId(rot3))});
accept('records','rotate-v3-wallet',rot3,p,{operation:'rotate',nextEpub:epub});
accept('records','rotate-v3-resolve',[rot3],p2,{operation:'resolve',currentEpub:epub});
const rot3second = rotationV3('wallet',p3,3,2,p2,at+40,[wid],epub2);
accept('records','rotate-v3-after-v2',[rot,rot3second],p3,{operation:'resolve',currentEpub:epub2});
accept('records','v2-after-v3-clears-epub',[rot3,rotation('wallet',p3,3,2,p2,at+40)],p3,{operation:'resolve'});
bad('rotate-v3-next-epub-tampered',{...rot3,nextEpub:p3},'bad-signature','rotate');
bad('rotate-v3-next-epub-missing',{...rot3,attest:jws({typ:'sociacl-rotate-attest-v3',principal:p,nextKey:p2,seq:1,iat:rot3.issuedAt,exp:rot3.issuedAt+600,auth:'wallet',linkId:wid,retainedLinks:rot3.retainedLinks})},'bad-attestation','rotate');
bad('rotate-v3-next-epub-malformed',{...rot3,nextEpub:'A'.repeat(43)+'.'+'A'.repeat(43)},'not-on-curve','rotate');
const v2Unsigned = { v:1, kind:'rotate', principal:p, seq:rot3.seq, prevKey:p, nextKey:p2, issuedAt:rot3.issuedAt, retainedLinks:rot3.retainedLinks, authorizer:{kind:'wallet',link:wid} };
bad('rotate-v3-signed-bytes-mismatch',{...rot3,nextSig:keySig(v2Unsigned,2)},'bad-signature','rotate');
accept('records','rotate-v3-tampered-does-not-resolve',[{...rot3,nextEpub:p3}],p,{operation:'resolve',diagnosticReasons:['bad-signature']});
bad('rotate-v3-revoked-recovery',[rot3],'rotation-conflict','resolve',{diagnosticReasons:['rotation-conflict'],revocations:[rev]});
bad('rotate-v3-attest-epub-mismatch',{...rot3,attest:jws({typ:'sociacl-rotate-attest-v3',principal:p,nextKey:p2,nextEpub:epub2,seq:1,iat:rot3.issuedAt,exp:rot3.issuedAt+600,auth:'wallet',linkId:wid,retainedLinks:rot3.retainedLinks})},'bad-attestation','rotate');
bad('rotate-v3-epub-equals-nextkey',rotationV3('wallet',p2,2,1,p,at+30,[wid],p2),'bad-sequence','rotate');
bad('rotate-v3-epub-equals-prevkey',rotationV3('wallet',p2,2,1,p,at+30,[wid],p),'bad-sequence','rotate');
accept('records','rotate-v3-epub-reuses-prior-epub',[rot3,rotationV3('wallet',p3,3,2,p2,at+40,[wid],epub)],p2,{operation:'resolve',currentEpub:epub,diagnosticReasons:['bad-sequence']});
accept('records','rotate-v3-epub-reuses-earlier-signing-key',[rot3,rotationV3('wallet',p3,3,2,p2,at+40,[wid],epub2),rotationV3('wallet',principal(4),4,3,p3,at+50,[wid],p2)],p3,{operation:'resolve',currentEpub:epub2,diagnosticReasons:['bad-sequence']});
accept('records','rotate-v3-nextkey-reuses-prior-epub',[rot3,rotationV3('wallet',epub,6,2,p2,at+40,[wid],epub2)],p2,{operation:'resolve',currentEpub:epub,diagnosticReasons:['bad-sequence']});

// Rotate v3 probes. Epub reuse is bad-sequence. A v2 rotation after a v3 clears currentEpub.
const v3claims = (r, over={}) => ({typ:'sociacl-rotate-attest-v3',principal:p,nextKey:r.nextKey,nextEpub:r.nextEpub,seq:r.seq,iat:r.issuedAt,exp:r.issuedAt+600,auth:r.authorizer.kind,linkId:r.authorizer.link,retainedLinks:r.retainedLinks,...over});
const v2claims = (r, over={}) => ({typ:'sociacl-rotate-attest-v2',principal:p,nextKey:r.nextKey,seq:r.seq,iat:r.issuedAt,exp:r.issuedAt+600,auth:r.authorizer.kind,linkId:r.authorizer.link,retainedLinks:r.retainedLinks,...over});
bad('probe-epub-equals-nextkey',rotationV3('wallet',p2,2,1,p,at+30,[wid],p2),'bad-sequence','rotate');
bad('probe-epub-equals-genesis',rotationV3('wallet',p2,2,1,p,at+30,[wid],p),'bad-sequence','rotate');
accept('records','probe-epub-reuse-across-rotations',[rot3,rotationV3('wallet',p3,3,2,p2,at+40,[wid],epub)],p2,{operation:'resolve',currentEpub:epub,diagnosticReasons:['bad-sequence']});
accept('records','probe-epub-equals-prior-signing-key',[rot3,rotationV3('wallet',p3,3,2,p2,at+40,[wid],p2)],p2,{operation:'resolve',currentEpub:epub,diagnosticReasons:['bad-sequence']});
bad('probe-v2-and-v3-copy-same-transition-fork',[rot,rot3],'rotation-fork','resolve');
bad('probe-v3-record-v2-attest',{...rot3,attest:jws(v2claims(rot3))},'bad-attestation','rotate');
bad('probe-v3-record-v2-attest-with-epub',{...rot3,attest:jws(v2claims(rot3,{nextEpub:epub}))},'bad-attestation','rotate');
bad('probe-v2-record-v3-attest',{...rot,attest:jws(v3claims({...rot,nextEpub:epub}))},'bad-attestation','rotate');
bad('probe-v2-record-v3-typ-no-epub',{...rot,attest:jws(v2claims(rot,{typ:'sociacl-rotate-attest-v3'}))},'bad-attestation','rotate');
{ const {nextEpub:_x,...stripped}=rot3; bad('probe-strip-epub-keep-sig',stripped,'bad-signature','rotate');
  const {nextSig:_s,attest:_a,authorizer:_au,...u}=stripped; const un={...u,authorizer:{kind:'wallet',link:wid}};
  const resigned={...stripped,nextSig:keySig(un,2),authorizer:{...un.authorizer,siwe:siwe(un)}};
  bad('probe-strip-epub-resigned-v3-attest',resigned,'bad-attestation','rotate');
  accept('records','probe-strip-epub-resigned-v2-attest',{...resigned,attest:jws(v2claims(resigned))},p,{operation:'rotate'});
  bad('probe-strip-epub-resigned-v2-attest-fork',[rot3,{...resigned,attest:jws(v2claims(resigned))}],'rotation-fork','resolve'); }
bad('probe-epub-null',{...rot3,nextEpub:null},'not-string','rotate');
bad('probe-epub-number',{...rot3,nextEpub:7},'not-string','rotate');
bad('probe-epub-empty',{...rot3,nextEpub:''},'empty','rotate');
{ const A='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'; const c=epub[42]; const nc=epub.slice(0,42)+A[A.indexOf(c)^1]+epub.slice(43);
  bad('probe-epub-noncanonical',{...rot3,nextEpub:nc},'non-canonical','rotate'); }
bad('probe-epub-hex-p-form',{...rot3,nextEpub:'p_'+'ab'.repeat(32)},'bad-length','rotate');
const rot3Oidc = rotationV3('oidc-fresh-login');
accept('records','probe-v3-oidc',rot3Oidc,p,{operation:'rotate',links:[[oid,oidc]],nextEpub:epub});
bad('probe-v3-oidc-wallet-active',rot3Oidc,'wallet-required','rotate');
accept('records','probe-v3-damaged-copy-plus-good',[{...rot3,authorizer:{kind:'wallet',link:wid}},rot3],p2,{operation:'resolve',currentEpub:epub});
accept('records','probe-v3-then-v2-clears-epub',[rot3,rotation('wallet',p3,3,2,p2,at+40)],p3,{operation:'resolve'});
accept('records','probe-v3-then-v3',[rot3,rotationV3('wallet',p3,3,2,p2,at+40,[wid],principal(7))],p3,{operation:'resolve',currentEpub:principal(7)});
accept('records','probe-v2-only-epub-null',[rot],p2,{operation:'resolve'});
accept('records','probe-no-rotations-epub-null',[],p,{operation:'resolve'});
accept('records','probe-v2-nextkey-reuses-prior-epub',[rot3,rotation('wallet',epub,6,2,p2,at+40)],p2,{operation:'resolve',currentEpub:epub,diagnosticReasons:['bad-sequence']});
accept('records','probe-v3-v2-v3-reuses-first-epub',[rot3,rotation('wallet',p3,3,2,p2,at+40),rotationV3('wallet',principal(4),4,3,p3,at+50,[wid],epub)],p3,{operation:'resolve',diagnosticReasons:['bad-sequence']});
accept('records','publish-v3',{candidate:rot3,siblings:[],prior:[]},p,{operation:'publish-check'});
bad('publish-v2-refused',{candidate:rot,siblings:[],prior:[]},'bad-record','publish-check');
bad('publish-both-versions',{candidate:rot3,siblings:[rot],prior:[]},'rotation-fork','publish-check');
const boundPoint = principal(9);
const genesisBinding = (epub = boundPoint, issuedAt = at, principalId = p, n = 1, claims = {}) => {
  const r = { v: 1, kind: 'genesis-epub', principal: principalId, epub, issuedAt };
  return { ...r, keySig: keySig(r, n), attest: jws({ typ: 'sociacl-genesis-epub-attest-v1', principal: principalId, epub, iat: issuedAt, exp: issuedAt + 600, ...claims }) };
};
const binding = genesisBinding();
accept('signing-bytes','genesis-epub',binding,hex(bytes(binding)),{linkId:val(ids.linkId(binding))});
accept('records','binding-valid-no-rotation',[],p,{operation:'resolve',currentEpub:boundPoint,genesisEpubBindings:[binding]});
accept('records','binding-bad-signature',[],p,{operation:'resolve',diagnosticReasons:['bad-signature'],genesisEpubBindings:[{...binding,keySig:'AA'}]});
accept('records','binding-bad-attestation',[],p,{operation:'resolve',diagnosticReasons:['bad-attestation'],genesisEpubBindings:[{...binding,attest:'aa.bb.cc'}]});
accept('records','binding-iat-mismatch',[],p,{operation:'resolve',diagnosticReasons:['bad-attestation'],genesisEpubBindings:[genesisBinding(boundPoint, at, p, 1, { iat: at - 1 })]});
accept('records','binding-after-first-rotation',[rot3,rotationV3('wallet',p3,3,2,p2,at+40,[wid],boundPoint)],p3,{operation:'resolve',currentEpub:boundPoint,diagnosticReasons:['bad-sequence'],genesisEpubBindings:[genesisBinding(boundPoint, at + 50)]});
bad('binding-two-freeze',[],'rotation-fork','resolve',{diagnosticReasons:['rotation-fork'],genesisEpubBindings:[binding,genesisBinding(principal(10), at + 1)]});
accept('records','binding-epub-equals-genesis',[],p,{operation:'resolve',diagnosticReasons:['bad-record'],genesisEpubBindings:[{v:1,kind:'genesis-epub',principal:p,epub:p,issuedAt:at,keySig:'AA',attest:'aa.bb.cc'}]});
accept('records','binding-reused-by-later-next-epub',[rot3,rotationV3('wallet',p3,3,2,p2,at+40,[wid],boundPoint)],p2,{operation:'resolve',currentEpub:epub,diagnosticReasons:['bad-sequence'],genesisEpubBindings:[binding]});
accept('records','probe-genesis-epub-at-seq-2',[rot3,rotationV3('wallet',p3,3,2,p2,at+40,[wid],boundPoint)],p2,{operation:'resolve',currentEpub:epub,diagnosticReasons:['bad-sequence'],genesisEpubBindings:[binding]});
accept('records','unwitnessed-genesis-epub-ignored',[rot3],p2,{operation:'resolve',currentEpub:epub,genesisEpub:epub});
accept('records','publish-junk-sibling',{candidate:rot3,siblings:[{kind:'nope'}],prior:[]},p,{operation:'publish-check'});
accept('records','publish-forged-sibling',{candidate:rot3,siblings:[{...rotationV3('wallet',principal(8),8,1,p,at+30,[wid],principal(11)),attest:'aa.bb.cc'}],prior:[]},p,{operation:'publish-check'});
accept('records','publish-bad-prior-skipped',{candidate:rotationV3('wallet',p3,3,2,p2,at+40,[wid],principal(7)),siblings:[],prior:[{...rot3,nextSig:'AA'},rot3]},p,{operation:'publish-check'});
bad('publish-seq2-reuses-genesis-epub',{candidate:rotationV3('wallet',p3,3,2,p2,at+40,[wid],boundPoint),siblings:[],prior:[rot3]},'bad-sequence','publish-check',{genesisEpubBindings:[binding]});
accept('records','junk-binding-skipped',[rot3],p2,{operation:'resolve',currentEpub:epub,diagnosticReasons:['bad-record'],genesisEpubBindings:[{kind:'nope'}]});
accept('records','r2-late-second-binding-skipped',[rot3],p2,{operation:'resolve',currentEpub:epub,diagnosticReasons:['bad-sequence'],genesisEpubBindings:[binding,genesisBinding(principal(10),at+50)]});
accept('records','binding-clock-skew',[],p,{operation:'resolve',currentEpub:boundPoint,now:at-30,policy:{...context.policy,clockSkewSeconds:60},genesisEpubBindings:[binding]});
const {attest:_unattestedAttest,...unattestedRot3}=rot3;
accept('records','r2-publish-signed-unattested-candidate',{candidate:unattestedRot3,siblings:[],prior:[]},p,{operation:'publish-check',now:at+30});
bad('r2-rotation-request-bad-signature',{...unattestedRot3,nextSig:'AA'},'bad-signature','rotation-request',{now:at+30});
const skewPolicy={...context.policy,clockSkewSeconds:60};
const backdated=(()=>{ const row=rotationV3('wallet',p3,3,1,p,at+15,[wid],principal(8)); const {attest:_a,...req}=row; return req; })();
bad('r3-request-backdated-before-revoke',backdated,'rotation-conflict','rotation-request',{now:at+60,policy:skewPolicy,revocations:[rev]});
bad('r3-publish-backdated-before-revoke',{candidate:backdated,siblings:[],prior:[]},'rotation-conflict','publish-check',{now:at+60,policy:skewPolicy,revocations:[rev]});
bad('r3-request-stale',unattestedRot3,'expired','rotation-request',{now:at+100000});
bad('r3-publish-stale',{candidate:unattestedRot3,siblings:[],prior:[]},'expired','publish-check',{now:at+100000});
bad('r3-request-offline-revoke',unattestedRot3,'revoked-link','rotation-request',{now:at+30,revocations:[offline(rev)]});
bad('r3-publish-offline-revoke',{candidate:unattestedRot3,siblings:[],prior:[]},'revoked-link','publish-check',{now:at+30,revocations:[offline(rev)]});
const {attest:_v2attest,...v2request}=rot;
bad('r3-request-v2',v2request,'bad-record','rotation-request',{now:at+30});
bad('r3-request-forged-attest',{...unattestedRot3,attest:'aa.bb.cc'},'bad-record','rotation-request',{now:at+30});
const seq5=(()=>{ const row=rotationV3('wallet',p3,3,5,p,at+30,[wid],principal(8)); const {attest:_a,...req}=row; return req; })();
accept('records','r3-request-seq-not-local',seq5,p,{operation:'rotation-request',now:at+30});
bad('r3-publish-seq-not-local',{candidate:seq5,siblings:[],prior:[]},'bad-sequence','publish-check',{now:at+30});
const {authorizer:_missingAuthorizer,...missingAuthorizer}=unattestedRot3;
bad('r3-request-missing-authorizer',missingAuthorizer,'bad-record','rotation-request',{now:at+30});
bad('r3-publish-request-missing-authorizer',{candidate:missingAuthorizer,siblings:[],prior:[]},'bad-record','publish-check',{now:at+30});
accept('records','r3-binding-valid-after-expiry',[],p,{operation:'resolve',currentEpub:boundPoint,now:at+2000,genesisEpubBindings:[binding]});
const lateSibling=(()=>{ const row=rotationV3('wallet',principal(8),8,1,p,at+1500,[wid],principal(11)); const {attest:_a,...req}=row; return req; })();
bad('r3-publish-expired-sibling-forks',{candidate:lateSibling,siblings:[rot3],prior:[]},'rotation-fork','publish-check',{now:at+1500});
const {attest:_bindingAttest,...bindingRequest}=binding;
accept('records','r3-genesis-epub-request',bindingRequest,p,{operation:'genesis-epub-request',now:at});
bad('r3-genesis-epub-request-bad-signature',{...bindingRequest,keySig:'AA'},'bad-signature','genesis-epub-request',{now:at});
bad('r3-genesis-epub-request-stale',bindingRequest,'expired','genesis-epub-request',{now:at+100000});
bad('r3-genesis-epub-request-future',(()=>{ const row=genesisBinding(boundPoint,at+1000); const {attest:_a,...req}=row; return req; })(),'future-record','genesis-epub-request',{now:at});
bad('r3-genesis-epub-request-forged-attest',{...bindingRequest,attest:'aa.bb.cc'},'bad-record','genesis-epub-request',{now:at});
bad('r3-genesis-epub-request-equals-genesis',{v:1,kind:'genesis-epub',principal:p,epub:p,issuedAt:at,keySig:'AA'},'bad-record','genesis-epub-request',{now:at});
accept('records','r3-genesis-epub-request-skew',bindingRequest,p,{operation:'genesis-epub-request',now:at+30,policy:skewPolicy});
{
  const body={v:1,kind:'rotate',principal:p,seq:rot3.seq,prevKey:p,nextKey:p2,nextEpub:epub,issuedAt:rot3.issuedAt,retainedLinks:[],authorizer:{kind:'wallet',link:wid}};
  const sibling={...body,nextSig:keySig(body,2),authorizer:{...body.authorizer,siwe:siwe(body)},attest:rot3.attest};
  accept('records','r2-publish-altered-claim-sibling',{candidate:rot3,siblings:[sibling],prior:[]},p,{operation:'publish-check'});
}
const draftLinks={v:1,kind:'rotate',principal:p,seq:1,prevKey:p,nextKey:p2,nextEpub:epub,retainedLinks:[wid]};
accept('records','r2-publish-draft-retained-links',{candidate:draftLinks,siblings:[],prior:[]},p,{operation:'draft-check',retainedLinks:[wid]});
bad('r2-publish-draft-retained-junk',{candidate:{...draftLinks,retainedLinks:['zz']},siblings:[],prior:[]},'bad-record','draft-check');
const draftSame={v:1,kind:'rotate',principal:p,seq:rot3.seq,prevKey:rot3.prevKey,nextKey:rot3.nextKey,nextEpub:rot3.nextEpub,retainedLinks:rot3.retainedLinks};
accept('records','r2-publish-draft-identical-sibling',{candidate:draftSame,siblings:[rot3],prior:[]},p,{operation:'draft-check'});
bad('r2-publish-draft-different-sibling',{candidate:{...draftSame,nextEpub:epub2},siblings:[rot3],prior:[]},'rotation-fork','draft-check');
bad('r4-publish-unsigned-draft',{candidate:draftLinks,siblings:[],prior:[]},'bad-record','publish-check');
bad('r4-draft-signed-record',{candidate:rot3,siblings:[],prior:[]},'bad-record','draft-check');
accept('records','r4-verify-rotate-after-expiry',rot3,p,{operation:'rotate',now:at+100000,nextEpub:epub});
const skew60={...context.policy,clockSkewSeconds:60};
const freshRequest=(()=>{ const row=rotationV3('wallet',p2,2,1,p,at+60,[wid],epub); const {attest:_a,...req}=row; return req; })();
const offlineRevokeAt = issuedAt => { const row = { v: 1, kind: 'revoke', principal: p, linkId: wid, issuedAt }; row.keySig = keySig(row); return row; };
const withinSkew = offlineRevokeAt(at + 90);
const beyondSkew = offlineRevokeAt(at + 121);
bad('r4-request-offline-revoke-within-skew',freshRequest,'revoked-link','rotation-request',{now:at+60,policy:skew60,revocations:[withinSkew]});
bad('r4-publish-offline-revoke-within-skew',{candidate:freshRequest,siblings:[],prior:[]},'revoked-link','publish-check',{now:at+60,policy:skew60,revocations:[withinSkew]});
accept('records','r4-request-offline-revoke-beyond-skew',freshRequest,p,{operation:'rotation-request',now:at+60,policy:skew60,revocations:[beyondSkew]});
accept('records','r4-publish-offline-revoke-beyond-skew',{candidate:freshRequest,siblings:[],prior:[]},p,{operation:'publish-check',now:at+60,policy:skew60,revocations:[beyondSkew]});
bad('r4-revoke-now-ignores-skew',withinSkew,'future-record','revoke-now',{now:at+60,policy:skew60});
accept('records','r4-rotate-ignores-future-offline-revoke',rot3,p,{operation:'rotate',now:at+60,policy:skew60,revocations:[withinSkew],nextEpub:epub});
const oidcBackdated=(()=>{ const row=rotationV3('oidc-fresh-login',p2,2,1,p,at+45,[oid],epub); const {attest:_a,...req}=row; return req; })();
const walletWithinHorizon=walletLink(p,at+50);
const walletBeyondHorizon=walletLink(p,at+121);
const withinLinks=[[val(ids.linkId(walletWithinHorizon)),walletWithinHorizon],[oid,oidc]];
const beyondLinks=[[val(ids.linkId(walletBeyondHorizon)),walletBeyondHorizon],[oid,oidc]];
bad('r5-request-oidc-wallet-within-skew',oidcBackdated,'wallet-required','rotation-request',{now:at+60,policy:skew60,links:withinLinks});
bad('r5-publish-oidc-wallet-within-skew',{candidate:oidcBackdated,siblings:[],prior:[]},'wallet-required','publish-check',{now:at+60,policy:skew60,links:withinLinks});
accept('records','r5-request-oidc-wallet-beyond-horizon',oidcBackdated,p,{operation:'rotation-request',now:at+60,policy:skew60,links:beyondLinks});

accept('signing-bytes','length-prefixed-decimals',['1','900','0'],hex(val(ids.lengthPrefixed(['1','900','0']))),{operation:'length-prefixed'});
accept('signing-bytes','length-prefixed-utf8',['é'],hex(val(ids.lengthPrefixed(['é']))),{operation:'length-prefixed'});
reject('signing-bytes','length-prefixed-null',[null],'not-string',{operation:'length-prefixed'});
reject('signing-bytes','length-prefixed-number',[1],'not-string',{operation:'length-prefixed'});
reject('signing-bytes','length-prefixed-object',[{toString:'no coercion'}],'not-string',{operation:'length-prefixed'});
reject('signing-bytes','length-prefixed-surrogate',['\ud800'],'unpaired-surrogate',{operation:'length-prefixed'});
const root = new URL('../../../vectors/ids/',import.meta.url); mkdirSync(root,{recursive:true});
for(const [name,value] of families) writeFileSync(new URL(name+'.json',root),JSON.stringify(value,null,2).replace(/"issuedAt": 1700000000,/g, name==='edges'?'"issuedAt": 1700000000,':'"issuedAt": 1700000000.0,')+'\n');
writeFileSync(new URL('test-keys.json',new URL('../test/',import.meta.url)),JSON.stringify({p,p2,p3,wallet,tenant,obj,network,source,secretScalars:[1,2,3,4,5]},null,2)+'\n');
console.log(`Wrote ${families.size} vector families`);
