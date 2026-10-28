// Public test scalars only. Never deploy these administrative or witness keys.
import { writeFileSync } from 'node:fs';
import { p256 } from '@noble/curves/nist.js';
import { verifyWitnessPolicyEnvelope } from '../src/index.js';
const secret = n => { const out = new Uint8Array(32); out[31] = n; return out; };
const b64 = b => Buffer.from(b).toString('base64url');
const principal = n => { const p = p256.getPublicKey(secret(n), false); return b64(p.slice(1,33)) + '.' + b64(p.slice(33)); };
const root = principal(17), point = principal(19), audience = 'panopticon-test', now = 1700000000;
const jwk = { kid: 'witness-1', kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', key_ops: ['verify'],
  x: point.slice(0,43), y: point.slice(44), notBefore: now - 1000, notAfter: now + 1000 };
const doc = { type: 'sociacl-witness-policy-v1', audience, revision: 7, issuedAt: now - 1, expiresAt: now + 60, jwks: { keys: [jwk] } };
const make = (value=doc, options={}) => {
  const payload = Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
  const message = Buffer.concat([Buffer.from(options.domain ?? 'sociacl-witness-policy-v1\n'), payload]);
  const sig = p256.sign(message, secret(options.scalar ?? 17), {lowS:true});
  return JSON.stringify({type:'sociacl-witness-policy-envelope-v1',payload:b64(payload),signature:b64(sig)});
};
const accept=[], reject=[];
const yes=(name,value=doc,ctx={})=>accept.push({name,input:make(value),canonical:typeof value==='string'?JSON.parse(value):value,...ctx});
const no=(name,input,ctx={})=>reject.push({name,input,reason:'bad-attestation',...ctx});
const change=(name,fn)=>{const d=structuredClone(doc);fn(d);no(name,make(d));};
yes('publisher-compact-export'); yes('exact-whitespace-bytes',JSON.stringify(doc,null,2)+'\n');
yes('empty-policy-removes-trust',{...doc,jwks:{keys:[]}});
yes('retired-witness-retained',{...doc,jwks:{keys:[{...jwk,notAfter:now-1}]}});
yes('issuance-inclusive',doc,{now:doc.issuedAt}); yes('expiry-last-second',doc,{now:doc.expiresAt-1});
yes('maximum-lifetime',{...doc,expiresAt:doc.issuedAt+86400});
yes('unicode-key-id',{...doc,jwks:{keys:[{...jwk,kid:'🔑'.repeat(128)}]}});
no('wrong-root',make(),{root:principal(18)}); no('bad-root',make(),{root:'not-a-key'});
no('wrong-audience',make(),{audience:'another-deployment'}); no('empty-audience',make(),{audience:''});
no('expired-at-boundary',make(),{now:doc.expiresAt}); no('future-at-boundary',make(),{now:doc.issuedAt-1});
no('unsafe-clock',make(),{now:9007199254740992}); no('wrong-signing-domain',make(doc,{domain:'another-domain\n'}));
for (const [field,value] of [['revision',0],['revision',true],['revision',9007199254740992],['revision',1.5],['issuedAt',true],['expiresAt',doc.issuedAt],['expiresAt',doc.issuedAt+86401],['type','other']]) change(`${field}-${value}`,d=>{d[field]=value;});
change('unknown-document-field',d=>{d.root=root;}); change('unknown-jwks-field',d=>{d.jwks.root=root;});
change('duplicate-kid',d=>{d.jwks.keys.push({...jwk,x:principal(20).slice(0,43),y:principal(20).slice(44)});});
change('duplicate-material',d=>{d.jwks.keys.push({...jwk,kid:'another'});});
for(const [field,value] of [['d','secret'],['extra',true],['alg','ES384'],['kty','RSA'],['crv','P-384'],['key_ops',['sign']],['key_ops',['verify','verify']],['use','enc'],['notBefore',now+1000],['notAfter',true],['notBefore',-1],['kid',''],['kid','x'.repeat(129)],['x',jwk.x+'='],['x','A'.repeat(43)]]) change(`key-${field}-${JSON.stringify(value).slice(0,30)}`,d=>{d.jwks.keys[0][field]=value;});
change('root-is-witness',d=>{d.jwks.keys[0].x=root.slice(0,43);d.jwks.keys[0].y=root.slice(44);});
change('missing-window',d=>{delete d.jwks.keys[0].notBefore;});
no('duplicate-document-member',make(JSON.stringify(doc).replace('"revision":7','"revision":6,"revision":7')));
no('escaped-duplicate-member',make(JSON.stringify(doc).replace('"revision":7','"revision":6,"rev\\u0069sion":7')));
no('duplicate-key-member',make(JSON.stringify(doc).replace('"kid":"witness-1"','"kid":"other","kid":"witness-1"')));
no('fractional-integer-spelling',make(JSON.stringify(doc).replace('"revision":7','"revision":7.0')));
no('exponent-integer-spelling',make(JSON.stringify(doc).replace('"revision":7','"revision":7e0')));
no('negative-zero',make(JSON.stringify(doc).replace('"revision":7','"revision":-0')));
no('invalid-utf8',make(Buffer.from([0xff]))); no('utf8-bom',make('\ufeff'+JSON.stringify(doc)));
no('payload-over-limit',make(' '.repeat(262145)));
// A maximum-size valid payload must not overflow the base64 decoder's call stack.
yes('payload-at-limit',JSON.stringify(doc)+' '.repeat(262144-Buffer.byteLength(JSON.stringify(doc))));
const outer=JSON.parse(make());
for(const field of ['payload','signature']) no(`padded-${field}`,JSON.stringify({...outer,[field]:outer[field]+'='}));
no('changed-bytes',JSON.stringify({...outer,payload:b64(Buffer.from(JSON.stringify(doc)+' '))}));
no('wrong-envelope-type',JSON.stringify({...outer,type:'other'}));
no('untrusted-root-hint',JSON.stringify({...outer,root}));
no('duplicate-envelope-member',JSON.stringify(outer).replace('"type":','"type":"other","type":'));
no('envelope-over-limit',' '.repeat(360449));
const raw=Buffer.from(outer.signature,'base64url'), order=p256.Point.Fn.ORDER;
const high=order-BigInt('0x'+raw.subarray(32).toString('hex'));
no('high-s-signature',JSON.stringify({...outer,signature:b64(Buffer.concat([raw.subarray(0,32),Buffer.from(high.toString(16).padStart(64,'0'),'hex')]))}));
no('short-signature',JSON.stringify({...outer,signature:b64(raw.subarray(1))}));
for(const c of accept) {const r=verifyWitnessPolicyEnvelope(c.input,c.root??root,c.audience??audience,c.now??now);if(!r.ok)throw Error(c.name+': '+r.reason);}
for(const c of reject) {const r=verifyWitnessPolicyEnvelope(c.input,c.root??root,c.audience??audience,c.now??now);if(r.ok)throw Error('unexpected accept '+c.name);}
writeFileSync(new URL('../../../vectors/ids/witness-policy.json',import.meta.url),JSON.stringify({v:1,family:'witness-policy',context:{root,audience,now},accept,reject},null,2)+'\n');
console.log(`${accept.length} accepted, ${reject.length} rejected policy fixtures`);
