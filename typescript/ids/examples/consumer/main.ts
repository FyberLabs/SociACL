import { parseTenantId, mintObjectId, objectSoul, grantSoul, parsePrincipalId, parseEip55, verifyRevokeNow, verifyRevoke, resolveWalletLinkNow, resolveWalletLink, historyState, type Revoke, type ResolutionContext, type ObjectId } from 'sociacl-ids';
const tenant = parseTenantId('01234567-89ab-cdef-0123-456789abcdef');
if (!tenant.ok) throw Error(tenant.reason);
const creator = parsePrincipalId('axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU');
if (!creator.ok) throw Error(creator.reason);
const created = mintObjectId('room', creator.value);
if (!created.ok) throw Error(created.reason);
const object: ObjectId = created.value;
if (!objectSoul('rooms', object).startsWith('s3rch/rooms/room_')) throw Error('consumer failed');
// @ts-expect-error Strings cannot be supplied as validated object ids.
const rejectUnparsed: ObjectId = 'raw';
void rejectUnparsed;

if (false) {
  // @ts-expect-error Packed declarations reject all three raw grant components.
  grantSoul('a', 'b', 'c');
}

// Fixed public test-only proofs from the shared corpus; no production credentials.
const fixture = {
  "revoke": {
    "v": 1,
    "kind": "revoke",
    "principal": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
    "linkId": "a90854a50712c3e090e4076385bec9d30c6831d5f04838c0589442ca23e74b1b",
    "issuedAt": 1700000020,
    "keySig": "pHHN9eC_0UxEflRA-aUtAl-AEPJKk_r7ddAeWArvc2gNLaKKm3k6KVAS-V6Al9IjNgmw57zbvU-4c3AOZRCoFQ"
  },
  "wallet": {
    "v": 1,
    "kind": "wallet",
    "principal": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY.T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
    "address": "0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718",
    "issuedAt": 1700000000.0,
    "nonce": "fixtureNonce123",
    "keySig": "iGXFYXbObvjtpzvvcJNRvvtTUMBsAmGZTGE7-ad8z7nRrW3jpyOLjUEBtoWqBWcx-jQ9QFDI7q9mA87wjAx9Og",
    "siwe": {
      "message": "s3r.ch wants you to sign in with your Ethereum account:\n0x1efF47bc3a10a45D4B230B5d10E37751FE6AA718\n\nSociACL link: a90854a50712c3e090e4076385bec9d30c6831d5f04838c0589442ca23e74b1b\n\nURI: https://s3r.ch/identity/link\nVersion: 1\nChain ID: 1\nNonce: fixtureNonce123\nIssued At: 2023-11-14T22:13:20Z",
      "signature": "0x84f6351b818c4597a06fbd9ae610321829dd7f9772701523c81e0023ee3738de53b9ea0083ce42b57e0bb525e6760b07cfc370a3e1d52f021f235b1acdfc0da31c"
    },
    "attest": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImZpeHR1cmUtMSIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJzb2NpYWNsLXdhbGxldC1hdHRlc3QtdjEiLCJwcmluY2lwYWwiOiJheGZSOHVFc1FrZjR2T2JsWTZSQThuY0RmWUV0NnpPZzlLRTVSZGlZd3BZLlQtTkM0djRhZjV1TzUtdEtmQS1lRml2T00xZHJNVjdPeTdaQWFEZV9VZlUiLCJsaW5rSWQiOiJhOTA4NTRhNTA3MTJjM2UwOTBlNDA3NjM4NWJlYzlkMzBjNjgzMWQ1ZjA0ODM4YzA1ODk0NDJjYTIzZTc0YjFiIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDA2MDB9.DbQ76adinFQJrdClbGXh_FwZd9KeYKAVSQirRzvG-4yP2xbuVLZZLkmSK3ljqUyg51AqPhdXQvvmnOb2axKcbg"
  },
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "kid": "fixture-1",
        "notBefore": 1699999000,
        "notAfter": 1700010000,
        "x": "UVkLelFRQNLXhMhWCGaP3--Mgv0fW-UkIVVKDcPQM-0",
        "y": "4MF9qJBKcn2K4b82v4p5Jg0BLwDU2AiI0dC7RP2hbaQ",
        "alg": "ES256",
        "use": "sig",
        "key_ops": [
          "verify"
        ]
      }
    ]
  },
  "now": 1700000060
} as const;
const current = parsePrincipalId(fixture.revoke.principal);
const address = parseEip55(fixture.wallet.address);
if (!current.ok || !address.ok) throw Error('invalid fixture identity');
// The packed Revoke declaration must allow omission of the timestamp witness.
const revoke: Revoke = {...fixture.revoke, principal: current.value};
const present = verifyRevokeNow(revoke, current.value, fixture.now);
const historical = verifyRevoke(revoke, current.value, fixture.jwks, fixture.now);
if (!present.ok || historical.ok || historical.reason !== 'bad-attestation') throw Error('revoke boundary failed');
const context: ResolutionContext = {
  jwks: fixture.jwks, links: new Map([[revoke.linkId,fixture.wallet]]),
  pinnedIss: new Set(), now: fixture.now,
  policy: {allowedDomains:['s3r.ch'],allowedUris:['https://s3r.ch/identity/link'],allowedChainIds:['1']},
  // This fixture's complete authenticated account history contains no rotations.
  history: (p,at,until) => ({ok:true,value:historyState(p,[],at,until)}),
};
const lookup = resolveWalletLinkNow(address.value,[fixture.wallet],[revoke],context);
const asOf = resolveWalletLink(address.value,[fixture.wallet],[revoke],context);
if (lookup.ok || lookup.reason !== 'revoked-link' || !asOf.ok) throw Error('lookup boundary failed');
console.log('Installed tarball parsers, declarations and present/history revocation work');

import { verifyWitnessPolicyEnvelope } from 'sociacl-ids';
if (verifyWitnessPolicyEnvelope('{}', '', 'test', 0).ok) throw Error('invalid policy accepted');

import { advanceWitnessPolicy } from 'sociacl-ids';
if (advanceWitnessPolicy('{}', null, '', 'test', 1, 0).ok) throw Error('invalid transition accepted');

// Browser adapter declarations and optional subpath ship in the tarball.
import { openWitnessPolicyStore } from 'sociacl-ids/indexeddb';
if (typeof openWitnessPolicyStore !== 'function') throw Error('missing IndexedDB export');
if (false) {
  const store = await openWitnessPolicyStore({ name: 'test', root: '', audience: 'test', minimumRevision: 7, now: () => 1700000000 });
  const state = await store.read();
  const revision: number = state.revision;
  void revision;
  store.close();
}


import { openWitnessPolicyClient } from 'sociacl-ids/witness-client';
if (typeof openWitnessPolicyClient !== 'function') throw Error('missing witness client export');
if (false) {
  const client = await openWitnessPolicyClient({ name: 'policy', root: '', audience: 'deployment',
    minimumRevision: 7, now: () => 1700000000, url: 'https://policy.example/api/v1/acl/sociacl/witness-policy' });
  const revision: number = (await client.refresh({ signal: new AbortController().signal })).revision;
  void revision;
  client.close();
}

import { verifyWitnessCheckpoint, type WitnessCheckpointExpectations } from 'sociacl-ids';
const checkpointContext: WitnessCheckpointExpectations = { managementRoot: '', root: '', rootEpoch: 1,
  audience: 'deployment', client: 'enrollment', challenge: '', minimumRevision: 1, now: 1700000000 };
if (verifyWitnessCheckpoint('{}', '{}', checkpointContext).ok) throw Error('invalid checkpoint accepted');
