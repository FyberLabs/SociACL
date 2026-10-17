declare const brand: unique symbol;
export type Brand<T, B extends string> = T & { readonly [brand]: B };
export type PrincipalId = Brand<string, 'PrincipalId'>;
export type PrincipalKey = Brand<string, 'PrincipalKey'>;
export type Eip55 = Brand<string, 'Eip55'>;
export type TenantId = Brand<string, 'TenantId'>;
export type OidcCredential = Readonly<{ iss: string; tenant: TenantId; sub: string }>;
export type ObjectId = Brand<string, 'ObjectId'>;
// A separate brand avoids intersecting two incompatible values of the same symbol.
declare const minted: unique symbol;
export type MintedObjectId = ObjectId & { readonly [minted]: true };
export type NetworkId = Brand<string, 'NetworkId'>;
export type SourceKey = Brand<string, 'SourceKey'>;
export type PathKey = Brand<string, 'PathKey'>;
export type Soul = Brand<string, 'Soul'>;
export type Reason = 'not-string' | 'empty' | 'too-long' | 'control-char' | 'invisible-char'
  | 'unpaired-surrogate' | 'whitespace' | 'bad-alphabet' | 'bad-length' | 'non-canonical'
  | 'bad-checksum' | 'not-on-curve' | 'reserved-kind' | 'unknown-network' | 'bad-host'
  | 'bad-port' | 'gun-chain' | 'bad-template' | 'bad-record' | 'bad-signature'
  | 'bad-attestation' | 'untrusted-issuer' | 'expired' | 'future-record' | 'bad-sequence'
  | 'rotation-fork' | 'unknown-link' | 'revoked-link' | 'ambiguous-link' | 'unsupported-wallet'
  | 'rng-failure';
export type Result<T> = { ok: true; value: T } | { ok: false; reason: Reason };
export type Collection = 'items' | 'rooms' | 'users-legacy';
export type ParsedSoul = { template: 'object' | 'user' | 'acl' | 'grant' | 'post'; ids: readonly string[] };
export type Siwe = Readonly<{ message: string; signature: `0x${string}` }>;
export type WalletLink = Readonly<{ v: 1; kind: 'wallet'; principal: PrincipalId; address: Eip55;
  issuedAt: number; nonce: string; keySig: string; siwe: Siwe }>;
export type OidcLink = Readonly<{ v: 1; kind: 'oidc'; principal: PrincipalId; cred: OidcCredential;
  issuedAt: number; nonce: string; keySig: string; attest: string }>;
export type Rotate = Readonly<{ v: 1; kind: 'rotate'; principal: PrincipalId; seq: number;
  prevKey: PrincipalId; nextKey: PrincipalId; issuedAt: number; nextSig: string;
  authorizer: { kind: 'wallet'; link: string; siwe: Siwe } | { kind: 'oidc-fresh-login' }; attest: string }>;
export type Revoke = Readonly<{ v: 1; kind: 'revoke'; principal: PrincipalId; linkId: string;
  issuedAt: number; keySig: string }>;
export type IdentityRecord = WalletLink | OidcLink | Rotate | Revoke;
export type UnsignedRecord = Omit<WalletLink, 'keySig' | 'siwe'> | Omit<OidcLink, 'keySig' | 'attest'>
  | Omit<Rotate, 'nextSig' | 'authorizer' | 'attest'> | Omit<Revoke, 'keySig'>;
export type Jwks = Readonly<{ keys: readonly Readonly<{ kty: 'EC'; crv: 'P-256'; kid: string;
  x: string; y: string; alg?: 'ES256'; use?: 'sig'; key_ops?: readonly string[] }>[] }>;
export type ResolutionContext = Readonly<{ jwks: Jwks; links: ReadonlyMap<string, WalletLink>;
  revocations?: readonly unknown[]; now: number }>;
