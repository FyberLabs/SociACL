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
  | 'rotation-fork' | 'rotation-conflict' | 'unknown-link' | 'revoked-link' | 'ambiguous-link' | 'unsupported-wallet'
  | 'rng-failure' | 'missing-history' | 'unretained-link' | 'wallet-required';
export type Result<T> = { ok: true; value: T } | { ok: false; reason: Reason };
export type Collection = 'items' | 'rooms' | 'users-legacy';
export type ParsedSoul = { template: 'object' | 'user' | 'acl' | 'grant' | 'post'; ids: readonly string[] };
export type Siwe = Readonly<{ message: string; signature: `0x${string}` }>;
export type WalletLink = Readonly<{ v: 1; kind: 'wallet'; principal: PrincipalId; address: Eip55;
  issuedAt: number; nonce: string; keySig: string; siwe: Siwe; attest: string }>;
export type OidcLink = Readonly<{ v: 1; kind: 'oidc'; principal: PrincipalId; cred: OidcCredential;
  issuedAt: number; nonce: string; keySig: string; attest: string }>;
export type Rotate = Readonly<{ v: 1; kind: 'rotate'; principal: PrincipalId; seq: number;
  prevKey: PrincipalId; nextKey: PrincipalId; retainedLinks: readonly string[]; issuedAt: number; nextSig: string;
  authorizer: { kind: 'wallet'; link: string; siwe: Siwe } | { kind: 'oidc-fresh-login'; link: string }; attest: string }>;
export type Revoke = Readonly<{ v: 1; kind: 'revoke'; principal: PrincipalId; linkId: string;
  issuedAt: number; keySig: string; attest: string }>;
export type IdentityRecord = WalletLink | OidcLink | Rotate | Revoke;
export type UnsignedRecord = Omit<WalletLink, 'keySig' | 'siwe' | 'attest'> | Omit<OidcLink, 'keySig' | 'attest'>
  | (Omit<Rotate, 'nextSig' | 'authorizer' | 'attest'> & {authorizer: {kind:'wallet'|'oidc-fresh-login';link:string}}) | Omit<Revoke, 'keySig' | 'attest'>;
export type Jwks = Readonly<{ keys: readonly Readonly<{ kty: 'EC'; crv: 'P-256'; kid: string;
  x: string; y: string; alg?: 'ES256'; use?: 'sig'; key_ops?: readonly string[] }>[] }>;
export type SiwePolicy = Readonly<{ allowedDomains: readonly string[]; allowedUris: readonly string[]; allowedChainIds: readonly string[]; clockSkewSeconds?: number }>;
// Authenticated at `until`, key active strictly before `at`. null means no later rotation;
// otherwise retainedLinks is the intersection of every rotation's commitments from at through until.
export type KeyState = Readonly<{ key: PrincipalId; currentKey: PrincipalId; retainedLinks: readonly string[] | null }>;
export type HistoryResolver = (principal: PrincipalId, at: number, until: number) => Result<KeyState>;
export type Diagnostic = Readonly<{ source: 'rotation' | 'link' | 'revoke'; index: number; reason: Reason }>;
export type Resolution<T> = Result<T> & { diagnostics: readonly Diagnostic[] };
export type ResolvedAccount = Readonly<{ currentKey: PrincipalId; rotations: readonly Rotate[] }>;
export type ResolutionContext = Readonly<{ jwks: Jwks; links: ReadonlyMap<string, unknown>;
  revocations?: readonly unknown[]; now: number; policy: SiwePolicy; pinnedIss: ReadonlySet<string>; history: HistoryResolver }>;
