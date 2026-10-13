/**
 * Light Check consume contract for s3r.ch.
 *
 * Copy or re-type these names in the Next app. Run Check in the
 * browser on the Gun mesh. Do not import the SociACL Rust crate.
 * Do not add this file as an npm package. This is a contract, not
 * a dependency.
 *
 * Reference implementation (Rust, this repo): crates/sociacl-gun.
 *
 * CHECK(see, object, accessor) at now.
 *   object   = GunFeedNode | held claim id | later opaque post/room
 *   claim id = the id itself (ens:… / unstoppable:… / fc:… / lens:… /
 *              rss3:…), linked from GunUserNode.indicators
 *   Do not invent s3rch/users/<wallet>/claims/…
 *   accessor = wallet / Gun peer
 *   hopcap 1, jointly stated grants
 *   revoke   = immediate for a current verifier; otherwise bounded by max-age
 *   hop      = optional Social Light factor; never a grant
 *   wrap     = SEA epub wrap of a DEK; never a grant
 *   same-group / named-circle = direct edges only; no transitive inheritance
 *
 * Wrapped keys, recipient-side discovery, rotation on revoke:
 * docs/encrypted-discovery.md. Spec only. The reference crate does
 * not evaluate these types yet. SEA priv and epriv never go on Gun.
 */

/** Fixed Gun root. */
export type S3rchRoot = "s3rch";

export type FeedSource = "rss3" | "rss" | "atom";

/**
 * In-graph feed node. Native Check object.
 * gun.get('s3rch').get('items').get(encodeKey(id))
 * Gun cannot store arrays: `tags` is a comma-separated string.
 */
export type GunFeedNode = {
  id: string;
  source: string;
  kind: string;
  author: string;
  body: string;
  ts: number;
  permalink: string;
  tags: string;
  provenance: string;
};

/**
 * UX only. tags is a list. Mapping is toGunNode / fromGunNode.
 * Dedupe: canonical id, else normalized permalink.
 */
export type FeedItem = {
  id: string;
  source: FeedSource;
  kind: string;
  author: string;
  body: string;
  ts: number;
  permalink: string;
  tags: string[];
  provenance: string;
};

/**
 * Fixed user node. gun.get('s3rch').get('users').get(wallet)
 * `indicators` are held-claim ids (ens:… / unstoppable:… / fc:… /
 * lens:… / rss3:…). On the Gun wire they are a comma-separated
 * string. Overlay uses this same shape (origin IndexedDB) until
 * s3r.ch prepareShareUserIntoMesh / prepareShareClaimIntoMesh.
 * Do not invent s3rch/users/<wallet>/claims/… or a second user node.
 */
export type GunUserNode = {
  id: string;
  indicators: string[];
  provenance: string;
  ts: number;
};

/**
 * Held-claim CheckObjectId prefixes fixed by s3r.ch.
 * The object id is the claim id itself, linked from
 * GunUserNode.indicators. Same Mesh Check path as a GunFeedNode id.
 */
export type HeldClaimPrefix =
  | "ens:"
  | "unstoppable:"
  | "fc:"
  | "lens:"
  | "rss3:";

/** Issuers prove a claim to the holder. They are not grants. */
export type IdentityClaimKind =
  | "wallet"
  | "rss3"
  | "ens"
  | "kyc_attestation"
  | "email"
  | "phone";

/**
 * Jointly stated see grant. hopcap 1. Privilege-down is immediate.
 * `from` inclusive, `until` exclusive. Dest stores `until`; Check
 * ANDs now ∈ [from, until).
 */
export type IdentitySeeGrant = {
  claimId: string;
  accessor: string;
  from: number;
  until: number;
};

/**
 * Untrusted edge handoff (ingest / seeder / URL cross).
 * user/agent id as we name them, claimed target, optional verb/context.
 * Decode does not verify. A hint never sets allowed.
 */
export type HandoffHint = {
  principal: string;
  target: string;
  verb?: string;
  context?: string;
};

/**
 * Permalink, RSS3 GI, RSS/Atom, or issuer HTTP.
 * Not a Gun node. Not a grant. A URL 200 is not see.
 */
export type UrlLeaf = {
  url: string;
};

/** Seed cache. gun.get('s3rch').get('meta'). Not a Check object. */
export type FeedMeta = {
  seededAt?: string;
  sourcesOk: number;
  sourcesTried: number;
  error?: string;
  count: number;
};

/**
 * Mesh Check / hop `object`. Examples:
 *   s3rch/items/<encodeKey(id)>     GunFeedNode
 *   ens:name.eth                    held claim (ENS)
 *   unstoppable:name.crypto         held claim (Unstoppable)
 *   fc:name                         held claim (Farcaster)
 *   lens:name                       held claim (Lens)
 *   rss3:0x…                        held claim (RSS3)
 * Claim id = the id itself, linked from GunUserNode.indicators.
 * Same checkSee / hop path as a GunFeedNode id.
 * Do not invent s3rch/users/<wallet>/claims/….
 * Later posts/rooms are opaque — s3r.ch owns those souls.
 */
export type CheckObjectId = string;

/** Wallet or s3rch/users/{wallet}. */
export type AccessorId = string;

export type CheckResult = {
  allowed: boolean;
  /**
   * Predicate / deny reason. A present hint never makes this a grant.
   * A present hop never makes this a grant.
   * A present wrap never makes this a grant.
   */
  reason: string;
};

/**
 * Live graph the browser reads. Only in-graph objects and jointly
 * stated see grants. Do not walk friend edges (hopcap 1).
 *
 * Mesh: each peer evaluates against its locally HAM-merged Gun graph
 * at now. Do not cache an allow across a privilege-down merge.
 */
export type SeeGraph = {
  hasObject(object: CheckObjectId): boolean;
  ownerOf(object: CheckObjectId): AccessorId | undefined;
  seeGrants(object: CheckObjectId): readonly IdentitySeeGrant[];
  /**
   * Object version this verifier has merged. Absent when the
   * object is missing. Encrypted re-check compares a zookie to
   * this value. A presenter-supplied version is not a substitute.
   */
  objectVersion(object: CheckObjectId): number | undefined;
  /**
   * Snapshot hash of this object on the verifier's merged graph.
   * Same binding as a zookie: one object, one hash. Absent when
   * the object is missing. A zookie is compared to
   * snapshotHash(zookie.object), not to a graph-wide hash.
   */
  snapshotHash(object: CheckObjectId): string | undefined;
};

/** Writable dest ACL. Cancel and admit land here, not on a URL. */
export type SeeAcl = SeeGraph & {
  putObject(object: CheckObjectId, owner: AccessorId): void;
  stateSeeGrant(owner: AccessorId, grant: IdentitySeeGrant): void;
  unstateSeeGrant(
    owner: AccessorId,
    accessor: AccessorId,
    object: CheckObjectId,
  ): void;
};

/** id.replace(/[.#$\[\]]/g, '_') */
export function encodeKey(id: string): string;

/** s3rch/items/<encodeKey(id)> */
export function itemSoul(id: string): string;

/** s3rch/users/<wallet> */
export function userSoul(wallet: string): string;

/** s3rch/meta — not a Check object. */
export function metaSoul(): string;

export function toGunNode(item: FeedItem): GunFeedNode;

/** Unknown source is not a feed node. Empty kind → "activity". */
export function fromGunNode(
  node: Partial<GunFeedNode> | null | undefined,
): FeedItem | null;

/** Does not verify. Does not mint. */
export function acceptHint(hint: HandoffHint): HandoffHint;

/**
 * CHECK(see, object, accessor) at now.
 * see maps to dest read. Hint is ignored for allowed.
 * Hop missing does not fail. Hop alone never allows. Hop may only
 * factor an already-named grant or owner path.
 * Owner sees their object. Else a live IdentitySeeGrant / MeshSeeGrant
 * must name this pair and now ∈ [from, until). meta, dest ACL souls,
 * and UrlLeaf fail closed.
 * A wrap is not an argument. A wrap is not a grant.
 * A hop, a hint, or a wrap never mints.
 */
export function checkSee(
  graph: SeeGraph,
  object: CheckObjectId,
  accessor: AccessorId,
  now: number,
  hint?: HandoffHint,
  hop?: HopFactor,
): CheckResult;

/**
 * Dest Check AND the presented grant window.
 * from denies until now is in range.
 */
export function checkSeeGrant(
  graph: SeeGraph,
  grant: IdentitySeeGrant,
  object: CheckObjectId,
  accessor: AccessorId,
  now: number,
  hint?: HandoffHint,
  hop?: HopFactor,
): CheckResult;

/**
 * Destination re-authorizes, then may put a GunFeedNode into items.
 * Hint / URL fetch is not authorization.
 */
export function admitFeedNode(
  acl: SeeAcl,
  node: GunFeedNode,
  owner: AccessorId,
  hint?: HandoffHint,
): { object: CheckObjectId } | { denied: true };

/** Jointly stated. hopcap 1. */
export function applySeeGrant(
  acl: SeeAcl,
  owner: AccessorId,
  grant: IdentitySeeGrant,
): void;

/** Privilege-down is immediate. Dest ACL only. */
export function cancelSee(
  acl: SeeAcl,
  owner: AccessorId,
  accessor: AccessorId,
  object: CheckObjectId,
): void;

/* -------------------------------------------------------------------------- */
/* Mesh — dest ACL + Social Light hop factor                                  */
/*                                                                            */
/* Copy / re-type with the types above. Same file. Not an npm package.        */
/* Grants HAM-merge under s3rch/acl. They do not fork items or users.         */
/* Held claim CheckObjectId = claim id itself (ens:… / fc:… / …).             */
/* Linked from GunUserNode.indicators. No users/<wallet>/claims/ path.        */
/* Overlay stays local until s3r.ch prepareShare* then putObject.             */
/* -------------------------------------------------------------------------- */

/** Dest ACL collection. Sibling of items / users / meta. Not a Check object. */
export type S3rchAcl = "acl";

/**
 * Dest-ACL path key. encodeKey, then `/` → `_`, so a grant soul stays
 * five segments when the object id still contains slashes
 * (`rss3:act/1_x`, `s3rch/items/…`). Not a second encodeKey for items
 * or users.
 */
export function aclKey(id: string): string;

/**
 * Owner / accessor key on dest ACL. `s3rch/users/<wallet>` collapses
 * to the wallet. Anything else is aclKey.
 */
export function aclPrincipalKey(id: string): string;

/**
 * Owner dest-ACL root. Not a Check object.
 * gun.get('s3rch').get('acl').get(aclPrincipalKey(owner))
 */
export function aclSoul(owner: AccessorId): string;

/**
 * Jointly stated see grant under the object owner's dest ACL.
 * Does not fork items or users.
 * gun.get('s3rch').get('acl')
 *   .get(aclPrincipalKey(owner))
 *   .get(aclKey(object))
 *   .get(aclPrincipalKey(accessor))
 */
export function grantSoul(
  owner: AccessorId,
  object: CheckObjectId,
  accessor: AccessorId,
): string;

/**
 * In-graph see grant. HAM-merges across peers.
 * `stated` 1 = jointly stated, 0 = cancelled (privilege-down).
 * `from` inclusive, `until` exclusive.
 * Cancel is owner-only on dest ACL and must bump Gun HAM state so
 * the next Check after merge denies. Do not cache an allow.
 */
export type MeshSeeGrant = {
  object: CheckObjectId;
  accessor: AccessorId;
  from: number;
  until: number;
  stated: 0 | 1;
};

/**
 * One dest-ACL grant node. Soul is grantSoul(owner, object, accessor).
 * Peers HAM-merge by hamState (higher wins). Cancel bumps hamState.
 */
export type GunAclEdge = {
  soul: string;
  owner: AccessorId;
  grant: MeshSeeGrant;
  hamState: number;
};

/** Named Social Light channels. Same as sociacl-core. Hop is not a grant. */
export type SocialLightChannel = "convention-badge" | "enrolled-station";

/**
 * Optional Check factor. Opaque SLHP bytes or the structured hop
 * sociacl-core already names. Destination re-authorizes.
 * Hop missing does not fail. Hop alone never allows.
 * Hop never mints a grant. URL handoffs stay untrusted HandoffHint.
 */
export type HopFactor =
  | Uint8Array
  | {
      channel: SocialLightChannel;
      attestationBytes?: Uint8Array;
      shareToken?: string;
    };

/**
 * Identity. Does not verify. Does not mint. Mirror acceptHint.
 */
export function acceptHop(hop: HopFactor): HopFactor;

/**
 * SLHP decode. Does not verify. Does not mint. Mirror acceptHint.
 * Attestation bytes stay opaque.
 */
export function decodeHop(bytes: Uint8Array): HopFactor;

/* -------------------------------------------------------------------------- */
/* Wrapped keys, private rows, group predicates (spec)                        */
/*                                                                            */
/* docs/encrypted-discovery.md. Copy / re-type with the types above.          */
/* The reference crate still evaluates plaintext MeshSeeGrant only.          */
/* A wrap is not a grant. SEA priv and epriv never go on Gun.                 */
/* same-group and named-circle: hopcap 1, jointly stated, no inheritance.    */
/* -------------------------------------------------------------------------- */

/**
 * Light predicate an object may name. The accessor does not pick a
 * richer one. owner and delegate are today's see path. same-group
 * and named-circle are direct edges only.
 */
export type LightPredicate =
  | "owner"
  | "delegate"
  | "same-group"
  | "named-circle";

/**
 * DEK or group-key material. Not a grant.
 * reader-epub: ECDH-derived wrap to that SEA epub.
 * group-epoch: wrap to the group key for this epoch.
 * scope item-dek + reader-epub: per-item DEK to one reader.
 * scope group-key + reader-epub: group epoch key to one member.
 * scope item-dek + group-epoch: item DEK to the group's epoch key.
 * revisionId is sealed inside the authenticated payload.
 * A cleartext label a peer can swap is not this field.
 * Readers reject a wrap whose revisionId is not the winning
 * EpochManifest revision. Not a grant.
 */
export type WrappedKey = {
  scope: "item-dek" | "group-key";
  epoch: number;
  target: "reader-epub" | "group-epoch";
  /** SEA epub, or group id when target is group-epoch. */
  targetId: string;
  object?: CheckObjectId;
  group?: string;
  /** EpochManifest.revisionId covered by the wrap authentication. */
  revisionId: string;
  wrappedKey: string;
};

/**
 * One SEA keypair for the account. Devices inherit this same
 * keypair through enrollment. They do not mint a second pair.
 * pub and epub may sit on the user node. priv and epriv never
 * go on Gun. Enrollment does not mint a grant.
 */
export type AccountSeaKey = {
  account: AccessorId;
  pub: string;
  epub: string;
};

/**
 * public-plain: today's plaintext MeshSeeGrant (open whether it stays
 * for public content). private-row: blinded or encrypted grant row.
 */
export type GrantStorage = "public-plain" | "private-row";

/**
 * Hash of the canonical grant bytes. Stored on the visible row.
 * Not an owner id and not an owner SEA pub.
 * The signature over the grant stays inside the ciphertext.
 * When the grant names an encrypted item, the canonical bytes
 * include the item ciphertext digest, so this hash covers it.
 */
export type GrantCommitment = {
  hash: string;
};

/**
 * Owner signature over item authenticity.
 * Signed bytes, in order: item id, epoch, version, plaintext
 * digest, revisionId. revisionId is part of that tuple.
 * The owner signs that tuple, then encrypts the plaintext and
 * this signature together. The ciphertext digest is not an
 * input to the signature. The signature sits inside the
 * encrypted item. The visible grant row does not carry it
 * and does not carry the owner pub.
 * GrantCommitment still covers the ciphertext digest, computed
 * after encryption.
 * Not a grant. A reader who holds the DEK cannot produce this
 * signature, and cannot relabel revisionId under it.
 */
export type ItemContentAuth = {
  object: CheckObjectId;
  epoch: number;
  version: number;
  plaintextDigest: string;
  revisionId: string;
  signature: string;
};

/**
 * Canonical grant inside the ciphertext. The owner signature
 * covers these fields, including grantRevision.
 * grantRevision is monotonic for one object and accessor.
 * The visible row has no hamState. Among opened entries for
 * the same object and accessor, the greatest grantRevision
 * wins. A stated 1 payload does not undo a stated 0 payload
 * at a lower or equal grantRevision.
 * Not a merge field on the lane entry. Not a grant by itself.
 */
export type SignedGrantPayload = {
  object: CheckObjectId;
  accessor: AccessorId;
  from: number;
  until: number;
  stated: 0 | 1;
  epoch: number;
  owner: AccessorId;
  grantRevision: number;
};

/**
 * Canonical bytes for an inbox entry id.
 * Order: laneId, grantCiphertext, commitment hash, wrap.
 * entryId is the hash of that encoding. A change to the
 * ciphertext, the commitment, the wrap, or the lane is a new id.
 */
export type InboxEntryBody = {
  laneId: string;
  grantCiphertext: string;
  commitment: GrantCommitment;
  wrap?: WrappedKey;
};

/**
 * Spec signature. The reference crate does not run this.
 * SHA-256 of the canonical bytes below, as lowercase hex
 * (64 chars). Not a hex encoding of the raw body. Does not mint.
 *
 * Canonical bytes are the concatenation, for each field in
 * order, of a uint32 little-endian length and then the UTF-8
 * bytes of that field. An empty field is 4 zero bytes.
 * Integers are ASCII decimal with no sign and no leading zeros.
 * The value 0 is the single byte 0x30.
 *
 * Fields:
 * 1. "s3rch-inbox-entry-v1"
 * 2. laneId
 * 3. grantCiphertext
 * 4. commitment.hash
 * 5. "1" when wrap is present, otherwise "0"
 * 6. wrap.scope, or empty
 * 7. decimal wrap.epoch, or empty
 * 8. wrap.target, or empty
 * 9. wrap.targetId, or empty
 * 10. wrap.object, or empty
 * 11. wrap.group, or empty
 * 12. wrap.revisionId, or empty
 * 13. wrap.wrappedKey, or empty
 * Fields 6-13 are empty when wrap is absent.
 */
export function inboxEntryId(body: InboxEntryBody): string;

/**
 * Visible lane entry. Replaces plaintext enumeration of
 * grantSoul for private items. No owner field.
 * Append-only and content-addressed: entryId is inboxEntryId
 * of the lane, ciphertext, commitment, and wrap. A body that
 * does not hash to entryId is rejected. No hamState contest
 * and no in-place replacement. Order between a live grant and
 * a cancel is grantRevision inside SignedGrantPayload.
 * A wrap on the row is not a grant.
 * laneId is the reader's one lane, not a shared bucket.
 */
export type BlindedGrantRow = {
  laneId: string;
  /** Hash of the canonical InboxEntryBody. Not a mutable slot. */
  entryId: string;
  /** Ciphertext of the canonical grant, including the owner id and the signature. */
  grantCiphertext: string;
  commitment: GrantCommitment;
  wrap?: WrappedKey;
};

/**
 * Optional outer envelope when the writer is already known
 * (named-writers). Relays verify writerSignature over entryId
 * without opening the grant. The default public lane stays
 * content-addressed and does not carry writerPub.
 * Not a grant.
 */
export type InboxEnvelope = {
  laneId: string;
  entryId: string;
  ciphertext: string;
  writerPub: string;
  writerSignature: string;
};

/**
 * Exactly one private lane per reader account. Not a Check object.
 * Not a shared bucket. Not one lane per device, sender, or epoch.
 * laneId is not the plaintext accessor id. Scanning it is not Check
 * and does not mint.
 */
export type RecipientInbox = {
  accessor: AccessorId;
  laneId: string;
};

/**
 * Opened grant the holder shows to the destination.
 * Not written to Gun. The destination recomputes GrantCommitment
 * from grantBytes, checks the signature with seaPub, and checks
 * that seaPub is the enrolled key for owner. grantBytes include
 * grantRevision. Then presenter binding and a fresh
 * EpochStatusProof, then Check.
 * A presentation alone grants nothing. A presentation is not a grant.
 */
export type GrantPresentation = {
  owner: AccessorId;
  grant: MeshSeeGrant;
  /** Monotonic order inside the signed payload. */
  grantRevision: number;
  /** Canonical bytes the commitment hashes. Covers grantRevision. */
  grantBytes: string;
  signature: string;
  /** Enrolled account SEA pub. Not a field of BlindedGrantRow. */
  seaPub: string;
};

/**
 * Destination nonce signed by the reader's SEA key.
 * Signed bytes: nonce and the grant commitment hash.
 * readerPub is the enrolled pub for the accessor.
 * Not a grant. A valid binding does not set allowed.
 */
export type PresenterBinding = {
  nonce: string;
  signature: string;
  readerPub: string;
};

declare const presenterChannelBrand: unique symbol;

/**
 * Opaque capability. Only the authenticated transport can
 * construct a value. channelBrand is a private instance field
 * holding presenterChannelBrand, so a structural object literal
 * is not assignable. checkPresentedGrant also requires
 * `channel instanceof AuthenticatedPresenterChannel`,
 * hasTransportBrand(), accessor equal to the grant accessor,
 * and readerPub equal to the enrolled SEA pub for that accessor.
 * hasTransportBrand is true only when channelBrand is that symbol.
 * A channel minted for another principal fails closed. Not a grant.
 */
export class AuthenticatedPresenterChannel {
  private constructor(accessor: AccessorId, readerPub: string);
  readonly accessor: AccessorId;
  readonly readerPub: string;
  private readonly channelBrand: typeof presenterChannelBrand;
  hasTransportBrand(): boolean;
}

/**
 * Outstanding nonce this verifier issued for one presentation.
 * The presenter does not supply this object.
 * Single use. Dead when now >= expiresAt.
 */
export type PresenterChallenge = {
  nonce: string;
  expiresAt: number;
};

/**
 * Verifier-held challenge state. checkPresentedGrant consumes
 * the matching nonce: it leaves outstanding and is recorded spent.
 * A second use of that nonce fails closed.
 */
export type VerifierChallengeState = {
  outstanding: readonly PresenterChallenge[];
  spent: readonly string[];
};

/**
 * Result of checkPresentedGrant, including the spent challenge.
 */
export type PresentedGrantDecision = {
  result: CheckResult;
  challenges: VerifierChallengeState;
};

/**
 * Check zookie on the light surface. Same three fields as the
 * core freshness token: object, object version, snapshot hash.
 * A zookie for an older object version is not a cached allow.
 * Not a grant.
 */
export type LightZookie = {
  object: CheckObjectId;
  objectVersion: number;
  snapshotHash: string;
};

/**
 * Fresh owner-signed epoch/status, required beside the zookie
 * at destination re-check of an encrypted grant.
 * The signature is checked with the enrolled owner pub from the
 * presentation, not from a field on the visible row.
 * Freshness, with the verifier's skewAllowanceMs:
 * signedAt <= now + skewAllowanceMs, and
 * now - signedAt <= maxAgeMs. Otherwise fail closed.
 * The zookie is compared to SeeGraph.objectVersion and
 * SeeGraph.snapshotHash(object). An older object version, a newer
 * version this graph has not merged, or a different snapshot
 * hash fails closed.
 * Revocation is immediate only for a current verifier (merged
 * privilege-down, and a proof inside max-age and skew).
 * Otherwise it is bounded by max-age. Not a grant.
 */
export type EpochStatusProof = {
  object: CheckObjectId;
  epoch: number;
  revisionId: string;
  stated: 0 | 1;
  signedAt: number;
  maxAgeMs: number;
  signature: string;
  zookie: LightZookie;
};

/**
 * Spec signature. The reference crate does not run this.
 * Commitment mismatch or a bad owner signature fails closed.
 * challenges is the verifier's outstanding nonce set.
 * A binding nonce must match one outstanding challenge,
 * now must be before expiresAt, and that nonce is then spent.
 * A channel argument must be an AuthenticatedPresenterChannel
 * instance whose hasTransportBrand() is true, whose accessor
 * equals the accessor argument, and whose readerPub equals the
 * enrolled SEA pub for that accessor. An object literal fails
 * instanceof and fails the brand check. A branded channel for
 * another principal fails closed. Omitted binding and omitted
 * channel fails closed. Omitted, stale, future-dated beyond
 * skew, or superseded status fails closed.
 * A proof alone grants nothing.
 * A hop, a hint, or a wrap never mints.
 */
export function checkPresentedGrant(
  row: BlindedGrantRow,
  presentation: GrantPresentation,
  graph: SeeGraph,
  accessor: AccessorId,
  now: number,
  skewAllowanceMs: number,
  challenges: VerifierChallengeState,
  hint?: HandoffHint,
  hop?: HopFactor,
  binding?: PresenterBinding,
  channel?: AuthenticatedPresenterChannel,
  status?: EpochStatusProof,
): PresentedGrantDecision;

/**
 * Author-only local DEK. Not a Gun row and not a grant.
 * Other readers do not use this path. Enrolled devices of the
 * same account share the one SEA keypair and may unwrap a
 * self-wrap in the author's single lane.
 */
export type AuthorFastUnwrap = {
  object: CheckObjectId;
  epoch: number;
  dek: string;
};

/**
 * How the introduction binds SEA keys to the account.
 * enrollment: the reader's trusted enrollment record for
 * account already names this pub and this epub.
 * account-signature: signature by the account identity
 * (the key already enrolled for that AccessorId), over pub
 * and epub. A signature by the introduced pub is not this
 * binding. A missing epub or a swapped epub fails closed.
 * Not a grant.
 */
export type AccountKeyBinding =
  | { kind: "enrollment" }
  | { kind: "account-signature"; signature: string };

/**
 * First introduction on the one lane.
 * Carries the sender SEA pub and epub, plus an account binding
 * from enrollment or from the account identity. Not a self-signature.
 * Not a grant. Does not open a second lane. Does not mint.
 * priv and epriv never go on Gun.
 */
export type FirstContactIntro = {
  account: AccessorId;
  pub: string;
  epub: string;
  binding: AccountKeyBinding;
};

/**
 * Owner-signed epoch revision. Devices that share the account
 * key can mint different keys for the same next epoch.
 * revisionId = epochRevisionId of the canonical body:
 * object, epoch, previousEpoch, deviceId, keyCommitment.
 * A new key commitment is a new revision id.
 * deviceId is a local enrollment id. Not a Gun device
 * record, not a second SEA keypair, and not a grant.
 * The current revisionId is the one named by the epoch winner.
 * The winner is recomputed from every verified finalization
 * this replica has seen. A later smaller finalizationId
 * replaces it. Readers reject content under a revision that
 * is not that winner.
 * Every WrappedKey for that epoch carries the same revisionId
 * inside the authenticated payload.
 * Self-wrap in the author lane, or inside the encrypted item.
 * Not an owner pub on a visible grant row. Not a grant.
 */
export type EpochManifest = {
  object: CheckObjectId;
  previousEpoch: number;
  epoch: number;
  deviceId: string;
  revisionId: string;
  /** Commitment to the epoch key. Not the key. */
  keyCommitment: string;
  signature: string;
};

/**
 * Canonical manifest body. revisionId is the hash of this
 * encoding, not of the signature and not of revisionId itself.
 */
export type EpochManifestBody = {
  object: CheckObjectId;
  epoch: number;
  previousEpoch: number;
  deviceId: string;
  keyCommitment: string;
};

/**
 * Spec signature. The reference crate does not run this.
 * SHA-256, lowercase hex, of the same length-prefixed UTF-8
 * encoding as inboxEntryId. Does not mint.
 *
 * Fields:
 * 1. "s3rch-epoch-revision-v1"
 * 2. object
 * 3. decimal epoch
 * 4. decimal previousEpoch
 * 5. deviceId
 * 6. keyCommitment
 */
export function epochRevisionId(body: EpochManifestBody): string;

/**
 * Owner-signed candidate for one epoch step. The named
 * revisionId must be the lexicographically smallest id in
 * candidateRevisionIds. A finalization that fails that check
 * is ignored.
 * Replicas keep every verified finalization for the same
 * object, epoch, and previousFinalizationId. The winner is
 * the smallest finalizationId in that set. A later smaller
 * finalizationId replaces the previous winner. Arrival order
 * does not pick a different winner.
 * Not a grant. Not an owner pub on a visible grant row.
 */
export type EpochFinalization = {
  object: CheckObjectId;
  previousEpoch: number;
  epoch: number;
  revisionId: string;
  /** Sorted ascending. This finalization's candidate ids. */
  candidateRevisionIds: readonly string[];
  /** Accepted finalization of the previous epoch, or "". */
  previousFinalizationId: string;
  /**
   * SHA-256 lowercase hex of the length-prefixed fields:
   * "s3rch-epoch-finalization-v1", object, decimal epoch,
   * decimal previousEpoch, revisionId, previousFinalizationId,
   * then each candidateRevisionIds entry in sorted order.
   */
  finalizationId: string;
  signature: string;
};

/**
 * Protocol delay before a winning finalization is current.
 * 24 hours. Every replica uses this same constant.
 * The window restarts when a smaller finalizationId becomes
 * the winner. It does not freeze the set.
 */
export const EPOCH_SETTLE_WINDOW_MS: 86400000;

/**
 * One replica's view of one epoch step.
 * seen is every verified EpochFinalization for this parent.
 * The winner is the smallest finalizationId in seen.
 * winnerSeenAt is when this replica first observed that id.
 * A later smaller id replaces the winner and sets a new
 * winnerSeenAt. Not a grant.
 */
export type EpochReplicaView = {
  object: CheckObjectId;
  epoch: number;
  previousFinalizationId: string;
  seen: readonly EpochFinalization[];
  winnerSeenAt: number;
};

/**
 * Spec signature. The reference crate does not run this.
 * True only when view.seen has a winner and
 * now >= winnerSeenAt + EPOCH_SETTLE_WINDOW_MS.
 * A smaller finalizationId after that instant still replaces
 * the winner, and this function is then false until the new
 * window elapses. Does not mint.
 */
export function epochStepCurrent(view: EpochReplicaView, now: number): boolean;

/**
 * Rescan of one UTC day shard of the one lane.
 * day is YYYY-MM-DD. seen holds entry ids already accepted.
 * Dedup by entryId. This is the lane scan. A per-device cursor
 * is not part of this contract: the visible row has no device
 * id, and opening ciphertext to learn one does not yield a
 * lossless cursor. Not a second lane. Not a grant.
 */
export type DailyShardScan = {
  laneId: string;
  day: string;
  seen: readonly string[];
};

/**
 * Who may append to the one lane. Default is public-filtered:
 * any principal may append, and the reader drops spam.
 * First contact under that default requires proof-of-work or
 * a stamp. Quotas are per sender and do not spend the
 * reader's capacity. named-writers is the allowlist.
 * A passed hook is not a grant.
 */
export type InboxWritePolicy = "public-filtered" | "named-writers";

export type InboxWriteHook = {
  policy: InboxWritePolicy;
  /** Required when policy is named-writers. */
  writers?: readonly AccessorId[];
};

/**
 * Verifier-issued proof-of-work challenge. The writer does not
 * choose the nonce or the difficulty. Single use. Dead when
 * now >= expiresAt.
 */
export type AdmissionChallenge = {
  nonce: string;
  /** Leading zero bits required in the SHA-256 work digest. */
  difficulty: number;
  expiresAt: number;
};

/**
 * What the writer shows. Quotas, difficulty, and replay state
 * are not fields here.
 * proof-of-work: SHA-256 of the length-prefixed fields
 * "s3rch-inbox-pow-v1", challenge.nonce, row.entryId, solution
 * has at least challenge.difficulty leading zero bits.
 * stamp: signature by a trusted issuer over the length-prefixed
 * fields "s3rch-inbox-stamp-v1" and row.entryId.
 * A stamp is not a grant.
 */
export type AdmissionEvidence =
  | { kind: "proof-of-work"; solution: string }
  | { kind: "stamp"; issuer: string; signature: string };

/**
 * One sender's remaining appends. Keyed by AccessorId.
 * The writer does not supply this entry.
 */
export type SenderQuota = {
  sender: AccessorId;
  remaining: number;
};

/**
 * Verifier-held admission state. The writer does not supply it.
 * knownSenders is the record this verifier already trusts.
 * A writer absent from that list is first contact. A caller
 * flag is not a field and does not change that.
 * senderQuotas has one counter per sender. A missing sender
 * has remaining 0. laneRemaining is the one shared capacity
 * for this lane, not a copy per sender.
 * spent holds challenge nonces and stamp signatures already used.
 */
export type VerifierAdmissionState = {
  challenge?: AdmissionChallenge;
  stampIssuers: readonly string[];
  spent: readonly string[];
  knownSenders: readonly AccessorId[];
  senderQuotas: readonly SenderQuota[];
  laneRemaining: number;
};

/**
 * Admission beside an append. Evidence is checked against
 * VerifierAdmissionState. First contact is not a field here.
 * A claimed quota on this object is not a field and is ignored
 * if a caller adds one.
 */
export type InboxAdmission = {
  evidence?: AdmissionEvidence;
};

/**
 * filterInboxAppend result. state is the verifier's counters
 * after the call, with a used nonce or stamp signature spent.
 */
export type InboxAppendResult = {
  decision: InboxWriteDecision;
  state: VerifierAdmissionState;
};

export type InboxWriteDecision = {
  allowAppend: boolean;
  /** Local drop label. Not a Check reason and not a grant. */
  filter:
    | "ok"
    | "spam"
    | "unnamed-writer"
    | "stamp-required"
    | "stamp-mismatch"
    | "replay"
    | "sender-quota"
    | "reader-capacity";
};

/**
 * Spec signature. The reference crate does not run this.
 * public-filtered is the default: any writer may append.
 * state is the verifier's challenge, issuers, replay set,
 * known senders, per-sender quotas, and the one lane capacity.
 * The writer does not pass those.
 * First contact is writer absent from state.knownSenders.
 * That writer requires evidence that verifies against state
 * and row.entryId. A proof-of-work solution for another entry,
 * or a stamp signed over another entry, is stamp-mismatch.
 * A nonce or stamp signature already in state.spent is replay.
 * The counter for this writer is the senderQuotas entry with
 * that sender. Missing or remaining 0 is sender-quota. Other
 * senders and laneRemaining stay as they were.
 * laneRemaining at 0 is reader-capacity. That sender's counter
 * stays as it was. On ok, that sender's remaining and
 * laneRemaining each drop by 1, and a new sender is added to
 * knownSenders. named-writers refuses anyone outside writers.
 * Commitment mismatch is checkPresentedGrant, not this hook.
 * SociACL does not store the filter.
 * A passed hook is not a grant.
 */
export function filterInboxAppend(
  hook: InboxWriteHook,
  writer: AccessorId,
  row: BlindedGrantRow,
  state: VerifierAdmissionState,
  now: number,
  admission?: InboxAdmission,
): InboxAppendResult;

/**
 * Direct membership. Hopcap 1. Jointly stated.
 * stated 1 = live, 0 = cancelled. Cancel bumps hamState.
 * One-sided membership is not a grant. Not a walk.
 * Nested groups and nested circles do not grant.
 */
export type MeshMembership = {
  predicate: "same-group" | "named-circle";
  setId: string;
  accessor: AccessorId;
  stated: 0 | 1;
  hamState: number;
};

/**
 * Group or circle the object names. One predicate.
 * Does not change GunFeedNode or GunUserNode.
 */
export type ObjectSetName = {
  object: CheckObjectId;
  predicate: "same-group" | "named-circle";
  setId: string;
  stated: 0 | 1;
  hamState: number;
};

/**
 * See graph plus direct group and circle edges.
 * Check does not walk from one set into another.
 */
export type GroupSeeGraph = SeeGraph & {
  objectSet(object: CheckObjectId): ObjectSetName | undefined;
  membership(
    predicate: "same-group" | "named-circle",
    setId: string,
    accessor: AccessorId,
  ): MeshMembership | undefined;
};

/**
 * CHECK(see) when the object names same-group or named-circle.
 * Hopcap 1. Direct jointly stated edge only.
 * No transitive inheritance.
 * Both the object-set edge and the membership edge must be stated 1.
 * Hop missing does not fail. Hop alone never allows.
 * A hop, a hint, or a wrap never mints.
 * stated 0 denies. now is the Check instant; membership has no
 * from/until window on this surface.
 */
export function checkGroupSee(
  graph: GroupSeeGraph,
  predicate: "same-group" | "named-circle",
  object: CheckObjectId,
  accessor: AccessorId,
  now: number,
  hint?: HandoffHint,
  hop?: HopFactor,
): CheckResult;

/**
 * One edge after privilege-down.
 * grant.stated is 0. hamState is the bumped value.
 */
export type CancelledGrant = {
  grant: MeshSeeGrant | MeshMembership;
  hamState: number;
};

/**
 * Owner's choice at revoke, after stated 0 and the hamState bump.
 * forward-only: new epoch for later writes; old ciphertext stays.
 * re-encrypt: rewrite existing ciphertext in place under the new DEK.
 * Either way, bytes a revoked reader already unwrapped stay readable
 * to them. An older epoch wrap does not mint.
 */
export type RevokeCipherMode = "forward-only" | "re-encrypt";

/**
 * Revoke record for an encrypted object.
 * Order: stated 0 and a hamState bump, then rewrapped keys for
 * the winning revision of the next epoch, remaining readers only,
 * then cipher mode. Immediate deny is for a current verifier.
 * Other verifiers are bounded by EpochStatusProof.maxAgeMs.
 */
export type EpochRotation = {
  object: CheckObjectId;
  revokedEpoch: number;
  nextEpoch: number;
  /** Winning EpochManifest.revisionId for nextEpoch. */
  revisionId: string;
  cancelled: readonly CancelledGrant[];
  rewrapped: readonly WrappedKey[];
  cipher: RevokeCipherMode;
};

/**
 * Spec signature. The reference crate does not run this.
 * Privilege-down first (stated 0, hamState bump), then wraps of
 * the winning next-epoch revision. A wrap written here is not a grant.
 */
export function rotateOnRevoke(rotation: EpochRotation): void;

/**
 * One current reader during migration. Plaintext for this
 * reader stays until acknowledged is set, or atGate is set
 * because readerVersion >= ProtocolMigration.versionGate.
 * One reader's ack does not clear another reader's copy.
 */
export type ReaderMigration = {
  accessor: AccessorId;
  acknowledged: boolean;
  atGate: boolean;
};

/**
 * In-place encryption when a protocol version is applied.
 * Only the owner re-encrypts a shared item and issues wraps.
 * Plaintext removal is per reader: after that reader's ack,
 * or when that reader is at or above versionGate.
 * There is no single flag for every reader.
 * Readers do not issue wraps.
 * Plaintext already replicated elsewhere is a historical leak.
 * Not a grant.
 */
export type ProtocolMigration = {
  object: CheckObjectId;
  fromVersion: number;
  toVersion: number;
  rewrapped: readonly WrappedKey[];
  readers: readonly ReaderMigration[];
  versionGate: number;
};

/**
 * Not a Check object. SociACL runs no index and does not store this.
 * public: one index, public content only.
 * private-group: that group's own index.
 * local: one person, after push/pull, on device.
 * An index hit never mints.
 */
export type ContentIndexTier = "public" | "private-group" | "local";

/**
 * Conformance stub names. Descriptions are in
 * docs/encrypted-discovery.md. The reference crate does not
 * run these. None of them mint a grant.
 */
export type EncryptedDiscoveryVector =
  | "content-auth-accept"
  | "content-auth-reader-forge"
  | "content-auth-revision-relabel"
  | "content-auth-owner-pub-hidden"
  | "content-auth-sign-then-encrypt"
  | "inbox-content-address-distinct"
  | "inbox-replace-rejected"
  | "inbox-wrap-swap"
  | "inbox-stamp-mismatch"
  | "inbox-pow-verified"
  | "inbox-fabricated-quota"
  | "inbox-spent-challenge"
  | "inbox-known-sender"
  | "inbox-sender-quota-map"
  | "inbox-lane-capacity"
  | "grant-revision-order"
  | "epoch-late-manifest"
  | "epoch-arrival-order"
  | "epoch-settle-window"
  | "id-sha256-canonical"
  | "zookie-object-snapshot"
  | "intro-epub-required"
  | "intro-binding-ok"
  | "intro-binding-swap-epub"
  | "intro-self-signature-rejected"
  | "intro-not-a-grant"
  | "presenter-proof-alone"
  | "presenter-nonce-ok"
  | "presenter-bad-key"
  | "presenter-spent-nonce"
  | "presenter-expired-challenge"
  | "presenter-forged-channel"
  | "presenter-channel-wrong-principal"
  | "presenter-binding-not-a-grant";
