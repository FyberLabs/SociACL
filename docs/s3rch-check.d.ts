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
 * Randomized commitment to the canonical grant. The visible
 * row stores hash only. Not an owner id and not an owner SEA pub.
 * hash is SHA-256, lowercase hex, of the length-prefixed fields:
 * 1. "s3rch-grant-commitment-v1"
 * 2. blinding (64 lowercase hex chars from 32 fresh random bytes)
 * 3. object
 * 4. accessor
 * 5. decimal from
 * 6. decimal until
 * 7. decimal stated
 * 8. decimal epoch
 * 9. owner
 * 10. decimal grantRevision
 * 11. itemCiphertextDigest
 * blinding is fresh per row. It sits inside the ciphertext and
 * in GrantPresentation. It is not a field of the visible row.
 * An unsalted hash of the grant bytes is not this commitment.
 * Guessing the owner, the window, the epoch, or the revision
 * does not open the row.
 * The signature over the grant stays inside the ciphertext.
 */
export type GrantCommitment = {
  hash: string;
};

/**
 * Owner signature over item authenticity.
 * plaintextDigest is SHA-256 of the raw plaintext bytes,
 * lowercase hex.
 * The signed bytes use the same length-prefixed UTF-8
 * encoding as inboxEntryId. The signature is over those
 * bytes. It is not a hex encoding of the plaintext.
 * Fields:
 * 1. "s3rch-item-auth-v1"
 * 2. object
 * 3. decimal epoch
 * 4. decimal version
 * 5. plaintextDigest
 * 6. revisionId
 * The owner signs that encoding, then encrypts the plaintext
 * and this signature together. The ciphertext digest is not
 * an input to the signature. The signature sits inside the
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
 * itemCiphertextDigest is the SHA-256 lowercase hex of the
 * item ciphertext when the grant names an encrypted item,
 * and "" otherwise. The owner signature covers it. The
 * destination hashes the fetched ciphertext and passes that
 * digest to checkPresentedGrant. SeeGraph.snapshotHash is
 * not this comparison.
 * payload digest is SHA-256, lowercase hex, of the
 * length-prefixed fields "s3rch-grant-payload-v1", object,
 * accessor, decimal from, decimal until, decimal stated,
 * decimal epoch, owner, decimal grantRevision,
 * itemCiphertextDigest. The signature covers those bytes.
 * Two payloads with the same grantRevision: stated 0 wins
 * before any digest comparison. A live payload does not
 * replace a cancellation at that revision. When stated
 * matches, the smaller payload digest wins. A later smaller
 * digest replaces a stored larger one. A larger digest at
 * that revision fails closed. Arrival order does not pick
 * the payload.
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
  itemCiphertextDigest: string;
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
 * (named-writers). body is the full InboxEntryBody. The relay
 * recomputes inboxEntryId(body), checks it equals entryId, and
 * verifies writerSignature over that id, without opening the
 * grant. The default public lane stays content-addressed and
 * does not carry writerPub.
 * Not a grant.
 */
export type InboxEnvelope = {
  /** Full content-addressed entry. entryId is inboxEntryId(body). */
  body: InboxEntryBody;
  entryId: string;
  writerPub: string;
  /** Over entryId. The relay recomputes entryId from body. */
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
 * from blinding and grantBytes, checks the signature with seaPub,
 * and checks that seaPub is the enrolled key for owner.
 * grantBytes decode to one SignedGrantPayload. grant, owner, and
 * grantRevision must match that payload. A mismatch fails closed
 * before verifier state changes. Then presenter binding and a fresh
 * EpochStatusProof, then Check.
 * A presentation alone grants nothing. A presentation is not a grant.
 */
export type GrantPresentation = {
  owner: AccessorId;
  grant: MeshSeeGrant;
  /** Monotonic order inside the signed payload. */
  grantRevision: number;
  /** Canonical grant fields. The commitment also takes blinding. */
  grantBytes: string;
  /**
   * Opening for GrantCommitment. Fresh per row. Not a field of
   * BlindedGrantRow. Not an owner id.
   */
  blinding: string;
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
 * Instances the transport constructor recorded. Not exported.
 * A copy of the prototype is not in this set.
 */
declare const presenterChannelInstances: WeakSet<AuthenticatedPresenterChannel>;

/**
 * Opaque capability. Only the authenticated transport can
 * construct a value. The brand is the ECMAScript private field
 * #channelBrand, not a TypeScript private keyword and not a
 * reflectable property. presenterChannelInstances records the
 * instance at construction. The constructor freezes the object.
 * accessor and readerPub stay the values from that constructor.
 * checkPresentedGrant accepts a channel only when
 * `channel instanceof AuthenticatedPresenterChannel`,
 * hasTransportBrand() is true, the instance is in
 * presenterChannelInstances, accessor equals the grant accessor,
 * and readerPub equals the enrolled SEA pub for that accessor.
 * hasTransportBrand is true only for that private field and set.
 * Copying a brand value onto a new object fails the private
 * field and the set. A channel minted for another principal
 * fails closed. Not a grant.
 */
export class AuthenticatedPresenterChannel {
  private constructor(accessor: AccessorId, readerPub: string);
  readonly accessor: AccessorId;
  readonly readerPub: string;
  readonly #channelBrand: typeof presenterChannelBrand;
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
 * Highest signed grant revision this verifier has accepted
 * for one object and accessor. The presenter does not supply it.
 */
export type VerifierGrantRevision = {
  object: CheckObjectId;
  accessor: AccessorId;
  grantRevision: number;
  stated: 0 | 1;
  /**
   * Smaller digest wins when grantRevision and stated tie
   * and this field already holds a digest.
   * stated 0 wins over stated 1 at the same revision.
   * Empty when the record was raised from an EpochStatusProof
   * that names the revision and stated without the payload.
   * An empty digest is unknown. It is not the smallest digest.
   * The first payload whose grantRevision and stated match
   * this record is accepted, and its digest is stored here.
   * A payload whose stated does not match still follows the
   * stated-0 rule. Later payloads at that revision use the
   * stored digest.
   */
  payloadDigest: string;
};

/**
 * Verifier-held grant order. checkPresentedGrant compares the
 * presentation to current and returns the updated record.
 */
export type VerifierGrantRevisionState = {
  current: readonly VerifierGrantRevision[];
};

/**
 * Result of checkPresentedGrant, including the spent challenge
 * and the updated grant-revision record.
 */
export type PresentedGrantDecision = {
  result: CheckResult;
  challenges: VerifierChallengeState;
  revisions: VerifierGrantRevisionState;
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
 * Names this accessor and this grantRevision, not only the object.
 * The signature is checked with the enrolled owner pub from the
 * presentation, not from a field on the visible row.
 * Signed bytes use the length-prefixed UTF-8 encoding:
 * 1. "s3rch-epoch-status-v1"
 * 2. object
 * 3. decimal epoch
 * 4. revisionId
 * 5. accessor
 * 6. decimal grantRevision
 * 7. decimal stated
 * 8. decimal signedAt
 * 9. decimal maxAgeMs
 * 10. zookie.object
 * 11. decimal zookie.objectVersion
 * 12. zookie.snapshotHash
 * Freshness, with the verifier's skewAllowanceMs and
 * policyMaxAgeMs: signedAt <= now + skewAllowanceMs, and
 * now - signedAt is within the smaller of maxAgeMs and
 * policyMaxAgeMs. Otherwise fail closed.
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
  /** The accessor this proof refreshes. Not another reader. */
  accessor: AccessorId;
  /** Owner-signed high water for that accessor. */
  grantRevision: number;
  stated: 0 | 1;
  signedAt: number;
  maxAgeMs: number;
  signature: string;
  zookie: LightZookie;
};

/**
 * Group or circle check inside checkPresentedGrant.
 * Required when the opened grant is same-group or named-circle.
 * Absent for an ordinary see grant. Not a grant by itself.
 */
export type PresentedGroup = {
  predicate: "same-group" | "named-circle";
  setId: string;
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
 * enrolled SEA pub for that accessor. The brand is an
 * ECMAScript private field plus the module WeakSet. An object
 * literal fails instanceof and fails the brand check. Copying
 * the brand onto another object fails closed. A branded channel
 * for another principal fails closed. Omitted binding and omitted
 * channel fails closed. Omitted, stale, future-dated beyond
 * skew, or superseded status fails closed.
 * Decode SignedGrantPayload from grantBytes first. If grant,
 * owner, or grantRevision disagree with that payload, fail
 * closed before revisions changes. Check uses the decoded
 * payload.
 * The decoded grant, status, status.zookie, and epochView
 * name the same object. status.epoch, the grant epoch, and
 * epochView.epoch match. status.accessor is the grant accessor
 * and the accessor argument. A mismatch fails closed before
 * challenges are spent and before revisions changes.
 * A verified proof whose grantRevision is higher than the
 * record, or whose stated is 0 at an equal revision against
 * a stored stated 1, updates the record from the proof.
 * The presenter cannot keep the record on an older live row
 * by withholding the cancel.
 * revisions is that verifier record, plus its payloadDigest.
 * A presented revision lower than the record fails closed.
 * At an equal revision, stated 0 wins before digest order.
 * A live payload does not replace a stored cancellation.
 * When stated matches and the stored payloadDigest is already
 * a digest, a larger payloadDigest fails closed and a smaller
 * one replaces the record. An empty stored payloadDigest is
 * unknown. It does not count as a smaller digest. The first
 * payload with the same grantRevision and the same stated is
 * stored. A cancel at that revision still beats a live payload.
 * A higher signed revision replaces the record. The holder
 * does not choose that record.
 * When the decoded payload names an item ciphertext digest,
 * fetchedItemDigest is the SHA-256 lowercase hex of the
 * ciphertext the destination fetched. It must equal that
 * field. A mismatch or a missing argument fails closed before
 * revisions changes. SeeGraph.snapshotHash is not this digest.
 * When the payload field is empty, fetchedItemDigest is omitted.
 * epochView is the verifier's epoch state for that same object.
 * status.revisionId must be the read key: settledRevisionId
 * while epochStepCurrent(epochView, now) is false, and the
 * recomputed winner once it is true. Any other revision fails
 * closed. The presenter does not supply epochView.
 * When group is set, graph is a GroupSeeGraph and this
 * function runs checkGroupSee after the same binding,
 * revision, and freshness checks. When group is omitted,
 * it runs checkSee / checkSeeGrant. A group object with
 * no group argument fails closed.
 * The age bound is the smaller of status.maxAgeMs and
 * policyMaxAgeMs. policyMaxAgeMs is the verifier's cap.
 * The owner does not set it. A proof older than that bound
 * fails closed.
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
  revisions: VerifierGrantRevisionState,
  epochView: EpochReplicaView,
  policyMaxAgeMs: number,
  hint?: HandoffHint,
  hop?: HopFactor,
  binding?: PresenterBinding,
  channel?: AuthenticatedPresenterChannel,
  status?: EpochStatusProof,
  group?: PresentedGroup,
  fetchedItemDigest?: string,
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
 * object, epoch, previousEpoch, deviceId, keyCommitment,
 * settleWindowMs, aclSnapshot.
 * A new key commitment is a new revision id.
 * aclSnapshot commits to each recipient and that accessor's
 * own cancel revision. A manifest whose snapshot misses a
 * cancel this replica already has for that accessor is ignored.
 * settleWindowMs is the owner-signed wait for this object,
 * or the same number as GroupEpochConfig for a group epoch.
 * In range SETTLE_WINDOW_MIN_MS through SETTLE_WINDOW_MAX_MS.
 * The default the owner signs is SETTLE_WINDOW_DEFAULT_MS.
 * Out of range, the manifest is ignored.
 * deviceId is a local enrollment id. Not a Gun device
 * record, not a second SEA keypair, and not a grant.
 * The pending winner is recomputed from every verified
 * finalization this replica has seen. A later smaller
 * finalizationId replaces it. Readers use the last settled
 * revision until that winner's settle window elapses, then
 * switch. They reject further writes under a revision the
 * settled result has superseded. Content bound to a revision
 * a later smaller finalizationId displaces is not current.
 * The owner re-encrypts those writes under the new winner.
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
  /**
   * Owner-signed settle window for this object, in milliseconds.
   * Group epochs repeat GroupEpochConfig.settleWindowMs.
   */
  settleWindowMs: number;
  /**
   * SHA-256 lowercase hex of the ACL snapshot. Covered by
   * revisionId. See aclSnapshotId.
   */
  aclSnapshot: string;
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
  /** Decimal milliseconds. Covered by revisionId. */
  settleWindowMs: number;
  /** aclSnapshotId of the per-accessor cancel rows. */
  aclSnapshot: string;
};

/**
 * One accessor in an ACL snapshot. stated 1 receives a wrap
 * only while now is inside from and until.
 * stated 0 is a cancel at grantRevision and receives none.
 * A stated-1 entry with until <= now is expired. The candidate
 * that names it does not settle. The buffer stays buffered.
 * The owner publishes a new revision whose key was not wrapped
 * to that accessor, and whose snapshot lists that accessor
 * stated 0. That replacement starts its own settle window.
 * Not a grant.
 */
export type AclSnapshotEntry = {
  accessor: AccessorId;
  grantRevision: number;
  stated: 0 | 1;
  /** Grant window. Covered by aclSnapshotId. */
  from: number;
  until: number;
};

/**
 * Who receives a wrap for this candidate, and the cancel
 * applied for each accessor. Entries are sorted by accessor.
 * There is no single cancel high-water across accessors.
 * A replica that knows accessor A is cancelled at revision R
 * ignores a snapshot that lists A as stated 1, omits A, or
 * lists A cancelled below R.
 * A stated-1 entry with until <= now does not settle. Not a grant.
 */
export type AclSnapshotBody = {
  entries: readonly AclSnapshotEntry[];
};

/**
 * Spec signature. The reference crate does not run this.
 * SHA-256, lowercase hex, of the length-prefixed UTF-8
 * encoding. Fields: "s3rch-acl-snapshot-v1", then each
 * entry in accessor order as accessor, decimal grantRevision,
 * decimal stated, decimal from, decimal until. Does not mint.
 */
export function aclSnapshotId(body: AclSnapshotBody): string;

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
 * 7. decimal settleWindowMs
 * 8. aclSnapshot
 */
export function epochRevisionId(body: EpochManifestBody): string;

/**
 * Bounds for an owner-signed settle window.
 * Minimum is 1 hour. A shorter wait lets one replica switch
 * keys before a competing finalization arrives over an ordinary
 * delay. Re-convergence would still correct the winner, and
 * readers would churn keys in the meantime.
 * Maximum is 72 hours. A longer wait holds remaining readers
 * on the previous key through a long weekend partition. Past
 * three days the delay is an availability stall, not a race
 * buffer. Privilege-down is not part of this wait.
 * Default is 24 hours. One day covers devices that publish a
 * few hours apart, including a device offline overnight, and
 * it stays under the maximum. The owner signs the default by
 * writing SETTLE_WINDOW_DEFAULT_MS. An omitted number is that
 * same decimal in the canonical body.
 */
export const SETTLE_WINDOW_MIN_MS: 3600000;
export const SETTLE_WINDOW_MAX_MS: 259200000;
export const SETTLE_WINDOW_DEFAULT_MS: 86400000;

/**
 * Owner-signed settle window for one group or circle.
 * Signed bytes, length-prefixed: "s3rch-group-epoch-config-v1",
 * setId, predicate, decimal settleWindowMs.
 * A group epoch manifest carries this same settleWindowMs.
 * A mismatch is ignored. Sits with the manifest, in the author
 * lane or inside the encrypted item. Not an owner pub on a
 * visible grant row. Not a grant.
 */
export type GroupEpochConfig = {
  setId: string;
  predicate: "same-group" | "named-circle";
  settleWindowMs: number;
  signature: string;
};

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
 * The signature covers finalizationId, not revisionId alone.
 * Signed bytes, length-prefixed:
 * 1. "s3rch-epoch-finalization-sig-v1"
 * 2. finalizationId
 * finalizationId already covers the candidate list and
 * previousFinalizationId. A signature over revisionId alone
 * does not verify. Changing the parent or the candidate list
 * changes finalizationId, so the old signature fails.
 * A finalization is on the current chain only when
 * previousFinalizationId is the winner of the previous epoch,
 * or "" for the first epoch. A later smaller finalizationId
 * at an epoch drops every later finalization that names the
 * displaced id, or names a descendant of that id, off the
 * current chain. Replicas keep those finalizations. They are
 * not the winner and they do not extend the chain.
 * The owner rebuilds outward. Each invalidated epoch, parent
 * before child, gets a new finalization. Its
 * previousFinalizationId is the new parent winner. Its
 * revisionId is a new manifest. It does not reuse the
 * displaced finalizationId. That candidate starts its own
 * settle window. Content bound to a displaced descendant is
 * not current. The owner re-encrypts it under the rebuilt
 * winner after that window, and issues wraps for the new
 * snapshot. Readers stay on the last settled revision that
 * still sits on the current chain.
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
 * One replica's view of one epoch step.
 * seen is every verified EpochFinalization for this parent.
 * The winner is the smallest finalizationId in seen.
 * winnerSeenAt is when this replica first observed that id.
 * A later smaller id replaces the winner and sets a new
 * winnerSeenAt.
 * settleWindowMs is the in-range value from the winning
 * manifest, which matches GroupEpochConfig for a group epoch.
 * settledRevisionId is the last revision whose window already
 * elapsed. Readers use that key while a candidate is pending
 * and switch to the winner once the window elapses.
 * The window does not delay privilege-down or grantRevision.
 * Not a grant.
 */
export type EpochReplicaView = {
  object: CheckObjectId;
  epoch: number;
  previousFinalizationId: string;
  seen: readonly EpochFinalization[];
  winnerSeenAt: number;
  settleWindowMs: number;
  settledRevisionId: string;
};

/**
 * Spec signature. The reference crate does not run this.
 * False when settleWindowMs is outside SETTLE_WINDOW_MIN_MS
 * through SETTLE_WINDOW_MAX_MS.
 * True only when view.seen has a winner and
 * now >= winnerSeenAt + settleWindowMs.
 * While false, readers keep settledRevisionId.
 * A smaller finalizationId after that instant still replaces
 * the winner. Readers then stay on settledRevisionId until
 * the new window elapses, and then switch.
 * A candidate with a stated-1 snapshot entry whose until is
 * <= now is not current, even after the window. The buffer
 * stays buffered until a replacement that excludes that
 * accessor settles.
 * A cancel or a higher grantRevision applies when seen.
 * This wait does not delay that. Does not mint.
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
 * challenges holds every outstanding admission nonce. Issuing
 * one does not drop another. spent holds challenge nonces and
 * stamp signatures already used. Spending one nonce leaves
 * the other challenges in place.
 */
export type VerifierAdmissionState = {
  challenges: readonly AdmissionChallenge[];
  stampIssuers: readonly string[];
  spent: readonly string[];
  knownSenders: readonly AccessorId[];
  senderQuotas: readonly SenderQuota[];
  laneRemaining: number;
};

declare const writerChannelBrand: unique symbol;

/** Instances the transport constructor recorded. Not exported. */
declare const writerChannelInstances: WeakSet<AuthenticatedWriterChannel>;

/**
 * Transport identity for an append. Same runtime brand as
 * AuthenticatedPresenterChannel: ECMAScript #channelBrand,
 * module WeakSet, frozen writer and writerPub. Not a grant.
 * Not a writer pub on the stored row.
 */
export class AuthenticatedWriterChannel {
  private constructor(writer: AccessorId, writerPub: string);
  readonly writer: AccessorId;
  readonly writerPub: string;
  readonly #channelBrand: typeof writerChannelBrand;
  hasTransportBrand(): boolean;
}

/**
 * Signature over row.entryId by the writer's enrolled SEA pub.
 * Checked at append. Not stored on the content-addressed row.
 * Not a grant.
 */
export type WriterAppendProof = {
  writer: AccessorId;
  writerPub: string;
  signature: string;
};

/**
 * How filterInboxAppend learns the writer. A bare accessor
 * is not a member of this union. channel or signature is
 * checked before knownSenders, the allowlist, and quotas.
 */
export type WriterAppendAuth =
  | { kind: "channel"; channel: AuthenticatedWriterChannel }
  | { kind: "signature"; proof: WriterAppendProof };

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
    | "writer-auth"
    | "stamp-required"
    | "stamp-mismatch"
    | "replay"
    | "sender-quota"
    | "reader-capacity";
};

/**
 * Spec signature. The reference crate does not run this.
 * public-filtered is the default: any writer may append.
 * state is the verifier's challenges, issuers, replay set,
 * known senders, per-sender quotas, and the one lane capacity.
 * writerAuth is a transport channel or a signature over
 * row.entryId. The writer id is taken only after that check
 * matches the enrolled pub. A bare accessor is writer-auth
 * and does not read knownSenders or quotas. The stored row
 * still has no writer pub.
 * The writer does not pass the counters.
 * A matching challenge nonce is spent alone. Other outstanding
 * challenges stay.
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
  row: BlindedGrantRow,
  state: VerifierAdmissionState,
  now: number,
  writerAuth: WriterAppendAuth,
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
 * The settle window does not delay that privilege-down.
 * A revoked reader is absent from every candidate epoch's wraps.
 * forward-only: new epoch for later writes; old ciphertext stays
 * under the last settled key while the candidate is pending.
 * re-encrypt: rewrite existing ciphertext under the candidate DEK.
 * Remaining readers keep the last settled key until the window
 * elapses, then switch. Either way, bytes a revoked reader
 * already unwrapped stay readable to them. An older epoch wrap
 * does not mint.
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
 * One current reader during migration. acknowledged is an
 * authenticated receipt that this reader has the wrap.
 * atGate means readerVersion >= versionGate. atGate alone
 * does not remove plaintext. Plaintext for this reader stays
 * until acknowledged is set.
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
 * Plaintext removal is per reader, after that reader's
 * authenticated wrap receipt. A version at or above
 * versionGate does not by itself remove plaintext.
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
  | "commitment-blinding"
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
  | "grant-revision-stale"
  | "grant-item-digest"
  | "writer-auth-required"
  | "inbox-concurrent-challenges"
  | "presenter-brand-unforgeable"
  | "revoke-no-old-key-writes"
  | "grant-payload-mismatch"
  | "grant-revision-tie"
  | "grant-revision-digest-tie"
  | "grant-empty-digest"
  | "epoch-proof-matches-winner"
  | "epoch-buffer-until-settle"
  | "epoch-stale-acl"
  | "epoch-reencrypt-displaced"
  | "epoch-rebuild-descendants"
  | "epoch-finalization-sig"
  | "epoch-expire-before-settle"
  | "inbox-envelope-body"
  | "item-auth-canonical"
  | "status-policy-max-age"
  | "status-binds-accessor"
  | "status-object-match"
  | "status-signed-encoding"
  | "presented-group-check"
  | "migration-wrap-receipt"
  | "epoch-late-manifest"
  | "epoch-arrival-order"
  | "epoch-settle-window"
  | "epoch-settle-bounds"
  | "epoch-settle-pending-key"
  | "epoch-settle-skips-revoke"
  | "epoch-group-window"
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
