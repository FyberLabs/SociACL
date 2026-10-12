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
 *   hopcap 1, jointly stated grants, revoke immediate
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
 */
export type WrappedKey = {
  scope: "item-dek" | "group-key";
  epoch: number;
  target: "reader-epub" | "group-epoch";
  /** SEA epub, or group id when target is group-epoch. */
  targetId: string;
  object?: CheckObjectId;
  group?: string;
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
 */
export type GrantCommitment = {
  hash: string;
};

/**
 * Visible lane entry. Replaces plaintext enumeration of
 * grantSoul for private items. No owner field.
 * A wrap on the row is not a grant. hamState: higher wins.
 * laneId is the reader's one lane, not a shared bucket.
 */
export type BlindedGrantRow = {
  laneId: string;
  /** Entry id inside the one lane. Not a plaintext accessor path. */
  entryId: string;
  /** Ciphertext of the canonical grant, including the owner id and the signature. */
  grantCiphertext: string;
  commitment: GrantCommitment;
  wrap?: WrappedKey;
  hamState: number;
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
 * that seaPub is the enrolled key for owner. Then Check runs.
 * A presentation is not a grant.
 */
export type GrantPresentation = {
  owner: AccessorId;
  grant: MeshSeeGrant;
  /** Canonical bytes the commitment hashes. */
  grantBytes: string;
  signature: string;
  /** Enrolled account SEA pub. Not a field of BlindedGrantRow. */
  seaPub: string;
};

/**
 * Spec signature. The reference crate does not run this.
 * Commitment mismatch or a bad signature fails closed.
 * A hop, a hint, or a wrap never mints.
 */
export function checkPresentedGrant(
  row: BlindedGrantRow,
  presentation: GrantPresentation,
  graph: SeeGraph,
  accessor: AccessorId,
  now: number,
  hint?: HandoffHint,
  hop?: HopFactor,
): CheckResult;

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
 * Who may append to the one lane. Default is public-filtered:
 * any principal may append, and the reader drops spam.
 * named-writers appends only from writers.
 * A passed hook is not a grant.
 */
export type InboxWritePolicy = "public-filtered" | "named-writers";

export type InboxWriteHook = {
  policy: InboxWritePolicy;
  /** Required when policy is named-writers. */
  writers?: readonly AccessorId[];
};

export type InboxWriteDecision = {
  allowAppend: boolean;
  /** Local drop label. Not a Check reason and not a grant. */
  filter: "ok" | "spam" | "unnamed-writer";
};

/**
 * Spec signature. The reference crate does not run this.
 * public-filtered is the default: any writer may append.
 * The reader then drops oversized rows and rows over a local
 * rate. Commitment mismatch is checkPresentedGrant, not this
 * hook. SociACL does not store the filter.
 */
export function filterInboxAppend(
  hook: InboxWriteHook,
  writer: AccessorId,
  rowBytes: number,
): InboxWriteDecision;

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
 * the next epoch, remaining readers only, then cipher mode.
 */
export type EpochRotation = {
  object: CheckObjectId;
  revokedEpoch: number;
  nextEpoch: number;
  cancelled: readonly CancelledGrant[];
  rewrapped: readonly WrappedKey[];
  cipher: RevokeCipherMode;
};

/**
 * Spec signature. The reference crate does not run this.
 * Privilege-down first (stated 0, hamState bump), then wraps of
 * the next epoch. A wrap written here is not a grant.
 */
export function rotateOnRevoke(rotation: EpochRotation): void;

/**
 * In-place encryption when a protocol version is applied.
 * The object id stays. The body is replaced with ciphertext.
 * Plaintext already replicated elsewhere is a historical leak.
 * Not a grant.
 */
export type ProtocolMigration = {
  object: CheckObjectId;
  fromVersion: number;
  toVersion: number;
  rewrapped: readonly WrappedKey[];
};

/**
 * Not a Check object. SociACL runs no index and does not store this.
 * public: one index, public content only.
 * private-group: that group's own index.
 * local: one person, after push/pull, on device.
 * An index hit never mints.
 */
export type ContentIndexTier = "public" | "private-group" | "local";
