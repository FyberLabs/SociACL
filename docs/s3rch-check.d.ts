/**
 * Light Check consume contract for s3r.ch.
 *
 * Copy or re-type these names in the Next app. Run Check in the
 * browser on the Gun mesh. Do not import the SociACL Rust crate.
 * Do not add this file as an npm package. This is a contract, not
 * a dependency.
 *
 * Reference implementation (Rust, this repo):
 *   crates/sociacl-gun — plaintext MeshSeeGrant Check
 *   crates/sociacl-encdisc — encrypted-discovery slice
 *     (account SEA key, enrollment, wrap edge, canonical ids,
 *      blinded rows, presenter binding, inbox admission,
 *      epoch admission, rotateOnRevoke,
 *      envelope path, manifest soul, status authority,
 *      group-inbox ssig, account-key log)
 */
declare const sociaclObjectId: unique symbol;
declare const sociaclPrincipalId: unique symbol;

/** Object id. A copied contract file does not import the ids package. */
export type ObjectId = string & { readonly [sociaclObjectId]: "ObjectId" };
/** Genesis principal. A copied contract file does not import the ids package. */
export type PrincipalId = string & { readonly [sociaclPrincipalId]: "PrincipalId" };

/**
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
 *   request  = access request; never a grant
 *   same-group / named-circle = direct edges only; no transitive inheritance
 *
 * Wrapped keys, recipient-side discovery, rotation on revoke:
 * docs/encrypted-discovery.md. sociacl-gun evaluates plaintext see
 * grants and direct same-group / named-circle edges. It does not
 * evaluate a wrap. sociacl-encdisc implements the account key, the
 * wrap edge, the canonical ids, blinded rows, checkPresentedGrant,
 * inbox admission, epoch admission, rotateOnRevoke, and in-place
 * migration. A shard-close watermark is not implemented.
 * SEA priv and epriv never go on Gun.
 */

/** Fixed Gun root. */
export type S3rchRoot = "s3rch";

export type FeedSource = "rss3" | "rss" | "atom";

/**
 * In-graph feed node. Native Check object.
 * gun.get('s3rch').get('items').get(<id>)
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
 * Account identity for a forum agent is the GunDB SEA pubkey
 * (`PrincipalId`). A wallet and a Panopticon OAuth subject are
 * linked credentials. They are not this key and not a second
 * identity plane.
 *
 * Status soul, not a grant soul:
 * gun.get('s3rch').get('forums').get(<forumId>).get('agents').get(<seaPubkey>)
 * `forumId` is a minted object id of kind `forum`.
 * `seaPubkey` is that SEA pubkey, not a `p_` key and not a wallet.
 * Check `see` on the admitted object id stored in `id`.
 * State is data, not a grant.
 * `started`, `tokens`, and `runtime` are this agent's counters.
 * `tokens` is not a transfer.
 */
export type ForumAgentState = "idle" | "working" | "needs" | "emergency";

export type ForumAgentStatus = {
  /** Minted object id of kind `status`. The embedded principal is `seaPubkey`. */
  id: ObjectId;
  forumId: ObjectId;
  seaPubkey: PrincipalId;
  task: string;
  result: string;
  /** Comma-separated need object ids. Gun has no arrays. */
  needs: string;
  progress: number;
  state: ForumAgentState;
  lastPrompt: string;
  lastUpdate: number;
  type: string;
  started: number;
  tokens: number;
  runtime: number;
  /** Optional robotics vitals. A UX toggle. Not a grant. */
  hb?: number;
  batt?: number;
  link?: number;
  /** Comma-separated feed item ids attached to the drawer. Not a chat tree. */
  artifacts?: string;
};

/**
 * Need object. Soul:
 * s3rch/forums/<forumId>/needs/<needId>
 * `stated` 1 is open. `stated` 0 is resolved.
 * Anyone with Check see on this need may resolve (`stated` or
 * hamState update). The update is accepted only when that Check
 * allows the writer on this need id. A missing admission does not
 * accept the update. The admitted object owner stays the owner.
 * A status node, a chat item, a hop, and a hint do not mint.
 */
export type ForumNeedSeverity = "need" | "emergency";

export type ForumNeed = {
  /** Minted object id of kind `need`. */
  id: ObjectId;
  forumId: ObjectId;
  /**
   * SEA pubkey the need is about. Not compared to the forum id or
   * to the principal embedded in that id. Not a role token.
   */
  subject: PrincipalId;
  severity: ForumNeedSeverity;
  body: string;
  stated: 0 | 1;
  hamState: number;
  ts: number;
};

/**
 * Pinned emergency for the global alarm.
 * Soul: s3rch/forums/<forumId>/alarm
 * `pinned` is 1. The header alarm is also the fan-in of status
 * tiles whose `state` is `emergency`. Either input is enough.
 * This node is data. It is not a grant.
 */
export type ForumAlarm = {
  forumId: ObjectId;
  need: ObjectId;
  pinned: 1;
};

/**
 * Forum template. The template chooses one mode for the whole forum.
 * distinct-principals: each role token is a different SEA principal.
 * role-labels: one SEA principal wears several role tokens.
 * A role token is not a Check predicate and not a principal.
 * Soul: s3rch/forums/<forumId>/template
 */
export type ForumRoleMode = "distinct-principals" | "role-labels";

export type ForumTemplate = {
  forumId: ObjectId;
  mode: ForumRoleMode;
};

/**
 * One role token on one SEA principal.
 * Soul: s3rch/forums/<forumId>/roles/<roleToken>/<seaPubkey>
 * `role` is a lowercase token (letters, digits, hyphen). A display
 * title is not this token. The token is not a Check predicate.
 */
export type ForumRoleMembership = {
  forumId: ObjectId;
  role: string;
  principal: PrincipalId;
};

/**
 * Forum chat statement. Same [`GunFeedNode`] under `s3rch/items`.
 * `tags` includes `forum:<forumId>`. There is no `s3rch/chat` soul
 * and no `s3rch/forums/<forumId>/chat` soul. An @role in the body
 * is addressing. It is not authority.
 */
export type ForumChatItem = GunFeedNode;

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
 * Unsigned see-grant data, not admission or proof of ownership.
 * Check requires an admitted signed mesh row and signed object record.
 * `from` inclusive, `until` exclusive.
 */
export type IdentitySeeGrant = {
  object: ObjectId;
  accessor: PrincipalId;
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
 * Mesh Check / hop `object`. A stored id from the ids parser.
 * ens:name.eth, unstoppable:name.crypto, fc:name, lens:name, and
 * rss3:0x… are parse rejects, not object ids. s3rch/items/<id> is a
 * parse reject. Do not invent s3rch/users/<wallet>/claims/….
 * GunUserNode.indicators still names held claims; Check does not
 * read those strings as object ids.
 */
export type CheckObjectId = ObjectId;

/** Stored principal. A wallet string is not this id. */
export type AccessorId = PrincipalId;

export type CheckResult = {
  allowed: boolean;
  /**
   * Predicate / deny reason. A present hint never makes this a grant.
   * A present hop never makes this a grant.
   * A present wrap never makes this a grant.
   * A present request never makes this a grant.
   */
  reason: string;
};

/**
 * Live graph the browser reads. Only in-graph objects, jointly
 * stated see grants, and separate post grants. Do not walk friend
 * edges (hopcap 1).
 *
 * Mesh: each peer evaluates against its locally HAM-merged Gun graph
 * at now. Do not cache an allow across a privilege-down merge.
 */
export type SeeGraph = {
  hasObject(object: CheckObjectId): boolean;
  ownerOf(object: CheckObjectId): AccessorId | undefined;
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
 * Rotation history for one principal. A missing result is not an
 * empty history. admitRow and reverifyPrincipal fail closed.
 */
export type SeeResolver = {
  rotations(principal: PrincipalId): readonly unknown[] | undefined;
  ctx: object;
};

/** Signed object owner. Domain sociacl-object-v2. The owner signs it. */
export type ObjectRecord = {
  object: ObjectId;
  owner: PrincipalId;
  issuedAt: number;
  sig: string;
};

/** Admitted owner. A mismatched owner is `bad-record` and is not stored. */
export type ObjectAdmission = {
  owner: PrincipalId;
  issuedAt: number;
};

/**
 * One admitted see row. mode witnessed is a retired stated-0 cancel.
 * The tie-break bytes returned to the caller are a copy.
 */
export type VerifiedRow = {
  mode: "present" | "witnessed";
  grant: {
    owner: PrincipalId;
    object: ObjectId;
    accessor: PrincipalId;
    stated: 0 | 1;
    from: number;
    until: number;
    hamState: number;
    issuedAt: number;
    sig: string;
    attest?: string;
  };
};

/**
 * Admit a signed sociacl-object-v2 record. The owner is the record.
 * The object id embeds that genesis principal. Anything else is bad-record.
 * The same owner later is a no-op while the stored record still verifies.
 * A stored record is replaced only when the new issuedAt is strictly newer,
 * the stored record no longer verifies, and the new signer is not a key
 * the stored history marks retired.
 */
export function putObject(
  graph: object,
  record: unknown,
  resolver: SeeResolver,
): { ok: true; value: ObjectAdmission; kept: boolean } | { ok: false; reason: string };

/**
 * Admit one sociacl-post-grant-v2 row. The owner is the admitted object
 * record. Missing history is `missing-history`. No object record is
 * `unknown`. A row owner that is not that record is `bad-record`.
 * A retired cancel is `stated` 0 in the signed bytes. A retired
 * `stated` 1 row is `unwitnessed-retired-key`.
 */
export function admitPost(
  graph: object,
  row: unknown,
  resolver: SeeResolver,
): { ok: true; value: VerifiedRow; kept: boolean } | { ok: false; reason: string };

/** Admit one sociacl-see-grant-v2 row. Missing history is missing-history. */
export function admitRow(
  graph: object,
  row: unknown,
  resolver: SeeResolver,
): { ok: true; value: VerifiedRow; kept: boolean } | { ok: false; reason: string };

/** Recheck one principal. A retired object record stops counting until it is re-signed. Missing history drops that principal's rows and object records. */
export function reverifyPrincipal(
  graph: object,
  principal: PrincipalId,
  resolver: SeeResolver,
): { ok: true; value: { dropped: number } } | { ok: false; reason: string };

/**
 * CHECK(see, object, accessor) at now.
 * see maps to dest read. Hint is ignored for allowed.
 * Hop missing does not fail. Hop alone never allows.
 * An owner allow comes only from an admitted object record.
 * A delegate allow is an
 * admitted stated-1 row with now in [from, until).
 * A primitive graph is bad-record. A wrap is not an argument.
 * A hop, a hint, or a wrap never mints.
 */
export function checkSee(
  graph: object,
  object: CheckObjectId,
  accessor: AccessorId,
  now: number,
  hint?: HandoffHint,
  hop?: HopFactor,
): CheckResult;

/**
 * Allow-post for a s3r.ch View.
 * Allowed only when checkSee would allow the same triple on the
 * admitted see graph. The object owner comes from the admitted
 * sociacl-object-v2 record and may post. Any other accessor also
 * needs a live sociacl-post-grant-v2 row with now in [from, until).
 * A retired-key post cancel is stated 0 inside those signed bytes.
 * A post row alone does not allow. A see row does not allow post.
 * checkGroupSee is not this gate. Hopcap is 1.
 * Hop missing does not fail. Hop alone never allows.
 * A hop, a hint, a wrap, a request, or an inbox delivery never grants.
 * Do not cache an allow across a privilege-down merge.
 * This check does not verify a signature.
 */
export function checkPost(
  graph: SeeGraph,
  object: CheckObjectId,
  accessor: AccessorId,
  now: number,
  hint?: HandoffHint,
  hop?: HopFactor,
): CheckResult;

/**
 * A hop, a hint, a wrap, a request, or an inbox delivery never grants.
 * The result is false for every kind.
 */
export function factorGrants(
  kind: "hop" | "hint" | "wrap" | "inbox" | "request",
): false;

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
 * Owner dest-ACL root. Not a Check object.
 * gun.get('s3rch').get('acl').get(<owner>)
 */
export function aclSoul(owner: AccessorId): string | null;

/**
 * Jointly stated see grant under the object owner's dest ACL.
 * Does not fork items or users.
 * gun.get('s3rch').get('acl')
 *   .get(<owner>)
 *   .get(<object>)
 *   .get(<accessor>)
 */
export function grantSoul(
  owner: AccessorId,
  object: CheckObjectId,
  accessor: AccessorId,
): string | null;

/**
 * Forum soul helpers. The consumer implements these names.
 * This file declares them. Filled strings are in
 * `vectors/mesh/forums.json`. Not a grant soul. Not a chat soul.
 *
 * Status soul: `s3rch/forums/<forumId>/agents/<seaPubkey>`.
 */
export function forumAgentSoul(forumId: ObjectId, seaPubkey: PrincipalId): string;

/** `s3rch/forums/<forumId>/needs/<needId>`. */
export function forumNeedSoul(forumId: ObjectId, needId: ObjectId): string;

/** `s3rch/forums/<forumId>/alarm`. Pinned emergency. Not a grant. */
export function forumAlarmSoul(forumId: ObjectId): string;

/** `s3rch/forums/<forumId>/template`. */
export function forumTemplateSoul(forumId: ObjectId): string;

/**
 * `s3rch/forums/<forumId>/roles/<roleToken>/<seaPubkey>`.
 * The role token is not a Check predicate.
 */
export function forumRoleSoul(
  forumId: ObjectId,
  roleToken: string,
  seaPubkey: PrincipalId,
): string;

/** Child soul under the agent status node. Not a chat tree. */
export function forumSubtaskSoul(
  forumId: ObjectId,
  seaPubkey: PrincipalId,
  subtaskId: ObjectId,
): string;

/** Child soul under the agent status node. Not a chat tree. */
export function forumUpdateSoul(
  forumId: ObjectId,
  seaPubkey: PrincipalId,
  updateId: ObjectId,
): string;

/**
 * Tag for a forum chat statement on a GunFeedNode.
 * Spelling: `forum:<forumId>`. Not a soul.
 */
export function forumChatTag(forumId: ObjectId): string;

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

/**
 * In-graph post grant. Separate soul from MeshSeeGrant.
 * Same fields and the same cancel rule.
 * `stated` 1 = live, 0 = cancelled (privilege-down).
 * `from` inclusive, `until` exclusive.
 * Cancel is owner-only, sets stated to 0, and bumps hamState.
 * Do not cache an allow after that merge.
 */
/** Signed sociacl-post-grant-v2 row. `issuedAt` is inside the signed bytes. */
export type MeshPostGrant = {
  owner: PrincipalId;
  object: ObjectId;
  accessor: PrincipalId;
  stated: 0 | 1;
  from: number;
  until: number;
  hamState: number;
  issuedAt: number;
  sig: string;
  attest?: string;
};

/** Length-prefixed domain for postGrantBytes. */
export const POST_GRANT_DOMAIN: "sociacl-post-grant-v2";

/**
 * Six-segment post soul. Each principal is `p_` plus 128 lowercase hex.
 * Not a label soul and not a five-segment see soul.
 * Throws when owner, object, or accessor is not an already-parsed id.
 * A parsed triple returns the soul string.
 */
export function postSoul(
  owner: PrincipalId,
  object: ObjectId,
  accessor: PrincipalId,
): string;

/**
 * Length-prefixed v2 signing bytes. Domain sociacl-post-grant-v2,
 * then owner, object, accessor, decimal stated, decimal from,
 * decimal until, decimal hamState, and decimal issuedAt.
 * Lengths are uint32 little-endian. Integers are ASCII decimal
 * with no leading zeros. Check does not verify a signature.
 */
export function postGrantBytes(grant: MeshPostGrant): Uint8Array;

/**
 * Access request. An untrusted hint. Not a grant.
 * scope is only `read` or `read+post`. status is only `pending`
 * or `withdrawn`. Any other spelling is rejected.
 * message is at most 280 Unicode scalar values and may be empty.
 * A non-string field is `not-string` before coercion.
 */
export type AccessRequest = {
  requestId: string;
  requester: PrincipalId;
  object: ObjectId;
  scope: "read" | "read+post";
  status: "pending" | "withdrawn";
  message: string;
  issuedAt: number;
  /**
   * P-256 signature over accessRequestBytes. Raw r||s, base64url.
   * Present authority only. A retired key does not count.
   * An Ed25519 signature does not verify.
   */
  sig: string;
};

/**
 * Members auto-approve on the owner's client.
 * grantApprovedRequest evaluates checkGroupSee on the stored object id.
 * Hop and hint are not inputs. There is no hosted evaluator.
 */
export type MembersAutoApprove = {
  predicate: "same-group" | "named-circle";
  now: number;
};

/**
 * Owner-signed rows. post is null for scope read.
 * Both rows are sociacl-see-grant-v2 and sociacl-post-grant-v2.
 * Nothing is written unless both checks pass.
 */
export type AccessApproval =
  | {
      granted: true;
      requestId: string;
      see: VerifiedRow;
      post: VerifiedRow | null;
      /** Set when the stored row already matched. No new signature and no ham bump. */
      unchanged?: true;
    }
  | {
      granted: false;
      reason: string;
    };

/** Length-prefixed domain for accessRequestBytes. */
export const REQUEST_DOMAIN: "sociacl-access-request-v2";

/** Length-prefixed domain for requestId. */
export const REQUEST_ID_DOMAIN: "sociacl-request-id-v2";

/**
 * SHA-256 lowercase hex of domain sociacl-request-id-v2, the requester,
 * and the object. Scope, message, and status are not inputs.
 * The request id and the object are the same parsed id.
 * A non-string argument is `not-string`.
 */
export function requestId(
  requester: unknown,
  object: unknown,
): { ok: true; value: string } | { ok: false; reason: string };

/**
 * Length-prefixed bytes the requester signs.
 * Domain sociacl-access-request-v2, the request id, requester, object,
 * scope, status, message, and decimal issuedAt. Lengths are uint32
 * little-endian. Does not verify a signature and does not grant.
 */
export function accessRequestBytes(request: AccessRequest): Uint8Array;

/**
 * Snapshot one access request. Scope is `read` or `read+post`.
 * Status is `pending` or `withdrawn`. The message is at most 280
 * Unicode scalar values and may be empty. A missing or non-string
 * scope, status, message, requester, or object is `not-string`.
 * A missing request id is `bad-record`. A wrong domain or a missing
 * signature is `legacy-row`.
 */
export function parseAccessRequest(
  row: unknown,
):
  | { ok: true; value: { request: AccessRequest; bytes: Uint8Array } }
  | { ok: false; reason: string };

/**
 * Present authority for the requester. A retired key is refused.
 * Kind is not a parameter.
 */
export function verifyAccessRequest(
  row: unknown,
  rotations: readonly unknown[],
  ctx: object,
):
  | {
      ok: true;
      value: {
        key: PrincipalId;
        mode: "present";
        request: AccessRequest;
        bytes: Uint8Array;
      };
    }
  | { ok: false; reason: string };

/**
 * Owner's client. Writes a sociacl-see-grant-v2 row for an approved
 * pending request, and a sociacl-post-grant-v2 row when the scope is
 * read+post. The owner signs both under the current key. issuedAt on
 * those rows is the resolver's now. The requester signature is checked
 * with verifySignedAt. Only a present key counts. Both ham ceilings
 * are checked against one resolved history before either row is written.
 * Both rows are written, or neither is. There is no staged ticket.
 * An identical approval returns the stored row with `unchanged: true`
 * only after the current key resolves, the scalar owns that key, and
 * members allow, and only when the stored row is signed by that key.
 * It does not sign or bump ham. A retired-key row is signed again.
 * A different window is a new decision. The window is copied once.
 * Members auto-approve over an owner cancel is `not-kept` and writes
 * nothing. A manual approval re-grants above that cancel. When `now`
 * equals the latest rotation time the result is `rotation-boundary`.
 * members, when supplied, requires the label owner to parse as the
 * admitted signed owner and a real membership reason from
 * checkGroupSee. The owner shortcut is not membership. A withdrawn
 * request writes nothing. A caller who is not the admitted object
 * owner writes nothing. A hop, a hint, a wrap, a request, or an inbox
 * delivery is not an approval. There is no hosted evaluator.
 */
export function grantApprovedRequest(
  graph: SeeGraph & {
    checkGroupSee?(
      predicate: "same-group" | "named-circle",
      object: ObjectId,
      accessor: PrincipalId,
      now: number,
    ): CheckResult;
  },
  owner: PrincipalId,
  request: AccessRequest,
  window: { from: number; until: number },
  members: MembersAutoApprove | null,
  signer: { scalar: Uint8Array; resolver: SeeResolver },
): AccessApproval;

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
/* Wrapped keys and private rows stay spec. Group edges are evaluated.       */
/*                                                                            */
/* docs/encrypted-discovery.md. Copy / re-type with the types above.          */
/* sociacl-gun evaluates plaintext MeshSeeGrant and MeshPostGrant rows       */
/* and direct same-group / named-circle edges. It does not evaluate a wrap.  */
/* An inbox delivery is not a grant.                                          */
/* sociacl-encdisc implements the account key, the wrap edge, the canonical   */
/* ids, blinded rows, checkPresentedGrant, inbox admission, epoch admission,  */
/* rotateOnRevoke, and in-place migration. A shard-close watermark is not     */
/* implemented.                                                               */
/* A wrap is not a grant. An inbox append is not a grant.                     */
/* SEA priv and epriv never go on Gun.                                        */
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
 * crates/sociacl-encdisc seals this payload. sociacl-gun does
 * not read wrap bytes.
 * Where the SEA byte layout is not locked, the wire fails closed:
 * reader wrap is ECDH P-256. The shared secret is the 32-byte x
 * coordinate. The AES-256-GCM key is SHA-256 of the length-prefixed
 * fields "s3rch-sea-secret-v1" and the lowercase hex of that
 * coordinate. SEA.encrypt's password-salt envelope is not this wrap.
 * Group-epoch wrap has no reader epub. Its AES key is SHA-256 of
 * "s3rch-group-epoch-wrap-v1" and the lowercase hex of the 32-byte
 * group key.
 * AES-GCM plaintext, length-prefixed, domain "s3rch-wrapped-key-v1":
 * scope, decimal epoch, target, targetId, object or empty, group
 * or empty, revisionId, lowercase hex of the 32-byte key. The
 * cleartext label must match or the open fails as one error.
 * wrappedKey is lowercase hex. Version 0x01 is a reader wrap:
 * 65-byte uncompressed ephemeral point, 12-byte nonce, ciphertext
 * and 16-byte tag. Version 0x02 is a group-epoch wrap: nonce,
 * ciphertext, and tag. The DEK and the group key are 32 bytes.
 * A target outside the already-named set is not wrapped. This
 * slice does not read the graph and does not mint membership.
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
 * One SEA keypair for the account. The account id is the genesis
 * SEA pub (sociacl-ids PrincipalId). Devices inherit this same
 * keypair through enrollment. They do not mint a second pair or
 * an identity. pub and epub may sit on the user node. priv and
 * epriv never go on Gun. Enrollment does not mint a grant.
 * Wallets and OIDC subjects are linked credentials, not this id.
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
 * The verifying pub is the enrolled pub of graph.ownerOf(object).
 * A signature under a reader's own key does not pass.
 * The signature string is lowercase hex of low-s IEEE P1363 r||s
 * (128 hex chars) from one P-256 ECDSA-SHA256 over those bytes.
 * A SEA {m,s} envelope, a DER encoding, or a high-s encoding does
 * not verify. crates/sociacl-encdisc verifies this signature. It
 * does not build the item ciphertext.
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
 * An encrypted item also names manifest, the soul
 * s3rch/items/<itemId>/m/<rev>. That field is grantManifestBytes.
 * It is outside this v1 payload encoding. CHECK rejects a missing
 * soul or a soul that is not that item and rev. An author-lane
 * copy does not satisfy the grantee.
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
 * SHA-256 of the canonical bytes below, as lowercase hex
 * (64 chars). Not a hex encoding of the raw body. Does not mint.
 * crates/sociacl-encdisc runs this hash. The hash does not admit
 * the row. Admission is filterInboxAppend.
 *
 * Canonical bytes are the concatenation, for each field in
 * order, of a uint32 little-endian length and then the UTF-8
 * bytes of that field. An empty field is 4 zero bytes.
 * Integers are ASCII decimal with no sign and no leading zeros.
 * The value 0 is the single byte 0x30.
 * A value above 9007199254740991 (2^53-1) is rejected, the
 * same bound as JavaScript Number.isSafeInteger.
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
 * verifies writerSignature over the length-prefixed fields
 * "s3rch-writer-append-v1" and entryId, without opening the
 * grant. The same bytes as WriterAppendProof. The default
 * public lane stays content-addressed and does not carry
 * writerPub. A replicated public row is not admitted until
 * this verifier runs filterInboxAppend and records entryId.
 * A body that no longer hashes to that entryId is not admitted.
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
 * laneId is 32 bytes, lowercase hex, chosen when the account
 * key is minted. It is not the plaintext accessor id. A shorter
 * string, uppercase hex, or any other shape is rejected at
 * registration. Scanning it is not Check and does not mint.
 */
export type RecipientInbox = {
  accessor: AccessorId;
  laneId: string;
};

/**
 * Opened grant the holder shows to the destination.
 * Not written to Gun. The destination recomputes GrantCommitment
 * from blinding and grantBytes, checks that owner equals
 * graph.ownerOf(object), checks the signature with seaPub,
 * and checks that seaPub is the enrolled key for that owner.
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
 * Signed bytes, length-prefixed:
 * 1. "s3rch-presenter-binding-v1"
 * 2. nonce
 * 3. commitment hash
 * 4. audience
 * audience is the string on the outstanding challenge.
 * The verifier chooses it and it names that verifier.
 * A signature that omits it, or names a different audience,
 * does not verify. The nonce is not spent.
 * A concatenated string with no lengths, or another framing,
 * does not verify.
 * readerPub is checked against VerifierEnrollmentState.
 * It is not the enrollment record.
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
 * audience is chosen by this verifier. It names that verifier.
 * The presenter signs it with the nonce. A signature for
 * another verifier's audience does not match this challenge.
 */
export type PresenterChallenge = {
  nonce: string;
  expiresAt: number;
  audience: string;
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
 * The signature is checked with the enrolled pub of
 * graph.ownerOf(object), not with a pub the presenter names
 * and not from a field on the visible row.
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
 * The reference crate runs this check.
 * Commitment mismatch or a bad owner signature fails closed.
 * challenges is the verifier's outstanding nonce set.
 * A binding nonce must match one outstanding challenge,
 * now must be before expiresAt, the signed audience must
 * equal that challenge's audience, and that nonce is then
 * spent. A different audience fails closed and the nonce
 * stays outstanding.
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
 * name the same object. status.accessor is the grant accessor
 * and the accessor argument. While epochStepCurrent is false
 * and settledRevisionId is set, status.epoch and the grant
 * epoch match epochView.settledEpoch, not the pending
 * epochView.epoch. Once epochStepCurrent is true, status.epoch,
 * the grant epoch, and epochView.epoch match. A mismatch fails
 * closed before challenges are spent and before revisions
 * changes.
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
 * snapshot and currentAcl are the same inputs epochStepCurrent
 * uses. The presenter does not supply them.
 * The read key is settledRevisionId while that function is
 * false, including when the timer has elapsed and the snapshot
 * still names an expired or cancelled recipient. status.revisionId
 * must be that read key. A proof for the pending candidate
 * while the function is false fails closed. Once the function
 * is true, the read key is the recomputed winner. Any other
 * revision fails closed.
 * When group is set, graph is a GroupSeeGraph and this
 * function runs checkGroupSee after the same binding,
 * revision, and freshness checks. checkGroupSee does not
 * read the decoded payload. allowed is true only when that
 * call allows, the decoded payload has stated 1, and now
 * is in [from, until). from is inclusive and until is
 * exclusive, same as MeshSeeGrant. stated 0 denies. A
 * payload outside that window denies. A live membership
 * edge does not override either deny. The revision record
 * may still store the cancel. When group is omitted,
 * it runs checkSee. A group object is an
 * authenticated, currently grantable object-set edge. A
 * stated bit alone does not name it. A group object with
 * no group argument fails closed.
 * The age bound is the smaller of status.maxAgeMs and
 * policyMaxAgeMs. policyMaxAgeMs is the verifier's cap.
 * The owner does not set it. A proof older than that bound
 * fails closed.
 * A proof alone grants nothing.
 * enrollment is the verifier's account-to-pub map. The
 * presenter does not supply it. Decode the payload first.
 * graph.ownerOf(decoded.object) must be present and must
 * equal the decoded owner and presentation.owner. A missing
 * owner or a different account fails closed before the
 * signature is accepted, before challenges are spent, and
 * before revisions change. presentation.seaPub must then
 * equal the enrolled pub for that graph owner. The status
 * proof is checked with that same pub.
 * binding.readerPub and channel.readerPub must equal the
 * enrolled pub for the grant accessor. A missing account or
 * a different pub fails closed the same way. A signature
 * that verifies under some other key, including a reader's
 * own key, is not enough.
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
  enrollment: VerifierEnrollmentState,
  snapshot: AclSnapshotBody,
  currentAcl: AclSnapshotBody,
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
 * revisionId is the EpochManifest this DEK belongs to.
 * The epoch number is not enough. A DEK for another revision,
 * including a displaced manifest of the same epoch, is not
 * this record. The author does not open superseded content
 * with it.
 */
export type AuthorFastUnwrap = {
  object: CheckObjectId;
  epoch: number;
  revisionId: string;
  dek: string;
};

/**
 * How the introduction binds SEA keys to the account.
 * enrollment: the reader's trusted enrollment record for
 * account already names this pub and this epub.
 * account-signature: signature by the account identity.
 * The verification key is EnrolledSeaPub.identityPub for
 * that account. The introduction does not supply it.
 * It is the account's one SEA pub, not a second keypair.
 * A missing identityPub fails closed.
 * Signed bytes, length-prefixed:
 * 1. "s3rch-account-binding-v1"
 * 2. account
 * 3. pub
 * 4. epub
 * The signed pub must equal identityPub, and the signed
 * epub must equal the enrolled epub.
 * A check that uses the introduced pub as the verification
 * key is not this binding.
 * A signature that omits account, or concatenates pub and
 * epub with no lengths, does not verify. A missing epub
 * or a swapped epub fails closed.
 * The signature string is lowercase hex of low-s IEEE P1363
 * r||s from one P-256 ECDSA-SHA256 over those bytes. A SEA
 * {m,s} envelope, DER, or high-s does not verify.
 * crates/sociacl-encdisc checks this binding. It does not
 * write the Gun user node.
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
 * A grantee accepts the manifest at ManifestSoul. An author-lane
 * copy, or a copy inside the ciphertext, does not satisfy that
 * grantee. statusAuthPub, when present, is covered by revisionId.
 * It is not an account identity. Not a grant.
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
  /**
   * Designated status SEA pub for this head. Omitted from the
   * canonical body when absent. An empty string is rejected.
   * When present it is the last field
   * of epochRevisionId. It is not an account identity. A status
   * proof signed by any other key verifies only when that key
   * equals this pub and the same pub on StatusAuthorityBinding,
   * and the binding seq is the account-key log head.
   */
  statusAuthPub?: string;
  /**
   * Owner signature over revisionId, not over keyCommitment
   * alone. Signed bytes, length-prefixed:
   * 1. "s3rch-epoch-manifest-sig-v1"
   * 2. revisionId
   * revisionId already covers object, epoch, previousEpoch,
   * deviceId, keyCommitment, settleWindowMs, aclSnapshot, and
   * statusAuthPub when that field is present.
   * A signature over keyCommitment alone does not verify.
   */
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
  /**
   * Omitted from the encoding when absent or empty.
   * Present, it is one more length-prefixed field.
   */
  statusAuthPub?: string;
};

/**
 * One accessor in an ACL snapshot. stated 1 receives a wrap
 * only while now is inside from and until.
 * stated 0 is a cancel at grantRevision and receives none.
 * A stated-1 entry with until <= now is expired. The candidate
 * that names it does not settle. The buffer stays buffered.
 * The same expiry closes a key that has already settled.
 * settledKeyOpen is then false, and new writes stay buffered.
 * The owner publishes a new revision whose key was not wrapped
 * to that accessor, and whose snapshot lists that accessor
 * stated 0. That replacement starts its own settle window.
 * scope direct is one grant. same-group and named-circle name
 * one MeshMembership. hamState is that membership's hamState.
 * A replica that knows the membership is cancelled at hamState
 * H ignores a snapshot that lists that accessor live for that
 * set, omits that set, or names a hamState below H.
 * Not a grant.
 */
export type AclSnapshotEntry = {
  accessor: AccessorId;
  grantRevision: number;
  stated: 0 | 1;
  /** Grant window. Covered by aclSnapshotId. */
  from: number;
  until: number;
  /** direct, or the membership predicate this wrap follows. */
  scope: "direct" | "same-group" | "named-circle";
  /** Empty when scope is direct. */
  setId: string;
  /**
   * MeshMembership.hamState for a group or circle.
   * 0 when scope is direct. Covered by aclSnapshotId.
   */
  hamState: number;
};

/**
 * Who receives a wrap for this candidate, and the cancel
 * applied for each accessor. Entries are sorted by accessor
 * in bytewise UTF-8 order. U+E000 precedes U+10000.
 * There is no single cancel high-water across accessors.
 * A replica that knows accessor A is cancelled at revision R
 * ignores a snapshot that lists A as stated 1, omits A, or
 * lists A cancelled below R.
 * For a group or circle entry, the same rule uses hamState
 * on that predicate and setId. A lower hamState does not hide
 * a removal this replica has already merged.
 * objectSet is the object-to-set edge. Member hamState does
 * not stand in for it. A replica that has merged a newer
 * ObjectSetName ignores a snapshot whose predicate, setId,
 * or stated disagrees, or whose hamState is lower, or that
 * omits the edge this replica has.
 * A stated-1 entry with until <= now does not settle. Not a grant.
 */
export type AclObjectSet = {
  predicate: "same-group" | "named-circle";
  setId: string;
  stated: 0 | 1;
  /** ObjectSetName.hamState. Not a member hamState. */
  hamState: number;
};

export type AclSnapshotBody = {
  /** Absent for a direct-grant object. */
  objectSet?: AclObjectSet;
  entries: readonly AclSnapshotEntry[];
};

/**
 * crates/sociacl-encdisc runs this hash. It does not mint.
 * SHA-256, lowercase hex, of the length-prefixed UTF-8
 * encoding. Fields:
 * 1. "s3rch-acl-snapshot-v1"
 * 2. "1" when objectSet is present, otherwise "0"
 * 3. objectSet.predicate, or empty
 * 4. objectSet.setId, or empty
 * 5. decimal objectSet.stated, or empty
 * 6. decimal objectSet.hamState, or empty
 * then each entry in bytewise UTF-8 accessor order as accessor, decimal
 * grantRevision, decimal stated, decimal from, decimal until,
 * scope, setId, decimal hamState. Does not mint.
 */
export function aclSnapshotId(body: AclSnapshotBody): string;

/**
 * SHA-256, lowercase hex, of the same length-prefixed UTF-8
 * encoding as inboxEntryId. Does not mint.
 * crates/sociacl-encdisc runs this hash. Admission enforces
 * the settle-window bounds. The hash alone does not settle
 * the epoch.
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
 * 9. statusAuthPub, only when present
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
 * owner, setId, predicate, decimal settleWindowMs, decimal
 * configRevision.
 * owner must equal GroupSeeGraph.ownerOfSet(predicate, setId).
 * The signature is checked with the enrolled pub of that
 * account. A missing set owner, a different owner, or a
 * signature under some other key fails closed.
 * configRevision is monotonic for that predicate and setId.
 * The greatest configRevision for that pair wins. A higher
 * revision for another predicate or setId does not. A lower
 * revision is ignored.
 * At the same configRevision, the smaller digest of those
 * signed bytes wins. Arrival order does not pick the config.
 * A group epoch manifest repeats the settleWindowMs of that
 * winning config. A manifest that repeats an older window
 * is ignored. Sits with the manifest, in the author lane or
 * inside the encrypted item. Not an owner pub on a visible
 * grant row. Not a grant.
 */
export type GroupEpochConfig = {
  /** Account that owns the set. Must match ownerOfSet. */
  owner: AccessorId;
  setId: string;
  predicate: "same-group" | "named-circle";
  settleWindowMs: number;
  /** Monotonic for this set and predicate. */
  configRevision: number;
  signature: string;
};

/**
 * Owner-signed candidate for one epoch step. The named
 * revisionId must be the lexicographically smallest id among
 * candidateRevisionIds that each resolve to a verified
 * EpochManifest with this same object, epoch, and previousEpoch.
 * An id that does not resolve, or that names another object
 * or epoch, is not in that minimum. A finalization that fails
 * that check is ignored.
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
 * or "" for the first epoch. A child names previousEpoch equal
 * to that parent epoch, and its own epoch is the next number.
 * A later epoch does not attach by previousFinalizationId alone.
 * A later smaller finalizationId
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
 * snapshot. Each remaining accessor gets a new signed payload
 * whose grantRevision is greater than that accessor's previous
 * record, and an EpochStatusProof that names that new
 * grantRevision and stated 1. The old payload stays at the
 * lower revision. An equal-revision digest comparison does
 * not keep the displaced ciphertext. Readers stay on the last
 * settled revision that still sits on the current chain.
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
 * elapsed. settledEpoch is the epoch of the on-chain
 * finalization for settledRevisionId. A separate caller epoch
 * does not replace that number.
 * Readers use that key while a candidate is pending and switch
 * to the winner once the window elapses. A presentation during
 * the window names settledEpoch, not the pending epoch.
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
  /** Epoch of settledRevisionId. Not the pending candidate. */
  settledEpoch: number;
};

/**
 * The reference crate runs this for the read key inside checkPresentedGrant.
 * snapshot is the ACL body of the winning manifest. Its
 * aclSnapshotId must be that manifest's aclSnapshot.
 * current is the ACL this replica has already merged.
 * The writer of the finalization does not supply either.
 * False when settleWindowMs is outside SETTLE_WINDOW_MIN_MS
 * through SETTLE_WINDOW_MAX_MS.
 * False when snapshot has a stated-1 entry with until <= now,
 * or from > now.
 * False when, for an accessor the snapshot lists, current has
 * a higher grantRevision, live or cancel, stated 0 against a
 * snapshot stated 1, an earlier until, or a later from.
 * False when current knows a higher membership hamState cancel,
 * a higher object-set hamState, a different object-set predicate
 * or setId, or a past until for an accessor the snapshot still
 * lists as stated 1.
 * False when one of snapshot and current has objectSet and
 * the other does not.
 * True only when view.seen has a winner, the snapshot still
 * matches current, and now >= winnerSeenAt + settleWindowMs.
 * While false, readers keep settledRevisionId and settledEpoch.
 * A smaller finalizationId after that instant still replaces
 * the winner. Readers then stay on settledRevisionId until
 * the new window elapses, and then switch.
 * The buffer stays buffered until a snapshot that excludes
 * each expired or cancelled accessor settles.
 * settledKeyOpen repeats that expiry check on the key that
 * has already settled. An until that passes after settlement
 * does not leave new writes on that key.
 * A cancel or a higher grantRevision applies when seen.
 * This wait does not delay that. Does not mint.
 */
export function epochStepCurrent(
  view: EpochReplicaView,
  snapshot: AclSnapshotBody,
  current: AclSnapshotBody,
  now: number,
): boolean;

/**
 * Whether new ciphertext may use the settled key.
 * settled is the ACL snapshot of view.settledRevisionId.
 * current is the ACL this replica has already merged.
 * The writer does not supply either.
 * False when any stated-1 entry has until <= now or from > now.
 * False when, for an accessor settled lists as stated 1,
 * current has stated 0, a higher grantRevision, an earlier
 * until, or a later from.
 * False on the same membership and object-set mismatches
 * as epochStepCurrent.
 * False when view.seen has a winner and that winner's
 * revisionId is not view.settledRevisionId, or when
 * now < view.winnerSeenAt + view.settleWindowMs.
 * The winner is the smallest finalizationId in seen.
 * A pending successor, including a late smaller id still
 * inside its settle window, does not leave the old key
 * writable.
 * While false, new writes are buffered. They are not encrypted
 * under settledRevisionId. The owner publishes a new revision
 * whose key was not wrapped to that accessor, and whose
 * snapshot lists that accessor stated 0. That replacement
 * starts its own settle window.
 * Ciphertext already written under the settled key stays.
 * Readers keep bytes they already unwrapped.
 * This check runs after settlement, not only when a candidate
 * is about to settle. crates/sociacl-encdisc runs this check.
 * Does not mint.
 */
export function settledKeyOpen(
  view: EpochReplicaView,
  settled: AclSnapshotBody,
  current: AclSnapshotBody,
  now: number,
): boolean;

/**
 * Rescan of one UTC day shard of the one lane.
 * day is YYYY-MM-DD. seen holds entry ids already accepted.
 * Dedup by entryId. This is the lane scan. A per-device cursor
 * is not part of this contract: the visible row has no device
 * id, and opening ciphertext to learn one does not yield a
 * lossless cursor. crates/sociacl-encdisc rescans the whole shard.
 * A shard-close watermark is not implemented. Not a second lane.
 * Not a grant.
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
 * proof-of-work: nonce names exactly one outstanding
 * AdmissionChallenge. SHA-256 of the length-prefixed fields
 * "s3rch-inbox-pow-v1", that nonce, row.entryId, solution
 * has at least that challenge's difficulty leading zero bits.
 * Only that nonce is spent. A solution that also meets
 * another challenge does not spend the other nonce. A nonce
 * that is not outstanding fails closed. Difficulty 0 still
 * names one nonce.
 * stamp: signature by a trusted issuer over the length-prefixed
 * fields "s3rch-inbox-stamp-v1" and row.entryId.
 * A stamp is not a grant.
 */
export type AdmissionEvidence =
  | { kind: "proof-of-work"; nonce: string; solution: string }
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
 * senderQuotas has one counter per known sender. A known
 * sender with no row has remaining 0.
 * firstContactRemaining is the verifier-chosen start for a
 * sender absent from knownSenders, after their evidence
 * verifies. The writer does not set it. 0 rejects that
 * first contact as sender-quota and does not add the sender.
 * Above 0, the counter is created at that value.
 * admitted lists entryIds this verifier has accepted. A
 * replicated row is not admitted until this check records
 * it. admitted is not a field of the stored row.
 * laneRemaining is the one shared capacity for this lane,
 * not a copy per sender.
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
  /** Verifier-chosen. Not a writer claim. */
  firstContactRemaining: number;
  /** Entry ids this verifier has admitted. Not on the row. */
  admitted: readonly string[];
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
 * The constructor is private. openWithPossession mints a value
 * only after `signature` verifies under writerPub. Signed bytes,
 * length-prefixed:
 * 1. "s3rch-writer-channel-v1"
 * 2. writer
 * A caller who knows writerPub and not the private key cannot
 * mint. A forbidden writer name is the same reserved list as
 * hop_forbidden.
 */
export class AuthenticatedWriterChannel {
  private constructor(writer: AccessorId, writerPub: string);
  static openWithPossession(
    writer: AccessorId,
    writerPub: string,
    signature: string,
  ): AuthenticatedWriterChannel;
  readonly writer: AccessorId;
  readonly writerPub: string;
  readonly #channelBrand: typeof writerChannelBrand;
  hasTransportBrand(): boolean;
}

/**
 * Signature by the writer's enrolled SEA pub.
 * Signed bytes, length-prefixed:
 * 1. "s3rch-writer-append-v1"
 * 2. row.entryId
 * InboxEnvelope.writerSignature covers those same bytes.
 * A bare hex string, raw digest bytes, or another framing
 * does not verify.
 * Checked at append. writerPub is the claimed key. It is not
 * the enrollment record. Not stored on the content-addressed
 * row. Not a grant.
 */
export type WriterAppendProof = {
  writer: AccessorId;
  writerPub: string;
  signature: string;
};

/**
 * One enrolled account SEA pair. The writer does not supply it.
 * pub is the signing key. epub is the encryption key.
 * identityPub is that same SEA pub, held by the verifier
 * before the introduction. It is not a second keypair.
 * account-signature is checked under identityPub.
 * An introduction compares pub and epub. An append compares pub.
 */
export type EnrolledSeaPub = {
  account: AccessorId;
  pub: string;
  epub: string;
  /** Account-identity verification key. The one SEA pub. */
  identityPub: string;
};

/**
 * Verifier-held enrollment. The writer does not supply it.
 * pub is the enrolled SEA pub for that account.
 * epub is the enrolled SEA epub for that account.
 * An introduction's enrollment binding requires both to match.
 * A swapped epub fails closed. account-signature is checked
 * under identityPub, not under the introduced pub.
 * An append compares writerPub to pub.
 * Not a field of the stored row. Not a grant.
 */
export type VerifierEnrollmentState = {
  accounts: readonly EnrolledSeaPub[];
};

/**
 * How filterInboxAppend learns the writer. A bare accessor
 * is not a member of this union. channel or signature is
 * checked against VerifierEnrollmentState before knownSenders,
 * the allowlist, and quotas. The claimed writerPub is not
 * that enrollment record.
 * The relay that runs this check learns the writer id for
 * that entryId. The stored public row still has no writer
 * pub and no admission receipt. A peer that only replicates
 * the row does not learn the writer, and that replica is
 * not an admitted append.
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
  /**
   * Writer id the accepting relay learned. Set only when
   * allowAppend is true. Not a field of the stored row. A peer
   * that only replicates the row does not receive this.
   */
  learnedWriter?: AccessorId;
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
 * crates/sociacl-encdisc runs this. An append is not a grant.
 * public-filtered is the default: any writer may append.
 * state is the verifier's challenges, issuers, replay set,
 * known senders, per-sender quotas, and the one lane capacity.
 * enrollment is the verifier's account-to-pub map. The writer
 * does not pass it. writerAuth is a transport channel or a
 * signature over the length-prefixed writer-append bytes.
 * The claimed writerPub must
 * equal the enrolled pub for that writer. A missing account
 * or a different pub is writer-auth and does not read
 * knownSenders, the allowlist, or quotas. A bare accessor is
 * the same failure. The stored row still has no writer pub.
 * The relay that accepts the append learns that writer id.
 * A later replicating peer does not learn it from the row.
 * The writer does not pass the counters.
 * A matching challenge nonce is spent alone. Other outstanding
 * challenges stay.
 * First contact is writer absent from state.knownSenders.
 * That writer requires evidence that verifies against state
 * and row.entryId. A proof-of-work solution for another entry,
 * or a stamp signed over another entry, is stamp-mismatch.
 * A nonce or stamp signature already in state.spent is replay.
 * A known sender uses the senderQuotas entry for that sender.
 * A missing row or remaining 0 is sender-quota. Other senders
 * and laneRemaining stay as they were.
 * A sender absent from knownSenders is first contact. After
 * evidence verifies, remaining starts at firstContactRemaining.
 * At 0 the result is sender-quota and the sender is not added.
 * Above 0 the counter is created at that value, then the
 * accept below drops it by 1.
 * laneRemaining at 0 is reader-capacity. That sender's counter
 * stays as it was. On ok, that sender's remaining and
 * laneRemaining each drop by 1, the sender is in knownSenders,
 * and row.entryId is in admitted. An entryId already in
 * admitted is not a new append. The counters stay.
 * A replicated row whose entryId is absent from admitted is
 * not admitted. The auth and the evidence are presented at
 * this check. They are not fields of the stored row.
 * named-writers refuses anyone outside writers.
 * Commitment mismatch is checkPresentedGrant, not this hook.
 * SociACL does not store the filter.
 * A passed hook is not a grant.
 */
export function filterInboxAppend(
  hook: InboxWriteHook,
  row: BlindedGrantRow,
  state: VerifierAdmissionState,
  now: number,
  enrollment: VerifierEnrollmentState,
  writerAuth?: WriterAppendAuth,
  admission?: InboxAdmission,
): InboxAppendResult;

/**
 * One party's assent. The signature covers the predicate, set id,
 * accessor, set owner, stated bit, hamState, and observed cancel ids.
 * spoken is false when that party has not signed.
 */
export type MembershipAssent = {
  stated: boolean;
  hamState: number;
  /** Cancel ids this assent lists. A live assent lists every known cancel. */
  observed: readonly string[];
  /** Ed25519 signature. Absent when spoken is false. */
  signature?: Uint8Array;
  spoken: boolean;
};

/**
 * One cancel id, signed on its own. The signature covers the id,
 * the row it names, and the prior ids. Check keeps an id whose
 * signature verifies even when another signature on the row does not.
 */
export type SignedCancel = {
  /** Exactly 64 lowercase hex characters. SHA-256 of the replica, a nonce, and the prior ids. */
  id: string;
  /** Prior cancel ids, each exactly 64 lowercase hex characters. */
  prior: readonly string[];
  signer: AccessorId;
  signature: Uint8Array;
};

/**
 * Direct membership. Hopcap 1. Jointly stated.
 * stated 1 = live, 0 = cancelled. Cancel bumps hamState.
 * One-sided membership is not a grant. Not a walk.
 * Nested groups and nested circles do not grant.
 * Check compares accessor, setId, and predicate to the request.
 * It does not trust the lookup key that returned the row.
 */
export type MeshMembership = {
  predicate: "same-group" | "named-circle";
  setId: string;
  accessor: AccessorId;
  stated: 0 | 1;
  hamState: number;
  /** Set owner named by the assents. Must match ownerOfSet. */
  setOwner: AccessorId;
  /** True when a verified cancel or a spoken retraction removed the row. */
  removed: boolean;
  /** Member assent, signed by the accessor. */
  member: MembershipAssent;
  /** Set-owner assent, signed by setOwner. */
  setParty: MembershipAssent;
  /** Grow-only cancel ids for this membership. */
  cancels: readonly SignedCancel[];
};

/**
 * Group or circle the object names. One predicate.
 * Does not change GunFeedNode or GunUserNode.
 * Check compares object to the requested object.
 * It does not trust the lookup key that returned the row.
 */
export type ObjectSetName = {
  object: CheckObjectId;
  predicate: "same-group" | "named-circle";
  setId: string;
  stated: 0 | 1;
  hamState: number;
  /** Object owner who signed the edge. Must match ownerOf. */
  objectOwner: AccessorId;
  /** Stated bit covered by the signature. */
  signedStated: 0 | 1;
  /** Cancel ids this edge lists. */
  observed: readonly string[];
  /** Ed25519 signature by the enrolled object owner. */
  signature: Uint8Array;
  /** Grow-only cancel ids for this edge. */
  cancels: readonly SignedCancel[];
};

/**
 * See graph plus direct group and circle edges.
 * Check does not walk from one set into another.
 * enrolledKey is the verifier's map. A key on the row is not it.
 */
export type GroupSeeGraph = SeeGraph & {
  objectSet(object: CheckObjectId): ObjectSetName | undefined;
  membership(
    predicate: "same-group" | "named-circle",
    setId: string,
    accessor: AccessorId,
  ): MeshMembership | undefined;
  /**
   * Account that owns this set. Absent when the set is unknown.
   * GroupEpochConfig.owner must equal this. The config does
   * not choose it. Absent fails closed.
   */
  ownerOfSet(
    predicate: "same-group" | "named-circle",
    setId: string,
  ): AccessorId | undefined;
  /**
   * Enrolled Ed25519 verify key for this principal. 32 bytes.
   * Absent when the account is not enrolled. Check uses this
   * key for object-set rows, membership assents, and cancels.
   */
  enrolledKey(principal: AccessorId): Uint8Array | undefined;
};

/**
 * CHECK(see) when the object names same-group or named-circle.
 * The reference crate evaluates this on plaintext mesh rows.
 * It does not read a wrapped key.
 * Hopcap 1. Direct jointly stated edge only.
 * No transitive inheritance.
 * Both the object-set edge and the membership edge must be stated 1.
 * Check compares the row's object, set id, and accessor to the
 * request. Signatures were checked at admission.
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
 * Plaintext edge, or a private-row cancel.
 * plain carries CancelledGrant: stated 0 and a bumped hamState.
 * private-row carries a signed payload with stated 0 and a
 * grantRevision greater than the live row, plus an
 * EpochStatusProof for that accessor, that grantRevision, and
 * stated 0. A plain edge does not cancel a private row.
 * Not a grant by itself.
 */
export type RotationCancel =
  | { kind: "plain"; grant: CancelledGrant }
  | {
      kind: "private-row";
      payload: SignedGrantPayload;
      signature: string;
      status: EpochStatusProof;
    };

/**
 * Revoke record for an encrypted object.
 * Order: the RotationCancel, then rewrapped keys for the winning
 * revision of the next epoch, remaining readers only, then cipher
 * mode. A private-row object uses kind private-row. Immediate deny
 * is for a current verifier. Other verifiers are bounded by
 * EpochStatusProof.maxAgeMs.
 */
export type EpochRotation = {
  object: CheckObjectId;
  revokedEpoch: number;
  nextEpoch: number;
  /** Winning EpochManifest.revisionId for nextEpoch. */
  revisionId: string;
  cancelled: readonly RotationCancel[];
  rewrapped: readonly WrappedKey[];
  cipher: RevokeCipherMode;
};

/**
 * Merged live hamState for one accessor. The presenter does not
 * supply it. A plaintext cancel must be strictly greater.
 */
export type PriorHamState = {
  accessor: AccessorId;
  hamState: number;
};

/**
 * crates/sociacl-encdisc runs this check. Privilege-down first
 * (stated 0, hamState strictly greater than priorHam), then wraps
 * of the winning next-epoch revision. readers maps each enrolled
 * epub to its accessor before a revoked accessor is excluded.
 * The settle window does not delay privilege-down. A wrap written
 * here is not a grant.
 */
export function rotateOnRevoke(
  rotation: EpochRotation,
  readers: readonly EnrolledSeaPub[],
  priorHam: readonly PriorHamState[],
): void;

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
 * Authenticated receipt that this reader has the wrap.
 * signature is a SEA signature over the length-prefixed fields
 * "s3rch-wrap-receipt-v1", object, accessor, decimal toVersion,
 * revisionId, and entryId. A caller boolean is not this receipt.
 * A concatenated string with no lengths does not verify.
 * Not a grant.
 */
export type WrapReceipt = {
  accessor: AccessorId;
  signature: string;
};

/**
 * Reader version the verifier holds. atGate on ReaderMigration
 * must equal version >= versionGate. The writer does not set it.
 */
export type MigrationReaderVersion = {
  accessor: AccessorId;
  version: number;
  /** Enrolled SEA epub. The wrap targetId must be this value. */
  epub: string;
};

/**
 * Structural admission input. crates/sociacl-encdisc verifies
 * the receipt signature before acknowledged is set.
 * grants are the merged plaintext edges. The caller does not
 * add an accessor here to widen the set.
 */
export type MigrationAdmissionInput = {
  migration: ProtocolMigration;
  owner: AccessorId;
  caller: AccessorId;
  now: number;
  storage: GrantStorage;
  grants: readonly GunAclEdge[];
  payloads: readonly SignedGrantPayload[];
  receipts: readonly WrapReceipt[];
  readerVersions: readonly MigrationReaderVersion[];
  soulHamState: number;
};

/**
 * What admission decided. grantsSee stays false.
 * historicalReplicaRemains stays true: replacement does not
 * claw back a plaintext copy already stored elsewhere.
 * The version gate does not drop plaintext.
 */
export type MigrationAdmission = {
  object: CheckObjectId;
  plaintextRetained: readonly AccessorId[];
  plaintextDropped: readonly AccessorId[];
  soulReplaced: boolean;
  soulHamState: number;
  cancelled: readonly GunAclEdge[];
  skippedPublic: boolean;
  ciphertextPublished: boolean;
  grantsSee: false;
  delaysPrivilegeDown: false;
  widened: false;
  historicalReplicaRemains: true;
};

/**
 * Owner-only admission. The TypeScript contract checks structure.
 * The Rust crate also verifies the wrap receipt, the owner
 * item-auth signature, and the current epoch revision.
 * atGate does not drop plaintext. One reader's receipt does not
 * clear another reader. The soul stays until every current reader
 * has a receipt. A live grant whose window has not ended is current,
 * including one whose from is still ahead of now. Each edge soul is
 * grantSoul(owner, object, accessor). A wrap named here is not a
 * grant. A reader does not call this. Items kept on the public
 * plaintext path are not rewritten. Whether that path stays is open.
 */
export function applyProtocolMigration(
  input: MigrationAdmissionInput,
): MigrationAdmission;

/**
 * Ciphertext envelope, including the first revision.
 * Not a second Check object. The root locator is not this path.
 */
export type ItemRevisionSoul = `s3rch/items/${string}/r/${string}`;

/**
 * Write-once locator at s3rch/items/<itemId>.
 * first names the first rev. The node has no ciphertext.
 * Not a Check object and not a grant.
 */
export type ItemLocator = {
  v: 2;
  enc: 1;
  first: string;
};

/**
 * Signed manifest body at ManifestSoul.
 * statusAuthPub is omitted from the canonical bytes when absent.
 * An empty statusAuthPub is rejected.
 * The node is { v: 1, manifest, msig } and carries no account pub.
 * Not a grant.
 */
export type RevisionManifest = {
  itemId: string;
  e: number;
  rev: string;
  parent: string;
  keyId: string;
  envDigest: string;
  statusAuthPub?: string;
};

/** Grant-tuple field. Soul of the manifest for this item and rev. */
export type ManifestSoul = `s3rch/items/${string}/m/${string}`;

/**
 * Current-account designation of the status authority.
 * Signed by the current account SEA pub. Not an identity. Not a grant.
 * The authority pub cannot sign a manifest, a grant proof, or a
 * replacement binding.
 */
export type StatusAuthorityBinding = {
  /** provider:encoded-id */
  account: string;
  /** Current SEA pub. */
  accountPub: string;
  /** Designated SEA pub. */
  statusAuthPub: string;
  /** Account-key log head. */
  seq: number;
};

/**
 * Group-inbox sender authentication.
 * ssig covers these fields. The signing key is the sender's current
 * account SEA pub. A key derived from the group epoch key is refused
 * before unwrap. Not a grant and not a membership.
 */
export type GroupInboxWriteSig = {
  tag: string;
  entryId: string;
  senderPub: string;
  /** SHA-256 of the length-prefixed ephemeral, ciphertext, and iv. */
  bodyHash: string;
};

/**
 * v2 group-inbox entry at s3rch/ginbox/<tag>/<entryId>.
 * ssig is the sender's current account SEA signature. Not a grant.
 */
export type GroupInboxEntry = {
  v: 1;
  senderPub: string;
  eph: string;
  ct: string;
  iv: string;
  ssig: string;
};

/**
 * Append-only account-key log entry. Identity for the five statement
 * checks is keyPub, the current SEA pub at this seq.
 * prev is the hash of the previous entry, or "none" at seq 0.
 * Not a grant.
 */
export type AccountKeyLogEntry = {
  account: string;
  keyPub: string;
  seq: number;
  prev: string;
};

/**
 * Head signed by the login provider or the wallet.
 * The SEA key does not sign these bytes.
 */
export type AccountKeyLogHead = {
  account: string;
  seq: number;
  entryHash: string;
};

/** s3rch/items/<itemId>/r/<rev>. The first revision uses this path. */
export function itemRevisionSoul(itemId: string, rev: string): ItemRevisionSoul;

/** s3rch/items/<itemId>/m/<rev>. Not a grant. */
export function manifestSoul(itemId: string, rev: string): ManifestSoul;

/** s3rch/items/<itemId>. Write-once locator. Not ciphertext. */
export function itemRootSoul(itemId: string): string;

/** s3rch/ginbox/<tag>/<entryId>. */
export function groupInboxSoul(tag: string, entryId: string): string;

/**
 * SHA-256 lowercase hex of the length-prefixed fields
 * "s3rch-env-digest-v1", itemId, decimal e, rev, alg, iv, ct.
 * This is H(itemId || e || rev || alg || iv || ct).
 * Checked against the revision node before the body is accepted.
 */
export function envDigest(
  itemId: string,
  e: number,
  rev: string,
  alg: string,
  iv: string,
  ct: string,
): string;

/**
 * Canonical revision manifest. statusAuthPub is omitted when absent.
 * An empty statusAuthPub is rejected.
 * msig is the current account SEA signature over these bytes.
 * Fields: "s3rch-revision-manifest-v1", itemId, decimal e, rev, parent,
 * keyId, envDigest, and statusAuthPub when present.
 */
export function revisionManifestBytes(manifest: RevisionManifest): Uint8Array;

/**
 * Signed grant-tuple field. Outside s3rch-grant-payload-v1.
 * Fields: "s3rch-grant-manifest-v1", itemId, rev, manifest soul.
 */
export function grantManifestBytes(
  itemId: string,
  rev: string,
  manifest: ManifestSoul,
): Uint8Array;

/**
 * Fields: "s3rch-status-authority-v1", account, accountPub,
 * statusAuthPub, decimal seq. The current account SEA pub signs this.
 */
export function statusAuthorityBytes(binding: StatusAuthorityBinding): Uint8Array;

/** SHA-256 of "s3rch-group-inbox-body-v1", eph, ct, iv. */
export function groupInboxBodyHash(eph: string, ct: string, iv: string): string;

/**
 * Fields: "s3rch-group-inbox-ssig-v1", tag, entryId, senderPub, bodyHash.
 * The sender's current account SEA pub signs this.
 */
export function groupInboxSigBytes(sig: GroupInboxWriteSig): Uint8Array;

/**
 * Fields: "s3rch-account-key-log-v1", account, keyPub, decimal seq, prev.
 * The entry hash is SHA-256 of these bytes.
 */
export function accountKeyLogBytes(entry: AccountKeyLogEntry): Uint8Array;

/** SHA-256 of accountKeyLogBytes. */
export function accountKeyEntryHash(entry: AccountKeyLogEntry): string;

/**
 * Fields: "s3rch-account-key-head-v1", account, decimal seq, entryHash.
 * The provider or the wallet signs this. The SEA key does not.
 */
export function accountKeyHeadBytes(head: AccountKeyLogHead): Uint8Array;

/** The SEA key does not sign the account-key log head. */
export function accountKeyHeadSignedBySea(): boolean;

/**
 * A hop, a status statement, a chat node, a manifest, a binding,
 * an ssig, a log entry, and an envelope do not mint a grant.
 */
export function consumeStatementMints(kind: string): boolean;

/**
 * Root locator. hasCiphertext refuses. first must equal the first rev.
 * The locator is not a Check object and not a grant.
 */
export function acceptItemLocator(
  v: 2,
  enc: 1,
  first: string,
  expectedFirst: string,
  hasCiphertext: boolean,
): { ok: true } | { ok: false; reason: string };

/**
 * Fetch path is the revision soul. There is no root-ciphertext fallback.
 * envDigest must match the envelope at that soul before the body is accepted.
 */
export function acceptEnvelope(input: {
  itemId: string;
  e: number;
  rev: string;
  fetchedSoul: string;
  rootHasCiphertext: boolean;
  alg: string;
  iv: string;
  ct: string;
  envDigest: string;
}): { ok: true } | { ok: false; reason: string };

/**
 * CHECK rejects a missing soul or a soul that is not this item and rev.
 * An author-lane copy does not satisfy a grantee.
 */
export function acceptGrantManifest(input: {
  manifest?: string;
  itemId: string;
  rev: string;
  authorLaneOnly: boolean;
}): { ok: true } | { ok: false; reason: string };

/**
 * The manifest node carries no account pub. envDigest must equal the
 * envelope digest. The manifest is not a grant.
 */
export function acceptRevisionManifest(input: {
  nodeV: number;
  manifest: RevisionManifest;
  itemId: string;
  rev: string;
  envelopeDigest: string;
  carriesAccountPub: boolean;
}): { ok: true } | { ok: false; reason: string };

/**
 * A status proof signed by the current account key is accepted on its own.
 * Any other key verifies only when it equals statusAuthPub on the binding
 * and on the manifest, the binding account equals the log head account,
 * the binding signature verifies under the current account key, and seq
 * is the log head. A missing binding refuses every other signer.
 * purpose "manifest", "grant", and "binding" accept only the current
 * account key. The proof does not mint.
 */
export function acceptStatusSigner(input: {
  signingPub: string;
  currentAccountPub: string;
  binding?: StatusAuthorityBinding;
  manifestStatusAuthPub?: string;
  logHeadAccount?: string;
  logHeadSeq?: number;
  bindingSignedByCurrent: boolean;
  purpose: "status" | "manifest" | "grant" | "binding";
}): { ok: true } | { ok: false; reason: string };

/**
 * ssig is checked under senderPub before unwrap. senderPub must be a
 * current-epoch member and that account's current SEA pub. A signature
 * under a key derived from the group epoch key, including
 * derive(ECDH(member, groupEpub), "writer"), is refused. ssig does not
 * mint see or a membership. The group key encrypts only.
 */
export function acceptGroupInboxSender(input: {
  senderPub: string;
  currentAccountPub: string;
  member: boolean;
  signatureUnderSender: boolean;
  derivedFromGroupKey: boolean;
}): { ok: true } | { ok: false; reason: string };

/**
 * An entry already accepted on an earlier check.
 * A later entry may stop here only for this account at seq + 1.
 */
export type AccountKeyAnchor = {
  account: string;
  seq: number;
  hash: string;
};

/**
 * Fail closed. The verifier checks a signature over accountKeyHeadBytes
 * under the provider or wallet key. expectedAccount is the owner or
 * member being resolved. head.account and every chain entry must equal
 * it. A valid head for another account is refused. The account SEA pub
 * does not sign that head. The hash chain links the head to seq 0 or
 * to an anchor already accepted for the same account. The anchor
 * shortcut requires entry.seq == anchor.seq + 1. The walk covers a
 * head at KEYRING_HISTORY_MAX. A missing head, a signature that does
 * not verify, a chain that does not link, a prev mismatch, or no
 * answer from the provider or wallet refuses. The highest cached seq
 * is not the current key. A superseded keyPub does not authenticate.
 */
export function acceptCurrentKey(input: {
  head?: AccountKeyLogHead;
  entries: readonly AccountKeyLogEntry[];
  anchor?: AccountKeyAnchor;
  providerAnswered: boolean;
  providerPub: string;
  headSignature: string;
  expectedAccount: string;
  statementKeyPub: string;
}): { ok: true; keyPub: string } | { ok: false; reason: string };

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
 * docs/encrypted-discovery.md. crates/sociacl-encdisc runs the
 * epoch, rotation, freshness, and migration checks. It does not run
 * a shard-close watermark. None of them mint a grant.
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
  | "inbox-pow-nonce"
  | "inbox-fabricated-quota"
  | "inbox-spent-challenge"
  | "inbox-known-sender"
  | "inbox-sender-quota-map"
  | "inbox-lane-capacity"
  | "grant-revision-order"
  | "grant-revision-stale"
  | "grant-item-digest"
  | "writer-auth-required"
  | "writer-enrollment-pub"
  | "public-append-relay-learns-writer"
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
  | "epoch-object-set"
  | "epoch-rebuild-descendants"
  | "epoch-finalization-sig"
  | "epoch-expire-before-settle"
  | "epoch-settle-needs-snapshot"
  | "epoch-settled-read"
  | "epoch-stale-membership"
  | "epoch-manifest-sig"
  | "inbox-envelope-body"
  | "item-auth-canonical"
  | "status-policy-max-age"
  | "status-binds-accessor"
  | "status-object-match"
  | "status-signed-encoding"
  | "presented-group-check"
  | "presented-group-cancel"
  | "migration-wrap-receipt"
  | "migration-per-reader"
  | "migration-soul-replaces"
  | "migration-no-widen"
  | "migration-privilege-down"
  | "migration-public-skipped"
  | "migration-reader-cannot-issue"
  | "migration-receipt-canonical"
  | "migration-historical-replica"
  | "epoch-late-manifest"
  | "epoch-arrival-order"
  | "epoch-settle-window"
  | "epoch-settle-bounds"
  | "epoch-settle-pending-key"
  | "epoch-settle-skips-revoke"
  | "epoch-group-window"
  | "epoch-candidate-scope"
  | "presented-settlement-acl"
  | "inbox-first-contact-quota"
  | "writer-append-canonical"
  | "inbox-replicated-row"
  | "rotate-private-cancel"
  | "id-sha256-canonical"
  | "zookie-object-snapshot"
  | "intro-epub-required"
  | "intro-binding-ok"
  | "intro-binding-canonical"
  | "intro-binding-swap-epub"
  | "intro-self-signature-rejected"
  | "intro-not-a-grant"
  | "presenter-proof-alone"
  | "presenter-nonce-ok"
  | "presenter-binding-canonical"
  | "presenter-audience"
  | "epoch-settled-expiry"
  | "epoch-settled-cancel"
  | "epoch-live-revision-window"
  | "intro-enrolled-epub"
  | "intro-account-identity"
  | "epoch-settled-pending"
  | "author-fast-revision"
  | "epoch-group-owner"
  | "presented-enrollment"
  | "presented-graph-owner"
  | "presenter-bad-key"
  | "presenter-spent-nonce"
  | "presenter-expired-challenge"
  | "presenter-forged-channel"
  | "presenter-channel-wrong-principal"
  | "presenter-binding-not-a-grant"
  | "envelope-revision-path"
  | "envelope-root-refused"
  | "grant-manifest-soul"
  | "grant-manifest-author-lane"
  | "status-authority-binding"
  | "status-authority-not-identity"
  | "group-inbox-ssig"
  | "group-inbox-writer-key-refused"
  | "account-key-fail-closed"
  | "account-key-superseded"
  | "account-key-anchor-non-adjacent"
  | "account-key-anchor-wrong-account"
  | "account-key-log-at-limit"
  | "account-key-head-signature"
  | "account-key-head-wrong-account"
  | "consume-statement-does-not-mint";
