/**
 * Light Check consume contract for AImmune / Brewnix IR site console.
 *
 * Copy or re-type these names in the Next app (MockCheck-first).
 * Run Check in the browser on logical site objects. Do not import
 * the SociACL Rust crate. Do not add this file as an npm package.
 * This is a contract, not a dependency. No NAPI / WASM on the
 * Next light path.
 *
 * Duplicate of the light names in docs/s3rch-check.d.ts
 * (CheckResult, AccessorId, HandoffHint). Import by comment /
 * re-type. Do not create an npm package to share them.
 *
 * Binding (objects + masks, do not fork):
 *   Brewnix/inference-iface docs/sociacl-ir-binding-v0.md
 * Primitives: PR #11 (delegate), PR #13 / docs/s3rch-check.d.ts
 * (light see), docs/verbs.md.
 *
 * CHECK(action, object, accessor) at now.
 *   object   = site:{site_id} | site:{site_id}:ir
 *   accessor = human / agent id (not a site-token type)
 *   action   = read | write | execute; see maps to read
 *   hopcap 1, jointly stated grants, revoke immediate
 *
 * break_glass is a Brewnix owner gate, not a SociACL verb.
 * privilege_grant body is Brewnix; SociACL authorizes minting.
 * contain never calls Check.
 * write without execute is annotate-only.
 * :host is later (when Host exists). Do not mint per-incident
 * ACL objects. No owner-console type. No site-token type.
 */

/**
 * Standing site object or IR keep-operating object.
 * site_id is the envelope / grant / auditor scope token.
 * :host is later — not this cut. Do not invent
 * site:{site_id}:incident:{incident_id}.
 */
export type SiteObjectId = `site:${string}` | `site:${string}:ir`;

/** Human or agent. Not a machine site-token type. */
export type AccessorId = string;

/**
 * Same shape as docs/s3rch-check.d.ts CheckResult.
 * A present hint never makes this a grant.
 */
export type CheckResult = {
  allowed: boolean;
  /** Predicate / deny reason. A present hint never makes this a grant. */
  reason: string;
};

/**
 * Untrusted edge handoff (auditor URL / hop / ingest).
 * Same shape as docs/s3rch-check.d.ts HandoffHint.
 * Decode does not verify. A hint never sets allowed.
 */
export type HandoffHint = {
  principal: string;
  target: string;
  verb?: string;
  context?: string;
};

/** dest Check action bits. see maps to read (alias). */
export type ActionMask = "read" | "write" | "execute";

/**
 * Jointly stated keep-operating grant. hopcap 1.
 * Privilege-down is immediate. Owner stays owner.
 * `until` exclusive unix seconds. Omit = open.
 */
export type DelegateGrant = {
  object: SiteObjectId;
  accessor: AccessorId;
  mask: ActionMask;
  until?: number;
};

/**
 * Live graph the browser reads. Only in-graph site objects
 * and jointly stated delegate grants. Do not walk friend
 * edges (hopcap 1).
 */
export type DelegateGraph = {
  hasObject(object: SiteObjectId): boolean;
  ownerOf(object: SiteObjectId): AccessorId | undefined;
  delegateGrants(object: SiteObjectId): readonly DelegateGrant[];
};

/** Writable dest ACL. Cancel and apply land here, not on a URL. */
export type DelegateAcl = DelegateGraph & {
  putObject(object: SiteObjectId, owner: AccessorId): void;
  stateDelegateGrant(owner: AccessorId, grant: DelegateGrant): void;
  unstateDelegateGrant(
    owner: AccessorId,
    accessor: AccessorId,
    object: SiteObjectId,
  ): void;
};

/** see → read. Other masks pass through. */
export function mapAction(action: ActionMask | "see"): ActionMask;

/**
 * True for site:{id} and site:{id}:ir only.
 * :host and :incident: fail closed in this cut.
 */
export function isSiteObjectId(id: string): id is SiteObjectId;

/** Does not verify. Does not mint. Never sets allowed. */
export function acceptHint(hint: HandoffHint): HandoffHint;

/**
 * CHECK(action, object, accessor) at now.
 * see maps to dest read. Hint is ignored for allowed.
 * Owner of the object is allowed. Else a live DelegateGrant
 * must name this pair, include the mapped action in mask,
 * and now < until (or until omitted). Unknown / :host /
 * :incident: ids fail closed.
 */
export function checkDelegate(
  graph: DelegateGraph,
  object: SiteObjectId,
  accessor: AccessorId,
  action: ActionMask | "see",
  now: number,
  hint?: HandoffHint,
): CheckResult;

/** Owner-only. hopcap 1. Empty mask refused. */
export function applyDelegate(
  acl: DelegateAcl,
  owner: AccessorId,
  grant: DelegateGrant,
): void;

/** Privilege-down is immediate. Dest ACL only. Owner-only. */
export function cancelDelegate(
  acl: DelegateAcl,
  owner: AccessorId,
  accessor: AccessorId,
  object: SiteObjectId,
): void;

/** Same as cancelDelegate. Privilege-down is immediate. */
export function undelegate(
  acl: DelegateAcl,
  owner: AccessorId,
  accessor: AccessorId,
  object: SiteObjectId,
): void;

/**
 * Refresh only if checkDelegate still allows the same action
 * on the same object for this accessor at now. Owner stays
 * owner. Not a mint of a new grant. Signature only on this
 * light path.
 */
export function remintCapability(
  graph: DelegateGraph,
  object: SiteObjectId,
  accessor: AccessorId,
  action: ActionMask | "see",
  now: number,
): { refreshed: true } | { denied: true };
