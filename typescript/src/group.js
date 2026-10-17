/**
 * Plaintext same-group and named-circle rows for the s3r.ch light Check.
 * Hopcap 1. Both edges must be stated 1. One-sided membership is stored
 * and is not a grant. A hop, a hint, a wrap, or a request never mints.
 * A lower hamState does not hide a removal.
 *
 * Cancels are a grow-only set of collision-free ids. Each id is
 * exactly 64 lowercase hex characters. Prior ids are canonicalized
 * before the signature is checked. A live assent or edge lists every
 * known cancel. Object-set rows are signed by the object owner.
 * Membership assents are signed by that party.
 *
 * @typedef {"same-group" | "named-circle"} GroupPredicate
 * @typedef {import("node:crypto").KeyObject} KeyObject
 * @typedef {{ principal?: string, target?: string }} HandoffHint
 * @typedef {{ channel?: string }} HopFactor
 * @typedef {{ predicate: GroupPredicate, setId: string }} PresentedGroup
 * @typedef {{ stated: 0 | 1, from: number, until: number }} DecodedGroupPayload
 * @typedef {{
 *   allowed: boolean,
 *   reason: string,
 *   hint: HandoffHint | null,
 *   hop: HopFactor | null,
 *   storeCancel: boolean,
 * }} GroupPresentation
 * @typedef {{
 *   predicate: GroupPredicate,
 *   setId: string,
 *   accessor: string,
 *   stated: 0 | 1,
 *   hamState: number,
 *   removed?: boolean,
 *   setOwner?: string,
 *   member?: PartyStatement,
 *   setParty?: PartyStatement,
 *   cancels?: SignedCancel[],
 * }} MeshMembership
 * @typedef {{
 *   object: string,
 *   predicate: GroupPredicate,
 *   setId: string,
 *   stated: 0 | 1,
 *   hamState: number,
 *   objectOwner?: string,
 *   signedStated?: 0 | 1,
 *   observed?: string[],
 *   signature?: Uint8Array,
 *   cancels?: SignedCancel[],
 * }} ObjectSetName
 * @typedef {(principal: string) => Uint8Array | undefined} KeyLookup
 * @typedef {{
 *   ownerOf(object: string): string | undefined,
 *   seeGrants(object: string): readonly SeeGrant[],
 *   objectSet(object: string): ObjectSetName | undefined,
 *   membership(predicate: GroupPredicate, setId: string, accessor: string): MeshMembership | undefined,
 *   ownerOfSet(predicate: GroupPredicate, setId: string): string | undefined,
 *   enrolledKey(principal: string): Uint8Array | undefined,
 * }} GroupSeeGraph
 * @typedef {{
 *   accessor: string,
 *   predicate: GroupPredicate,
 *   setId: string,
 *   stated: 0 | 1,
 *   hamState: number,
 * }} GroupSnapshotMember
 * @typedef {{
 *   predicate: GroupPredicate,
 *   setId: string,
 *   stated: 0 | 1,
 *   hamState: number,
 * }} GroupSnapshotObjectSet
 * @typedef {{
 *   stated: boolean,
 *   hamState: number,
 *   observed: string[],
 *   signature: Uint8Array | null,
 *   spoken: boolean,
 * }} PartyStatement
 * @typedef {{
 *   id: string,
 *   prior: string[],
 *   signer: string,
 *   signature: Uint8Array,
 * }} SignedCancel
 * @typedef {{
 *   membership: MeshMembership,
 *   member: PartyStatement,
 *   setParty: PartyStatement,
 *   removed: boolean,
 *   soul: string,
 *   setOwner: string,
 *   cancels: SignedCancel[],
 * }} MembershipRecord
 * @typedef {{
 *   name: ObjectSetName,
 *   signedStated: 0 | 1,
 *   soul: string,
 *   objectOwner: string,
 *   observed: string[],
 *   signature: Uint8Array,
 *   cancels: SignedCancel[],
 * }} ObjectSetRecord
 * @typedef {{ accessor: string, from: number, until: number, stated?: 0 | 1, object?: string, claimId?: string, hamState?: number, owner?: string }} SeeGrant
 * @typedef {{ privateKey: KeyObject, publicKey: Uint8Array }} Issuer
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  verify,
} from "node:crypto";
import {
  canonicalAccessorId,
  canonicalPostEdge,
  nextPostHam,
  objectIdRejected,
  postRowEncodable,
  preferPost,
  sameObjectId,
} from "./post.js";

export {
  POST_GRANT_DOMAIN,
  POST_GRANT_SCOPE,
  checkPost,
  factorGrants,
  postGrantSigningBytes,
  postSoul,
} from "./post.js";

export {
  ACCESS_MESSAGE_MAX,
  ACCESS_REQUEST_DOMAIN,
  ACCESS_REQUEST_ID_DOMAIN,
  ACCESS_SCOPE_READ,
  ACCESS_SCOPE_READ_POST,
  ACCESS_STATUS_PENDING,
  ACCESS_STATUS_WITHDRAWN,
  acceptAccessRequest,
  accessRequestId,
  accessRequestSigningBytes,
  canonicalRequestAccessor,
  canonicalRequestObject,
  grantApprovedRequest,
  requestIssuerFromSeed,
  signAccessRequest,
} from "./request.js";

const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/**
 * Ed25519 signer from a 32-byte seed. The graph stores only the verify key.
 * @param {Uint8Array} seed
 * @returns {Issuer}
 */
export function issuerFromSeed(seed) {
  const seedBytes = new Uint8Array(seed);
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + seedBytes.length);
  pkcs8.set(PKCS8_PREFIX, 0);
  pkcs8.set(seedBytes, PKCS8_PREFIX.length);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const spki = new Uint8Array(createPublicKey(privateKey).export({ type: "spki", format: "der" }));
  return { privateKey, publicKey: spki.slice(spki.length - 32) };
}

/** @param {Uint8Array} raw */
function publicKeyFromRaw(raw) {
  const bytes = new Uint8Array(raw);
  const spki = new Uint8Array(SPKI_PREFIX.length + bytes.length);
  spki.set(SPKI_PREFIX, 0);
  spki.set(bytes, SPKI_PREFIX.length);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

/** @param {KeyObject} privateKey @param {Uint8Array} message */
function signBytes(privateKey, message) {
  return new Uint8Array(sign(null, message, privateKey));
}

/**
 * @param {Uint8Array | undefined} publicKey
 * @param {Uint8Array | null} message
 * @param {Uint8Array | null | undefined} signature
 */
function verifyBytes(publicKey, message, signature) {
  if (!publicKey || !message || !signature || signature.length !== 64) return false;
  try {
    return verify(null, message, publicKeyFromRaw(publicKey), signature);
  } catch {
    return false;
  }
}

/** @param {Uint8Array} bytes */
function bytesToHex(bytes) {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

const CANCEL_ID = /^[0-9a-f]{64}$/;

/**
 * Exactly 64 lowercase hex characters. Uppercase and a trailing
 * nibble are different spellings of the same bytes, so they are not ids.
 * @param {string} id
 * @returns {string | null}
 */
function canonicalCancelId(id) {
  return typeof id === "string" && CANCEL_ID.test(id) ? id : null;
}

/**
 * Prior ids are a set. Case is folded before the signature bytes
 * are built, so a respelling is the same prior and not a new cancel.
 * A length other than 64, or a non-hex character, fails closed.
 * @param {readonly string[] | undefined | null} prior
 * @returns {string[] | null}
 */
function canonicalPriorIds(prior) {
  if (!Array.isArray(prior)) return null;
  /** @type {string[]} */
  const out = [];
  const seen = new Set();
  for (const raw of prior) {
    if (typeof raw !== "string" || raw.length !== 64) return null;
    const id = canonicalCancelId(raw.toLowerCase());
    if (!id) return null;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

/** @param {string} hex */
function decodeCanonicalHex(hex) {
  const id = canonicalCancelId(hex);
  if (!id) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(id.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** @param {Uint8Array[]} parts */
function concatBytes(parts) {
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** @param {Uint8Array[]} parts @param {string | null | undefined} value */
function pushStr(parts, value) {
  const bytes = new TextEncoder().encode(value == null ? "" : String(value));
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, bytes.length);
  parts.push(len, bytes);
}

/**
 * @param {Uint8Array[]} parts
 * @param {readonly string[]} ids
 * @returns {boolean}
 */
function pushIds(parts, ids) {
  const sorted = [...ids].sort();
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, sorted.length);
  parts.push(len);
  for (const id of sorted) {
    const bytes = decodeCanonicalHex(id);
    if (!bytes) return false;
    parts.push(bytes);
  }
  return true;
}

/** @param {string} domain */
function domainBytes(domain) {
  const text = new TextEncoder().encode(domain);
  const out = new Uint8Array(text.length + 1);
  out.set(text, 0);
  return out;
}

/** @param {string | null | undefined} object */
function plainObjectId(object) {
  const text = String(object ?? "");
  if (objectIdRejected(text)) return null;
  return text;
}

/** @param {SeeGrant} grant */
function grantObject(grant) {
  return plainObjectId(grant.claimId ?? grant.object ?? "") ?? "";
}

/** @param {string} setId */
export function canonicalSetId(setId) {
  const id = asciiTrim(String(setId ?? ""));
  if (!id) return null;
  const slash = id.indexOf("/");
  if (slash <= 0 || slash !== id.lastIndexOf("/")) return null;
  const head = id.slice(0, slash);
  const name = id.slice(slash + 1);
  if (!head || !name || name.includes("_")) return null;
  if (/[.#$[\]/]/.test(head) || /[.#$[\]/]/.test(name)) return null;
  if (aclPrincipalKey(head) !== head) return null;
  return `${head}/${name}`;
}

/** @param {string} setId @param {string} owner */
function setIdBindsOwner(setId, owner) {
  const canonical = canonicalSetId(setId);
  if (!canonical) return false;
  const head = canonical.slice(0, canonical.indexOf("/"));
  const ownerKey = aclPrincipalKey(owner);
  return ownerKey != null && aclPrincipalKey(head) === ownerKey;
}

/**
 * Injective path escape. `~` is the escape character.
 * @param {string} id
 * @param {boolean} slash
 */
function escapeKey(id, slash) {
  return String(id).replace(slash ? /[~.#$[\]/]/g : /[~.#$[\]]/g, (ch) => {
    switch (ch) {
      case "~":
        return "~0";
      case ".":
        return "~1";
      case "#":
        return "~2";
      case "$":
        return "~3";
      case "[":
        return "~4";
      case "]":
        return "~5";
      case "/":
        return "~6";
      default:
        return ch;
    }
  });
}

/** @param {string} id */
function unescapeKey(id) {
  let out = "";
  for (let i = 0; i < id.length; i += 1) {
    if (id[i] !== "~") {
      out += id[i];
      continue;
    }
    const decoded = { 0: "~", 1: ".", 2: "#", 3: "$", 4: "[", 5: "]", 6: "/" }[id[i + 1]];
    if (decoded == null) return null;
    out += decoded;
    i += 1;
  }
  return out;
}

/** @param {string} id */
export function encodeKey(id) {
  return escapeKey(id, false);
}

/**
 * ASCII whitespace only. U+FEFF and U+0085 are not trimmed.
 * @param {string} text
 */
function asciiTrim(text) {
  const value = String(text);
  let start = 0;
  let end = value.length;
  /** @param {number} code */
  const space = (code) =>
    code === 0x09 || code === 0x0a || code === 0x0b || code === 0x0c || code === 0x0d || code === 0x20;
  while (start < end && space(value.charCodeAt(start))) start += 1;
  while (end > start && space(value.charCodeAt(end - 1))) end -= 1;
  return value.slice(start, end);
}

/** @param {string} id */
export function aclKey(id) {
  return escapeKey(asciiTrim(id), true);
}

/** @param {string | null | undefined} id */
export function aclPrincipalKey(id) {
  return canonicalAccessorId(id);
}

/**
 * Both sides must parse. null is not the same principal as null.
 * @param {string | null | undefined} left
 * @param {string | null | undefined} right
 */
function samePrincipal(left, right) {
  const a = aclPrincipalKey(left);
  const b = aclPrincipalKey(right);
  return a != null && a === b;
}

const HELD_CLAIM_PREFIXES = ["ens:", "unstoppable:", "fc:", "lens:", "rss3:"];

/** @param {string} id */
function isItemShaped(id) {
  const parts = asciiTrim(String(id)).split("/");
  return parts.length === 3 && parts[0] === "s3rch" && parts[1] === "items" && parts[2] !== "";
}

/** @param {string} id */
function mayAliasToItemSoul(id) {
  const text = asciiTrim(String(id));
  if (isItemShaped(text)) return true;
  if (!text.includes("/") && HELD_CLAIM_PREFIXES.some((prefix) => text.startsWith(prefix))) return false;
  return true;
}

/** @param {string} id */
function itemSoulOf(id) {
  return `s3rch/items/${encodeKey(asciiTrim(String(id)))}`;
}

/**
 * A raw id and `s3rch/items/<encodeKey(id)>` name one object when
 * one side is an item soul. A held claim id without `/` does not.
 * @param {string} left
 * @param {string} right
 */
function itemSoulAlias(left, right) {
  const a = asciiTrim(String(left));
  const b = asciiTrim(String(right));
  if (!isItemShaped(a) && !isItemShaped(b)) return false;
  if (!mayAliasToItemSoul(a) || !mayAliasToItemSoul(b)) return false;
  return itemSoulOf(a) === b || itemSoulOf(b) === a;
}

/** @param {string} setId */
function setMapKey(setId) {
  return aclKey(canonicalSetId(setId) ?? "");
}

/**
 * @param {string} setOwner
 * @param {GroupPredicate} predicate
 * @param {string} setId
 * @param {string} accessor
 */
export function membershipSoul(setOwner, predicate, setId, accessor) {
  const ownerKey = aclPrincipalKey(setOwner);
  const accessorKey = aclPrincipalKey(accessor);
  if (!ownerKey || !accessorKey) return "";
  const canonical = canonicalSetId(setId);
  const setKey = canonical ? aclKey(canonical) : aclKey(setId);
  return `s3rch/acl/${ownerKey}/membership/${predicate}/${setKey}/${accessorKey}`;
}

/**
 * @param {string} objectOwner
 * @param {string} object
 */
export function objectSetSoul(objectOwner, object) {
  const ownerKey = aclPrincipalKey(objectOwner);
  if (!ownerKey) return "";
  return `s3rch/acl/${ownerKey}/object-set/edge/${aclKey(object)}`;
}

/** @param {string} object */
function closedReason(object) {
  const text = String(object).trim();
  if (text.includes("://")) return "url-leaf";
  if (text === "s3rch/meta") return "meta";
  if (text === "s3rch/acl" || text.startsWith("s3rch/acl/")) return "acl";
  return null;
}

/** @param {DecodedGroupPayload} payload @param {number} now */
function payloadLive(payload, now) {
  return payload.stated === 1 && now >= payload.from && now < payload.until;
}

/** @returns {PartyStatement} */
function absentParty() {
  return { stated: false, hamState: 0, observed: [], signature: null, spoken: false };
}

/** @param {readonly string[]} observed @param {readonly string[]} ids */
function covers(observed, ids) {
  const have = new Set(observed);
  return ids.every((id) => have.has(id));
}

/**
 * One canonical id per cancel. Duplicates are the same id, not a second prior.
 * @param {readonly SignedCancel[]} cancels
 */
function cancelIds(cancels) {
  /** @type {string[]} */
  const ids = [];
  const seen = new Set();
  for (const cancel of cancels) {
    const id = canonicalCancelId(cancel?.id);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    ids.push(id);
  }
  ids.sort();
  return ids;
}

/**
 * @param {readonly SignedCancel[]} cancels
 * @returns {SignedCancel[]}
 */
function uniqueCancels(cancels) {
  /** @type {SignedCancel[]} */
  const out = [];
  const seen = new Set();
  for (const cancel of cancels) {
    if (!cancel || seen.has(cancel.id)) continue;
    seen.add(cancel.id);
    out.push(cancel);
  }
  return out;
}

/**
 * @param {Uint8Array} replicaId
 * @param {readonly string[]} prior
 */
function newCancelId(replicaId, prior) {
  const canon = canonicalPriorIds(prior);
  if (!canon) throw new Error("cancel id is not 64 lowercase hex");
  const hash = createHash("sha256");
  hash.update(domainBytes("sociacl-cancel-id-v1"));
  hash.update(replicaId);
  hash.update(randomBytes(16));
  const sorted = [...canon].sort();
  const len = new Uint8Array(8);
  new DataView(len.buffer).setBigUint64(0, BigInt(sorted.length));
  hash.update(len);
  for (const id of sorted) {
    const bytes = decodeCanonicalHex(id);
    if (!bytes) throw new Error("cancel id is not 64 lowercase hex");
    hash.update(bytes);
  }
  return bytesToHex(hash.digest());
}

/**
 * @param {MembershipRecord} record
 * @param {"member" | "set"} role
 * @param {boolean} stated
 * @param {number} hamState
 * @param {readonly string[]} observed
 */
function partyMessage(record, role, stated, hamState, observed) {
  const accessor = aclPrincipalKey(record.membership.accessor);
  const owner = aclPrincipalKey(record.setOwner);
  if (accessor == null || owner == null) return null;
  /** @type {Uint8Array[]} */
  const parts = [domainBytes("sociacl-membership-assent-v1")];
  pushStr(parts, role);
  pushStr(parts, record.membership.predicate);
  pushStr(parts, record.membership.setId);
  pushStr(parts, accessor);
  pushStr(parts, owner);
  parts.push(Uint8Array.of(stated ? 1 : 0));
  const ham = new Uint8Array(8);
  new DataView(ham.buffer).setBigUint64(0, BigInt(hamState));
  parts.push(ham);
  if (!pushIds(parts, observed)) return null;
  return concatBytes(parts);
}

/** @param {ObjectSetRecord} record */
function objectMessage(record) {
  const owner = aclPrincipalKey(record.objectOwner);
  if (owner == null) return null;
  /** @type {Uint8Array[]} */
  const parts = [domainBytes("sociacl-object-set-v1")];
  pushStr(parts, aclKey(record.name.object));
  pushStr(parts, owner);
  pushStr(parts, record.name.predicate);
  pushStr(parts, record.name.setId);
  parts.push(Uint8Array.of(record.signedStated));
  const ham = new Uint8Array(8);
  new DataView(ham.buffer).setBigUint64(0, BigInt(record.name.hamState));
  parts.push(ham);
  if (!pushIds(parts, record.observed)) return null;
  return concatBytes(parts);
}

/**
 * @param {string} kind
 * @param {string} rowKey
 * @param {string} id
 * @param {readonly string[]} prior
 */
function cancelMessage(kind, rowKey, id, prior) {
  if (!rowKey) return null;
  const idBytes = decodeCanonicalHex(id);
  if (!idBytes) return null;
  /** @type {Uint8Array[]} */
  const parts = [domainBytes("sociacl-cancel-v1")];
  pushStr(parts, kind);
  pushStr(parts, rowKey);
  parts.push(idBytes);
  if (!pushIds(parts, prior)) return null;
  return concatBytes(parts);
}

/** @param {MembershipRecord} record */
function membershipRowKey(record) {
  const accessor = aclPrincipalKey(record.membership.accessor);
  if (accessor == null) return null;
  return `${record.membership.predicate}\0${record.membership.setId}\0${accessor}`;
}

/** @param {Map<string, Uint8Array>} enrolled @returns {KeyLookup} */
function mapLookup(enrolled) {
  return (principal) => {
    const id = aclPrincipalKey(principal);
    return id == null ? undefined : enrolled.get(id);
  };
}

/** @param {GroupSeeGraph} graph @returns {KeyLookup} */
function graphLookup(graph) {
  return (principal) => {
    if (typeof graph.enrolledKey !== "function") return undefined;
    const key = graph.enrolledKey(principal);
    return key instanceof Uint8Array && key.length === 32 ? key : undefined;
  };
}

/**
 * @param {KeyLookup} lookup
 * @param {SignedCancel} cancel
 * @param {string} kind
 * @param {string} rowKey
 * @param {(signer: string) => boolean} allow
 */
function cancelVerifies(lookup, cancel, kind, rowKey, allow) {
  if (!cancel || !allow(cancel.signer)) return false;
  const id = canonicalCancelId(cancel.id);
  const prior = canonicalPriorIds(cancel.prior);
  if (!id || !prior) return false;
  return verifyBytes(lookup(cancel.signer), cancelMessage(kind, rowKey, id, prior), cancel.signature);
}

/**
 * A verified cancel stored under its canonical id and prior.
 * @param {KeyLookup} lookup
 * @param {SignedCancel} cancel
 * @param {string} kind
 * @param {string} rowKey
 * @param {(signer: string) => boolean} allow
 * @returns {SignedCancel | null}
 */
function acceptedCancel(lookup, cancel, kind, rowKey, allow) {
  if (!cancelVerifies(lookup, cancel, kind, rowKey, allow)) return null;
  const id = canonicalCancelId(cancel.id);
  const prior = canonicalPriorIds(cancel.prior);
  if (!id || !prior) return null;
  return { id, prior, signer: cancel.signer, signature: cancel.signature };
}

/**
 * @param {KeyLookup} lookup
 * @param {readonly SignedCancel[]} cancels
 * @param {string} kind
 * @param {string} rowKey
 * @param {(signer: string) => boolean} allow
 */
function verifiedIds(lookup, cancels, kind, rowKey, allow) {
  return cancels.filter((cancel) => cancelVerifies(lookup, cancel, kind, rowKey, allow)).map((cancel) => cancel.id);
}

/** @param {MembershipRecord} record @param {string} signer */
function membershipCancelSigner(record, signer) {
  const key = aclPrincipalKey(signer);
  if (!key) return false;
  return key === aclPrincipalKey(record.membership.accessor) || key === aclPrincipalKey(record.setOwner);
}

/**
 * @param {KeyLookup} lookup
 * @param {PartyStatement} party
 * @param {"member" | "set"} role
 * @param {MembershipRecord} record
 */
function partySignatureOk(lookup, party, role, record) {
  if (!party.spoken) return true;
  const principal = role === "member" ? record.membership.accessor : record.setOwner;
  if (!party.signature) return false;
  const message = partyMessage(record, role, party.stated, party.hamState, party.observed);
  if (!message) return false;
  return verifyBytes(lookup(principal), message, party.signature);
}

/**
 * @param {KeyLookup} lookup
 * @param {MembershipRecord} record
 */
function publishMembership(lookup, record) {
  const rowKey = membershipRowKey(record);
  if (rowKey == null) {
    record.membership.stated = 0;
    record.removed = false;
    return;
  }
  const ids = verifiedIds(lookup, record.cancels, "membership", rowKey, (signer) =>
    membershipCancelSigner(record, signer),
  );
  const live = (/** @type {PartyStatement} */ party, /** @type {"member" | "set"} */ role) =>
    party.spoken &&
    party.stated &&
    covers(party.observed, ids) &&
    ids.length === record.cancels.length &&
    partySignatureOk(lookup, party, role, record);
  if (live(record.member, "member") && live(record.setParty, "set")) {
    record.membership.stated = 1;
    record.removed = false;
    return;
  }
  record.membership.stated = 0;
  const retracted = (/** @type {PartyStatement} */ party) => party.spoken && !party.stated && party.hamState > 0;
  record.removed = ids.length > 0 || retracted(record.member) || retracted(record.setParty);
}

/**
 * @param {KeyLookup} lookup
 * @param {ObjectSetRecord} record
 */
function objectSignatureOk(lookup, record) {
  const message = objectMessage(record);
  if (!message) return false;
  return verifyBytes(lookup(record.objectOwner), message, record.signature);
}

/**
 * @param {KeyLookup} lookup
 * @param {ObjectSetRecord} record
 */
function refreshObject(lookup, record) {
  const ids = verifiedIds(lookup, record.cancels, "object-set", aclKey(record.name.object), (signer) => {
    const key = aclPrincipalKey(signer);
    return key != null && key === aclPrincipalKey(record.objectOwner);
  });
  const live =
    record.signedStated === 1 &&
    ids.length === record.cancels.length &&
    covers(record.observed, ids) &&
    objectSignatureOk(lookup, record);
  record.name.stated = live ? 1 : 0;
}

/**
 * @param {PartyStatement} local
 * @param {PartyStatement} incoming
 * @param {readonly string[]} ids
 * @param {boolean} localOk
 * @param {boolean} incomingOk
 */
function pickParty(local, incoming, ids, localOk, incomingOk) {
  if (localOk && !incomingOk) return structuredClone(local);
  if (incomingOk && !localOk) return structuredClone(incoming);
  if (!localOk && !incomingOk) return absentParty();
  const localCovers = covers(local.observed, ids);
  const incomingCovers = covers(incoming.observed, ids);
  if (localCovers !== incomingCovers) return structuredClone(incomingCovers ? incoming : local);
  if (incoming.hamState > local.hamState) return structuredClone(incoming);
  if (incoming.hamState < local.hamState) return structuredClone(local);
  if (!incoming.stated && local.stated) return structuredClone(incoming);
  return structuredClone(local);
}

/**
 * Keep each cancel whose own signature verifies. A bad assent on
 * the other party does not drop those ids.
 * @param {KeyLookup} lookup
 * @param {MembershipRecord} record
 */
function retainAuthenticMembership(lookup, record) {
  const rowKey = membershipRowKey(record);
  if (rowKey == null) return null;
  const allow = (/** @type {string} */ signer) => membershipCancelSigner(record, signer);
  record.cancels = uniqueCancels(
    record.cancels.flatMap((cancel) => {
      const accepted = acceptedCancel(lookup, cancel, "membership", rowKey, allow);
      return accepted ? [accepted] : [];
    }),
  );
  if (record.member.spoken && !partySignatureOk(lookup, record.member, "member", record)) {
    record.member = absentParty();
  }
  if (record.setParty.spoken && !partySignatureOk(lookup, record.setParty, "set", record)) {
    record.setParty = absentParty();
  }
  if (record.cancels.length === 0 && !record.member.spoken && !record.setParty.spoken) return null;
  publishMembership(lookup, record);
  return record;
}

/**
 * @param {KeyLookup} lookup
 * @param {MembershipRecord} local
 * @param {MembershipRecord} incoming
 */
function mergeMembership(lookup, local, incoming) {
  /** @type {SignedCancel[]} */
  const cancels = uniqueCancels(structuredClone(local.cancels));
  const rowKey = membershipRowKey(incoming);
  const allow = (/** @type {string} */ signer) => membershipCancelSigner(incoming, signer);
  if (rowKey == null) return local;
  for (const cancel of incoming.cancels) {
    const accepted = acceptedCancel(lookup, cancel, "membership", rowKey, allow);
    if (accepted && !cancels.some((row) => row.id === accepted.id)) cancels.push(accepted);
  }
  const ids = cancelIds(cancels);
  const merged = structuredClone(local);
  merged.member = pickParty(
    local.member,
    incoming.member,
    ids,
    partySignatureOk(lookup, local.member, "member", local),
    partySignatureOk(lookup, incoming.member, "member", incoming),
  );
  merged.setParty = pickParty(
    local.setParty,
    incoming.setParty,
    ids,
    partySignatureOk(lookup, local.setParty, "set", local),
    partySignatureOk(lookup, incoming.setParty, "set", incoming),
  );
  merged.cancels = cancels;
  merged.membership.hamState = Math.max(local.membership.hamState, incoming.membership.hamState);
  publishMembership(lookup, merged);
  return merged;
}

/**
 * @param {KeyLookup} lookup
 * @param {ObjectSetRecord} local
 * @param {ObjectSetRecord} incoming
 * @param {readonly string[]} ids
 */
function pickObject(lookup, local, incoming, ids) {
  const localOk = objectSignatureOk(lookup, local);
  const incomingOk = objectSignatureOk(lookup, incoming);
  if (localOk && !incomingOk) return structuredClone(local);
  if (incomingOk && !localOk) return structuredClone(incoming);
  if (!localOk && !incomingOk) return structuredClone(local);
  const localCovers = covers(local.observed, ids);
  const incomingCovers = covers(incoming.observed, ids);
  if (localCovers !== incomingCovers) return structuredClone(incomingCovers ? incoming : local);
  if (incoming.name.hamState > local.name.hamState) return structuredClone(incoming);
  if (incoming.name.hamState < local.name.hamState) return structuredClone(local);
  if (incoming.signedStated === 0 && local.signedStated === 1) return structuredClone(incoming);
  if (local.signedStated === 0 && incoming.signedStated === 1) return structuredClone(local);
  const incomingKey = `${incoming.name.predicate}\0${incoming.name.setId}`;
  const localKey = `${local.name.predicate}\0${local.name.setId}`;
  return structuredClone(incomingKey < localKey ? incoming : local);
}

/**
 * @param {KeyLookup} lookup
 * @param {ObjectSetRecord} record
 */
function retainAuthenticObject(lookup, record) {
  const rowKey = aclKey(record.name.object);
  const allow = (/** @type {string} */ signer) => {
    const key = aclPrincipalKey(signer);
    return key != null && key === aclPrincipalKey(record.objectOwner);
  };
  record.cancels = uniqueCancels(
    record.cancels.flatMap((cancel) => {
      const accepted = acceptedCancel(lookup, cancel, "object-set", rowKey, allow);
      return accepted ? [accepted] : [];
    }),
  );
  if (!objectSignatureOk(lookup, record)) {
    if (record.cancels.length === 0) return null;
    record.signedStated = 0;
    record.signature = new Uint8Array();
    record.observed = [];
  }
  refreshObject(lookup, record);
  return record;
}

/**
 * @param {KeyLookup} lookup
 * @param {ObjectSetRecord} local
 * @param {ObjectSetRecord} incoming
 */
function mergeObjectSet(lookup, local, incoming) {
  /** @type {SignedCancel[]} */
  const cancels = uniqueCancels(structuredClone(local.cancels));
  const rowKey = aclKey(incoming.name.object);
  const allow = (/** @type {string} */ signer) =>
    samePrincipal(signer, incoming.objectOwner);
  for (const cancel of incoming.cancels) {
    const accepted = acceptedCancel(lookup, cancel, "object-set", rowKey, allow);
    if (accepted && !cancels.some((row) => row.id === accepted.id)) cancels.push(accepted);
  }
  const picked = pickObject(lookup, local, incoming, cancelIds(cancels));
  picked.cancels = cancels;
  refreshObject(lookup, picked);
  return picked;
}

/**
 * @param {MembershipRecord} record
 * @param {readonly GroupSnapshotMember[]} members
 */
function membershipHidden(record, members) {
  const accessor = aclPrincipalKey(record.membership.accessor);
  /** @type {GroupSnapshotMember | undefined} */
  let best;
  for (const row of members) {
    if (
      row.predicate !== record.membership.predicate ||
      row.setId !== record.membership.setId ||
      aclPrincipalKey(row.accessor) !== accessor
    ) {
      continue;
    }
    if (!best) {
      best = row;
      continue;
    }
    const rowRank = row.stated === 0 ? 1 : 0;
    const bestRank = best.stated === 0 ? 1 : 0;
    if (row.hamState > best.hamState || (row.hamState === best.hamState && rowRank > bestRank)) {
      best = row;
    }
  }
  if (!best) return true;
  if (best.stated !== 0) return true;
  return best.hamState < record.membership.hamState;
}

/**
 * In-memory group graph. Not a Gun peer.
 * See grants on the same object stay on the delegate path.
 */
export class MemoryGroupGraph {
  constructor() {
    /** @type {Map<string, { id: string, owner: string }>} */
    this.objects = new Map();
    /** @type {Map<string, SeeGrant>} */
    this.grants = new Map();
    /** @type {Map<string, import("./post.js").PostEdge>} */
    this.posts = new Map();
    /** @type {Map<string, string>} */
    this.setOwners = new Map();
    /** @type {Map<string, MembershipRecord>} */
    this.memberships = new Map();
    /** @type {Map<string, ObjectSetRecord>} */
    this.objectSets = new Map();
    /** @type {Map<string, Uint8Array>} */
    this.enrolled = new Map();
    this.replicaId = randomBytes(16);
  }

  /**
   * In-graph id and owner. A direct aclKey hit wins. Otherwise a raw
   * id and its item soul resolve to the stored object. The stored id
   * is the original spelling, so an item soul still matches its raw id.
   * @param {string} object
   * @returns {{ id: string, owner: string } | undefined}
   */
  objectRecord(object) {
    const text = plainObjectId(object);
    if (text == null) return undefined;
    const direct = this.objects.get(aclKey(text));
    if (direct) return { id: direct.id, owner: direct.owner };
    for (const stored of this.objects.values()) {
      if (itemSoulAlias(stored.id, text)) return { id: stored.id, owner: stored.owner };
    }
    return undefined;
  }

  /** @param {string} object */
  hasObject(object) {
    return this.objectRecord(object) !== undefined;
  }

  /** @param {string} object */
  ownerOf(object) {
    return this.objectRecord(object)?.owner;
  }

  /**
   * In-graph object id. See and post writes, cancels, and lookups use
   * this spelling once the object is stored.
   * @param {string} object
   */
  canonicalObjectId(object) {
    const text = plainObjectId(object);
    if (text == null) return String(object ?? "");
    return this.objectRecord(text)?.id ?? text;
  }

  /**
   * Members auto-approve gate. Same check as the free function.
   * Hop and hint are not arguments.
   * @param {GroupPredicate} predicate
   * @param {string} object
   * @param {string} accessor
   * @param {number} now
   */
  checkGroupSee(predicate, object, accessor, now) {
    const graph = /** @type {GroupSeeGraph} */ (/** @type {unknown} */ (this));
    return checkGroupSee(graph, predicate, object, accessor, now, null, null);
  }

  /**
   * @param {string} object
   * @param {string} owner
   */
  putObject(object, owner) {
    const id = plainObjectId(object);
    if (id == null) return;
    const next = asciiTrim(String(owner));
    const directKey = aclKey(id);
    if (this.objects.has(directKey)) {
      const prev = this.objects.get(directKey);
      if (prev && prev.id !== id) return;
      if (prev && !samePrincipal(prev.owner, next)) this.objectSets.delete(directKey);
      this.objects.set(directKey, { id, owner: next });
      return;
    }
    if (this.objectRecord(id)) return;
    this.objects.set(directKey, { id, owner: next });
  }

  /** @param {string} object */
  seeGrants(object) {
    const requested = this.canonicalObjectId(object);
    return [...this.grants.values()].filter(
      (grant) => sameObjectId(grantObject(grant), requested) && grant.stated !== 0,
    );
  }

  /**
   * See rows that name this object, accessor, and owner.
   * A raw id and its item soul count as one object.
   * @param {string} owner
   * @param {string} object
   * @param {string} accessor
   */
  matchingSee(owner, object, accessor) {
    const requested = this.canonicalObjectId(object);
    const who = canonicalAccessorId(accessor);
    const ownerKey = canonicalAccessorId(owner);
    /** @type {{ key: string, grant: SeeGrant }[]} */
    const rows = [];
    if (!who) return rows;
    for (const [key, grant] of this.grants) {
      if (canonicalAccessorId(grant.accessor) !== who) continue;
      if (grant.owner != null && (!ownerKey || canonicalAccessorId(grant.owner) !== ownerKey)) continue;
      if (!sameObjectId(grantObject(grant), requested)) continue;
      rows.push({ key, grant });
    }
    return rows;
  }

  /**
   * @param {string} owner
   * @param {SeeGrant} grant
   */
  stateSeeGrant(owner, grant) {
    const query = grantObject(grant);
    const record = this.objectRecord(query);
    const ownerKey = canonicalAccessorId(owner);
    const accessor = grant.accessor;
    if (!query || !record || !ownerKey || !canonicalAccessorId(accessor) || !samePrincipal(record.owner, owner)) return;
    const object = record.id;
    const rows = this.matchingSee(owner, object, accessor);
    const hamState = rows.reduce((max, row) => Math.max(max, row.grant.hamState ?? 0), 0) + 1;
    if (!Number.isSafeInteger(hamState)) return;
    for (const row of rows) this.grants.delete(row.key);
    /** @type {SeeGrant} */
    const stored = {
      ...grant,
      object,
      accessor,
      stated: /** @type {1} */ (1),
      hamState,
      owner: asciiTrim(String(owner)),
    };
    if (stored.claimId != null) stored.claimId = object;
    const key = grantKey(owner, object, accessor);
    if (key == null) return;
    this.grants.set(key, stored);
  }

  /**
   * @param {string} owner
   * @param {string} accessor
   * @param {string} object
   */
  unstateSeeGrant(owner, accessor, object) {
    const query = plainObjectId(object) ?? "";
    const who = asciiTrim(String(accessor));
    const record = this.objectRecord(query);
    const ownerKey = canonicalAccessorId(owner);
    if (!query || !who || !canonicalAccessorId(who) || !record || !ownerKey || !samePrincipal(record.owner, owner)) return;
    const id = record.id;
    const rows = this.matchingSee(owner, id, who);
    const prev = rows.reduce((best, row) => {
      if (!best || (row.grant.hamState ?? 0) >= (best.hamState ?? 0)) return row.grant;
      return best;
    }, /** @type {SeeGrant | undefined} */ (undefined));
    for (const row of rows) this.grants.delete(row.key);
    const key = grantKey(owner, id, who);
    if (key == null) return;
    this.grants.set(key, {
      ...(prev ?? {}),
      object: id,
      accessor: who,
      from: prev?.from ?? 0,
      until: prev?.until ?? 0,
      stated: 0,
      hamState: (prev?.hamState ?? 0) + 1,
      owner: asciiTrim(String(owner)),
    });
  }

  /**
   * @param {string} object
   * @param {string} accessor
   */
  seeGrant(object, accessor) {
    const record = this.objectRecord(object);
    const requested = record?.id ?? plainObjectId(object) ?? "";
    const who = aclPrincipalKey(accessor);
    if (!who) return undefined;
    const ownerNow = record?.owner;
    /** @type {{ soul: string, owner: string, hamState: number, grant: { object: string, accessor: string, from: number, until: number, stated: number } } | undefined} */
    let best;
    for (const grant of this.grants.values()) {
      const grantId = grantObject(grant);
      if (!sameObjectId(grantId, requested)) continue;
      if (aclPrincipalKey(grant.accessor) !== who) continue;
      const owner = grant.owner ?? "";
      const ownerKey = aclPrincipalKey(owner);
      if (!ownerNow || !ownerKey || ownerKey !== aclPrincipalKey(ownerNow)) continue;
      const hamState = grant.hamState ?? 0;
      if (best && hamState < best.hamState) continue;
      best = {
        soul: `s3rch/acl/${ownerKey}/${aclKey(requested)}/${who}`,
        owner,
        hamState,
        grant: {
          object: grantObject(grant),
          accessor: grant.accessor,
          from: grant.from ?? 0,
          until: grant.until ?? 0,
          stated: grant.stated === 0 ? 0 : 1,
        },
      };
    }
    return best;
  }

  /**
   * @param {string} object
   * @param {string} accessor
   */
  postGrant(object, accessor) {
    const record = this.objectRecord(object);
    const requested = record?.id ?? plainObjectId(object) ?? "";
    const who = aclPrincipalKey(accessor);
    if (!who) return undefined;
    const ownerNow = record?.owner;
    for (const edge of this.posts.values()) {
      if (!sameObjectId(edge.grant.object, requested)) continue;
      if (aclPrincipalKey(edge.grant.accessor) !== who) continue;
      const ownerKey = aclPrincipalKey(edge.owner);
      if (!ownerNow || !ownerKey || ownerKey !== aclPrincipalKey(ownerNow)) continue;
      return edge;
    }
    return undefined;
  }

  /**
   * Owner-only live post row. Does not write a see grant.
   * @param {string} owner
   * @param {{ object?: string, claimId?: string, accessor: string, from: number, until: number }} grant
   */
  statePostGrant(owner, grant) {
    const query = plainObjectId(grant.object ?? grant.claimId ?? "") ?? "";
    const who = asciiTrim(String(grant.accessor ?? ""));
    const record = this.objectRecord(query);
    const ownerKey = aclPrincipalKey(owner);
    if (!query || !who || !aclPrincipalKey(who) || !record || !ownerKey || !samePrincipal(record.owner, owner)) return;
    const object = record.id;
    const key = grantKey(owner, object, who);
    if (key == null) return;
    const prev = this.posts.get(key);
    const hamState = nextPostHam(prev?.hamState, false);
    if (hamState === undefined) return;
    const edge = canonicalPostEdge({
      soul: "",
      owner: asciiTrim(String(owner)),
      hamState,
      grant: { object, accessor: who, from: grant.from, until: grant.until, stated: 1 },
    });
    if (!postRowEncodable(edge)) return;
    this.posts.set(key, edge);
  }

  /**
   * Owner-only. stated 0 and a hamState bump.
   * @param {string} owner
   * @param {string} accessor
   * @param {string} object
   */
  unstatePostGrant(owner, accessor, object) {
    const query = plainObjectId(object) ?? "";
    const who = asciiTrim(String(accessor));
    const record = this.objectRecord(query);
    const ownerKey = aclPrincipalKey(owner);
    if (!query || !who || !aclPrincipalKey(who) || !record || !ownerKey || !samePrincipal(record.owner, owner)) return;
    const id = record.id;
    const key = grantKey(owner, id, who);
    if (key == null) return;
    const prev = this.posts.get(key);
    const hamState = nextPostHam(prev?.hamState, true);
    if (hamState === undefined) return;
    const edge = canonicalPostEdge({
      soul: "",
      owner: asciiTrim(String(owner)),
      hamState,
      grant: {
        object: prev?.grant.object ?? id,
        accessor: who,
        from: prev?.grant.from ?? 0,
        until: prev?.grant.until ?? 0,
        stated: 0,
      },
    });
    if (!postRowEncodable(edge)) return;
    this.posts.set(key, edge);
  }

  /** @param {import("./post.js").PostEdge} incoming */
  mergePost(incoming) {
    if (!postRowEncodable(incoming)) return;
    const query = plainObjectId(incoming.grant?.object ?? "") ?? "";
    const record = this.objectRecord(query);
    const grantOwner = incoming.owner ?? "";
    if (!query || !record || !grantOwner || !samePrincipal(record.owner, grantOwner)) return;
    const edge = canonicalPostEdge({
      ...incoming,
      grant: { ...incoming.grant, object: record.id },
    });
    const key = grantKey(edge.owner, edge.grant.object, edge.grant.accessor);
    if (key == null) return;
    const local = this.posts.get(key);
    this.posts.set(key, local ? preferPost(local, edge) : edge);
  }

  /**
   * @param {string} principal
   * @param {Uint8Array} publicKey
   */
  enrollSigner(principal, publicKey) {
    const id = aclPrincipalKey(principal);
    if (!id || publicKey.length !== 32) throw new Error("signer is not enrolled");
    const existing = this.enrolled.get(id);
    if (existing && bytesToHex(existing) !== bytesToHex(publicKey)) throw new Error("signer is not enrolled");
    this.enrolled.set(id, new Uint8Array(publicKey));
  }

  /** @param {string} principal */
  enrolledKey(principal) {
    const id = aclPrincipalKey(principal);
    return id == null ? undefined : this.enrolled.get(id);
  }

  /**
   * @param {string} owner
   * @param {GroupPredicate} predicate
   * @param {string} setId
   */
  recordSetOwner(owner, predicate, setId) {
    const name = asciiTrim(String(owner));
    const id = asciiTrim(String(setId));
    if (!name || !id) throw new Error("group name is empty");
    const canonical = canonicalSetId(id);
    if (!canonical) throw new Error("set id is not bound to this owner");
    const key = `${predicate}\0${aclKey(canonical)}`;
    const nameKey = aclPrincipalKey(name);
    if (!nameKey) throw new Error("set id is not bound to this owner");
    const existing = this.setOwners.get(key);
    if (existing && aclPrincipalKey(existing) !== nameKey) {
      throw new Error("set already has an owner");
    }
    if (!existing && !setIdBindsOwner(canonical, name)) throw new Error("set id is not bound to this owner");
    if (!existing) this.setOwners.set(key, name);
  }

  /**
   * @param {GroupPredicate} predicate
   * @param {string} setId
   */
  ownerOfSet(predicate, setId) {
    const canonical = canonicalSetId(setId);
    if (!canonical) return undefined;
    return this.setOwners.get(`${predicate}\0${aclKey(canonical)}`);
  }

  /**
   * @param {string} speaker
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {string} accessor
   * @returns {[boolean, boolean]}
   */
  #speaker(speaker, predicate, setId, accessor) {
    const owner = this.ownerOfSet(predicate, setId);
    if (!owner) throw new Error("set owner is unknown");
    const speakerKey = aclPrincipalKey(speaker);
    const speaksMember = speakerKey != null && speakerKey === aclPrincipalKey(accessor);
    const speaksSet = speakerKey != null && speakerKey === aclPrincipalKey(owner);
    if (!speaksMember && !speaksSet) throw new Error("membership speaker is not the member or the set owner");
    return [speaksMember, speaksSet];
  }

  /**
   * @param {string} principal
   * @param {KeyObject} secret
   */
  #requireSecret(principal, secret) {
    const id = aclPrincipalKey(principal);
    const key = id == null ? undefined : this.enrolled.get(id);
    if (!key) throw new Error("signer is not enrolled");
    const probe = signBytes(secret, domainBytes("sociacl-signer-probe-v1"));
    if (!verifyBytes(key, domainBytes("sociacl-signer-probe-v1"), probe)) {
      throw new Error("row signature is not valid");
    }
  }

  /**
   * @param {SignedCancel[]} cancels
   * @param {string} kind
   * @param {string} rowKey
   * @param {string} signer
   * @param {KeyObject} secret
   */
  #pushCancel(cancels, kind, rowKey, signer, secret) {
    const kept = uniqueCancels(cancels);
    cancels.length = 0;
    cancels.push(...kept);
    const prior = canonicalPriorIds(cancelIds(cancels));
    if (!prior) throw new Error("cancel id is not 64 lowercase hex");
    const id = newCancelId(this.replicaId, prior);
    const message = cancelMessage(kind, rowKey, id, prior);
    if (!message) throw new Error("cancel id is not 64 lowercase hex");
    cancels.push({
      id,
      prior,
      signer: asciiTrim(signer),
      signature: signBytes(secret, message),
    });
  }

  /**
   * @param {string} speaker
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {string} accessor
   * @param {KeyObject} secret
   */
  stateMembership(speaker, predicate, setId, accessor, secret) {
    const id = asciiTrim(String(setId));
    const who = asciiTrim(String(accessor));
    if (!id || !who) throw new Error("group name is empty");
    const [speaksMember, speaksSet] = this.#speaker(speaker, predicate, id, who);
    const canonical = canonicalSetId(id);
    if (!canonical) throw new Error("set id is not bound to this owner");
    this.#requireSecret(speaker, secret);
    const owner = this.ownerOfSet(predicate, canonical);
    if (!owner) throw new Error("set owner is unknown");
    const whoKey = aclPrincipalKey(who);
    if (whoKey == null) throw new Error("group name is empty");
    const key = `${predicate}\0${aclKey(canonical)}\0${whoKey}`;
    const record = this.memberships.get(key) ?? {
      membership: { predicate, setId: canonical, accessor: who, stated: /** @type {0} */ (0), hamState: 0 },
      member: absentParty(),
      setParty: absentParty(),
      removed: false,
      soul: "",
      setOwner: owner,
      cancels: [],
    };
    record.soul = membershipSoul(owner, predicate, canonical, who);
    record.setOwner = owner;
    record.membership.setId = canonical;
    record.membership.hamState += 1;
    const observed = cancelIds(record.cancels);
    if (speaksMember) this.#signParty(record, record.member, "member", true, observed, secret);
    if (speaksSet) this.#signParty(record, record.setParty, "set", true, observed, secret);
    publishMembership(mapLookup(this.enrolled), record);
    this.memberships.set(key, record);
  }

  /**
   * @param {string} speaker
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {string} accessor
   * @param {KeyObject} secret
   */
  cancelMembership(speaker, predicate, setId, accessor, secret) {
    const id = asciiTrim(String(setId));
    const who = asciiTrim(String(accessor));
    if (!id || !who) throw new Error("group name is empty");
    const [speaksMember, speaksSet] = this.#speaker(speaker, predicate, id, who);
    const canonical = canonicalSetId(id);
    if (!canonical) throw new Error("set id is not bound to this owner");
    this.#requireSecret(speaker, secret);
    const owner = this.ownerOfSet(predicate, canonical);
    if (!owner) throw new Error("set owner is unknown");
    const whoKey = aclPrincipalKey(who);
    if (whoKey == null) throw new Error("group name is empty");
    const key = `${predicate}\0${aclKey(canonical)}\0${whoKey}`;
    const record = this.memberships.get(key) ?? {
      membership: { predicate, setId: canonical, accessor: who, stated: /** @type {0} */ (0), hamState: 0 },
      member: absentParty(),
      setParty: absentParty(),
      removed: false,
      soul: "",
      setOwner: owner,
      cancels: [],
    };
    record.soul = membershipSoul(owner, predicate, canonical, who);
    record.setOwner = owner;
    record.membership.setId = canonical;
    const rowKey = membershipRowKey(record);
    if (!rowKey) throw new Error("group name is empty");
    this.#pushCancel(record.cancels, "membership", rowKey, speaker, secret);
    const observed = cancelIds(record.cancels);
    if (speaksMember) this.#signParty(record, record.member, "member", false, observed, secret);
    if (speaksSet) this.#signParty(record, record.setParty, "set", false, observed, secret);
    record.membership.hamState += 1;
    publishMembership(mapLookup(this.enrolled), record);
    this.memberships.set(key, record);
  }

  /**
   * @param {MembershipRecord} record
   * @param {PartyStatement} party
   * @param {"member" | "set"} role
   * @param {boolean} stated
   * @param {readonly string[]} observed
   * @param {KeyObject} secret
   */
  #signParty(record, party, role, stated, observed, secret) {
    const hamState = party.hamState + 1;
    const message = partyMessage(record, role, stated, hamState, observed);
    if (!message) throw new Error("cancel id is not 64 lowercase hex");
    party.stated = stated;
    party.hamState = hamState;
    party.observed = [...observed];
    party.spoken = true;
    party.signature = signBytes(secret, message);
  }

  /**
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {string} accessor
   */
  membership(predicate, setId, accessor) {
    const canonical = canonicalSetId(setId);
    if (!canonical) return undefined;
    const accessorKey = aclPrincipalKey(accessor);
    if (accessorKey == null) return undefined;
    const key = `${predicate}\0${aclKey(canonical)}\0${accessorKey}`;
    const record = this.memberships.get(key);
    if (!record) return undefined;
    return {
      ...record.membership,
      removed: record.removed,
      setOwner: record.setOwner,
      member: record.member,
      setParty: record.setParty,
      cancels: record.cancels,
    };
  }

  /**
   * @param {string} owner
   * @param {string} object
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {KeyObject} secret
   */
  nameObjectSet(owner, object, predicate, setId, secret) {
    const id = asciiTrim(String(setId));
    if (!id) throw new Error("group name is empty");
    const canonical = canonicalSetId(id);
    if (!canonical) throw new Error("set id is not bound to this owner");
    const objectId = plainObjectId(object);
    if (objectId == null) throw new Error("mesh object is not in-graph");
    const objectOwner = this.ownerOf(objectId);
    if (!objectOwner) throw new Error("mesh object is not in-graph");
    if (!samePrincipal(objectOwner, owner)) throw new Error("dest ACL write is owner-only");
    const setOwner = this.ownerOfSet(predicate, canonical);
    if (setOwner && !setIdBindsOwner(canonical, setOwner)) throw new Error("set id is not bound to this owner");
    this.#requireSecret(owner, secret);
    this.#writeObjectSet(objectId, objectOwner, predicate, canonical, 1, secret);
  }

  /**
   * @param {string} owner
   * @param {string} object
   * @param {KeyObject} secret
   */
  clearObjectSet(owner, object, secret) {
    const objectId = plainObjectId(object);
    if (objectId == null) throw new Error("mesh object is not in-graph");
    const objectOwner = this.ownerOf(objectId);
    if (!objectOwner) throw new Error("mesh object is not in-graph");
    if (!samePrincipal(objectOwner, owner)) throw new Error("dest ACL write is owner-only");
    this.#requireSecret(owner, secret);
    const existing = this.objectSets.get(aclKey(objectId));
    if (!existing) {
      this.#writeObjectSet(objectId, objectOwner, "same-group", "", 0, secret);
      return;
    }
    this.#writeObjectSet(objectId, objectOwner, existing.name.predicate, existing.name.setId, 0, secret);
  }

  /**
   * @param {string} object
   * @returns {(ObjectSetName & { signedStated?: 0 | 1, observed?: string[], signature?: Uint8Array, cancels?: SignedCancel[] }) | undefined}
   */
  objectSet(object) {
    const objectId = plainObjectId(object);
    if (objectId == null) return undefined;
    const record = this.objectSets.get(aclKey(objectId));
    if (!record) return undefined;
    return {
      ...record.name,
      objectOwner: record.objectOwner,
      signedStated: record.signedStated,
      observed: record.observed,
      signature: record.signature,
      cancels: record.cancels,
    };
  }

  /** @param {MemoryGroupGraph} other */
  mergeFrom(other) {
    for (const [key, record] of other.objects) {
      if (this.objects.has(key) || this.objectRecord(record.id)) continue;
      this.objects.set(key, { id: record.id, owner: record.owner });
    }
    for (const incoming of other.grants.values()) {
      const query = grantObject(incoming);
      const record = this.objectRecord(query);
      const grantOwner = incoming.owner ?? "";
      if (!query || !record || !grantOwner || !samePrincipal(record.owner, grantOwner)) {
        continue;
      }
      const object = record.id;
      const normalized = { ...structuredClone(incoming), object };
      const rows = this.matchingSee(grantOwner, object, normalized.accessor);
      let local = /** @type {SeeGrant | undefined} */ (undefined);
      for (const row of rows) {
        local = local ? preferGrant(local, row.grant) : row.grant;
        this.grants.delete(row.key);
      }
      const chosen = local ? preferGrant(local, normalized) : normalized;
      const stored = { ...chosen, object };
      const storedKey = grantKey(grantOwner, object, stored.accessor);
      if (storedKey == null) continue;
      this.grants.set(storedKey, stored);
    }
    for (const incoming of other.posts.values()) {
      this.mergePost(incoming);
    }
    for (const [key, owner] of other.setOwners) {
      const setKey = key.split("\0")[1] ?? "";
      const setId = unescapeKey(setKey);
      if (!setId || !setIdBindsOwner(setId, owner)) continue;
      const canonical = canonicalSetId(setId);
      if (!canonical) continue;
      const predicate = /** @type {GroupPredicate} */ (key.split("\0")[0]);
      const storedKey = `${predicate}\0${aclKey(canonical)}`;
      if (!this.setOwners.has(storedKey)) this.setOwners.set(storedKey, owner);
    }
    const lookup = mapLookup(this.enrolled);
    for (const incoming of other.memberships.values()) {
      const canonical = canonicalSetId(incoming.membership.setId);
      if (!canonical || incoming.membership.setId !== canonical) continue;
      if (!setIdBindsOwner(canonical, incoming.setOwner)) continue;
      if (!this.#membershipOwnerMatches(incoming)) continue;
      const accessorKey = aclPrincipalKey(incoming.membership.accessor);
      if (accessorKey == null) continue;
      const key = `${incoming.membership.predicate}\0${aclKey(canonical)}\0${accessorKey}`;
      const local = this.memberships.get(key);
      if (!local) {
        const kept = retainAuthenticMembership(lookup, structuredClone(incoming));
        if (!kept) continue;
        this.memberships.set(key, kept);
        continue;
      }
      this.memberships.set(key, mergeMembership(lookup, local, incoming));
    }
    for (const incoming of other.objectSets.values()) {
      if (!this.#objectOwnerMatches(incoming)) continue;
      if (incoming.signedStated === 1 && !canonicalSetId(incoming.name.setId)) continue;
      const key = aclKey(incoming.name.object);
      const local = this.objectSets.get(key);
      if (!local) {
        const kept = retainAuthenticObject(lookup, structuredClone(incoming));
        if (!kept) continue;
        this.objectSets.set(key, kept);
        continue;
      }
      this.objectSets.set(key, mergeObjectSet(lookup, local, incoming));
    }
  }

  /** @param {MembershipRecord} record */
  #membershipOwnerMatches(record) {
    const owner = this.ownerOfSet(record.membership.predicate, record.membership.setId);
    return samePrincipal(owner, record.setOwner);
  }

  /** @param {ObjectSetRecord} record */
  #objectOwnerMatches(record) {
    const owner = this.ownerOf(record.name.object);
    return samePrincipal(owner, record.objectOwner);
  }

  /**
   * @param {string} objectId
   * @param {string} objectOwner
   * @param {GroupPredicate} predicate
   * @param {string} setId
   * @param {0 | 1} stated
   * @param {KeyObject} secret
   */
  #writeObjectSet(objectId, objectOwner, predicate, setId, stated, secret) {
    const key = aclKey(objectId);
    const prev = this.objectSets.get(key);
    /** @type {SignedCancel[]} */
    const cancels = prev ? structuredClone(prev.cancels) : [];
    if (stated === 0) this.#pushCancel(cancels, "object-set", key, objectOwner, secret);
    /** @type {ObjectSetRecord} */
    const record = {
      name: {
        object: objectId,
        predicate,
        setId,
        stated,
        hamState: (prev?.name.hamState ?? 0) + 1,
      },
      signedStated: stated,
      soul: objectSetSoul(objectOwner, objectId),
      objectOwner,
      observed: cancelIds(cancels),
      signature: new Uint8Array(),
      cancels,
    };
    const message = objectMessage(record);
    if (!message) throw new Error("cancel id is not 64 lowercase hex");
    record.signature = signBytes(secret, message);
    refreshObject(mapLookup(this.enrolled), record);
    this.objectSets.set(key, record);
  }
}

/** @param {string} owner @param {string} object @param {string} accessor */
function grantKey(owner, object, accessor) {
  const ownerKey = aclPrincipalKey(owner);
  const accessorKey = aclPrincipalKey(accessor);
  if (ownerKey == null || accessorKey == null) return null;
  return `${ownerKey}\0${aclKey(object)}\0${accessorKey}`;
}

/**
 * Signing bytes for an equal-ham see tie-break.
 * A principal that does not parse is null, matching Rust `Option`.
 * @param {SeeGrant} grant
 * @returns {Uint8Array | null}
 */
function canonicalGrantBytes(grant) {
  const owner = aclPrincipalKey(grant.owner ?? "");
  const accessor = aclPrincipalKey(grant.accessor);
  if (owner == null || accessor == null) return null;
  /** @type {Uint8Array[]} */
  const parts = [domainBytes("sociacl-see-grant-v1")];
  pushStr(parts, owner);
  pushStr(parts, aclKey(grantObject(grant)));
  pushStr(parts, accessor);
  const times = new Uint8Array(16);
  const view = new DataView(times.buffer);
  view.setBigUint64(0, BigInt(grant.from ?? 0));
  view.setBigUint64(8, BigInt(grant.until ?? 0));
  parts.push(times, Uint8Array.of(grant.stated === 0 ? 0 : 1));
  return concatBytes(parts);
}

/** @param {Uint8Array} left @param {Uint8Array} right */
function bytesBefore(left, right) {
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i += 1) {
    if (left[i] !== right[i]) return left[i] < right[i];
  }
  return left.length < right.length;
}

/**
 * True when `left`'s window is a proper subset of `right`'s.
 * @param {SeeGrant} left
 * @param {SeeGrant} right
 */
function windowInside(left, right) {
  return (
    (left.from ?? 0) >= (right.from ?? 0) &&
    (left.until ?? 0) <= (right.until ?? 0) &&
    ((left.from ?? 0) > (right.from ?? 0) || (left.until ?? 0) < (right.until ?? 0))
  );
}

/** @param {SeeGrant} local @param {SeeGrant} incoming */
function preferGrant(local, incoming) {
  const incomingHam = incoming.hamState ?? 0;
  const localHam = local.hamState ?? 0;
  if (incomingHam > localHam) return incoming;
  if (incomingHam < localHam) return local;
  if (incoming.stated === 0 && local.stated !== 0) return incoming;
  if (local.stated === 0 && incoming.stated !== 0) return local;
  const localNarrower = windowInside(local, incoming);
  const incomingNarrower = windowInside(incoming, local);
  if (localNarrower && !incomingNarrower) return local;
  if (incomingNarrower && !localNarrower) return incoming;
  const incomingBytes = canonicalGrantBytes(incoming);
  const localBytes = canonicalGrantBytes(local);
  if (incomingBytes == null) return local;
  if (localBytes == null) return incoming;
  return bytesBefore(incomingBytes, localBytes) ? incoming : local;
}

/**
 * @param {GroupSeeGraph} graph
 * @param {ObjectSetName} edge
 * @param {string} owner
 */
function edgeAuthentic(graph, edge, owner) {
  if (edge.stated !== 1 || !edge.objectOwner || !edge.signature || !edge.observed || !edge.cancels) return false;
  if (!samePrincipal(edge.objectOwner, owner)) return false;
  const lookup = graphLookup(graph);
  if (!lookup(edge.objectOwner)) return false;
  /** @type {ObjectSetRecord} */
  const record = {
    name: { ...edge, stated: edge.signedStated === 0 ? 0 : 1 },
    signedStated: edge.signedStated === 0 ? 0 : 1,
    soul: "",
    objectOwner: edge.objectOwner,
    observed: edge.observed,
    signature: edge.signature,
    cancels: edge.cancels,
  };
  const ids = verifiedIds(lookup, record.cancels, "object-set", aclKey(record.name.object), (signer) => {
    const key = aclPrincipalKey(signer);
    return key != null && key === aclPrincipalKey(record.objectOwner);
  });
  return (
    record.signedStated === 1 &&
    ids.length === record.cancels.length &&
    covers(record.observed, ids) &&
    objectSignatureOk(lookup, record)
  );
}

/**
 * Authenticated, currently grantable edge for this object.
 * A stated bit alone does not name it. Matches Rust `object_set_grantable`.
 * @param {GroupSeeGraph} graph
 * @param {string} object
 */
function objectSetGrantable(graph, object) {
  const requested = plainObjectId(object);
  if (requested == null) return false;
  const edge = graph.objectSet(requested);
  if (!edge || !edge.object || aclKey(edge.object) !== aclKey(requested)) return false;
  const owner = graph.ownerOf(requested);
  if (!owner) return false;
  return edgeAuthentic(graph, edge, owner);
}

/**
 * @param {GroupSeeGraph} graph
 * @param {MeshMembership} row
 */
function membershipAuthentic(graph, row) {
  if (row.stated !== 1 || !row.member || !row.setParty || !row.cancels || !row.setOwner) return false;
  const lookup = graphLookup(graph);
  /** @type {MembershipRecord} */
  const record = {
    membership: row,
    member: row.member,
    setParty: row.setParty,
    removed: Boolean(row.removed),
    soul: "",
    setOwner: row.setOwner,
    cancels: row.cancels,
  };
  const rowKey = membershipRowKey(record);
  if (rowKey == null) return false;
  const ids = verifiedIds(lookup, record.cancels, "membership", rowKey, (signer) =>
    membershipCancelSigner(record, signer),
  );
  const live = (/** @type {PartyStatement} */ party, /** @type {"member" | "set"} */ role) =>
    party.spoken && party.stated && covers(party.observed, ids) && partySignatureOk(lookup, party, role, record);
  return ids.length === record.cancels.length && live(record.member, "member") && live(record.setParty, "set");
}

/**
 * @param {GroupSeeGraph} graph
 * @param {string} object
 * @param {string} accessor
 * @param {number} now
 */
function checkSee(graph, object, accessor, now) {
  const closed = closedReason(object);
  if (closed) return { allowed: false, reason: closed };
  const owner = graph.ownerOf(object);
  if (!owner) return { allowed: false, reason: "missing" };
  if (samePrincipal(owner, accessor)) return { allowed: true, reason: "owner" };
  const live = graph.seeGrants(object).some((grant) => {
    const grantOwner = grant.owner;
    const ownerOk = grantOwner == null || samePrincipal(grantOwner, owner);
    return (
      ownerOk &&
      sameObjectId(grantObject(grant), object) &&
      samePrincipal(grant.accessor, accessor) &&
      grant.stated !== 0 &&
      now >= grant.from &&
      now < grant.until
    );
  });
  if (live) return { allowed: true, reason: "delegate" };
  return { allowed: false, reason: "missing" };
}

/**
 * CHECK(see) for same-group or named-circle.
 * Hop missing does not fail. Hop alone never allows.
 * `now` is the Check instant. Membership has no window here.
 * A missing set owner fails closed.
 *
 * @param {GroupSeeGraph} graph
 * @param {GroupPredicate} predicate
 * @param {string} object
 * @param {string} accessor
 * @param {number} now
 * @param {HandoffHint | null | undefined} hint
 * @param {HopFactor | null | undefined} hop
 */
export function checkGroupSee(graph, predicate, object, accessor, now, hint, hop) {
  void now;
  const echoed = { hint: hint ?? null, hop: hop ?? null };
  const deny = (/** @type {string} */ reason) => ({ allowed: false, reason, ...echoed });
  const requestedObject = plainObjectId(object);
  if (requestedObject == null) return deny("missing");
  const closed = closedReason(requestedObject);
  if (closed) return deny(closed);
  const owner = graph.ownerOf(requestedObject);
  if (!owner) return deny("missing");
  const ownerKey = aclPrincipalKey(owner);
  const accessorKey = aclPrincipalKey(accessor);
  if (ownerKey && ownerKey === accessorKey) {
    return { allowed: true, reason: "owner", ...echoed };
  }
  const edge = graph.objectSet(requestedObject);
  if (!edge) return deny("missing");
  if (!edge.object || aclKey(edge.object) !== aclKey(requestedObject)) return deny("missing");
  if (!edge.objectOwner || !samePrincipal(edge.objectOwner, owner)) return deny("missing");
  if (edge.predicate !== predicate) return deny("missing");
  if (edge.stated !== 1) return deny("cancelled");
  const canonical = canonicalSetId(edge.setId);
  if (!canonical || edge.setId !== canonical) return deny("missing");
  const setOwner = graph.ownerOfSet(predicate, canonical);
  if (setOwner == null || !setIdBindsOwner(canonical, setOwner)) return deny("missing");
  if (!edgeAuthentic(graph, edge, owner)) return deny("missing");
  const membership = graph.membership(predicate, canonical, accessor);
  if (!membership) return deny("missing");
  if (membership.predicate !== predicate || membership.setId !== canonical) return deny("missing");
  if (!samePrincipal(membership.accessor, accessor)) return deny("missing");
  if (membership.setOwner == null || !samePrincipal(membership.setOwner, setOwner)) {
    return deny("missing");
  }
  if (membership.stated === 1 && membershipAuthentic(graph, membership)) {
    return { allowed: true, reason: predicate, ...echoed };
  }
  return deny(membership.removed ? "cancelled" : "missing");
}

/**
 * Group tail of a presentation. Binding and key unwrap stay outside.
 * Allowed only when checkGroupSee allows and the payload is stated 1
 * with now in [from, until). A live edge does not override a cancel.
 * Only an authenticated, currently grantable object-set edge forces
 * the group path. A stated bit alone does not.
 *
 * @param {GroupSeeGraph} graph
 * @param {PresentedGroup | null | undefined} group
 * @param {string} object
 * @param {string} accessor
 * @param {DecodedGroupPayload} payload
 * @param {number} now
 * @param {HandoffHint | null | undefined} hint
 * @param {HopFactor | null | undefined} hop
 * @returns {GroupPresentation}
 */
export function checkGroupPresentation(graph, group, object, accessor, payload, now, hint, hop) {
  const storeCancel = payload.stated === 0;
  const echoed = { hint: hint ?? null, hop: hop ?? null, storeCancel };
  const edge = graph.objectSet(String(object));
  if (!group) {
    if (objectSetGrantable(graph, object)) return { allowed: false, reason: "missing", ...echoed };
    const dest = checkSee(graph, object, accessor, now);
    if (dest.allowed && payloadLive(payload, now)) {
      return { allowed: true, reason: dest.reason, ...echoed };
    }
    return {
      allowed: false,
      reason: payloadLive(payload, now) ? dest.reason : "cancelled",
      ...echoed,
    };
  }
  if (!edge || edge.predicate !== group.predicate || edge.setId !== group.setId) {
    return { allowed: false, reason: "missing", ...echoed };
  }
  const see = checkGroupSee(graph, group.predicate, object, accessor, now, hint, hop);
  if (see.allowed && payloadLive(payload, now)) {
    return { allowed: true, reason: see.reason, ...echoed };
  }
  return {
    allowed: false,
    reason: payloadLive(payload, now) ? see.reason : "cancelled",
    ...echoed,
  };
}

/**
 * True when the snapshot hides a removal or a newer object-set edge.
 * Member hamState does not stand in for the object-set edge.
 *
 * @param {MemoryGroupGraph} graph
 * @param {string} object
 * @param {readonly GroupSnapshotMember[]} members
 * @param {GroupSnapshotObjectSet | null | undefined} objectSet
 */
export function snapshotUnderstatesGroup(graph, object, members, objectSet) {
  const current = graph.objectSet(object);
  if (!current) return objectSet != null;
  if (!objectSet) return true;
  if (
    objectSet.hamState < current.hamState ||
    objectSet.predicate !== current.predicate ||
    objectSet.setId !== current.setId ||
    objectSet.stated !== current.stated
  ) {
    return true;
  }
  for (const record of graph.memberships.values()) {
    if (
      record.removed &&
      record.membership.predicate === current.predicate &&
      record.membership.setId === current.setId &&
      membershipHidden(record, members)
    ) {
      return true;
    }
  }
  return false;
}
