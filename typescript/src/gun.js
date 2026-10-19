/**
 * Light Check consume implementation for s3r.ch.
 * Same names as docs/s3rch-check.d.ts. Copy or import from here.
 * Hint and hop never set allowed. A post grant is a separate row.
 * A hop, a hint, a wrap, a request, or an inbox delivery never grants.
 * Request signing lives in request.js and uses the ids keyring.
 * Stored-id see Check is see.js. Label rows stay out of this module.
 */

export { admitPost, checkPost, factorGrants } from "./post.js";

/** Length-prefixed domain for postGrantBytes. The ids constant, not a second string. */
export { POST_DOMAIN as POST_GRANT_DOMAIN, postGrantBytes, postSoul } from "../ids/src/index.js";

export { admitRow, checkSee, putObject, reverifyPrincipal } from "./see.js";

export function toGunNode(item) {
  return {
    id: item.id,
    source: item.source,
    kind: item.kind || "activity",
    author: item.author,
    body: item.body,
    ts: item.ts,
    permalink: item.permalink,
    tags: Array.isArray(item.tags) ? item.tags.join(",") : String(item.tags ?? ""),
    provenance: item.provenance,
  };
}

export function fromGunNode(node) {
  if (!node || !node.id) return null;
  const source = node.source;
  if (source !== "rss3" && source !== "rss" && source !== "atom") return null;
  return {
    id: node.id,
    source,
    kind: node.kind || "activity",
    author: node.author ?? "",
    body: node.body ?? "",
    ts: Number(node.ts) || 0,
    permalink: node.permalink ?? "",
    tags: String(node.tags ?? "")
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean),
    provenance: node.provenance ?? "",
  };
}

export function acceptHint(hint) {
  return { ...hint };
}

export function acceptHop(hop) {
  return hop;
}

export function decodeHop(bytes) {
  return bytes;
}
