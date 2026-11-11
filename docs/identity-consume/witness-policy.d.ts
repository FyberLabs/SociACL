/** Authenticate a Panopticon export; does NOT install trust or establish freshness.
 * Root and audience must come from independent trusted configuration; now from a
 * trusted clock. Before using returned JWKS, an adapter must atomically enforce
 * durable revision/key-history rules and trusted bootstrap freshness.
 * @param {unknown} envelope JSON text, including duplicate-member validation.
 * @param {string} root Pinned administrative P-256 public key in x.y encoding.
 * @param {string} audience Pinned deployment audience.
 * @param {number} now Trusted current Unix seconds, without skew.
 * @returns {import('./types.js').Result<import('./types.js').WitnessPolicy>}
 */
export function verifyWitnessPolicyEnvelope(envelope: unknown, root: string, audience: string, now: number): import("./types.js").Result<import("./types.js").WitnessPolicy>;
/** Calculate a candidate snapshot inside the adapter's serialized update.
 * Previous JSON MUST come from trusted, rollback-protected storage, never the
 * publisher or caller. Null is only for independently authorized first bootstrap.
 * Re-run against the latest state/clock after CAS conflicts or lock waits, then
 * atomically persist the WHOLE result before exposing its JWKS. This is pure:
 * it neither persists nor proves freshness of a previous snapshot.
 * @param {unknown} envelope
 * @param {unknown} previousJson
 * @param {string} root
 * @param {string} audience
 * @param {number} minimumRevision Independently provisioned positive bootstrap floor.
 * @param {number} now Trusted clock at serialized transition/commit.
 * @returns {import('./types.js').Result<WitnessPolicyState>}
 */
export function advanceWitnessPolicy(envelope: unknown, previousJson: unknown, root: string, audience: string, minimumRevision: number, now: number): import("./types.js").Result<WitnessPolicyState>;
export const MAX_WITNESS_POLICY_BYTES: 262144;
export const MAX_WITNESS_ENVELOPE_BYTES: 360448;
export const MAX_WITNESS_POLICY_HISTORY: 1024;
export const MAX_WITNESS_STATE_BYTES: 2097152;
import type { WitnessPolicyState } from './types.js';
