/** Authenticate a complete-history management checkpoint and matching live policy.
 * Expectations must be independently provisioned (challenge from a fresh request).
 * This pure verifier does NOT consume the challenge, reconcile local continuity,
 * install state, authorize recovery/root migration, or track a monotonic lease.
 * Every call rechecks both signatures and current transport expiry.
 * @param {unknown} envelope Exact checkpoint envelope JSON text.
 * @param {unknown} policyEnvelope Exact policy envelope JSON text.
 * @param {import('./types.js').WitnessCheckpointExpectations} expected
 * @returns {import('./types.js').Result<import('./types.js').WitnessCheckpoint>}
 */
export function verifyWitnessCheckpoint(envelope: unknown, policyEnvelope: unknown, expected: import("./types.js").WitnessCheckpointExpectations): import("./types.js").Result<import("./types.js").WitnessCheckpoint>;
/** Authenticate and reconcile a checkpoint against the latest trusted local state.
 * No bootstrap/reset: previousJson must name existing validated continuity.
 * Additional authenticated history is allowed, but no local restriction may be lost.
 * Run inside the adapter's serialized transaction; this function performs no I/O.
 * @param {unknown} envelope
 * @param {unknown} policyEnvelope
 * @param {unknown} previousJson
 * @param {import('./types.js').WitnessCheckpointExpectations} expected
 * @returns {import('./types.js').Result<import('./types.js').WitnessCheckpoint>}
 */
export function advanceWitnessCheckpoint(envelope: unknown, policyEnvelope: unknown, previousJson: unknown, expected: import("./types.js").WitnessCheckpointExpectations): import("./types.js").Result<import("./types.js").WitnessCheckpoint>;
export const MAX_WITNESS_CHECKPOINT_BYTES: number;
export const MAX_WITNESS_CHECKPOINT_ENVELOPE_BYTES: 3145728;
