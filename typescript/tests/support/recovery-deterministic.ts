/**
 * Deterministic recovery and delivery wrappers for tests.
 * Not imported by typescript/src and not listed in the package exports.
 * The production modules do not re-export these.
 */
export { sealRecoveryCopyWith } from "../../contract/recovery-seal.ts";
export { deliverKeyringWith } from "../../contract/delivery-seal.ts";
