/** @param {string} s @returns {Uint8Array} */
export function unb64(s: string): Uint8Array;
/** Shared precedence, lengths in UTF-16 code units, no coercion. @param {unknown} x @param {number} max @returns {Result<string>} */
export function text(x: unknown, max: number): Result<string>;
/** Snapshot data properties once. No getters, coercion or prototype reads. Proxies fail closed. @param {unknown} x @returns {Result<Record<string, unknown>>} */
export function data(x: unknown): Result<Record<string, unknown>>;
/** Little-endian UTF-8 length prefix. Callers pass strings this function already trusts.
 * @param {readonly string[]} fields */
export function lp(fields: readonly string[]): Uint8Array<ArrayBuffer>;
/** Public encoder. Only real, well-formed strings. No coercion.
 * `length` is read once. Each element is read and validated once, and the
 * first bad element returns before the rest of the array is touched.
 * @param {unknown} fields @returns {Result<Uint8Array>} */
export function lengthPrefixed(fields: unknown): Result<Uint8Array>;
export function ok<T>(value: T): Result<T>;
export function fail(reason: Reason): {
    ok: false;
    reason: Reason;
};
export const utf8: TextEncoder;
export function hex(bytes: Uint8Array): string;
export function unhex(s: string): Uint8Array<ArrayBuffer>;
export function b64(bytes: Uint8Array): string;
export function integer(n: unknown): boolean;
import type { Result } from './types.js';
import type { Reason } from './types.js';
