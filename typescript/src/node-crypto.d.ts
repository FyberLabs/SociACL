declare module "node:crypto" {
  export interface Hash {
    update(data: string | Uint8Array): Hash;
    digest(): Uint8Array;
  }
  export interface KeyObject {
    export(opts: { type: string; format: string }): Uint8Array;
  }
  export function createHash(algorithm: string): Hash;
  export function createPrivateKey(opts: {
    key: Uint8Array;
    format: "der";
    type: "pkcs8";
  }): KeyObject;
  export function createPublicKey(
    key: KeyObject | { key: Uint8Array; format: "der"; type: "spki" },
  ): KeyObject;
  export function randomBytes(size: number): Uint8Array;
  export function sign(algorithm: null, data: Uint8Array, key: KeyObject): Uint8Array;
  export function verify(
    algorithm: null,
    data: Uint8Array,
    key: KeyObject,
    signature: Uint8Array,
  ): boolean;
}
