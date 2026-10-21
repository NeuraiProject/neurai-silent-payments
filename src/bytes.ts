import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";

import { SilentPaymentError } from "./errors.js";

/** Bytes, or the same bytes as a hex string. */
export type BytesLike = Uint8Array | string;

export { bytesToHex, concatBytes, hexToBytes };

/** Copy of `value` as bytes; `length`, when given, is enforced. */
export function toBytes(value: BytesLike, name: string, length?: number): Uint8Array {
  let bytes: Uint8Array;
  if (typeof value === "string") {
    if (!/^([0-9a-fA-F]{2})*$/.test(value)) {
      throw new SilentPaymentError("invalid argument", `${name} is not a hex string`);
    }
    bytes = hexToBytes(value);
  } else if (value instanceof Uint8Array) {
    bytes = Uint8Array.from(value);
  } else {
    throw new SilentPaymentError("invalid argument", `${name} must be bytes or a hex string`);
  }
  if (length !== undefined && bytes.length !== length) {
    throw new SilentPaymentError("invalid argument", `${name} must be ${length} bytes`);
  }
  return bytes;
}

/** Unsigned lexicographic order, as std::vector<unsigned char> compares. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && compareBytes(a, b) === 0;
}

export function u32be(n: number): Uint8Array {
  return Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

export function u32le(n: number): Uint8Array {
  return Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
}

/** Overwrites secret bytes once they are no longer needed. JavaScript cannot
 *  guarantee that no other copy exists; this only shortens the lifetime of
 *  the buffers this library owns. */
export function wipe(...buffers: (Uint8Array | undefined)[]): void {
  for (const buffer of buffers) buffer?.fill(0);
}
