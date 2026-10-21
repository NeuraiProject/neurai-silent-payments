import { compareBytes, concatBytes, hexToBytes, u32be, u32le } from "./bytes.js";
import { isValidScalar } from "./ec.js";
import { SilentPaymentError } from "./errors.js";
import { TAG_INPUTS, TAG_SHARED_SECRET, taggedHash } from "./hashes.js";

/** Payments to one payment code (one scan key) in a single transaction. */
export const MAX_PAYMENTS_PER_CODE = 16;

/** A transaction output being spent: txid in display order (as the RPC prints it). */
export interface Outpoint {
  txid: string;
  vout: number;
}

/** Serialized outpoint: txid in internal byte order || vout (LE32). */
export function serializeOutpoint(outpoint: Outpoint): Uint8Array {
  const { txid, vout } = outpoint;
  if (typeof txid !== "string" || !/^[0-9a-fA-F]{64}$/.test(txid)) {
    throw new SilentPaymentError("invalid argument", "txid must be 32 bytes of hex");
  }
  if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) {
    throw new SilentPaymentError("invalid argument", "vout must be a 32-bit unsigned integer");
  }
  return concatBytes(hexToBytes(txid.toLowerCase()).reverse(), u32le(vout));
}

/**
 * Input hash h = TaggedHash(Inputs, N || smallest outpoint || A), where A is
 * the sum of the input public keys. Null when h is not a valid scalar.
 */
export function computeInputHash(context: Uint8Array, outpoints: Uint8Array[], inputKeySum: Uint8Array): Uint8Array | null {
  if (outpoints.length === 0) return null;
  let smallest = outpoints[0];
  for (const outpoint of outpoints) {
    if (compareBytes(outpoint, smallest) < 0) smallest = outpoint;
  }
  const h = taggedHash(TAG_INPUTS, concatBytes(context, smallest, inputKeySum));
  return isValidScalar(h) ? h : null;
}

/** Tweak t_k = TaggedHash(SharedSecret, N || S || BE32(k)); null when invalid. */
export function computeSharedTweak(context: Uint8Array, sharedSecret: Uint8Array, k: number): Uint8Array | null {
  const t = taggedHash(TAG_SHARED_SECRET, concatBytes(context, sharedSecret, u32be(k)));
  return isValidScalar(t) ? t : null;
}
