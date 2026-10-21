import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";

import { toBytes, type BytesLike } from "./bytes.js";
import { SilentPaymentError } from "./errors.js";

// All curve arithmetic goes through @noble/curves. Operations on secrets use
// getPublicKey (base point multiplication) and getSharedSecret (ECDH), which
// noble implements without secret-dependent branches.

const Point = secp256k1.Point;
type CurvePoint = InstanceType<typeof Point>;

export const CURVE_ORDER: bigint = Point.Fn.ORDER;

export function scalarFromBytes(bytes: Uint8Array): bigint {
  return bytesToNumberBE(bytes);
}

export function scalarToBytes(value: bigint): Uint8Array {
  return numberToBytesBE(value, 32);
}

/** A valid private key: 32 bytes in [1, n-1]. */
export function isValidScalar(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return false;
  const value = scalarFromBytes(bytes);
  return value > 0n && value < CURVE_ORDER;
}

export function addScalars(a: bigint, b: bigint): bigint {
  return (a + b) % CURVE_ORDER;
}

export function mulScalars(a: bigint, b: bigint): bigint {
  return (a * b) % CURVE_ORDER;
}

/** Compressed public key of a private key. */
export function publicKeyOf(privateKey: Uint8Array): Uint8Array {
  if (!isValidScalar(privateKey)) throw new SilentPaymentError("invalid private key");
  return secp256k1.getPublicKey(privateKey, true);
}

/** Compressed public key of a private key given as bytes or hex. */
export function getPublicKey(privateKey: BytesLike): Uint8Array {
  return publicKeyOf(toBytes(privateKey, "privateKey", 32));
}

/** Compressed SEC1 point on the curve; anything else is rejected. */
export function parsePoint(bytes: Uint8Array): CurvePoint {
  if (bytes.length !== 33 || (bytes[0] !== 0x02 && bytes[0] !== 0x03)) throw new SilentPaymentError("point");
  try {
    return Point.fromBytes(bytes);
  } catch {
    throw new SilentPaymentError("point");
  }
}

export function isValidPoint(bytes: Uint8Array): boolean {
  try {
    parsePoint(bytes);
    return true;
  } catch {
    return false;
  }
}

/** Compressed SEC1 point of scalar * point (ECDH, constant time). */
export function ecdh(scalar: Uint8Array, point: Uint8Array): Uint8Array {
  parsePoint(point);
  return secp256k1.getSharedSecret(scalar, point, true);
}

/** Sum of points, keeping repetitions; null when the sum is the point at infinity. */
export function sumPoints(points: Uint8Array[]): Uint8Array | null {
  let sum = Point.ZERO;
  for (const point of points) sum = sum.add(parsePoint(point));
  return sum.is0() ? null : sum.toBytes(true);
}

/** scalar * point for a public scalar (the tweak T = h*A); null when the
 *  scalar is not in [1, n-1]. Not for secrets: use ecdh for those. */
export function mulPublicPoint(point: Uint8Array, scalar: Uint8Array): Uint8Array | null {
  if (!isValidScalar(scalar)) return null;
  return parsePoint(point).multiply(scalarFromBytes(scalar)).toBytes(true);
}

/** B + t*G, or null when it is the point at infinity. */
export function addTweakToPoint(point: Uint8Array, tweak: Uint8Array): Uint8Array | null {
  const sum = parsePoint(point).add(Point.fromBytes(secp256k1.getPublicKey(tweak, true)));
  return sum.is0() ? null : sum.toBytes(true);
}
