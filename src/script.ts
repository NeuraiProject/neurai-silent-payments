import { bech32m } from "@scure/base";

import { concatBytes, toBytes, type BytesLike } from "./bytes.js";
import { isValidPoint } from "./ec.js";
import { SilentPaymentError } from "./errors.js";
import { hash160, sha256, TAG_AUTHSCRIPT, taggedHash } from "./hashes.js";
import { getNetwork, WITNESS_FAMILY, type NetworkName } from "./networks.js";

/** Auth type of an ECDSA key in a strict AuthScript descriptor. */
export const AUTH_TYPE_ECDSA = 0x02;
const OP_3 = 0x53;
const OP_TRUE = 0x51;

/**
 * Commitment of the strict ECDSA v3 output of a compressed key:
 * TaggedHash("NeuraiAuthScript", 0x03 || 0x02 || HASH160(key) || SHA256(OP_TRUE)).
 */
export function paymentCommitment(publicKey: BytesLike): Uint8Array {
  const key = toBytes(publicKey, "publicKey", 33);
  if (!isValidPoint(key)) throw new SilentPaymentError("point");
  return taggedHash(
    TAG_AUTHSCRIPT,
    concatBytes(Uint8Array.of(WITNESS_FAMILY, AUTH_TYPE_ECDSA), hash160(key), sha256(Uint8Array.of(OP_TRUE))),
  );
}

/** scriptPubKey OP_3 <32-byte commitment> of a compressed key. */
export function paymentScript(publicKey: BytesLike): Uint8Array {
  return concatBytes(Uint8Array.of(OP_3, 0x20), paymentCommitment(publicKey));
}

export function isNativeV3Script(script: BytesLike): boolean {
  const bytes = toBytes(script, "script");
  return bytes.length === 34 && bytes[0] === OP_3 && bytes[1] === 0x20;
}

/** Bech32m address (nq1r... / tnq1r...) of a native v3 scriptPubKey. */
export function scriptToAddress(script: BytesLike, network: NetworkName): string {
  const bytes = toBytes(script, "script");
  if (!isNativeV3Script(bytes)) throw new SilentPaymentError("invalid argument", "not a native v3 script");
  return bech32m.encode(getNetwork(network).addressHrp, [WITNESS_FAMILY, ...bech32m.toWords(bytes.subarray(2))]);
}

/** Address of the strict v3 output of a compressed key. */
export function paymentAddress(publicKey: BytesLike, network: NetworkName): string {
  return scriptToAddress(paymentScript(publicKey), network);
}
