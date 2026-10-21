import { createBase58check } from "@scure/base";

import { concatBytes, toBytes, type BytesLike } from "./bytes.js";
import { isValidScalar } from "./ec.js";
import { SilentPaymentError } from "./errors.js";
import { sha256 } from "./hashes.js";
import { getNetwork, type NetworkName } from "./networks.js";

const base58check = createBase58check(sha256);

/** WIF of a private key with a compressed public key (as dumpprivkey prints it). */
export function encodeWIF(privateKey: BytesLike, network: NetworkName): string {
  const key = toBytes(privateKey, "privateKey", 32);
  if (!isValidScalar(key)) throw new SilentPaymentError("invalid private key");
  return base58check.encode(concatBytes(Uint8Array.of(getNetwork(network).wifPrefix), key, Uint8Array.of(0x01)));
}

/** Private key of a compressed-key WIF of `network`. */
export function decodeWIF(wif: string, network: NetworkName): Uint8Array {
  let raw: Uint8Array;
  try {
    raw = base58check.decode(wif);
  } catch {
    throw new SilentPaymentError("invalid WIF");
  }
  if (raw.length !== 34 || raw[33] !== 0x01) throw new SilentPaymentError("invalid WIF", "only compressed-key WIFs are accepted");
  if (raw[0] !== getNetwork(network).wifPrefix) throw new SilentPaymentError("network", "WIF of another network");
  const key = raw.slice(1, 33);
  if (!isValidScalar(key)) throw new SilentPaymentError("invalid private key");
  return key;
}
