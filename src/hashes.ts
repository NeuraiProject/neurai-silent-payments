import { ripemd160 } from "@noble/hashes/legacy.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { concatBytes } from "./bytes.js";

export const TAG_INPUTS = "NeuraiSilentPayments/v0/Inputs";
export const TAG_SHARED_SECRET = "NeuraiSilentPayments/v0/SharedSecret";
export const TAG_AUTHSCRIPT = "NeuraiAuthScript";

/** BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg). */
export function taggedHash(tag: string, message: Uint8Array): Uint8Array {
  const tagHash = sha256(utf8ToBytes(tag));
  return sha256(concatBytes(tagHash, tagHash, message));
}

export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

export { sha256 };
