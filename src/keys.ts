import { hmac } from "@noble/hashes/hmac.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { mnemonicToSeedSync } from "@scure/bip39";

import { bytesToHex, concatBytes, equalBytes, toBytes, u32be, wipe, type BytesLike } from "./bytes.js";
import { encodeCode } from "./code.js";
import { CURVE_ORDER, isValidScalar, parsePoint, publicKeyOf, scalarFromBytes, scalarToBytes } from "./ec.js";
import { SilentPaymentError } from "./errors.js";
import { getNetwork, type NetworkName } from "./networks.js";

export const PURPOSE = 352;
const HARDENED = 0x80000000;

/** Keys of one identity. A view-only identity has no spend private key. */
export interface SilentPaymentKeys {
  network: NetworkName;
  scanPrivateKey: Uint8Array;
  scanPublicKey: Uint8Array;
  spendPrivateKey: Uint8Array;
  spendPublicKey: Uint8Array;
  /** Public payment code (nsp1... / tnsp1...). */
  code: string;
}

export interface ViewOnlyKeys {
  network: NetworkName;
  scanPrivateKey: Uint8Array;
  scanPublicKey: Uint8Array;
  spendPublicKey: Uint8Array;
  code: string;
}

/** View key in the format of the node's exportsilentpaymentviewkey and
 *  importsilentpaymentviewkey. Anyone holding it can link every payment. */
export interface ViewKey {
  scan_private_key: string;
  spend_pubkey: string;
  network: NetworkName;
}

interface ExtendedKey {
  key: Uint8Array;
  chainCode: Uint8Array;
}

function masterKey(seed: Uint8Array): ExtendedKey {
  const I = hmac(sha512, utf8ToBytes("Bitcoin seed"), seed);
  const key = I.slice(0, 32);
  if (!isValidScalar(key)) throw new SilentPaymentError("derivation failed");
  return { key, chainCode: I.slice(32) };
}

/** BIP32 hardened child. An invalid child fails explicitly, as in the node. */
function hardenedChild(parent: ExtendedKey, index: number): ExtendedKey {
  const I = hmac(sha512, parent.chainCode, concatBytes(Uint8Array.of(0), parent.key, u32be(index + HARDENED)));
  const il = scalarFromBytes(I.subarray(0, 32));
  if (il >= CURVE_ORDER) throw new SilentPaymentError("derivation failed");
  const child = (il + scalarFromBytes(parent.key)) % CURVE_ORDER;
  if (child === 0n) throw new SilentPaymentError("derivation failed");
  const result = { key: scalarToBytes(child), chainCode: I.slice(32) };
  wipe(I);
  return result;
}

function derivePath(seed: Uint8Array, path: number[]): Uint8Array {
  let node = masterKey(seed);
  for (const index of path) {
    const next = hardenedChild(node, index);
    wipe(node.key, node.chainCode);
    node = next;
  }
  wipe(node.chainCode);
  return node.key;
}

/** Keys of m/352'/coin'/network'/0'/{0',1'}/0' (spend, scan) from a BIP39 seed. */
export function deriveKeysFromSeed(seed: BytesLike, network: NetworkName): SilentPaymentKeys {
  const params = getNetwork(network);
  const bytes = toBytes(seed, "seed");
  if (bytes.length < 32) throw new SilentPaymentError("invalid argument", "seed must be at least 32 bytes");
  const account = [PURPOSE, params.coinType, params.id, 0];
  const spendPrivateKey = derivePath(bytes, [...account, 0, 0]);
  const scanPrivateKey = derivePath(bytes, [...account, 1, 0]);
  wipe(bytes);
  const scanPublicKey = publicKeyOf(scanPrivateKey);
  const spendPublicKey = publicKeyOf(spendPrivateKey);
  return {
    network,
    scanPrivateKey,
    scanPublicKey,
    spendPrivateKey,
    spendPublicKey,
    code: encodeCode({ network, scanPublicKey, spendPublicKey }),
  };
}

/** Keys from a BIP39 mnemonic and optional passphrase, as the node's
 *  -mnemonic/-mnemonicpassphrase wallet derives them. The mnemonic is not
 *  checked against a word list (any BIP39 language works). */
export function deriveKeysFromMnemonic(mnemonic: string, passphrase: string, network: NetworkName): SilentPaymentKeys {
  if (typeof mnemonic !== "string" || mnemonic.trim() === "") {
    throw new SilentPaymentError("invalid argument", "mnemonic is empty");
  }
  const seed = mnemonicToSeedSync(mnemonic, passphrase ?? "");
  try {
    return deriveKeysFromSeed(seed, network);
  } finally {
    wipe(seed);
  }
}

export function exportViewKey(keys: SilentPaymentKeys | ViewOnlyKeys): ViewKey {
  return {
    scan_private_key: bytesToHex(keys.scanPrivateKey),
    spend_pubkey: bytesToHex(keys.spendPublicKey),
    network: keys.network,
  };
}

/** View-only identity from a view key, with the node's import rules. */
export function importViewKey(viewKey: ViewKey): ViewOnlyKeys {
  const network = getNetwork(viewKey.network).name;
  const scanPrivateKey = toBytes(viewKey.scan_private_key, "scan_private_key", 32);
  const spendPublicKey = toBytes(viewKey.spend_pubkey, "spend_pubkey", 33);
  if (!isValidScalar(scanPrivateKey)) throw new SilentPaymentError("invalid private key");
  parsePoint(spendPublicKey);
  const scanPublicKey = publicKeyOf(scanPrivateKey);
  if (equalBytes(scanPublicKey.subarray(1), spendPublicKey.subarray(1))) {
    throw new SilentPaymentError("scan equals +-spend");
  }
  return { network, scanPrivateKey, scanPublicKey, spendPublicKey, code: encodeCode({ network, scanPublicKey, spendPublicKey }) };
}
