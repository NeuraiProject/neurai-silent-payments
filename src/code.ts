import { utf8ToBytes } from "@noble/hashes/utils.js";

import { equalBytes, toBytes } from "./bytes.js";
import { isValidPoint } from "./ec.js";
import { SilentPaymentError } from "./errors.js";
import { getNetwork, networkFromId, PROFILE_VERSION, type NetworkName } from "./networks.js";

/** Public payment code: network plus the scan and spend public keys. */
export interface PaymentCode {
  network: NetworkName;
  scanPublicKey: Uint8Array;
  spendPublicKey: Uint8Array;
}

export type CodeCheck = { valid: true; code: PaymentCode } | { valid: false; reason: string };

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST = 0x2bc830a3;
const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
export const CODE_PAYLOAD_SIZE = 67;

function polymod(values: number[]): number {
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ value) >>> 0;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk = (chk ^ GENERATOR[i]) >>> 0;
    }
  }
  return chk;
}

function expandHrp(hrp: string): number[] {
  const values: number[] = [];
  for (const c of hrp) values.push(c.charCodeAt(0) >> 5);
  values.push(0);
  for (const c of hrp) values.push(c.charCodeAt(0) & 31);
  return values;
}

/** Regroups bits; without padding it rejects leftover or non-zero bits. */
function convertBits(data: ArrayLike<number>, from: number, to: number, pad: boolean): number[] | null {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (let i = 0; i < data.length; i++) {
    acc = (acc << from) | data[i];
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
    acc &= (1 << bits) - 1;
  }
  if (pad) {
    if (bits) out.push((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
    return null;
  }
  return out;
}

/** Encodes a payment code (bech32m, version 0, 67-byte payload). */
export function encodeCode(code: PaymentCode): string {
  const params = getNetwork(code.network);
  const scan = toBytes(code.scanPublicKey, "scanPublicKey", 33);
  const spend = toBytes(code.spendPublicKey, "spendPublicKey", 33);
  if (!isValidPoint(scan) || !isValidPoint(spend)) throw new SilentPaymentError("point");
  const payload = new Uint8Array(CODE_PAYLOAD_SIZE);
  payload[0] = params.id;
  payload.set(scan, 1);
  payload.set(spend, 34);
  const data = [PROFILE_VERSION, ...(convertBits(payload, 8, 5, true) as number[])];
  const mod = polymod([...expandHrp(params.codeHrp), ...data, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (mod >>> (5 * (5 - i))) & 31);
  return params.codeHrp + "1" + [...data, ...checksum].map((v) => CHARSET[v]).join("");
}

/**
 * Decodes a payment code of `network` with the same rules and in the same
 * order as the node, so `reason` matches decodesilentpaymentcode. Like the
 * node, it works on the UTF-8 bytes of the text.
 */
export function checkCode(text: string, network: NetworkName): CodeCheck {
  const local = getNetwork(network);
  const fail = (reason: string): CodeCheck => ({ valid: false, reason });
  if (typeof text !== "string") return fail("charset");
  const raw = utf8ToBytes(text);
  if (raw.length < 8 || raw.length > 200) return fail("length");
  let lower = false;
  let upper = false;
  for (const c of raw) {
    if (c < 33 || c > 126) return fail("charset");
    if (c >= 0x61 && c <= 0x7a) lower = true;
    if (c >= 0x41 && c <= 0x5a) upper = true;
  }
  if (lower && upper) return fail("mixed case");
  const str = String.fromCharCode(...raw).toLowerCase();
  const pos = str.lastIndexOf("1");
  if (pos < 1 || pos + 7 > str.length) return fail("separator");
  const hrp = str.slice(0, pos);
  const values: number[] = [];
  for (const c of str.slice(pos + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) return fail("charset");
    values.push(v);
  }
  if (polymod([...expandHrp(hrp), ...values]) !== BECH32M_CONST) return fail("checksum");
  if (hrp !== "nsp" && hrp !== "tnsp") return fail("hrp");
  const data = values.slice(0, values.length - 6);
  if (data.length === 0 || data[0] !== PROFILE_VERSION) return fail("version");
  const payload = convertBits(data.slice(1), 5, 8, false);
  if (!payload) return fail("padding");
  if (payload.length !== CODE_PAYLOAD_SIZE) return fail("payload length");
  const networkId = payload[0];
  if (networkId > 2 || (hrp === "nsp") !== (networkId === 0)) return fail("hrp/network_id");
  if (networkId !== local.id) return fail("network");
  const scan = Uint8Array.from(payload.slice(1, 34));
  const spend = Uint8Array.from(payload.slice(34));
  if (!isValidPoint(scan) || !isValidPoint(spend)) return fail("point");
  if (equalBytes(scan.subarray(1), spend.subarray(1))) return fail("scan equals +-spend");
  return { valid: true, code: { network: networkFromId(networkId).name, scanPublicKey: scan, spendPublicKey: spend } };
}

/** Decodes a payment code of `network`; throws SilentPaymentError(reason). */
export function decodeCode(text: string, network: NetworkName): PaymentCode {
  const result = checkCode(text, network);
  if (!result.valid) throw new SilentPaymentError(result.reason, `invalid payment code: ${result.reason}`);
  return result.code;
}

/** Accepts a code string or an already decoded code of `network`. */
export function toPaymentCode(code: string | PaymentCode, network: NetworkName): PaymentCode {
  if (typeof code === "string") return decodeCode(code, network);
  if (code.network !== network) throw new SilentPaymentError("network", "payment code of another network");
  return decodeCode(encodeCode(code), network);
}

