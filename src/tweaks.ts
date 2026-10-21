// Light client scanning with the node's silent payment index
// (-silentpaymentindex): the format 1 records, their binary messages and
// JSON, scanning with the public tweaks, spends of found payments and an
// independent recomputation of a record from `getblock <hash> 3` to audit a
// server.

import { bytesToHex, concatBytes, equalBytes, hexToBytes, toBytes, u32le, wipe, type BytesLike } from "./bytes.js";
import { ecdh, isValidPoint, isValidScalar, mulPublicPoint, sumPoints } from "./ec.js";
import { SilentPaymentError } from "./errors.js";
import { taggedHash } from "./hashes.js";
import { getContext, type ChainOptions } from "./networks.js";
import { computeInputHash } from "./protocol.js";
import { getEligibleInputs, matchCandidates, type FoundPayment, type ScanKeys, type ScanTransaction } from "./receiver.js";
import { transactionsFromBlock } from "./rpc.js";
import { isNativeV3Script } from "./script.js";

export const INDEX_FORMAT = 1;
export const TAG_INDEX_BLOCK = "NeuraiSilentPayments/v0/IndexBlock";
const MAX_MONEY = 21000000000n * 100000000n;
const MAGIC = Uint8Array.of(0x4e, 0x53, 0x50, 0x54); // "NSPT"
const ZERO_HASH = "0".repeat(64);
const RANGE_STATUS = ["more", "tip", "wait", "incomplete"] as const;

/** A native v3 output of a candidate transaction. */
export interface IndexOutput {
  vout: number;
  /** The 32 bytes after OP_3 0x20 in the scriptPubKey. */
  commitment: Uint8Array;
  valueSat: bigint;
}

/** An eligible transaction with native v3 outputs and its public tweak. */
export interface IndexEntry {
  txid: string;
  /** T = h*A, 33-byte compressed point. */
  tweak: Uint8Array;
  outputs: IndexOutput[];
}

/** Index record of one block. Hashes and txids in display order. */
export interface IndexBlock {
  height: number;
  hash: string;
  prev: string;
  entries: IndexEntry[];
  /** Every native v3 output spent in the block. */
  spent: { txid: string; vout: number }[];
}

export type RangeStatus = (typeof RANGE_STATUS)[number];

export interface IndexRange {
  snapshot: { height: number; hash: string };
  syncedHeight: number;
  /** Height after the last block returned. */
  nextHeight: number;
  /** more: ask again now; tip: wait for a block; wait: retry later; incomplete: the server lacks data. */
  status: RangeStatus;
  blocks: IndexBlock[];
}

/** A payment found with scanTweaks: where it is, besides what scanTransaction gives. */
export interface IndexPayment extends FoundPayment {
  valueSat: bigint;
  height?: number;
  blockHash?: string;
}

export interface SpentPayment {
  txid: string;
  vout: number;
  /** Block that spends it. */
  height: number;
  blockHash: string;
}

const fail = (reason: string): never => {
  throw new SilentPaymentError(reason);
};

function displayHex(internal: Uint8Array): string {
  return bytesToHex(Uint8Array.from(internal).reverse());
}

function internalHash(display: string, name: string): Uint8Array {
  if (typeof display !== "string" || !/^[0-9a-fA-F]{64}$/.test(display)) {
    throw new SilentPaymentError("invalid argument", `${name} must be 32 bytes of hex`);
  }
  return hexToBytes(display.toLowerCase()).reverse();
}

function compactSize(n: number | bigint): Uint8Array {
  const v = BigInt(n);
  if (v < 253n) return Uint8Array.of(Number(v));
  if (v <= 0xffffn) return Uint8Array.of(253, Number(v & 0xffn), Number(v >> 8n));
  if (v <= 0xffffffffn) return concatBytes(Uint8Array.of(254), u32le(Number(v)));
  const out = new Uint8Array(9);
  out[0] = 255;
  new DataView(out.buffer).setBigUint64(1, v, true);
  return out;
}

function i64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, value, true);
  return out;
}

/** Strict reader: the same checks, in the same order and with the same
 *  reasons, as the node's DeserializeIndexBlock. */
class Reader {
  constructor(private readonly data: Uint8Array, public pos: number) {}

  remaining(): number {
    return this.data.length - this.pos;
  }

  bytes(size: number): Uint8Array {
    if (this.remaining() < size) fail("truncated");
    const out = this.data.slice(this.pos, this.pos + size);
    this.pos += size;
    return out;
  }

  u32(): number {
    const b = this.bytes(4);
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
  }

  i64(): bigint {
    return new DataView(this.bytes(8).buffer).getBigInt64(0, true);
  }

  /** Minimal CompactSize no larger than `max`. */
  compactSize(max: number): number {
    const first = this.bytes(1)[0];
    let value: bigint;
    if (first < 253) {
      value = BigInt(first);
    } else {
      const size = first === 253 ? 2 : first === 254 ? 4 : 8;
      const minimum = first === 253 ? 253n : first === 254 ? 0x10000n : 0x100000000n;
      const b = this.bytes(size);
      value = 0n;
      for (let i = size - 1; i >= 0; i--) value = (value << 8n) | BigInt(b[i]);
      if (value < minimum) fail("non-canonical compact size");
    }
    if (value > BigInt(max)) fail("count out of range");
    return Number(value);
  }
}

// Smallest encodings: a counter above (bytes left before it) / size is out of range.
const MIN_ENTRY = 32 + 33 + 1;
const MIN_OUTPUT = 1 + 32 + 8;
const MIN_SPENT = 32 + 1;
const MAX_VOUT = 0xffffffff;

function u32Field(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_VOUT) {
    throw new SilentPaymentError("invalid argument", `${name} must be an integer from 0 to 2^32 - 1`);
  }
  return value;
}

function amountField(value: unknown): bigint {
  if (typeof value !== "bigint") throw new SilentPaymentError("invalid argument", "valueSat must be a bigint");
  if (value < 0n || value > MAX_MONEY) fail("amount out of range");
  return value;
}

/** Canonical bytes of a block record. Every field is range-checked first, so
 *  nothing is truncated or wrapped into a different valid value. */
export function encodeIndexBlock(block: IndexBlock): Uint8Array {
  // Collected and copied once: blocks can have tens of thousands of parts,
  // too many to pass as arguments.
  const parts: Uint8Array[] = [internalHash(block.hash, "hash"), internalHash(block.prev, "prev"), u32le(u32Field(block.height, "height"))];
  parts.push(compactSize(block.entries.length));
  for (const entry of block.entries) {
    parts.push(internalHash(entry.txid, "txid"), toBytes(entry.tweak, "tweak", 33), compactSize(entry.outputs.length));
    for (const output of entry.outputs) {
      parts.push(compactSize(u32Field(output.vout, "vout")), toBytes(output.commitment, "commitment", 32), i64le(amountField(output.valueSat)));
    }
  }
  parts.push(compactSize(block.spent.length));
  for (const spent of block.spent) parts.push(internalHash(spent.txid, "txid"), compactSize(u32Field(spent.vout, "vout")));
  let size = 0;
  for (const part of parts) size += part.length;
  const out = new Uint8Array(size);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/** Reads one block record at `offset`. Errors carry the node's reasons:
 *  truncated, non-canonical compact size, count out of range, invalid tweak,
 *  entry without outputs, outputs out of order, amount out of range. */
export function decodeIndexBlock(data: BytesLike, offset = 0): { block: IndexBlock; offset: number } {
  const bytes = toBytes(data, "data");
  if (offset > bytes.length) fail("truncated");
  const r = new Reader(bytes, offset);
  const block = readIndexBlock(r);
  return { block, offset: r.pos };
}

function readIndexBlock(r: Reader): IndexBlock {
  const hash = displayHex(r.bytes(32));
  const prev = displayHex(r.bytes(32));
  const height = r.u32();
  const entries: IndexEntry[] = [];
  const entryCount = r.compactSize(Math.floor(r.remaining() / MIN_ENTRY));
  for (let e = 0; e < entryCount; e++) {
    const txid = displayHex(r.bytes(32));
    const tweak = r.bytes(33);
    if ((tweak[0] !== 0x02 && tweak[0] !== 0x03) || !isValidPoint(tweak)) fail("invalid tweak");
    const outputCount = r.compactSize(Math.floor(r.remaining() / MIN_OUTPUT));
    if (outputCount === 0) fail("entry without outputs");
    const outputs: IndexOutput[] = [];
    for (let i = 0; i < outputCount; i++) {
      const vout = r.compactSize(MAX_VOUT);
      const commitment = r.bytes(32);
      const valueSat = r.i64();
      if (valueSat < 0n || valueSat > MAX_MONEY) fail("amount out of range");
      if (i > 0 && vout <= outputs[i - 1].vout) fail("outputs out of order");
      outputs.push({ vout, commitment, valueSat });
    }
    entries.push({ txid, tweak, outputs });
  }
  const spent: { txid: string; vout: number }[] = [];
  const spentCount = r.compactSize(Math.floor(r.remaining() / MIN_SPENT));
  for (let i = 0; i < spentCount; i++) {
    const txid = displayHex(r.bytes(32));
    spent.push({ txid, vout: r.compactSize(MAX_VOUT) });
  }
  return { height, hash, prev, entries, spent };
}

/** TaggedHash("NeuraiSilentPayments/v0/IndexBlock", N || block bytes): lets
 *  clients compare servers. */
export function indexBlockDigest(block: IndexBlock | Uint8Array, options: ChainOptions): Uint8Array {
  const bytes = block instanceof Uint8Array ? block : encodeIndexBlock(block);
  return taggedHash(TAG_INDEX_BLOCK, concatBytes(getContext(options), bytes));
}

/**
 * Binary message of the node (REST .bin, RPC "hex"): "NSPT" || format ||
 * type || N, then one block (type 1) or a range (type 2). The context must
 * be the one of `options`, so data of another chain is refused.
 */
export function decodeIndexMessage(data: BytesLike, options: ChainOptions):
  { type: "block"; block: IndexBlock } | ({ type: "range" } & IndexRange) {
  const bytes = toBytes(data, "data");
  const r = new Reader(bytes, 0);
  if (!equalBytes(r.bytes(4), MAGIC)) fail("magic");
  if (r.bytes(1)[0] !== INDEX_FORMAT) fail("format");
  const type = r.bytes(1)[0];
  if (!equalBytes(r.bytes(35), getContext(options))) fail("context");
  let result: { type: "block"; block: IndexBlock } | ({ type: "range" } & IndexRange);
  if (type === 1) {
    result = { type: "block", block: readIndexBlock(r) };
  } else if (type === 2) {
    const snapshot = { height: r.u32(), hash: displayHex(r.bytes(32)) };
    const syncedHeight = r.u32();
    const nextHeight = r.u32();
    const status = RANGE_STATUS[r.bytes(1)[0]] ?? fail("status");
    const blocks: IndexBlock[] = [];
    const count = r.compactSize(Math.floor(r.remaining() / (32 + 32 + 4 + 2)));
    for (let i = 0; i < count; i++) blocks.push(readIndexBlock(r));
    result = { type: "range", snapshot, syncedHeight, nextHeight, status, blocks };
  } else {
    return fail("message type");
  }
  if (r.remaining() !== 0) fail("trailing bytes");
  return result;
}

/* eslint-disable @typescript-eslint/no-explicit-any */

/** A block of the node's JSON (getsilentpaymenttweaks, REST .json). With
 *  `options`, its digest is checked against the content. */
export function indexBlockFromJSON(json: any, options?: ChainOptions): IndexBlock {
  const notBlock = () => new SilentPaymentError("invalid argument", "not an index block");
  if (!json || typeof json !== "object" || !Array.isArray(json.entries) || !Array.isArray(json.spent)) throw notBlock();
  const block: IndexBlock = {
    height: json.height,
    hash: json.hash,
    prev: json.prev,
    entries: json.entries.map((e: any) => {
      if (!e || typeof e !== "object" || !Array.isArray(e.outputs)) throw notBlock();
      return {
        txid: e.txid,
        tweak: toBytes(e.tweak, "tweak", 33),
        outputs: e.outputs.map((o: any) => {
          if (!o || typeof o !== "object") throw notBlock();
          return { vout: o.vout, commitment: toBytes(o.commitment, "commitment", 32), valueSat: satoshiString(o.value_sat) };
        }),
      };
    }),
    spent: json.spent.map((s: any) => {
      if (!s || typeof s !== "object") throw notBlock();
      return { txid: s.txid, vout: s.vout };
    }),
  };
  // Range-checked by the encoder, then through the canonical bytes: the same
  // checks as the binary form.
  const bytes = encodeIndexBlock(block);
  const decoded = decodeIndexBlock(bytes);
  if (decoded.offset !== bytes.length) fail("trailing bytes");
  if (options && json.digest !== undefined && json.digest !== bytesToHex(indexBlockDigest(bytes, options))) fail("digest");
  return decoded.block;
}

/** Answer of getsilentpaymenttweaks / getsilentpaymenttweaksrange (or REST
 *  JSON). Checks format and context. A reorganisation is reported as
 *  { reorg: true, forkHeight }: continue from forkHeight + 1. */
export function parseIndexResponse(json: any, options: ChainOptions):
  { type: "block"; block: IndexBlock; inActiveChain?: boolean } | ({ type: "range" } & IndexRange) | { type: "reorg"; forkHeight: number } {
  if (json?.reorg === true) return { type: "reorg", forkHeight: u32Field(json.fork_height, "fork_height") };
  if (json?.format !== INDEX_FORMAT) fail("format");
  if (json.context !== bytesToHex(getContext(options))) fail("context");
  if (json.block) {
    const result: { type: "block"; block: IndexBlock; inActiveChain?: boolean } = { type: "block", block: indexBlockFromJSON(json.block, options) };
    if (typeof json.in_active_chain === "boolean") result.inActiveChain = json.in_active_chain;
    return result;
  }
  if (!Array.isArray(json.blocks) || !RANGE_STATUS.includes(json.status)) {
    throw new SilentPaymentError("invalid argument", "not an index response");
  }
  if (!json.snapshot || typeof json.snapshot !== "object") throw new SilentPaymentError("invalid argument", "not an index response");
  internalHash(json.snapshot.hash, "snapshot hash");
  return {
    type: "range",
    snapshot: { height: u32Field(json.snapshot.height, "snapshot height"), hash: json.snapshot.hash },
    syncedHeight: u32Field(json.synced_height, "synced_height"),
    nextHeight: u32Field(json.next_height, "next_height"),
    status: json.status,
    blocks: json.blocks.map((b: any) => indexBlockFromJSON(b, options)),
  };
}

/** value_sat of the node's JSON: a canonical decimal string (the node never
 *  sends a number, which could not hold every amount exactly). */
function satoshiString(value: unknown): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(value)) {
    throw new SilentPaymentError("invalid argument", "value_sat must be a decimal string");
  }
  return BigInt(value);
}

// Below 2^26 XNA two amounts of 8 decimals are more than one double apart,
// so a JSON number still identifies its amount exactly; above, it may not.
const EXACT_NUMBER_LIMIT = 2 ** 26;

/** Amount of an output in satoshis, without guessing: valueSat (bigint, safe
 *  integer or decimal string), or value in XNA as a decimal string or as a
 *  number below 2^26 XNA. Larger numbers have lost precision when the JSON
 *  was parsed and are refused: parse the RPC answer losslessly instead. */
function satoshis(value: unknown, valueSat: unknown): bigint {
  if (valueSat !== undefined) {
    if (typeof valueSat === "bigint") return valueSat;
    if (typeof valueSat === "number" && Number.isSafeInteger(valueSat)) return BigInt(valueSat);
    if (typeof valueSat === "string" && /^[0-9]{1,19}$/.test(valueSat)) return BigInt(valueSat);
    throw new SilentPaymentError("invalid argument", "valueSat must be an integer amount");
  }
  let text: string | null = null;
  if (typeof value === "number") {
    if (!(value >= 0 && value < EXACT_NUMBER_LIMIT)) {
      throw new SilentPaymentError("invalid argument", "amount as a JSON number of 2^26 XNA or more is not exact; parse the RPC answer losslessly");
    }
    text = value.toFixed(8);
  } else if (typeof value === "string") {
    text = value;
  }
  const match = text === null ? null : /^([0-9]{1,11})(?:\.([0-9]{1,8}))?$/.exec(text);
  if (!match) throw new SilentPaymentError("invalid argument", "output without an exact amount");
  return BigInt(match[1]) * 100000000n + BigInt((match[2] ?? "").padEnd(8, "0"));
}

/** Index entry of one transaction, or null if it is not a candidate (not
 *  eligible, or without native v3 outputs). */
export function computeIndexEntry(tx: ScanTransaction, options: ChainOptions): IndexEntry | null {
  const outputs: IndexOutput[] = [];
  tx.outputs.forEach((output, n) => {
    const script = toBytes(output.script, `outputs[${n}].script`);
    if (isNativeV3Script(script)) outputs.push({ vout: n, commitment: script.slice(2), valueSat: satoshis(output.value, output.valueSat) });
  });
  if (outputs.length === 0) return null;
  const eligible = getEligibleInputs(tx);
  if (!eligible) return null;
  const sum = sumPoints(eligible.publicKeys);
  if (!sum) return null;
  const h = computeInputHash(getContext(options), eligible.outpoints, sum);
  const tweak = h ? mulPublicPoint(sum, h) : null;
  return tweak ? { txid: tx.txid, tweak, outputs } : null;
}

/** The record a node should serve for a `getblock <hash> 3` result: an
 *  independent recomputation to audit a server. */
export function computeIndexBlock(block: any, options: ChainOptions): IndexBlock {
  const txs = transactionsFromBlock(block);
  const entries: IndexEntry[] = [];
  const spent: { txid: string; vout: number }[] = [];
  for (const tx of txs) {
    if (tx.isCoinbase) continue;
    for (const input of tx.inputs) {
      if (input.prevoutScript !== null && input.prevoutScript !== undefined && isNativeV3Script(input.prevoutScript)) {
        spent.push({ txid: input.txid, vout: input.vout });
      }
    }
    const entry = computeIndexEntry(tx, options);
    if (entry) entries.push(entry);
  }
  return { height: block.height, hash: block.hash, prev: block.previousblockhash ?? ZERO_HASH, entries, spent };
}

/**
 * Payments to `keys` in index blocks (or bare entries): one ECDH b_scan*T per
 * entry, then the same derivation as scanTransaction, with the same results.
 */
export function scanTweaks(source: IndexBlock[] | IndexEntry[], keys: ScanKeys, options: ChainOptions): IndexPayment[] {
  const scanKey = toBytes(keys.scanPrivateKey, "scanPrivateKey", 32);
  const spendPublicKey = toBytes(keys.spendPublicKey, "spendPublicKey", 33);
  if (!isValidScalar(scanKey)) throw new SilentPaymentError("invalid private key");
  if (!isValidPoint(spendPublicKey)) throw new SilentPaymentError("point");
  const context = getContext(options);
  const found: IndexPayment[] = [];
  const scanEntry = (entry: IndexEntry, block?: IndexBlock) => {
    const candidates = new Map<string, number[]>();
    const values = new Map<number, bigint>();
    for (const output of entry.outputs) {
      const id = "5320" + bytesToHex(output.commitment);
      const vouts = candidates.get(id);
      if (vouts) vouts.push(output.vout);
      else candidates.set(id, [output.vout]);
      values.set(output.vout, BigInt(output.valueSat));
    }
    if (candidates.size === 0) return;
    const shared = ecdh(scanKey, toBytes(entry.tweak, "tweak", 33));
    try {
      const payments = matchCandidates(context, shared, spendPublicKey, candidates, options.network, entry.txid, (payment) => {
        const result: IndexPayment = { ...payment, valueSat: values.get(payment.vout) ?? 0n };
        if (block) {
          result.height = block.height;
          result.blockHash = block.hash;
        }
        return result;
      });
      for (const payment of payments) found.push(payment); // not push(...): may be many outputs
    } finally {
      wipe(shared);
    }
  };
  try {
    for (const item of source) {
      if ("entries" in item) {
        for (const entry of item.entries) scanEntry(entry, item);
      } else {
        scanEntry(item);
      }
    }
  } finally {
    wipe(scanKey);
  }
  return found;
}

/** Which of `payments` the blocks spend, from their spent lists: no query
 *  about a particular output reaches the server. */
export function trackSpends(blocks: IndexBlock[], payments: { txid: string; vout: number }[]): SpentPayment[] {
  const wanted = new Set(payments.map((p) => `${p.txid.toLowerCase()}:${p.vout}`));
  const spent: SpentPayment[] = [];
  for (const block of blocks) {
    for (const s of block.spent) {
      if (wanted.has(`${s.txid.toLowerCase()}:${s.vout}`)) spent.push({ txid: s.txid, vout: s.vout, height: block.height, blockHash: block.hash });
    }
  }
  return spent;
}
