// Light client index of the node (-silentpaymentindex): format 1 against the
// vectors shared with the node's C++ tests (test/vectors/
// silentpayment_index_vectors.json, a copy of Neurai's
// src/test/data/silentpayment_index_vectors.json), and scanning with tweaks
// against scanTransaction.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import * as SP from "../dist/index.js";

const vectors = JSON.parse(readFileSync(new URL("./vectors/silentpayment_index_vectors.json", import.meta.url), "utf8"));
// The vectors use network id 2 (regtest) with another genesis.
const chain = { network: "regtest", genesisHash: vectors.context.slice(2, 66) };
const regtest = { network: "regtest" };
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const toBlock = (b) => ({
  height: b.height,
  hash: b.hash,
  prev: b.prev,
  entries: b.entries.map((e) => ({
    txid: e.txid,
    tweak: SP.hexToBytes(e.tweak),
    outputs: e.outputs.map((o) => ({ vout: o.vout, commitment: SP.hexToBytes(o.commitment), valueSat: BigInt(o.value_sat) })),
  })),
  spent: b.spent,
});
const plain = (value) => JSON.parse(JSON.stringify(value, (_, v) => (v instanceof Uint8Array ? SP.bytesToHex(v) : typeof v === "bigint" ? v.toString() : v)));
const reason = (fn) => {
  try {
    fn();
  } catch (error) {
    return error instanceof SP.SilentPaymentError ? error.reason : `unexpected: ${error}`;
  }
  return "no error";
};

/** Deterministic bytes for the scanning comparison. */
let counter = 0;
const next = () => new Uint8Array(createHash("sha256").update(`index-tests/${counter++}`).digest());
const nextScalar = () => ((BigInt("0x" + SP.bytesToHex(next())) % (N - 1n)) + 1n).toString(16).padStart(64, "0");

/** An eligible transaction paying `recipients` from fresh keys. */
function paymentTx(recipients) {
  const privs = Array.from({ length: 1 + (next()[0] % 3) }, nextScalar);
  const outpoints = privs.map(() => ({ txid: SP.bytesToHex(next()), vout: next()[0] % 4 }));
  const outputs = SP.createOutputs(privs.map((privateKey, i) => ({ ...outpoints[i], privateKey })), recipients, regtest);
  const change = SP.paymentScript(SP.getPublicKey(nextScalar()));
  return {
    txid: SP.bytesToHex(next()),
    version: 2,
    inputs: privs.map((priv, i) => {
      const pub = SP.getPublicKey(priv);
      return { ...outpoints[i], witness: ["02", "30" + "44".repeat(70) + "01", SP.bytesToHex(pub), "51"], prevoutScript: SP.paymentScript(pub) };
    }),
    outputs: [...outputs.map((o) => ({ script: o.script, valueSat: BigInt(Math.round(o.amount * 1e8)) })), { script: change, valueSat: 7n }],
  };
}

describe("index format: vectors shared with the node", () => {
  it("the context of the vectors", () => {
    expect(SP.bytesToHex(SP.getContext(chain))).toBe(vectors.context);
  });

  it("encodes, decodes and digests every block as the node does", () => {
    for (const v of vectors.blocks) {
      const block = toBlock(v.block);
      const bytes = SP.encodeIndexBlock(block);
      expect(SP.bytesToHex(bytes), v.description).toBe(v.bytes);
      const { block: decoded, offset } = SP.decodeIndexBlock(bytes);
      expect(offset).toBe(bytes.length);
      expect(plain(decoded)).toEqual(plain(block));
      expect(SP.bytesToHex(SP.indexBlockDigest(bytes, chain))).toBe(v.digest);
      expect(SP.bytesToHex(SP.indexBlockDigest(decoded, chain))).toBe(v.digest);
    }
  });

  it("decodes the block and range messages", () => {
    const one = SP.decodeIndexMessage(vectors.messages.block.hex, chain);
    expect(one.type).toBe("block");
    expect(SP.bytesToHex(SP.encodeIndexBlock(one.block))).toBe(vectors.blocks[vectors.messages.block.block_index].bytes);

    const range = SP.decodeIndexMessage(vectors.messages.range.hex, chain);
    const h = vectors.messages.range.header;
    expect(range.type).toBe("range");
    expect(range.snapshot).toEqual({ height: h.snapshot_height, hash: h.snapshot_hash });
    expect([range.syncedHeight, range.nextHeight, range.status]).toEqual([h.synced_height, h.next_height, "more"]);
    expect(range.blocks.map((b) => SP.bytesToHex(SP.encodeIndexBlock(b)))).toEqual(vectors.messages.range.block_indexes.map((i) => vectors.blocks[i].bytes));
  });

  it("refuses messages of another chain, format or shape", () => {
    const hex = vectors.messages.block.hex;
    expect(reason(() => SP.decodeIndexMessage(hex, regtest))).toBe("context");
    expect(reason(() => SP.decodeIndexMessage(hex + "00", chain))).toBe("trailing bytes");
    expect(reason(() => SP.decodeIndexMessage("4e535055" + hex.slice(8), chain))).toBe("magic");
    expect(reason(() => SP.decodeIndexMessage(hex.slice(0, 8) + "02" + hex.slice(10), chain))).toBe("format");
    expect(reason(() => SP.decodeIndexMessage(hex.slice(0, 10) + "07" + hex.slice(12), chain))).toBe("message type");
    expect(reason(() => SP.decodeIndexMessage(hex.slice(0, -2), chain))).toBe("truncated");
  });

  it("rejects the invalid vectors with the node's reasons", () => {
    for (const v of vectors.invalid) {
      if (v.error === "trailing bytes") {
        const { offset } = SP.decodeIndexBlock(v.bytes);
        expect(offset, v.description).toBe(v.bytes.length / 2 - 1);
      } else {
        expect(reason(() => SP.decodeIndexBlock(v.bytes)), v.description).toBe(v.error);
      }
    }
  });

  it("decodes a range of 1000 blocks", () => {
    const blocks = Array.from({ length: 1000 }, (_, i) => ({ ...toBlock(vectors.blocks[1].block), height: i + 1 }));
    const header = SP.hexToBytes(vectors.messages.range.hex.slice(0, (41 + 4 + 32 + 4 + 4 + 1) * 2));
    const count = Uint8Array.of(0xfd, 1000 & 0xff, 1000 >> 8);
    const body = blocks.map((b) => SP.encodeIndexBlock(b));
    const message = new Uint8Array(header.length + count.length + body.reduce((n, b) => n + b.length, 0));
    let at = 0;
    for (const part of [header, count, ...body]) {
      message.set(part, at);
      at += part.length;
    }
    const start = Date.now();
    const range = SP.decodeIndexMessage(message, chain);
    expect(range.blocks.length).toBe(1000);
    expect(range.blocks[999].height).toBe(1000);
    expect(Date.now() - start).toBeLessThan(5000);
  });

  it("every truncation of a block is rejected", () => {
    const full = SP.hexToBytes(vectors.blocks[1].bytes);
    for (let size = 0; size < full.length; size++) {
      expect(reason(() => SP.decodeIndexBlock(full.slice(0, size)))).not.toBe("no error");
    }
  });
});

describe("hostile or extreme input", () => {
  const A = SP.deriveKeysFromSeed(next(), "regtest");

  it("handles a block with 45000 outputs paying the same key", () => {
    // About what a full block of native v3 outputs holds. All repeat the
    // output of k = 0, so all of them are payments.
    const tx = paymentTx([{ code: A.code, amount: 1 }]);
    const entry = SP.computeIndexEntry(tx, regtest);
    const paid = entry.outputs.find((o) => SP.scanTweaks([{ ...entry, outputs: [o] }], A, regtest).length === 1);
    const outputs = Array.from({ length: 45000 }, (_, vout) => ({ vout, commitment: paid.commitment, valueSat: 1n }));
    const block = { height: 5, hash: "ab".repeat(32), prev: "cd".repeat(32), entries: [{ ...entry, outputs }], spent: [] };
    const bytes = SP.encodeIndexBlock(block);
    expect(SP.decodeIndexBlock(bytes).block.entries[0].outputs.length).toBe(45000);
    const json = JSON.parse(JSON.stringify(plain(block)).replaceAll('"valueSat"', '"value_sat"'));
    expect(SP.indexBlockFromJSON(json).entries[0].outputs.length).toBe(45000);
    const found = SP.scanTweaks([block], A, regtest);
    expect(found.length).toBe(45000);
    expect(found.every((p) => p.k === 0)).toBe(true);
  });

  it("never guesses an amount a JSON number cannot hold", () => {
    const tx = paymentTx([{ code: A.code, amount: 1 }]);
    const withValue = (value) => ({ ...tx, outputs: tx.outputs.map((o, n) => (n === 0 ? { script: o.script, value } : o)) });
    const sats = (value) => SP.computeIndexEntry(withValue(value), regtest).outputs.find((o) => o.vout === 0).valueSat;
    // 9007199254740993 satoshis: JSON.parse gives a different double.
    expect(reason(() => sats(JSON.parse("90071992.54740993")))).toBe("invalid argument");
    expect(reason(() => sats(2 ** 26))).toBe("invalid argument");
    expect(sats("90071992.54740993")).toBe(9007199254740993n);
    expect(reason(() => sats("1e-8"))).toBe("invalid argument");
    // Below 2^26 XNA a parsed number still names one amount: compare with the
    // exact decimal on many cases, the edges included.
    const texts = ["0.00000001", "67108863.99999999", "67108863.99999998", "33554431.99999999", "12345678.12345678"];
    for (let i = 0; i < 2000; i++) {
      const sat = BigInt("0x" + SP.bytesToHex(next()).slice(0, 16)) % (2n ** 26n * 100000000n);
      texts.push(`${sat / 100000000n}.${(sat % 100000000n).toString().padStart(8, "0")}`);
    }
    // One transaction with an output per case: one curve computation in all.
    const many = { ...tx, outputs: [...tx.outputs, ...texts.map((text) => ({ script: tx.outputs[0].script, value: JSON.parse(text) }))] };
    const got = SP.computeIndexEntry(many, regtest).outputs.slice(tx.outputs.length).map((o) => o.valueSat);
    expect(got).toEqual(texts.map((text) => {
      const [int, frac] = text.split(".");
      return BigInt(int) * 100000000n + BigInt(frac.padEnd(8, "0"));
    }));
  });

  it("range-checks the node's JSON before encoding it", () => {
    const base = { ...vectors.blocks[2].block };
    const withOutput = (patch) => ({ ...base, entries: [{ ...base.entries[0], outputs: [{ ...base.entries[0].outputs[0], ...patch }] }] });
    expect(plain(SP.indexBlockFromJSON(base))).toEqual(plain(toBlock(base)));
    for (const value of ["18446744073709551617", "0x10", " 1", "1.0", "-1", "", 1]) {
      expect(reason(() => SP.indexBlockFromJSON(withOutput({ value_sat: value }))), String(value)).toBe("invalid argument");
    }
    for (const value of ["9223372036854775808", "2100000000000000001"]) {
      expect(reason(() => SP.indexBlockFromJSON(withOutput({ value_sat: value }))), value).toBe("amount out of range");
    }
    expect(SP.indexBlockFromJSON(withOutput({ value_sat: "2100000000000000000" })).entries[0].outputs[0].valueSat).toBe(2100000000000000000n);
    for (const vout of [2 ** 32, -1, 1.5, "1"]) {
      expect(reason(() => SP.indexBlockFromJSON(withOutput({ vout }))), String(vout)).toBe("invalid argument");
      expect(reason(() => SP.indexBlockFromJSON({ ...base, spent: [{ txid: "11".repeat(32), vout }] })), String(vout)).toBe("invalid argument");
    }
    for (const height of [2 ** 32, -1, 0.5, "5", undefined]) {
      expect(reason(() => SP.indexBlockFromJSON({ ...base, height })), String(height)).toBe("invalid argument");
    }
    expect(reason(() => SP.indexBlockFromJSON({ ...base, entries: [{ ...base.entries[0], outputs: null }] }))).toBe("invalid argument");
    expect(reason(() => SP.encodeIndexBlock({ ...toBlock(base), entries: [{ ...toBlock(base).entries[0], outputs: [{ vout: 0, commitment: new Uint8Array(32), valueSat: 1 }] }] })))
      .toBe("invalid argument");
    expect(reason(() => SP.parseIndexResponse({ format: 1, context: vectors.context, snapshot: { height: -1, hash: "aa".repeat(32) }, synced_height: 0,
      blocks: [], next_height: 1, status: "tip" }, chain))).toBe("invalid argument");
  });
});

describe("scanning with tweaks", () => {
  const A = SP.deriveKeysFromSeed(next(), "regtest");
  const B = SP.deriveKeysFromSeed(next(), "regtest");

  it("finds exactly what scanTransaction finds", () => {
    for (let round = 0; round < 40; round++) {
      const recipients = [{ code: A.code, amount: 1 }, { code: B.code, amount: 2 }, { code: A.code, amount: 0.5 }];
      const tx = paymentTx(recipients.slice(0, 1 + (round % 3)));
      const entry = SP.computeIndexEntry(tx, regtest);
      expect(entry.outputs.length).toBe(tx.outputs.length); // every native v3 output, change included
      for (const keys of [A, B, SP.importViewKey(SP.exportViewKey(A))]) {
        const viaTx = SP.scanTransaction(tx, keys, regtest);
        const viaIndex = SP.scanTweaks([entry], keys, regtest);
        expect(viaIndex.map((p) => [p.vout, p.k, SP.bytesToHex(p.tweak), SP.bytesToHex(p.publicKey), p.address]))
          .toEqual(viaTx.map((p) => [p.vout, p.k, SP.bytesToHex(p.tweak), SP.bytesToHex(p.publicKey), p.address]));
        expect(viaIndex.map((p) => p.valueSat)).toEqual(viaTx.map((p) => p.valueSat));
      }
    }
  });

  it("not every transaction is a candidate", () => {
    const tx = paymentTx([{ code: A.code, amount: 1 }]);
    expect(SP.computeIndexEntry({ ...tx, version: 1 }, regtest)).toBeNull();
    expect(SP.computeIndexEntry({ ...tx, outputs: [{ script: "76a914" + "00".repeat(20) + "88ac", valueSat: 1n }] }, regtest)).toBeNull();
    const v1 = { ...tx, inputs: tx.inputs.map((i) => ({ ...i, prevoutScript: "5120" + "00".repeat(32) })) };
    expect(SP.computeIndexEntry(v1, regtest)).toBeNull();
  });

  it("reports the block of each payment and its later spend", () => {
    const tx = paymentTx([{ code: A.code, amount: 1 }, { code: A.code, amount: 2 }]);
    const block = { height: 77, hash: "ab".repeat(32), prev: "cd".repeat(32), entries: [SP.computeIndexEntry(tx, regtest)], spent: [] };
    const found = SP.scanTweaks([block], A, regtest);
    expect(found.map((p) => [p.k, p.height, p.blockHash])).toEqual([[0, 77, block.hash], [1, 77, block.hash]]);
    const later = { height: 90, hash: "ef".repeat(32), prev: "01".repeat(32), entries: [], spent: [{ txid: tx.txid, vout: found[1].vout }, { txid: "22".repeat(32), vout: 0 }] };
    expect(SP.trackSpends([block, later], found)).toEqual([{ txid: tx.txid, vout: found[1].vout, height: 90, blockHash: later.hash }]);
  });

  it("reads the node's JSON and checks its digest", () => {
    const v = vectors.blocks[1];
    const json = { ...v.block, digest: v.digest };
    expect(plain(SP.indexBlockFromJSON(json, chain))).toEqual(plain(toBlock(v.block)));
    expect(reason(() => SP.indexBlockFromJSON({ ...json, digest: "00".repeat(32) }, chain))).toBe("digest");
    const unordered = JSON.parse(JSON.stringify(json));
    unordered.entries[0].outputs.reverse();
    expect(reason(() => SP.indexBlockFromJSON(unordered, chain))).toBe("outputs out of order");

    const response = { format: 1, context: vectors.context, block: json, in_active_chain: true };
    expect(SP.parseIndexResponse(response, chain).inActiveChain).toBe(true);
    expect(reason(() => SP.parseIndexResponse(response, regtest))).toBe("context");
    expect(reason(() => SP.parseIndexResponse({ ...response, format: 2 }, chain))).toBe("format");
    expect(SP.parseIndexResponse({ reorg: true, fork_height: 41, snapshot: {} }, chain)).toEqual({ type: "reorg", forkHeight: 41 });
    const range = SP.parseIndexResponse({ format: 1, context: vectors.context, snapshot: { height: 9, hash: "aa".repeat(32) }, synced_height: 9,
      blocks: [json], next_height: 70124, status: "tip" }, chain);
    expect([range.type, range.status, range.blocks.length]).toEqual(["range", "tip", 1]);
  });
});
