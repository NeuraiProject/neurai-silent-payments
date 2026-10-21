import { readFileSync } from "node:fs";

import { bech32m } from "@scure/base";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import NeuraiKey from "@neuraiproject/neurai-key";
import { describe, expect, it } from "vitest";

import SP, {
  bytesToHex,
  checkCode,
  computeInputHash,
  createOutputs,
  decodeCode,
  decodeWIF,
  deriveKeysFromMnemonic,
  deriveKeysFromSeed,
  encodeCode,
  encodeWIF,
  exportViewKey,
  getContext,
  getEligibleInputs,
  hexToBytes,
  importViewKey,
  NETWORKS,
  paymentAddress,
  paymentPrivateKey,
  paymentPrivateKeyWIF,
  paymentScript,
  scanTransaction,
  serializeOutpoint,
  SilentPaymentError,
  transactionsFromBlock,
} from "../dist/index.js";

const lab = JSON.parse(readFileSync(new URL("./vectors/lab-nip047.json", import.meta.url), "utf8"));
const R = deriveKeysFromMnemonic(lab.identity.mnemonic, lab.identity.passphrase, "regtest");
const regtest = { network: "regtest" };

/** Serialized outpoint (internal txid order + LE32 vout) -> { txid, vout }. */
function outpointFromHex(hex) {
  const bytes = hexToBytes(hex);
  const vout = bytes[32] | (bytes[33] << 8) | (bytes[34] << 16) | (bytes[35] << 24);
  return { txid: bytesToHex(bytes.slice(0, 32).reverse()), vout: vout >>> 0 };
}

const pub = (priv) => secp256k1.getPublicKey(hexToBytes(priv), true);

/** An eligible transaction spending strict v3 outputs of `privs`. */
function eligibleTx(privs, outpoints, outputScripts, txid = "11".repeat(32)) {
  return {
    txid,
    version: 2,
    inputs: privs.map((priv, i) => ({
      ...outpoints[i],
      witness: ["02", "30" + "44".repeat(70) + "01", bytesToHex(pub(priv)), "51"],
      prevoutScript: paymentScript(pub(priv)),
    })),
    outputs: outputScripts.map((script, n) => ({ script, value: n + 1 })),
  };
}

const randomKey = (i) => bytesToHex(secp256k1.utils.randomSecretKey(new Uint8Array(48).fill(i + 1)));

describe("lab vectors (NIP-047, checked against the node)", () => {
  it("derives the lab identity and context", () => {
    const v = lab.vectors[0];
    expect(R.code).toBe(v.code);
    expect(bytesToHex(R.scanPublicKey)).toBe(v.B_scan);
    expect(bytesToHex(R.spendPublicKey)).toBe(v.B_spend);
    expect(bytesToHex(getContext(regtest))).toBe(v.context_N);
  });

  for (const v of lab.vectors) {
    it(`sender reproduces ${v.scenario}`, () => {
      const outpoints = v.outpoints.map(outpointFromHex);
      const inputs = v.input_privs_fixture.map((privateKey, i) => ({ ...outpoints[i], privateKey }));
      const payments = v.groups[0].payments;
      const outputs = createOutputs(inputs, payments.map(() => ({ code: v.code })), regtest);
      expect(outputs.map((o) => o.k)).toEqual(payments.map((p) => p.k));
      expect(outputs.map((o) => bytesToHex(o.publicKey))).toEqual(payments.map((p) => p.P));
      expect(outputs.map((o) => bytesToHex(o.script))).toEqual(payments.map((p) => p.spk));
      expect(outputs.map((o) => o.address)).toEqual(v.addresses);
      const A = secp256k1.Point.fromBytes(pub(v.input_privs_fixture[0]));
      const sum = v.input_privs_fixture.slice(1).reduce((acc, p) => acc.add(secp256k1.Point.fromBytes(pub(p))), A).toBytes(true);
      expect(bytesToHex(sum)).toBe(v.A);
      expect(bytesToHex(computeInputHash(getContext(regtest), v.outpoints.map(hexToBytes), sum))).toBe(v.h);
    });

    it(`receiver finds ${v.scenario} and d_k opens it`, () => {
      const outpoints = v.outpoints.map(outpointFromHex);
      const payments = v.groups[0].payments;
      const tx = eligibleTx(v.input_privs_fixture, outpoints, ["0014" + "00".repeat(20), ...payments.map((p) => p.spk)]);
      const found = scanTransaction(tx, R, regtest);
      expect(found.map((f) => [f.vout, f.k, bytesToHex(f.tweak), bytesToHex(f.publicKey)])).toEqual(
        payments.map((p, i) => [i + 1, p.k, p.t, p.P]),
      );
      for (const f of found) {
        expect(bytesToHex(secp256k1.getPublicKey(paymentPrivateKey(R.spendPrivateKey, f.tweak), true))).toBe(bytesToHex(f.publicKey));
      }
      // A view-only identity finds the same payments.
      const view = importViewKey(exportViewKey(R));
      expect(scanTransaction(tx, view, regtest).map((f) => f.vout)).toEqual(found.map((f) => f.vout));
    });
  }
});

describe("payment codes", () => {
  it("round-trips on every network", () => {
    for (const network of ["main", "test", "regtest"]) {
      const keys = deriveKeysFromMnemonic(lab.identity.mnemonic, "", network);
      expect(keys.code.startsWith(NETWORKS[network].codeHrp + "1")).toBe(true);
      expect(keys.code.length).toBe(network === "main" ? 119 : 120);
      const decoded = decodeCode(keys.code, network);
      expect(bytesToHex(decoded.scanPublicKey)).toBe(bytesToHex(keys.scanPublicKey));
      expect(encodeCode(decoded)).toBe(keys.code);
      expect(decodeCode(keys.code.toUpperCase(), network).network).toBe(network);
    }
  });

  const encode = (hrp, data) => bech32m.encode(hrp, data, 200);
  const payload = (id, scan, spend) => Uint8Array.from([id, ...scan, ...spend]);
  const valid = decodeCode(R.code, "regtest");
  const wordsOf = (bytes) => [0, ...bech32m.toWords(bytes)];

  const cases = [
    ["length", "tnsp1qq"],
    ["charset", R.code.slice(0, 20) + " " + R.code.slice(21)],
    ["charset", R.code.slice(0, 20) + "é" + R.code.slice(21)],
    ["mixed case", R.code.slice(0, 20) + R.code[20].toUpperCase() + R.code.slice(21)],
    ["separator", "tnspqqqqqqqqqqqqqqqq"],
    ["separator", "tnsp1qqqqq"],
    ["charset", "tnsp1qqqqqqqbqqq"],
    ["checksum", R.code.slice(0, -1) + (R.code.endsWith("q") ? "p" : "q")],
    ["hrp", encode("nq", wordsOf(payload(2, valid.scanPublicKey, valid.spendPublicKey)))],
    ["version", encode("tnsp", [1, ...bech32m.toWords(payload(2, valid.scanPublicKey, valid.spendPublicKey))])],
    ["padding", encode("tnsp", [0, ...bech32m.toWords(payload(2, valid.scanPublicKey, valid.spendPublicKey)).slice(0, -1), 1])],
    ["payload length", encode("tnsp", wordsOf(payload(2, valid.scanPublicKey, valid.spendPublicKey).slice(0, 66)))],
    ["hrp/network_id", encode("nsp", wordsOf(payload(1, valid.scanPublicKey, valid.spendPublicKey)))],
    ["hrp/network_id", encode("tnsp", wordsOf(payload(3, valid.scanPublicKey, valid.spendPublicKey)))],
    ["network", encode("tnsp", wordsOf(payload(1, valid.scanPublicKey, valid.spendPublicKey)))],
    ["point", encode("tnsp", wordsOf(payload(2, Uint8Array.from([2, ...new Array(32).fill(0xff)]), valid.spendPublicKey)))],
    ["point", encode("tnsp", wordsOf(payload(2, Uint8Array.from([4, ...valid.scanPublicKey.slice(1)]), valid.spendPublicKey)))],
    ["scan equals +-spend", encode("tnsp", wordsOf(payload(2, valid.scanPublicKey, Uint8Array.from([valid.scanPublicKey[0] ^ 1, ...valid.scanPublicKey.slice(1)]))))],
  ];
  for (const [reason, text] of cases) {
    it(`rejects with "${reason}": ${text.slice(0, 24)}…`, () => {
      expect(checkCode(text, "regtest")).toEqual({ valid: false, reason });
      expect(() => decodeCode(text, "regtest")).toThrowError(SilentPaymentError);
    });
  }
});

describe("sender rules", () => {
  const inputs = [{ txid: "aa".repeat(32), vout: 0, privateKey: randomKey(1) }];

  it("follows the recipients order and counts k per scan key", () => {
    const other = deriveKeysFromMnemonic(lab.identity.mnemonic, "other", "regtest");
    const outputs = createOutputs(inputs, [{ code: R.code, amount: 5n }, { code: other.code }, { code: R.code, amount: 7n }], regtest);
    expect(outputs.map((o) => [o.code, o.k, o.amount])).toEqual([[R.code, 0, 5n], [other.code, 0, undefined], [R.code, 1, 7n]]);
  });

  it("refuses more than 16 payments to one code", () => {
    expect(createOutputs(inputs, Array(16).fill({ code: R.code }), regtest)).toHaveLength(16);
    expect(() => createOutputs(inputs, Array(17).fill({ code: R.code }), regtest)).toThrow("more than 16 payments to one code");
  });

  it("refuses codes sharing a scan key with different spend keys", () => {
    const fake = encodeCode({ network: "regtest", scanPublicKey: R.scanPublicKey, spendPublicKey: pub(randomKey(9)) });
    expect(() => createOutputs(inputs, [{ code: R.code }, { code: fake }], regtest)).toThrow("codes with the same scan key and different spend keys");
  });

  it("refuses keys that cancel out, other networks and ineligible inputs", () => {
    const a = BigInt("0x" + randomKey(2));
    const negA = (secp256k1.Point.Fn.ORDER - a).toString(16).padStart(64, "0");
    const cancel = [{ txid: "aa".repeat(32), vout: 0, privateKey: a.toString(16).padStart(64, "0") }, { txid: "bb".repeat(32), vout: 1, privateKey: negA }];
    expect(() => createOutputs(cancel, [{ code: R.code }], regtest)).toThrow("input keys sum to zero");
    expect(() => createOutputs(inputs, [{ code: R.code }], { network: "test" })).toThrow(/network/);
    expect(() => createOutputs([{ ...inputs[0], script: paymentScript(pub(randomKey(3))) }], [{ code: R.code }], regtest)).toThrow(SilentPaymentError);
    expect(() => createOutputs(inputs, [], regtest)).toThrow("no recipients");
  });

  it("refuses mainnet until strict v3 outputs are active there", () => {
    const main = deriveKeysFromMnemonic(lab.identity.mnemonic, "", "main");
    expect(() => createOutputs(inputs, [{ code: main.code }], { network: "main" })).toThrow(/not active on mainnet/);
    expect(createOutputs(inputs, [{ code: main.code }], { network: "main", mainnetActive: true })[0].address.startsWith("nq1r")).toBe(true);
  });

  it("is deterministic", () => {
    const first = createOutputs(inputs, [{ code: R.code }, { code: R.code }], regtest).map((o) => bytesToHex(o.script));
    for (let i = 0; i < 50; i++) {
      expect(createOutputs(inputs, [{ code: R.code }, { code: R.code }], regtest).map((o) => bytesToHex(o.script))).toEqual(first);
    }
  });
});

describe("receiver rules", () => {
  const privs = [randomKey(4), randomKey(5)];
  const outpoints = [{ txid: "cc".repeat(32), vout: 3 }, { txid: "dd".repeat(32), vout: 0 }];
  const outputs = createOutputs(privs.map((privateKey, i) => ({ ...outpoints[i], privateKey })), [{ code: R.code }, { code: R.code }], regtest);
  const base = () => eligibleTx(privs, outpoints, outputs.map((o) => o.script));

  it("finds the payments of an eligible transaction", () => {
    expect(scanTransaction(base(), R, regtest).map((f) => [f.vout, f.k, f.value])).toEqual([[0, 0, 1], [1, 1, 2]]);
    expect(getEligibleInputs(base()).publicKeys).toHaveLength(2);
  });

  const mutations = {
    "version 1": (tx) => { tx.version = 1; },
    "coinbase": (tx) => { tx.isCoinbase = true; },
    "no prevout script": (tx) => { tx.inputs[1].prevoutScript = null; },
    "prevout not v3": (tx) => { tx.inputs[0].prevoutScript = "0014" + "11".repeat(20); },
    "prevout of another key": (tx) => { tx.inputs[1].prevoutScript = paymentScript(pub(randomKey(7))); },
    "auth type": (tx) => { tx.inputs[0].witness[0] = "03"; },
    "template": (tx) => { tx.inputs[0].witness[3] = "52"; },
    "witness size": (tx) => { tx.inputs[1].witness.push("00"); },
    "uncompressed key": (tx) => { tx.inputs[0].witness[2] = "04" + "11".repeat(64); },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    it(`ignores a transaction with ${name}`, () => {
      const tx = base();
      mutate(tx);
      expect(getEligibleInputs(tx)).toBeNull();
      expect(scanTransaction(tx, R, regtest)).toEqual([]);
    });
  }

  it("stops at the first missing k and ignores other identities", () => {
    const tx = base();
    tx.outputs = [tx.outputs[1]]; // only k = 1
    expect(scanTransaction(tx, R, regtest)).toEqual([]);
    const other = deriveKeysFromMnemonic(lab.identity.mnemonic, "other", "regtest");
    expect(scanTransaction(base(), other, regtest)).toEqual([]);
  });

  it("reads getblock verbosity 3", () => {
    const tx = base();
    const block = {
      tx: [
        { txid: "ee".repeat(32), version: 2, vin: [{ coinbase: "51" }], vout: [{ value: 50, scriptPubKey: { hex: bytesToHex(outputs[0].script) } }] },
        {
          txid: tx.txid,
          version: 2,
          vin: tx.inputs.map((i) => ({ txid: i.txid, vout: i.vout, txinwitness: i.witness, prevout: { scriptPubKey: { hex: bytesToHex(i.prevoutScript) } } })),
          vout: tx.outputs.map((o, n) => ({ value: o.value, valueSat: (n + 1) * 1e8, scriptPubKey: { hex: bytesToHex(o.script) } })),
        },
      ],
    };
    const txs = transactionsFromBlock(block);
    expect(txs[0].isCoinbase).toBe(true);
    expect(scanTransaction(txs[0], R, regtest)).toEqual([]);
    expect(scanTransaction(txs[1], R, regtest).map((f) => [f.vout, f.valueSat])).toEqual([[0, 1e8], [1, 2e8]]);
  });
});

describe("keys", () => {
  it("matches neurai-key derivation and v3 addresses", () => {
    for (const [network, nkNetwork, coin, id] of [["main", "xna", 1900, 0], ["test", "xna-test", 1, 1], ["regtest", "xna-test", 1, 2]]) {
      const keys = deriveKeysFromMnemonic(lab.identity.mnemonic, lab.identity.passphrase, network);
      const hd = NeuraiKey.getHDKey(nkNetwork, lab.identity.mnemonic, lab.identity.passphrase);
      expect(bytesToHex(hd.derive(`m/352'/${coin}'/${id}'/0'/0'/0'`).privateKey)).toBe(bytesToHex(keys.spendPrivateKey));
      expect(bytesToHex(hd.derive(`m/352'/${coin}'/${id}'/0'/1'/0'`).privateKey)).toBe(bytesToHex(keys.scanPrivateKey));
      expect(paymentAddress(keys.spendPublicKey, network)).toBe(NeuraiKey.publicKeyToAddress(nkNetwork, bytesToHex(keys.spendPublicKey)));
    }
  });

  it("derives from a seed like from its mnemonic", () => {
    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    expect(deriveKeysFromSeed(seed, "test").code).toBe(deriveKeysFromSeed(bytesToHex(seed), "test").code);
    expect(() => deriveKeysFromSeed(seed.slice(0, 31), "test")).toThrow(SilentPaymentError);
  });

  it("exports and imports view keys with the node's rules", () => {
    const view = exportViewKey(R);
    expect(view).toEqual({ scan_private_key: bytesToHex(R.scanPrivateKey), spend_pubkey: bytesToHex(R.spendPublicKey), network: "regtest" });
    expect(importViewKey(view).code).toBe(R.code);
    const mirrored = { ...view, spend_pubkey: bytesToHex(R.scanPublicKey) };
    expect(() => importViewKey(mirrored)).toThrow("scan equals +-spend");
  });

  it("encodes WIFs as dumpprivkey does", () => {
    const wif = encodeWIF(R.spendPrivateKey, "regtest");
    expect(wif.startsWith("c")).toBe(true);
    expect(bytesToHex(decodeWIF(wif, "regtest"))).toBe(bytesToHex(R.spendPrivateKey));
    expect(() => decodeWIF(wif, "main")).toThrow(/network/);
    expect(paymentPrivateKeyWIF(R.spendPrivateKey, "01".repeat(32), "test").length).toBe(52);
  });

  it("serializes outpoints like the node", () => {
    expect(bytesToHex(serializeOutpoint({ txid: "00".repeat(31) + "01", vout: 258 }))).toBe("01" + "00".repeat(31) + "02010000");
  });

  it("exposes the same functions on the default export", () => {
    expect(SP.createOutputs).toBe(createOutputs);
    expect(SP.scanTransaction).toBe(scanTransaction);
  });
});
