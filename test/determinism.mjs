// Determinism check: derives a large, fixed set of cases from a seeded
// stream, checks that sender and receiver agree on every one, and prints a
// SHA-256 digest of all results. The digest must be the same on every run,
// Node.js version and platform. index_digest covers the light client index
// entries (tweaks) of the same cases, kept apart so `digest` stays comparable
// with earlier runs.
//
//   node test/determinism.mjs [cases]

import { createHash } from "node:crypto";

import * as SP from "../dist/index.js";

const SEED = "neurai-silent-payments/determinism/v1";
const CASES = Number(process.argv[2] ?? 200);
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

let counter = 0;
/** 32 deterministic bytes per call (SHA-256 of seed and counter). */
function next() {
  return new Uint8Array(createHash("sha256").update(`${SEED}/${counter++}`).digest());
}
const nextInt = (max) => Number(BigInt("0x" + SP.bytesToHex(next())) % BigInt(max));
function nextScalar() {
  const value = (BigInt("0x" + SP.bytesToHex(next())) % (N - 1n)) + 1n;
  return value.toString(16).padStart(64, "0");
}

const hex = SP.bytesToHex;
const failures = [];
const check = (ok, what) => { if (!ok) failures.push(what); };
const results = { identities: [], sends: [], codes: [] };
const index = [];
const networks = ["main", "test", "regtest"];
const options = (network) => ({ network, mainnetActive: true });

// Identities from fixed seeds on every network.
const identities = [];
for (let i = 0; i < 12; i++) {
  const seed = new Uint8Array([...next(), ...next()]);
  for (const network of networks) {
    const keys = SP.deriveKeysFromSeed(seed, network);
    identities.push(keys);
    results.identities.push([network, keys.code, SP.exportViewKey(keys).scan_private_key]);
  }
}

// Sender cases, each scanned back by every recipient identity.
for (let c = 0; c < CASES; c++) {
  const network = networks[nextInt(3)];
  const pool = identities.filter((k) => k.network === network);
  const privs = Array.from({ length: 1 + nextInt(4) }, nextScalar);
  const outpoints = privs.map(() => ({ txid: hex(next()), vout: nextInt(5) }));
  const recipients = Array.from({ length: 1 + nextInt(5) }, () => ({ code: pool[nextInt(pool.length)].code, amount: nextInt(1e8) }));
  const outputs = SP.createOutputs(privs.map((privateKey, i) => ({ ...outpoints[i], privateKey })), recipients, options(network));
  results.sends.push([network, outputs.map((o) => [o.code, o.k, hex(o.script), o.address, o.amount])]);

  const tx = {
    txid: hex(next()),
    version: 2,
    inputs: privs.map((priv, i) => {
      const pub = SP.getPublicKey(priv);
      return { ...outpoints[i], witness: ["02", "30" + "44".repeat(70) + "01", hex(pub), "51"], prevoutScript: SP.paymentScript(pub) };
    }),
    // valueSat: amounts up to 1e8 XNA, beyond what a JSON number holds exactly in general.
    outputs: outputs.map((o) => ({ script: o.script, value: o.amount, valueSat: BigInt(o.amount) * 100000000n })),
  };
  const entry = SP.computeIndexEntry(tx, options(network));
  index.push([network, hex(entry.tweak), entry.outputs.map((o) => [o.vout, hex(o.commitment), o.valueSat.toString()])]);
  for (const keys of new Set(recipients.map((r) => pool.find((k) => k.code === r.code)))) {
    const found = SP.scanTransaction(tx, keys, options(network));
    const viaIndex = SP.scanTweaks([entry], keys, options(network));
    check(JSON.stringify(viaIndex.map((f) => [f.vout, f.k, hex(f.tweak)])) === JSON.stringify(found.map((f) => [f.vout, f.k, hex(f.tweak)])),
      `case ${c}: scanTweaks of ${keys.code.slice(0, 12)}`);
    const expected = outputs.map((o, n) => [o.code, n, o.k]).filter(([code]) => code === keys.code).map(([, n, k]) => [n, k]);
    check(JSON.stringify(found.map((f) => [f.vout, f.k])) === JSON.stringify(expected), `case ${c}: scan of ${keys.code.slice(0, 12)}`);
    for (const f of found) {
      const d = SP.paymentPrivateKey(keys.spendPrivateKey, f.tweak);
      check(hex(SP.getPublicKey(d)) === hex(f.publicKey), `case ${c}: d_k of vout ${f.vout}`);
    }
  }
}

// Code mutations: the decoder's verdict is part of the digest.
for (let c = 0; c < CASES * 2; c++) {
  const keys = identities[nextInt(identities.length)];
  let text = keys.code;
  const kind = nextInt(5);
  const pos = nextInt(text.length);
  if (kind === 0) text = text.slice(0, pos) + "qpzry9x8gf2tvdw0s3jn54khce6mua7l"[nextInt(32)] + text.slice(pos + 1);
  else if (kind === 1) text = text.slice(0, pos) + text.slice(pos).toUpperCase();
  else if (kind === 2) text = text.slice(0, pos);
  else if (kind === 3) text = text.slice(0, pos) + text[(pos + 1) % text.length] + text[pos] + text.slice(pos + 2);
  const network = networks[nextInt(3)];
  const verdict = SP.checkCode(text, network);
  results.codes.push([text, network, verdict.valid ? "valid" : verdict.reason]);
}

const digest = createHash("sha256").update(JSON.stringify(results)).digest("hex");
const indexDigest = createHash("sha256").update(JSON.stringify(index)).digest("hex");
console.log(JSON.stringify({ digest, index_digest: indexDigest, cases: CASES, node: process.version, platform: `${process.platform}-${process.arch}`, failures }));
process.exit(failures.length ? 1 : 0);
