// Integration test against a real Neurai node on a private regtest chain.
// The node is the reference implementation of NIP-047: every result of the
// library is compared with what the node derives, detects and accepts.
//
//   NEURAID=/path/to/neuraid node test/regtest/run.mjs
//
// It starts its own node in a temporary directory, mines on that private
// chain only, and writes test/regtest/out/report.json.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as SP from "../../dist/index.js";

const NEURAID = process.env.NEURAID ?? "neuraid";
const OUT = new URL("./out/", import.meta.url);
const hex = SP.bytesToHex;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Disposable test identities.
const NODE = { mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow", passphrase: "neurai-sp-js node" };
const Y = SP.deriveKeysFromMnemonic("letter advice cage absurd amount doctor acoustic avoid letter advice cage above", "neurai-sp-js Y", "regtest");
const Z = SP.deriveKeysFromMnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "", "regtest");

const results = [];
function check(name, ok, detail) {
  results.push({ name, passed: Boolean(ok), detail: detail === undefined ? null : detail });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}`);
}

class Node {
  constructor(name, network, rpcPort) {
    this.name = name;
    this.network = network;
    this.rpcPort = rpcPort;
    this.dir = mkdtempSync(join(tmpdir(), `neurai-sp-${name}-`));
  }

  async start(extra = []) {
    const flag = { main: [], test: ["-testnet"], regtest: ["-regtest"] }[this.network];
    const args = [
      ...flag, `-datadir=${this.dir}`, "-server", "-rpcuser=sp", "-rpcpassword=sp", `-rpcport=${this.rpcPort}`,
      `-port=${this.rpcPort + 1}`, "-listen=0", "-connect=0", "-dnsseed=0", "-discover=0", "-listenonion=0",
      "-addresstype=ecdsa", "-bip44=1", `-mnemonic=${NODE.mnemonic}`, `-mnemonicpassphrase=${NODE.passphrase}`,
      "-fallbackfee=0.01", "-txindex=1", "-keypool=20", ...extra,
    ];
    this.log = [];
    this.proc = spawn(NEURAID, args, { stdio: ["ignore", "pipe", "pipe"] });
    this.proc.stdout.on("data", (d) => this.log.push(String(d)));
    this.proc.stderr.on("data", (d) => this.log.push(String(d)));
    for (let i = 0; i < 240; i++) {
      if (this.proc.exitCode !== null) throw new Error(`${this.name} exited: ${this.log.join("").slice(-800)}`);
      try {
        await this.rpc("getblockcount");
        return;
      } catch {
        await sleep(250);
      }
    }
    throw new Error(`${this.name}: RPC did not come up`);
  }

  async rpc(method, ...params) {
    const response = await fetch(`http://127.0.0.1:${this.rpcPort}/`, {
      method: "POST",
      headers: { Authorization: "Basic " + Buffer.from("sp:sp").toString("base64"), "Content-Type": "application/json" },
      body: JSON.stringify({ id: method, method, params }),
    });
    const body = await response.json();
    if (body.error) {
      const error = new Error(`${method}: ${body.error.message}`);
      error.code = body.error.code;
      throw error;
    }
    return body.result;
  }

  async stop() {
    if (!this.proc || this.proc.exitCode !== null) return;
    try { await this.rpc("stop"); } catch { this.proc.kill("SIGTERM"); }
    for (let i = 0; i < 240 && this.proc.exitCode === null; i++) await sleep(250);
    if (this.proc.exitCode === null) this.proc.kill("SIGKILL");
    rmSync(this.dir, { recursive: true, force: true });
  }
}

const amount = (x) => Number(x.toFixed(8));

async function mine(node, blocks = 1) {
  const hashes = await node.rpc("generatetoaddress", blocks, await node.rpc("getnewaddress", "", "ecdsa"));
  return hashes[hashes.length - 1];
}

async function waitFor(what, fn, timeout = 60000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    last = await fn();
    if (last) return last;
    await sleep(250);
  }
  throw new Error(`timeout waiting for ${what}: ${JSON.stringify(last)}`);
}

/** Deterministic stream for the decoder comparison. */
function stream(seed) {
  let counter = 0;
  return () => createHash("sha256").update(`${seed}/${counter++}`).digest().readUInt32BE(0);
}

/** The node's light client index (-silentpaymentindex) against the library. */
async function lightClient(node, { Y, Z, nodeView, yFound, y2, z2, spendTxid }) {
  const regtest = { network: "regtest" };
  const key = (p) => `${p.txid}:${p.vout}:${p.k}`;
  const info = await node.rpc("getsilentpaymentindexinfo");
  check("index complete, with the library's context", info.complete === true && info.context === hex(SP.getContext(regtest)), info);
  const tip = await node.rpc("getblockcount");

  // Every record equals the library's own recomputation from getblock 3,
  // tweaks included, and its digest checks.
  let entries = 0;
  const differences = [];
  for (let height = 1; height <= tip; height++) {
    const hash = await node.rpc("getblockhash", height);
    const served = SP.parseIndexResponse(await node.rpc("getsilentpaymenttweaks", hash), regtest).block;
    const recomputed = SP.computeIndexBlock(await node.rpc("getblock", hash, 3), regtest);
    if (hex(SP.encodeIndexBlock(served)) !== hex(SP.encodeIndexBlock(recomputed))) differences.push(height);
    entries += served.entries.length;
  }
  check(`records of ${tip} blocks equal the library's recomputation (${entries} entries)`, differences.length === 0 && entries >= 4, differences);

  // One range, as JSON, RPC hex and REST binary.
  const json = SP.parseIndexResponse(await node.rpc("getsilentpaymenttweaksrange", 1, 1000), regtest);
  const fromHex = SP.decodeIndexMessage(await node.rpc("getsilentpaymenttweaksrange", 1, 1000, "", "hex"), regtest);
  const rest = await fetch(`http://127.0.0.1:${node.rpcPort}/rest/sptweaksrange/v1/1/1000.bin`);
  const fromRest = SP.decodeIndexMessage(new Uint8Array(await rest.arrayBuffer()), regtest);
  const bytesOf = (r) => r.blocks.map((b) => hex(SP.encodeIndexBlock(b))).join();
  check("range as JSON, RPC hex and REST binary agree", json.status === "tip" && json.blocks.length === tip &&
    bytesOf(json) === bytesOf(fromHex) && bytesOf(json) === bytesOf(fromRest) && rest.headers.get("cache-control") === "public, max-age=5");

  // A light client paging through the index finds what full scanning found.
  const blocks = [];
  let next = 1;
  let anchor = await node.rpc("getblockhash", 0);
  for (let pages = 0; pages < 100; pages++) {
    const page = SP.parseIndexResponse(await node.rpc("getsilentpaymenttweaksrange", next, 7, anchor), regtest);
    blocks.push(...page.blocks);
    next = page.nextHeight;
    if (page.blocks.length) anchor = page.blocks[page.blocks.length - 1].hash;
    if (page.status !== "more") break;
  }
  check("paging with anchors covers the chain", blocks.length === tip && bytesOf({ blocks }) === bytesOf(json));
  const yIndex = SP.scanTweaks(blocks, Y, regtest);
  check("scanTweaks finds Y's payments as scanTransactions did", JSON.stringify(yIndex.map(key).sort()) === JSON.stringify([...yFound, ...y2].map(key).sort()),
    yIndex.map(key));
  check("scanTweaks finds Z's payment", JSON.stringify(SP.scanTweaks(blocks, Z, regtest).map(key)) === JSON.stringify(z2.map(key)));
  const nodeList = await node.rpc("listsilentpayments", true);
  const viaView = SP.scanTweaks(blocks, SP.importViewKey(nodeView), regtest);
  check("scanTweaks with the node's view key finds what the node's wallet found",
    JSON.stringify(viaView.map(key).sort()) === JSON.stringify(nodeList.map(key).sort()) && viaView.length >= 2);
  check("found payments carry their blocks", yIndex.every((p) => p.blockHash && p.height > 0 && p.valueSat > 0n));
  const spent = SP.trackSpends(blocks, yIndex);
  const spendBlock = (await node.rpc("getrawtransaction", spendTxid, 1)).blockhash;
  check("trackSpends sees the spend of Y's payments", spent.length === yIndex.length && spent.every((s) => s.blockHash === spendBlock));

  // Reorganisation: the old anchor is reported, with the fork height.
  const oldTip = await node.rpc("getbestblockhash");
  await node.rpc("invalidateblock", oldTip);
  await mine(node, 2);
  const reorg = SP.parseIndexResponse(await node.rpc("getsilentpaymenttweaksrange", tip + 1, 10, oldTip), regtest);
  check("an anchor left behind by a reorganisation is reported", reorg.type === "reorg" && reorg.forkHeight === tip - 1, reorg);
}

async function main() {
  const node = new Node("regtest", "regtest", 19601);
  const report = { started: new Date().toISOString(), node: null };
  try {
    await node.start(["-silentpaymentindex", "-rest"]);
    const info = await node.rpc("getnetworkinfo");
    report.node = { version: info.subversion };

    // Chain and identity.
    check("genesis hash matches NETWORKS.regtest", (await node.rpc("getblockhash", 0)) === SP.NETWORKS.regtest.genesisHash);
    const nodeKeys = SP.deriveKeysFromMnemonic(NODE.mnemonic, NODE.passphrase, "regtest");
    const nodeCode = await node.rpc("getsilentpaymentcode");
    check("code of the node wallet equals the library derivation", nodeCode.code === nodeKeys.code, nodeCode.code);
    check("scan and spend public keys equal", nodeCode.scan_pubkey === hex(nodeKeys.scanPublicKey) && nodeCode.spend_pubkey === hex(nodeKeys.spendPublicKey));
    const nodeView = await node.rpc("exportsilentpaymentviewkey", "reveal view key");
    check("exported view key equals exportViewKey", JSON.stringify(nodeView) === JSON.stringify(SP.exportViewKey(nodeKeys)), nodeView.network);
    await mine(node, 200);

    // Decoder: the node and the library give the same verdict and reason.
    const rand = stream("decoder");
    const bases = [nodeKeys.code, Y.code, Z.code, SP.deriveKeysFromMnemonic(NODE.mnemonic, "", "test").code,
      SP.deriveKeysFromMnemonic(NODE.mnemonic, "", "main").code];
    const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l1bio ";
    const mismatches = [];
    let compared = 0;
    for (let i = 0; i < 400; i++) {
      let text = bases[rand() % bases.length];
      const pos = rand() % text.length;
      switch (rand() % 6) {
        case 0: text = text.slice(0, pos) + charset[rand() % charset.length] + text.slice(pos + 1); break;
        case 1: text = text.slice(0, pos) + text.slice(pos).toUpperCase(); break;
        case 2: text = text.slice(0, pos); break;
        case 3: text = text.slice(0, pos) + text[(pos + 1) % text.length] + text[pos] + text.slice(pos + 2); break;
        case 4: text = text.toUpperCase(); break;
        default: break;
      }
      const viaNode = await node.rpc("decodesilentpaymentcode", text);
      const viaLib = SP.checkCode(text, "regtest");
      compared++;
      const same = viaNode.isvalid === viaLib.valid && (viaLib.valid || viaNode.error === viaLib.reason);
      if (!same) mismatches.push({ text, node: viaNode, lib: viaLib });
    }
    check(`decoder verdicts equal on ${compared} codes`, mismatches.length === 0, mismatches.slice(0, 5));

    // Library as sender, node as receiver.
    const inputs = [];
    for (let i = 0; i < 3; i++) {
      const address = await node.rpc("getnewaddress", "", "ecdsa");
      await node.rpc("sendtoaddress", address, 2 + i);
      inputs.push({ address, privateKey: SP.decodeWIF(await node.rpc("dumpprivkey", address), "regtest") });
    }
    await mine(node);
    const utxos = await node.rpc("listunspent", 1, 9999999, inputs.map((i) => i.address));
    const senderInputs = utxos.map((u) => ({
      txid: u.txid,
      vout: u.vout,
      script: u.scriptPubKey,
      privateKey: inputs.find((i) => i.address === u.address).privateKey,
      amount: u.amount,
    }));
    check("three strict v3 inputs funded", senderInputs.length === 3 && senderInputs.every((i) => SP.isNativeV3Script(i.script)));
    const recipients = [{ code: nodeKeys.code, amount: 1.0 }, { code: Y.code, amount: 1.5 }, { code: nodeKeys.code, amount: 0.75 }];
    const outputs = SP.createOutputs(senderInputs, recipients, { network: "regtest" });
    const again = SP.createOutputs(senderInputs, recipients, { network: "regtest" });
    check("createOutputs is deterministic", JSON.stringify(outputs.map((o) => o.address)) === JSON.stringify(again.map((o) => o.address)));
    const totalIn = senderInputs.reduce((s, i) => s + i.amount, 0);
    const change = amount(totalIn - recipients.reduce((s, r) => s + r.amount, 0) - 0.01);
    const destinations = {};
    for (const o of outputs) destinations[o.address] = o.amount;
    destinations[await node.rpc("getnewaddress", "", "ecdsa")] = change;
    let raw = await node.rpc("createrawtransaction", senderInputs.map(({ txid, vout }) => ({ txid, vout })), destinations);
    const version = (await node.rpc("decoderawtransaction", raw)).version;
    if (version !== 2) raw = "02000000" + raw.slice(8); // receivers only scan version 2
    const signed = await node.rpc("signrawtransaction", raw);
    check("node signs the library's transaction", signed.complete === true, signed.errors);
    const sentTxid = await node.rpc("sendrawtransaction", signed.hex);
    const blockHash = await mine(node);
    const decoded = await node.rpc("getrawtransaction", sentTxid, 1);
    const voutOf = (address) => decoded.vout.findIndex((v) => (v.scriptPubKey.addresses ?? [])[0] === address);
    const expectedNode = outputs.filter((o) => o.code === nodeKeys.code).map((o) => [voutOf(o.address), o.k]);
    const nodeFound = await waitFor("node detection", async () => {
      const list = (await node.rpc("listsilentpayments")).filter((p) => p.txid === sentTxid);
      return list.length === 2 ? list : null;
    });
    check("node detects both payments to its code with the library's k",
      JSON.stringify(nodeFound.map((p) => [p.vout, p.k]).sort()) === JSON.stringify(expectedNode.sort()), nodeFound);
    check("node reports the amounts", nodeFound.every((p) => p.amount === recipients[outputs.findIndex((o) => voutOf(o.address) === p.vout)].amount));

    const block = await node.rpc("getblock", blockHash, 3);
    const txs = SP.transactionsFromBlock(block);
    const yFound = SP.scanTransactions(txs, Y, { network: "regtest" });
    check("library finds the payment to Y", yFound.length === 1 && yFound[0].txid === sentTxid && yFound[0].vout === voutOf(outputs[1].address) && yFound[0].k === 0, yFound.map((f) => [f.vout, f.k]));
    const viaView = SP.scanTransactions(txs, SP.importViewKey(nodeView), { network: "regtest" });
    check("library with the node's view key finds what the node found",
      JSON.stringify(viaView.map((f) => [f.vout, f.k]).sort()) === JSON.stringify(nodeFound.map((p) => [p.vout, p.k]).sort()));

    // Node as sender, library as receiver.
    const sent = await node.rpc("sendsilentpayments", [{ code: Y.code, amount: 1.25 }, { code: Y.code, amount: 0.5 }, { code: Z.code, amount: 0.3 }]);
    const block2 = await node.rpc("getblock", await mine(node), 3);
    const txs2 = SP.transactionsFromBlock(block2);
    const y2 = SP.scanTransactions(txs2, Y, { network: "regtest" });
    const z2 = SP.scanTransactions(txs2, Z, { network: "regtest" });
    const want = (from, to) => sent.payments.slice(from, to).map((p) => [p.vout, p.k]);
    check("library finds the node's two payments to Y", JSON.stringify(y2.map((f) => [f.vout, f.k])) === JSON.stringify(want(0, 2)), { lib: y2.map((f) => [f.vout, f.k]), node: want(0, 2) });
    check("library finds the node's payment to Z", JSON.stringify(z2.map((f) => [f.vout, f.k])) === JSON.stringify(want(2, 3)));
    check("amounts read from the block", y2.map((f) => f.value).join() === "1.25,0.5" && z2[0]?.value === 0.3);
    check("the node's code does not match payments to others", SP.scanTransactions(txs2, SP.importViewKey(nodeView), { network: "regtest" }).length === 0);

    // Spending the received payments with d_k.
    const received = [...yFound, ...y2];
    const prevtxs = received.map((f) => ({ txid: f.txid, vout: f.vout, scriptPubKey: hex(f.script), amount: f.value }));
    const wifs = received.map((f) => SP.paymentPrivateKeyWIF(Y.spendPrivateKey, f.tweak, "regtest"));
    const spendTotal = amount(received.reduce((s, f) => s + f.value, 0) - 0.01);
    const spendRaw = await node.rpc("createrawtransaction", received.map(({ txid, vout }) => ({ txid, vout })),
      { [await node.rpc("getnewaddress", "", "ecdsa")]: spendTotal });
    const spendSigned = await node.rpc("signrawtransaction", spendRaw, prevtxs, wifs);
    check("d_k signs all three received payments", spendSigned.complete === true, spendSigned.errors);
    const spendTxid = await node.rpc("sendrawtransaction", spendSigned.hex);
    await mine(node);
    const spendTx = await node.rpc("getrawtransaction", spendTxid, 1);
    check("the spend confirms on chain", spendTx.confirmations >= 1);

    await lightClient(node, { Y, Z, nodeView, yFound, y2, z2, spendTxid });

    report.digest = createHash("sha256").update(JSON.stringify(results.map((r) => [r.name, r.passed]))).digest("hex");
  } catch (error) {
    check("run completed", false, String(error.stack ?? error));
  } finally {
    await node.stop();
  }
  report.passed = results.filter((r) => r.passed).length;
  report.failed = results.filter((r) => !r.passed).length;
  report.results = results;
  mkdirSync(OUT, { recursive: true });
  writeFileSync(new URL("report.json", OUT), JSON.stringify(report, null, 1) + "\n");
  console.log(`${report.passed} passed, ${report.failed} failed`);
  process.exit(report.failed ? 1 : 0);
}

main();
