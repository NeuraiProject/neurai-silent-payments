# neurai-silent-payments

Silent payments for Neurai (NIP-047, profile 0) in JavaScript and TypeScript.

A receiver publishes one reusable **payment code** (`nsp1…` on mainnet, `tnsp1…` on testnet and regtest). Every
payment to it arrives at a new strict ECDSA witness v3 address that only the receiver can link to the code. The
sender derives that address from its own transaction inputs; the receiver finds it by scanning transactions.

The library is pure: no network access, no randomness. For the same inputs it gives the same results as the
Neurai node (tested against `neuraid` on regtest, see [Testing](#testing)). It runs in browsers, Node.js and
React Native.

> **Status: experimental.** NIP-047 is in testing on testnet. Strict ECDSA v3 outputs are **not active on
> mainnet** yet, and until they are anyone can spend them: `createOutputs` refuses mainnet unless you pass
> `mainnetActive: true`.

## Install

```bash
npm install @neuraiproject/neurai-silent-payments
```

```js
import * as SP from "@neuraiproject/neurai-silent-payments";      // ESM
const SP = require("@neuraiproject/neurai-silent-payments");       // CommonJS
```

For a plain `<script>` tag, `dist/NeuraiSilentPayments.global.js` defines `globalThis.NeuraiSilentPayments`.

## Receiving

```js
// Keys of m/352'/coin'/network'/0'/{0',1'}/0', as the node's wallet derives them
// from the same mnemonic and passphrase.
const keys = SP.deriveKeysFromMnemonic(mnemonic, passphrase, "test");
console.log(keys.code); // tnsp1… : share it instead of an address

// Scan blocks. getblock with verbosity 3 adds the spent output of every input,
// which scanning needs (the node reads it from its block undo data).
const block = await rpc("getblock", blockHash, 3);
const payments = SP.scanTransactions(SP.transactionsFromBlock(block), keys, { network: "test" });
// [{ txid, vout, k, value, valueSat, address, publicKey, script, tweak }]

// Private key of a payment, e.g. for signrawtransaction's privkeys argument.
const wif = SP.paymentPrivateKeyWIF(keys.spendPrivateKey, payments[0].tweak, "test");
```

A view-only identity scans without the spend key:

```js
const view = SP.exportViewKey(keys);   // { scan_private_key, spend_pubkey, network }
const viewer = SP.importViewKey(view); // same format as the node's import/exportsilentpaymentviewkey
SP.scanTransactions(txs, viewer, { network: "test" });
```

## Sending

Choose the inputs first: the outputs depend on them, and they must not change afterwards. Every input must be a
strict ECDSA v3 output spent with the default template, and the transaction must have version 2, or the receiver
will not find the payment.

```js
const outputs = SP.createOutputs(
  [{ txid, vout, privateKey, script: utxo.scriptPubKey }],   // `script` makes the library check the input
  [{ code: "tnsp1…", amount: 1.5 }, { code: "tnsp1…", amount: 0.2 }],
  { network: "test" },
);
// [{ code, k, address, script, publicKey, amount }] in the order of the recipients.
// Add them to the transaction together with the change, then sign it.
```

Several payments to the same code get `k = 0, 1, …` (at most 16 per code and transaction).

## API

| Function | Purpose |
|---|---|
| `deriveKeysFromMnemonic(mnemonic, passphrase, network)`, `deriveKeysFromSeed(seed, network)` | Identity keys and payment code |
| `encodeCode(code)`, `decodeCode(text, network)`, `checkCode(text, network)` | Payment codes; errors carry the node's `reason` |
| `exportViewKey(keys)`, `importViewKey(viewKey)` | View-only identities |
| `createOutputs(inputs, recipients, options)` | Sender: outputs paying payment codes |
| `scanTransaction(tx, keys, options)`, `scanTransactions(txs, keys, options)` | Receiver: payments in transactions |
| `getEligibleInputs(tx)` | Input keys and outpoints of an eligible transaction, or `null` |
| `transactionsFromBlock(block)`, `transactionFromRpc(tx)` | Read `getblock <hash> 3` |
| `scanTweaks(blocks, keys, options)`, `trackSpends(blocks, payments)` | Light client: payments and their spends from the node's index |
| `parseIndexResponse(json, options)`, `indexBlockFromJSON(json, options)` | Read the index RPC/REST JSON (format, context and digest checked) |
| `decodeIndexMessage(bytes, options)`, `decodeIndexBlock(bytes)`, `encodeIndexBlock(block)`, `indexBlockDigest(block, options)` | Binary format 1 of the index |
| `computeIndexBlock(getblock3, options)`, `computeIndexEntry(tx, options)` | Recompute index records to audit a server |
| `paymentPrivateKey(spendPrivateKey, tweak)`, `paymentPrivateKeyWIF(…, network)` | Private key d_k of a payment |
| `paymentScript(publicKey)`, `paymentAddress(publicKey, network)`, `scriptToAddress(script, network)` | Strict v3 outputs |
| `encodeWIF(privateKey, network)`, `decodeWIF(wif, network)`, `getPublicKey(privateKey)` | Key helpers |
| `getContext(options)`, `computeInputHash(…)`, `computeSharedTweak(…)`, `serializeOutpoint(…)` | Protocol primitives |
| `NETWORKS`, `getNetwork(name)`, `MAX_PAYMENTS_PER_CODE` | Network parameters (`main`, `test`, `regtest`) |

`options` is `{ network, genesisHash? }`; `genesisHash` replaces the built-in genesis, for example after a test
network reset. Bytes are accepted as `Uint8Array` or hex strings; txids use the RPC (display) order. Errors are
`SilentPaymentError` with a stable `reason`.

## Where receivers get the data

Scanning needs, for every candidate transaction, the public keys and outpoints of its inputs and the scripts they
spend. Options for an application:

- **The node's light client index** (`-silentpaymentindex`, see below): per block, only the public tweak and the
  v3 outputs of each candidate. One ECDH per candidate on the device; every client downloads the same data, so
  the server does not learn which payments are yours.
- **Its own node:** `getblock <hash> 3` per block, scanned on the device. Private, but every block is downloaded.
- **A node holding the view key** (`importsilentpaymentviewkey`): the node scans and reports payments; it learns
  which payments belong to the user.

## Light clients: the node's index

A node started with `-silentpaymentindex` serves, for every block, each eligible transaction with a native v3
output, its public tweak `T = h·A` and all its v3 outputs, plus every v3 output the block spends. The receiver
computes `b_scan·T` per entry and gets exactly what `scanTransaction` gives.

```js
const chain = { network: "test" };
let next = 1, anchor = await rpc("getblockhash", 0);
for (;;) {
  const page = SP.parseIndexResponse(await rpc("getsilentpaymenttweaksrange", next, 500, anchor), chain);
  if (page.type === "reorg") {                              // forget what was found above forkHeight
    next = page.forkHeight + 1;
    anchor = await rpc("getblockhash", page.forkHeight);
    continue;
  }
  const found = SP.scanTweaks(page.blocks, keys, chain);      // [{ txid, vout, k, tweak, valueSat, height, blockHash, ... }]
  const spent = SP.trackSpends(page.blocks, knownPayments);  // payments spent in these blocks
  if (page.blocks.length) anchor = page.blocks.at(-1).hash;
  next = page.nextHeight;
  if (page.status !== "more") break;                         // "tip": wait for a new block
}
```

The same data comes from REST (`/rest/sptweaksrange/v1/<height>/<count>.bin?anchor=<hash>`, read with
`decodeIndexMessage`), which suits caches and CDNs: the record of a block hash never changes. Every answer
carries the chain context, and the library refuses data of another chain.

A server can leave data out, and a client cannot notice from the data alone. Each block has a `digest`
(checked by `parseIndexResponse`) to compare servers cheaply, and `computeIndexBlock` recomputes a record from
`getblock <hash> 3` of another source to audit a server by sampling.

Amounts are never guessed. The index carries them as decimal strings of satoshis. When `computeIndexBlock` reads
`getblock` JSON, an output amount given as a JSON number is accepted only below 2^26 XNA, where the parsed number
still identifies a single amount; above that it throws, and the answer must be parsed losslessly (amounts as
strings, as `@neuraiproject/neurai-rpc` does) or carry `valueSat`.

## Security notes

- Secrets are `Uint8Array`s that the library overwrites when it no longer needs them, but JavaScript cannot
  guarantee that no other copy exists. Keep keys in memory only while needed.
- The view key links every payment of the identity. A payment's private key d_k together with the view key reveals
  the spend key: never export d_k to someone who may hold the view key.
- Curve operations use `@noble/curves`. The code check is bech32m and detects any error of up to 4 characters only
  in strings of up to 90 characters (codes have 119/120): prefer copy and paste or QR codes to typing.

## Testing

Unit tests run against the built package and include the NIP-047 lab vectors:

```bash
npm ci
npm test
```

`scripts/test-in-docker.sh` runs everything below in Docker; set `NEURAID_DIR` to a directory with `neuraid` to
include the regtest test.

`npm run test:determinism` derives a fixed set of cases from a seeded stream, checks that sender and receiver agree
on every one and prints a digest that must be identical on every run and Node.js version.

The index format is checked against `test/vectors/silentpayment_index_vectors.json`, a copy of the vectors of
the node's C++ tests (`src/test/data/silentpayment_index_vectors.json` in Neurai).

`npm run test:regtest` compares the library with a real node on a private regtest chain (identity, view key,
decoder verdicts, payments in both directions, spending with d_k, and the node's index: every record against
the library's own recomputation, JSON/hex/REST forms, paging with anchors, scanning, spends and reorganisations).
It needs `NEURAID` pointing to a `neuraid` binary with NIP-047 and the index, and writes
`test/regtest/out/report.json`.

## License

MIT
