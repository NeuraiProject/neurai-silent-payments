import { bytesToHex, equalBytes, toBytes, wipe, type BytesLike } from "./bytes.js";
import { addScalars, addTweakToPoint, ecdh, isValidPoint, isValidScalar, mulScalars, scalarFromBytes, scalarToBytes, sumPoints } from "./ec.js";
import { SilentPaymentError } from "./errors.js";
import { getContext, type ChainOptions, type NetworkName } from "./networks.js";
import { computeInputHash, computeSharedTweak, MAX_PAYMENTS_PER_CODE, serializeOutpoint } from "./protocol.js";
import { isNativeV3Script, paymentScript, scriptToAddress } from "./script.js";
import { encodeWIF } from "./wif.js";

/** A transaction input with its witness and the scriptPubKey it spends. */
export interface TxInput {
  txid: string;
  vout: number;
  /** Witness stack items. */
  witness: BytesLike[];
  /** scriptPubKey of the spent output; without it the input is not eligible. */
  prevoutScript?: BytesLike | null;
}

export interface TxOutput {
  script: BytesLike;
  /** Amount in XNA, as the RPC prints it (carried unchanged). */
  value?: number;
  /** Amount in satoshis, as the RPC prints it (carried unchanged). */
  valueSat?: number | bigint;
}

/** What scanning needs of a transaction (see transactionsFromBlock). */
export interface ScanTransaction {
  txid: string;
  version: number;
  isCoinbase?: boolean;
  inputs: TxInput[];
  outputs: TxOutput[];
}

export interface EligibleInputs {
  publicKeys: Uint8Array[];
  outpoints: Uint8Array[];
}

/** Receiver keys: a full identity or a view-only one. */
export interface ScanKeys {
  scanPrivateKey: BytesLike;
  spendPublicKey: BytesLike;
}

export interface FoundPayment {
  txid: string;
  vout: number;
  k: number;
  /** t_k: secret. With the spend key it gives the private key of the output. */
  tweak: Uint8Array;
  /** P_k, the key of the output. */
  publicKey: Uint8Array;
  script: Uint8Array;
  address: string;
  value?: number;
  valueSat?: number | bigint;
}

const OP_TRUE = 0x51;
const AUTH_TYPE_ECDSA = 0x02;

/**
 * Public keys and outpoints of an eligible transaction, or null. Eligible
 * means version 2, not a coinbase, and every input spends a native v3 output
 * with the strict template [0x02, signature, 33-byte key, OP_TRUE] whose key
 * is the one committed by the spent output. Same rules as the node.
 */
export function getEligibleInputs(tx: ScanTransaction): EligibleInputs | null {
  if (tx.isCoinbase || tx.version !== 2 || !Array.isArray(tx.inputs) || tx.inputs.length === 0) return null;
  const stacks: Uint8Array[][] = [];
  for (const input of tx.inputs) {
    const stack = (input.witness ?? []).map((item, i) => toBytes(item, `witness[${i}]`));
    if (stack.length !== 4 || !equalBytes(stack[0], Uint8Array.of(AUTH_TYPE_ECDSA)) ||
        !equalBytes(stack[3], Uint8Array.of(OP_TRUE)) || stack[2].length !== 33) return null;
    stacks.push(stack);
  }
  const publicKeys: Uint8Array[] = [];
  const outpoints: Uint8Array[] = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    const input = tx.inputs[i];
    // The spent script decides the family: a v1 AuthScript spend with an
    // ECDSA key and OP_TRUE has the same witness shape.
    if (input.prevoutScript === undefined || input.prevoutScript === null) return null;
    const prevout = toBytes(input.prevoutScript, "prevoutScript");
    const key = stacks[i][2];
    if (!isNativeV3Script(prevout) || !isValidPoint(key) || !equalBytes(paymentScript(key), prevout)) return null;
    publicKeys.push(key);
    outpoints.push(serializeOutpoint(input));
  }
  return { publicKeys, outpoints };
}

/** Payments to `keys` in one transaction (empty when there are none). */
export function scanTransaction(tx: ScanTransaction, keys: ScanKeys, options: ChainOptions): FoundPayment[] {
  const scanKey = toBytes(keys.scanPrivateKey, "scanPrivateKey", 32);
  const spendPublicKey = toBytes(keys.spendPublicKey, "spendPublicKey", 33);
  if (!isValidScalar(scanKey)) throw new SilentPaymentError("invalid private key");
  if (!isValidPoint(spendPublicKey)) throw new SilentPaymentError("point");
  try {
    return scan(tx, scanKey, spendPublicKey, getContext(options), options.network);
  } finally {
    wipe(scanKey);
  }
}

/** Payments to `keys` in several transactions, in order. */
export function scanTransactions(txs: ScanTransaction[], keys: ScanKeys, options: ChainOptions): FoundPayment[] {
  return txs.flatMap((tx) => scanTransaction(tx, keys, options));
}

function scan(tx: ScanTransaction, scanKey: Uint8Array, spendPublicKey: Uint8Array, context: Uint8Array, network: NetworkName): FoundPayment[] {
  const candidates = new Map<string, number[]>();
  tx.outputs.forEach((output, n) => {
    const script = toBytes(output.script, `outputs[${n}].script`);
    if (isNativeV3Script(script)) {
      const id = bytesToHex(script);
      const vouts = candidates.get(id);
      if (vouts) vouts.push(n);
      else candidates.set(id, [n]);
    }
  });
  if (candidates.size === 0) return []; // no possible payment: skip the ECDH
  const eligible = getEligibleInputs(tx);
  if (!eligible) return [];
  const sum = sumPoints(eligible.publicKeys);
  if (!sum) return [];
  const h = computeInputHash(context, eligible.outpoints, sum);
  if (!h) return [];
  const bh = scalarToBytes(mulScalars(scalarFromBytes(scanKey), scalarFromBytes(h)));
  const shared = ecdh(bh, sum);
  wipe(bh);
  try {
    return matchCandidates(context, shared, spendPublicKey, candidates, network, tx.txid, (payment) => {
      const output = tx.outputs[payment.vout];
      if (output.value !== undefined) payment.value = output.value;
      if (output.valueSat !== undefined) payment.valueSat = output.valueSat;
      return payment;
    });
  } finally {
    wipe(shared);
  }
}

/**
 * Receiver loop shared by scanTransaction and scanTweaks: P_k for k = 0, 1, ...
 * until the first k without an output. `candidates` maps the hex of each
 * native v3 script to its vouts; `complete` adds what the caller knows of the
 * output (amounts, block).
 */
export function matchCandidates<T extends FoundPayment>(
  context: Uint8Array,
  shared: Uint8Array,
  spendPublicKey: Uint8Array,
  candidates: Map<string, number[]>,
  network: NetworkName,
  txid: string,
  complete: (payment: FoundPayment) => T,
): T[] {
  const found: T[] = [];
  for (let k = 0; k < MAX_PAYMENTS_PER_CODE; k++) {
    const tweak = computeSharedTweak(context, shared, k);
    const publicKey = tweak ? addTweakToPoint(spendPublicKey, tweak) : null;
    if (!tweak || !publicKey) break;
    const script = paymentScript(publicKey);
    const hits = candidates.get(bytesToHex(script));
    if (!hits) { // the sequence ends at the first missing k
      wipe(tweak);
      break;
    }
    for (const n of hits) {
      found.push(complete({
        txid,
        vout: n,
        k,
        tweak: Uint8Array.from(tweak),
        publicKey,
        script,
        address: scriptToAddress(script, network),
      }));
    }
    wipe(tweak);
  }
  return found;
}

/** d_k = b_spend + t_k: private key of a received payment. */
export function paymentPrivateKey(spendPrivateKey: BytesLike, tweak: BytesLike): Uint8Array {
  const spend = toBytes(spendPrivateKey, "spendPrivateKey", 32);
  const t = toBytes(tweak, "tweak", 32);
  if (!isValidScalar(spend) || !isValidScalar(t)) throw new SilentPaymentError("invalid private key");
  const d = addScalars(scalarFromBytes(spend), scalarFromBytes(t));
  wipe(spend, t);
  if (d === 0n) throw new SilentPaymentError("invalid private key");
  return scalarToBytes(d);
}

/** d_k as a WIF, e.g. for signrawtransaction's privkeys argument. */
export function paymentPrivateKeyWIF(spendPrivateKey: BytesLike, tweak: BytesLike, network: NetworkName): string {
  const d = paymentPrivateKey(spendPrivateKey, tweak);
  try {
    return encodeWIF(d, network);
  } finally {
    wipe(d);
  }
}
