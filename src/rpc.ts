import { SilentPaymentError } from "./errors.js";
import type { ScanTransaction, TxInput, TxOutput } from "./receiver.js";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * A transaction of `getblock <hash> 3` (or any decoded transaction whose
 * inputs carry `prevout.scriptPubKey.hex`) in the form scanning needs.
 */
export function transactionFromRpc(tx: any): ScanTransaction {
  if (!tx || typeof tx !== "object" || typeof tx.txid !== "string" || !Array.isArray(tx.vin) || !Array.isArray(tx.vout)) {
    throw new SilentPaymentError("invalid argument", "not a decoded transaction");
  }
  const isCoinbase = tx.vin.length > 0 && typeof tx.vin[0].coinbase === "string";
  const inputs: TxInput[] = isCoinbase
    ? []
    : tx.vin.map((vin: any) => ({
        txid: vin.txid,
        vout: vin.vout,
        witness: Array.isArray(vin.txinwitness) ? vin.txinwitness : [],
        prevoutScript: vin.prevout?.scriptPubKey?.hex ?? null,
      }));
  const outputs: TxOutput[] = tx.vout.map((vout: any) => {
    const output: TxOutput = { script: vout.scriptPubKey?.hex ?? "" };
    if (vout.value !== undefined) output.value = vout.value;
    if (vout.valueSat !== undefined) output.valueSat = vout.valueSat;
    return output;
  });
  return { txid: tx.txid, version: tx.version, isCoinbase, inputs, outputs };
}

/** Transactions of a block returned by `getblock <hash> 3`. */
export function transactionsFromBlock(block: any): ScanTransaction[] {
  if (!block || !Array.isArray(block.tx) || block.tx.some((tx: any) => typeof tx !== "object")) {
    throw new SilentPaymentError("invalid argument", "use getblock with verbosity 3");
  }
  return block.tx.map(transactionFromRpc);
}
