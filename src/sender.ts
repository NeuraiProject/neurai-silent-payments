import { bytesToHex, equalBytes, toBytes, wipe, type BytesLike } from "./bytes.js";
import { toPaymentCode, encodeCode, type PaymentCode } from "./code.js";
import { addScalars, addTweakToPoint, ecdh, isValidScalar, mulScalars, publicKeyOf, scalarFromBytes, scalarToBytes } from "./ec.js";
import { SilentPaymentError } from "./errors.js";
import { getContext, type ChainOptions } from "./networks.js";
import { computeInputHash, computeSharedTweak, MAX_PAYMENTS_PER_CODE, serializeOutpoint, type Outpoint } from "./protocol.js";
import { paymentScript, scriptToAddress } from "./script.js";

/** An input of the transaction being built, with the private key that spends it. */
export interface SenderInput extends Outpoint {
  privateKey: BytesLike;
  /** scriptPubKey of the spent output. When given, it must be the strict v3
   *  output of the key: otherwise receivers would not find the payment. */
  script?: BytesLike;
}

export interface Recipient<T = unknown> {
  code: string | PaymentCode;
  /** Carried to the output unchanged (the library does not interpret it). */
  amount?: T;
}

export interface SenderOptions extends ChainOptions {
  /** Strict ECDSA v3 outputs are not active on mainnet yet: until they are,
   *  anyone can spend them. Set this only once the node enforces them there. */
  mainnetActive?: boolean;
}

export interface DerivedOutput<T = unknown> {
  /** Payment code the output pays. */
  code: string;
  /** Index of the payment among the outputs to that code. */
  k: number;
  /** P_k = B_spend + t_k*G. */
  publicKey: Uint8Array;
  /** Strict v3 scriptPubKey of P_k. */
  script: Uint8Array;
  address: string;
  amount?: T;
}

/**
 * Outputs paying `recipients`, in the same order, for a transaction that
 * spends exactly `inputs`. Every input must be a strict ECDSA v3 output
 * spent with the default template, and the transaction must have version 2:
 * receivers ignore any other transaction. The inputs must not change after
 * this call, since the outputs depend on them.
 *
 * Errors use the node's reasons: "no recipients", "input keys sum to zero",
 * "invalid input hash", "invalid scan key", "codes with the same scan key
 * and different spend keys", "more than 16 payments to one code",
 * "payment key derivation failed" and "duplicated destination".
 */
export function createOutputs<T = unknown>(
  inputs: SenderInput[],
  recipients: Recipient<T>[],
  options: SenderOptions,
): DerivedOutput<T>[] {
  if (options.network === "main" && options.mainnetActive !== true) {
    throw new SilentPaymentError("not active on mainnet", "strict ECDSA v3 outputs are not active on mainnet: they could be spent by anyone");
  }
  if (!Array.isArray(inputs) || inputs.length === 0) throw new SilentPaymentError("no inputs");
  if (!Array.isArray(recipients) || recipients.length === 0) throw new SilentPaymentError("no recipients");
  const context = getContext(options);

  let sum = 0n;
  const outpoints: Uint8Array[] = [];
  for (const input of inputs) {
    const key = toBytes(input.privateKey, "privateKey", 32);
    if (!isValidScalar(key)) throw new SilentPaymentError("invalid private key");
    if (input.script !== undefined && !equalBytes(paymentScript(publicKeyOf(key)), toBytes(input.script, "script"))) {
      throw new SilentPaymentError("ineligible input", `input ${input.txid}:${input.vout} is not the strict v3 output of its key`);
    }
    sum = addScalars(sum, scalarFromBytes(key));
    wipe(key);
    outpoints.push(serializeOutpoint(input));
  }
  if (sum === 0n) throw new SilentPaymentError("input keys sum to zero");
  const a = scalarToBytes(sum);
  const h = computeInputHash(context, outpoints, publicKeyOf(a));
  if (!h) {
    wipe(a);
    throw new SilentPaymentError("invalid input hash");
  }
  const ah = scalarToBytes(mulScalars(sum, scalarFromBytes(h)));
  wipe(a);

  const shared = new Map<string, { secret: Uint8Array; spend: Uint8Array; next: number }>();
  const seen = new Set<string>();
  const outputs: DerivedOutput<T>[] = [];
  try {
    for (const recipient of recipients) {
      const code = toPaymentCode(recipient.code, options.network);
      const scanId = bytesToHex(code.scanPublicKey);
      let group = shared.get(scanId);
      if (!group) {
        let secret: Uint8Array;
        try {
          secret = ecdh(ah, code.scanPublicKey);
        } catch {
          throw new SilentPaymentError("invalid scan key");
        }
        group = { secret, spend: code.spendPublicKey, next: 0 };
        shared.set(scanId, group);
      } else if (!equalBytes(group.spend, code.spendPublicKey)) {
        throw new SilentPaymentError("codes with the same scan key and different spend keys");
      }
      const k = group.next++;
      if (k >= MAX_PAYMENTS_PER_CODE) throw new SilentPaymentError("more than 16 payments to one code");
      const t = computeSharedTweak(context, group.secret, k);
      const publicKey = t ? addTweakToPoint(code.spendPublicKey, t) : null;
      wipe(t ?? undefined);
      if (!publicKey) throw new SilentPaymentError("payment key derivation failed");
      const script = paymentScript(publicKey);
      const scriptId = bytesToHex(script);
      if (seen.has(scriptId)) throw new SilentPaymentError("duplicated destination");
      seen.add(scriptId);
      const output: DerivedOutput<T> = {
        code: encodeCode(code),
        k,
        publicKey,
        script,
        address: scriptToAddress(script, options.network),
      };
      if (recipient.amount !== undefined) output.amount = recipient.amount;
      outputs.push(output);
    }
  } finally {
    wipe(ah);
    for (const group of shared.values()) wipe(group.secret);
  }
  return outputs;
}
