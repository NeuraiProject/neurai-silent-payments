// NIP-047 silent payments for Neurai (profile 0, strict ECDSA witness v3).
// Pure functions: no network access, no randomness. Same results as the
// Neurai node for the same inputs, also for the node's light client index.

import { bytesToHex, hexToBytes } from "./bytes.js";
import { checkCode, decodeCode, encodeCode } from "./code.js";
import { getPublicKey } from "./ec.js";
import { SilentPaymentError } from "./errors.js";
import { deriveKeysFromMnemonic, deriveKeysFromSeed, exportViewKey, importViewKey } from "./keys.js";
import { getContext, getNetwork, NETWORKS } from "./networks.js";
import { computeInputHash, computeSharedTweak, MAX_PAYMENTS_PER_CODE, serializeOutpoint } from "./protocol.js";
import { getEligibleInputs, paymentPrivateKey, paymentPrivateKeyWIF, scanTransaction, scanTransactions } from "./receiver.js";
import { transactionFromRpc, transactionsFromBlock } from "./rpc.js";
import { isNativeV3Script, paymentAddress, paymentCommitment, paymentScript, scriptToAddress } from "./script.js";
import { createOutputs } from "./sender.js";
import {
  computeIndexBlock,
  computeIndexEntry,
  decodeIndexBlock,
  decodeIndexMessage,
  encodeIndexBlock,
  INDEX_FORMAT,
  indexBlockDigest,
  indexBlockFromJSON,
  parseIndexResponse,
  scanTweaks,
  trackSpends,
} from "./tweaks.js";
import { decodeWIF, encodeWIF } from "./wif.js";

export type { BytesLike } from "./bytes.js";
export type { CodeCheck, PaymentCode } from "./code.js";
export type { SilentPaymentKeys, ViewKey, ViewOnlyKeys } from "./keys.js";
export type { ChainOptions, NetworkName, NetworkParams } from "./networks.js";
export type { Outpoint } from "./protocol.js";
export type { EligibleInputs, FoundPayment, ScanKeys, ScanTransaction, TxInput, TxOutput } from "./receiver.js";
export type { DerivedOutput, Recipient, SenderInput, SenderOptions } from "./sender.js";
export type { IndexBlock, IndexEntry, IndexOutput, IndexPayment, IndexRange, RangeStatus, SpentPayment } from "./tweaks.js";

export {
  bytesToHex,
  checkCode,
  computeIndexBlock,
  computeIndexEntry,
  computeInputHash,
  computeSharedTweak,
  createOutputs,
  decodeCode,
  decodeIndexBlock,
  decodeIndexMessage,
  decodeWIF,
  deriveKeysFromMnemonic,
  deriveKeysFromSeed,
  encodeCode,
  encodeIndexBlock,
  encodeWIF,
  exportViewKey,
  getContext,
  getEligibleInputs,
  getNetwork,
  getPublicKey,
  hexToBytes,
  importViewKey,
  INDEX_FORMAT,
  indexBlockDigest,
  indexBlockFromJSON,
  isNativeV3Script,
  MAX_PAYMENTS_PER_CODE,
  NETWORKS,
  parseIndexResponse,
  paymentAddress,
  paymentCommitment,
  paymentPrivateKey,
  paymentPrivateKeyWIF,
  paymentScript,
  scanTransaction,
  scanTransactions,
  scanTweaks,
  scriptToAddress,
  serializeOutpoint,
  SilentPaymentError,
  trackSpends,
  transactionFromRpc,
  transactionsFromBlock,
};

const NeuraiSilentPayments = {
  bytesToHex,
  checkCode,
  computeIndexBlock,
  computeIndexEntry,
  computeInputHash,
  computeSharedTweak,
  createOutputs,
  decodeCode,
  decodeIndexBlock,
  decodeIndexMessage,
  decodeWIF,
  deriveKeysFromMnemonic,
  deriveKeysFromSeed,
  encodeCode,
  encodeIndexBlock,
  encodeWIF,
  exportViewKey,
  getContext,
  getEligibleInputs,
  getNetwork,
  getPublicKey,
  hexToBytes,
  importViewKey,
  INDEX_FORMAT,
  indexBlockDigest,
  indexBlockFromJSON,
  isNativeV3Script,
  MAX_PAYMENTS_PER_CODE,
  NETWORKS,
  parseIndexResponse,
  paymentAddress,
  paymentCommitment,
  paymentPrivateKey,
  paymentPrivateKeyWIF,
  paymentScript,
  scanTransaction,
  scanTransactions,
  scanTweaks,
  scriptToAddress,
  serializeOutpoint,
  SilentPaymentError,
  trackSpends,
  transactionFromRpc,
  transactionsFromBlock,
};

export default NeuraiSilentPayments;
