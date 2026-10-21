import { hexToBytes } from "./bytes.js";
import { SilentPaymentError } from "./errors.js";

/** Network names as the Neurai node reports them. */
export type NetworkName = "main" | "test" | "regtest";

export interface NetworkParams {
  name: NetworkName;
  /** network_id of NIP-047: 0 main, 1 test, 2 regtest. */
  id: 0 | 1 | 2;
  /** Human-readable part of payment codes. */
  codeHrp: "nsp" | "tnsp";
  /** Human-readable part of strict v3 addresses. */
  addressHrp: "nq" | "tnq";
  /** BIP44 coin type of the m/352' derivation. */
  coinType: number;
  /** Genesis block hash in display order (as the RPC prints it). */
  genesisHash: string;
  /** Version byte of WIF private keys. */
  wifPrefix: number;
}

export const NETWORKS: Readonly<Record<NetworkName, Readonly<NetworkParams>>> = Object.freeze({
  main: Object.freeze({
    name: "main",
    id: 0,
    codeHrp: "nsp",
    addressHrp: "nq",
    coinType: 1900,
    genesisHash: "00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806",
    wifPrefix: 128,
  }),
  test: Object.freeze({
    name: "test",
    id: 1,
    codeHrp: "tnsp",
    addressHrp: "tnq",
    coinType: 1,
    genesisHash: "0000008b384aeffecdab182575dc4e86c9f07f90318c65088532660ed9a8a021",
    wifPrefix: 239,
  }),
  regtest: Object.freeze({
    name: "regtest",
    id: 2,
    codeHrp: "tnsp",
    addressHrp: "tnq",
    coinType: 1,
    genesisHash: "5241e503402b81548ea32dbfd7b670829b30fb83220a92ad9804ad893ecdce71",
    wifPrefix: 239,
  }),
}) as Readonly<Record<NetworkName, Readonly<NetworkParams>>>;

export const PROFILE_VERSION = 0;
export const WITNESS_FAMILY = 3;

export function getNetwork(name: NetworkName): Readonly<NetworkParams> {
  const params = (NETWORKS as Record<string, Readonly<NetworkParams>>)[name];
  if (!params) throw new SilentPaymentError("invalid argument", `unknown network "${String(name)}"`);
  return params;
}

export function networkFromId(id: number): Readonly<NetworkParams> {
  const params = Object.values(NETWORKS).find((n) => n.id === id);
  if (!params) throw new SilentPaymentError("invalid argument", `unknown network id ${id}`);
  return params;
}

/** Network and chain of an operation. `genesisHash` (display order) replaces
 *  the built-in one, e.g. after a test network reset. */
export interface ChainOptions {
  network: NetworkName;
  genesisHash?: string;
}

/** Hash context N = network_id || genesis (display order) || profile || family. */
export function getContext(options: ChainOptions): Uint8Array {
  const params = getNetwork(options.network);
  const genesis = options.genesisHash ?? params.genesisHash;
  if (!/^[0-9a-fA-F]{64}$/.test(genesis)) {
    throw new SilentPaymentError("invalid argument", "genesisHash must be 32 bytes of hex");
  }
  const context = new Uint8Array(35);
  context[0] = params.id;
  context.set(hexToBytes(genesis.toLowerCase()), 1);
  context[33] = PROFILE_VERSION;
  context[34] = WITNESS_FAMILY;
  return context;
}
