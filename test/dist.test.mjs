import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import vm from "node:vm";

import { describe, expect, it } from "vitest";

import * as esm from "../dist/index.js";

const require = createRequire(import.meta.url);
const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("published builds", () => {
  it("CommonJS and ESM give the same results", () => {
    const cjs = require("../dist/index.cjs");
    expect(Object.keys(cjs).filter((k) => k !== "default").sort()).toEqual(Object.keys(esm).filter((k) => k !== "default").sort());
    expect(cjs.deriveKeysFromMnemonic(mnemonic, "", "test").code).toBe(esm.deriveKeysFromMnemonic(mnemonic, "", "test").code);
  });

  it("the global build defines NeuraiSilentPayments", () => {
    const context = vm.createContext({ TextEncoder, TextDecoder, Uint8Array, crypto: globalThis.crypto });
    vm.runInContext(readFileSync(new URL("../dist/NeuraiSilentPayments.global.js", import.meta.url), "utf8"), context);
    const api = context.NeuraiSilentPayments;
    expect(api.deriveKeysFromMnemonic(mnemonic, "", "test").code).toBe(esm.deriveKeysFromMnemonic(mnemonic, "", "test").code);
  });
});
