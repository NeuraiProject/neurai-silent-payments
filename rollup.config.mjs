import { createRequire } from "node:module";
import nodeResolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import dts from "rollup-plugin-dts";

const require = createRequire(import.meta.url);
const pkg = require("./package.json");
const dependencies = new Set(Object.keys(pkg.dependencies ?? {}));
// @scure/base also ships its TypeScript sources: point the bundle at the
// compiled module (as neurai-key does).
const scureBasePath = require.resolve("@scure/base/index.js");

// ESM and CommonJS builds keep the dependencies external; the global build
// bundles them so that a <script> tag is enough.
const external = (id) => {
  const [scopeOrName, maybeName] = id.split("/");
  const name = scopeOrName.startsWith("@") ? `${scopeOrName}/${maybeName}` : scopeOrName;
  return dependencies.has(name);
};

const plugins = () => [
  {
    name: "scure-base-module",
    resolveId: (source) => (source === "@scure/base" ? scureBasePath : null),
  },
  nodeResolve({ browser: true, extensions: [".js"] }),
  typescript({ tsconfig: "./tsconfig.json", declaration: false, declarationMap: false }),
];

export default [
  {
    input: "./src/index.ts",
    external,
    plugins: plugins(),
    output: { file: "./dist/index.js", format: "esm", sourcemap: true },
  },
  {
    input: "./src/index.ts",
    external,
    plugins: plugins(),
    output: { file: "./dist/index.cjs", format: "cjs", sourcemap: true, exports: "named" },
  },
  {
    input: "./src/global.ts",
    plugins: plugins(),
    output: { file: "./dist/NeuraiSilentPayments.global.js", format: "iife", name: "NeuraiSilentPaymentsBundle", sourcemap: true },
  },
  {
    input: "./src/index.ts",
    plugins: [dts()],
    output: [
      { file: "./dist/index.d.ts", format: "esm" },
      { file: "./dist/index.d.cts", format: "esm" },
    ],
  },
];
