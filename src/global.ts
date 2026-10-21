import NeuraiSilentPayments from "./index.js";

declare global {
  // eslint-disable-next-line no-var
  var NeuraiSilentPayments: typeof import("./index.js").default;
}

globalThis.NeuraiSilentPayments = NeuraiSilentPayments;

export default NeuraiSilentPayments;
