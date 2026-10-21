/**
 * Error of this library. `reason` is a short, stable identifier. For payment
 * codes and output derivation it is the same text the Neurai node reports
 * (for example "checksum", "network" or "more than 16 payments to one code"),
 * so applications can compare both.
 */
export class SilentPaymentError extends Error {
  readonly reason: string;

  constructor(reason: string, message?: string) {
    super(message ?? reason);
    this.name = "SilentPaymentError";
    this.reason = reason;
  }
}
