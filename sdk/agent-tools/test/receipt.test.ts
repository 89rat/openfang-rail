import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { canonical, verifyReceipt } from "../src/receipt.js";

/**
 * Fixture: a REAL receipt captured from https://hcrb.in on 2026-10-06 during a settled
 * base64url x402 call (tx 0x…, payer 0x2fF40B2b…). It is not hand-written, which is the point —
 * a synthetic receipt would not have carried the streaming field that broke this SDK.
 */
const fx = JSON.parse(
  readFileSync(new URL("./fixtures-live-receipt.json", import.meta.url), "utf8"),
) as { receipt: Record<string, any>; expectedSigner: string };

describe("XDR-1 receipt canonical form", () => {
  it("appends successor|stream_state when the worker sets a stream state", () => {
    // Measured 2026-10-06: canonical() stopped at `tier`, but the worker signs
    // `…|tier|successor|stream_state` whenever a stream state is set, and every live paid receipt
    // carries stream_state="active". The mismatch recovered 0x0AEA435c… instead of the published
    // signer, so this SDK reported verified:false on every paid call.
    expect(fx.receipt.stream_state).toBe("active");
    const c = canonical(fx.receipt as any);
    expect(c.endsWith("|active")).toBe(true);
    expect(c.split("|")).toHaveLength(13); // 11 base fields + successor + stream_state
    expect(c.split("|").slice(0, 11).join("|")).toBe(
      [fx.receipt.v, fx.receipt.tool, fx.receipt.tool_version, fx.receipt.input_hash,
       fx.receipt.output_hash, fx.receipt.payer, fx.receipt.recipient, fx.receipt.amount,
       fx.receipt.nonce, fx.receipt.ts, fx.receipt.tier].join("|"),
    );
  });

  it("keeps the 11-field form when no stream state is set", () => {
    const { successor, stream_state, ...rest } = fx.receipt;
    void successor; void stream_state;
    const c = canonical(rest as any);
    expect(c.split("|")).toHaveLength(11);
    expect(c.endsWith("|paid")).toBe(true);
  });

  // The two cases where a naive "append when the field exists" rule diverges from the sender.
  // worker/src/index.ts `canon` appends only when the flag is TRUTHY and defaults stream_state to
  // "active". A first version of this fix used `!== undefined` / `?? ""` and would have failed both.
  it("omits the pair when stream_state is present but empty (sender treats it as falsy)", () => {
    const c = canonical({ ...fx.receipt, stream_state: "" } as any);
    expect(c.split("|")).toHaveLength(11);
  });

  it("defaults stream_state to 'active' when only successor is set", () => {
    const { stream_state, ...rest } = fx.receipt;
    void stream_state;
    const c = canonical({ ...rest, successor: "0xabc" } as any);
    expect(c.split("|")).toHaveLength(13);
    expect(c.endsWith("|0xabc|active")).toBe(true);
  });
});

describe("XDR-1 receipt verification", () => {
  it("verifies the real live receipt against the published signer", async () => {
    const v = await verifyReceipt(fx.receipt as any, fx.expectedSigner);
    expect(v.verified).toBe(true);
    expect(v.reason).toBe("signature recovers to the published receipt signer");
    expect(String(v.recovered).toLowerCase()).toBe(fx.expectedSigner.toLowerCase());
  });

  it("still refuses a receipt whose signature does not recover to the published signer", async () => {
    const v = await verifyReceipt(fx.receipt as any, "0x0000000000000000000000000000000000000001");
    expect(v.verified).toBe(false);
    expect(v.reason).toBe("recovered signer does not match receipt_signing_address");
  });
});
