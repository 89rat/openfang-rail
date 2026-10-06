import { keccak256, recoverAddress, toBytes, stringToBytes } from "viem";
import type { Receipt, ReceiptVerification } from "./types.js";

/** Canonical XDR-1 string, exactly as the code402 worker signs it. */
export function canonical(r: Receipt): string {
  const parts: Array<string | number> = [r.v, r.tool, r.tool_version, r.input_hash, r.output_hash, r.payer, r.recipient, r.amount, r.nonce, r.ts, r.tier];
  // Mirrors the sender character for character — worker/src/index.ts `canon`:
  //   if (r.successor || r.stream_state) parts.push(r.successor || "", r.stream_state || "active");
  //
  // Two details matter and are easy to get subtly wrong:
  //   * the pair is appended only when the flag is TRUTHY, so a receipt carrying stream_state: ""
  //     takes the 11-field form;
  //   * stream_state falls back to "active", not to "", when successor is set without it.
  //
  // Measured 2026-10-06 against the live rail: this file had stopped at `tier` entirely, so every
  // paid receipt (stream_state="active") recovered 0x0AEA435c… instead of the published signer
  // 0xa036e2e3… and this SDK reported verified:false on every call. The worker had already fixed the
  // same omission on 2026-09-22 (its comment: "omitting it was the live RECEIPT_INVALID bug") —
  // this SDK held a hand-copied duplicate that drifted.
  if (r.successor || r.stream_state) {
    parts.push(r.successor || "", r.stream_state || "active");
  }
  return parts.join("|");
}

export const hashJson = (v: unknown): `0x${string}` => keccak256(stringToBytes(JSON.stringify(v)));

/**
 * Verify an XDR-1 receipt: secp256k1 over the RAW keccak256 of the canonical string
 * (no EIP-191 prefix). Recovered signer must equal `expectedSigner` (from mcp.json
 * receipts.receipt_signing_address). Optionally also pins input/output hashes.
 */
export async function verifyReceipt(
  r: Receipt | undefined,
  expectedSigner: string | undefined,
  opts: { input?: unknown; output?: unknown } = {},
): Promise<ReceiptVerification> {
  if (!r) return { verified: false, reason: "no receipt in response" };
  if (r.v !== "XDR-1") return { verified: false, reason: `unsupported receipt version ${r.v}` };
  if (!r.signature) return { verified: false, reason: "receipt is unsigned" };
  if (!expectedSigner) return { verified: false, reason: "no receipt_signing_address published by the catalog; cannot verify" };
  let recovered: `0x${string}`;
  try {
    recovered = await recoverAddress({ hash: keccak256(stringToBytes(canonical(r))), signature: toBytes(r.signature as `0x${string}`) });
  } catch (e) {
    return { verified: false, reason: `signature unrecoverable: ${(e as Error).message}` };
  }
  if (recovered.toLowerCase() !== expectedSigner.toLowerCase()) {
    return { verified: false, reason: "recovered signer does not match receipt_signing_address", recovered, expected: expectedSigner };
  }
  if (opts.input !== undefined && hashJson(opts.input) !== r.input_hash) return { verified: false, reason: "input_hash does not match what we sent", recovered, expected: expectedSigner };
  if (opts.output !== undefined && hashJson(opts.output) !== r.output_hash) return { verified: false, reason: "output_hash does not match the returned result", recovered, expected: expectedSigner };
  return { verified: true, reason: "signature recovers to the published receipt signer", recovered, expected: expectedSigner };
}
