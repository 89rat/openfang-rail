import { keccak256, stringToBytes, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sign as secpSign } from "viem/accounts";

// Test-only keys. Never used on any chain. Do not reuse.
export const PAYER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;
export const SIGNER_KEY = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba" as const;
export const payer = privateKeyToAccount(PAYER_KEY);
export const receiptSigner = privateKeyToAccount(SIGNER_KEY);

export const USDC_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
export const SELLER = "0xc59c85e661d34084a7769f955d17fd38254a6235";

export const catalog = {
  name: "code402",
  receipts: { format: "XDR-1", receipt_signing_address: receiptSigner.address },
  tools: [
    { name: "iban-check", description: "Validate an IBAN.", call: "POST /v1/tools/iban-check/call", input_schema: { type: "object", required: ["iban"], properties: { iban: { type: "string" } } }, price_usdc: 0.000999, price_usdc_ceiling: 0.004995 },
    { name: "rent-deposit-guard", description: "Deposit safety.", call: "POST /v1/tools/rent-deposit-guard/call", input_schema: { type: "object", required: ["deposit_iban"], properties: { deposit_iban: { type: "string" } } }, price_usdc: 0.02 },
  ],
};

export const kh = (v: unknown) => keccak256(stringToBytes(JSON.stringify(v)));

export function challenge402(amount: string, chainId = 84532) {
  const net = chainId === 8453 ? "base" : "base-sepolia";
  return {
    x402Version: 1,
    accepts: [{ scheme: "exact", network: net, maxAmountRequired: amount, payTo: SELLER, asset: USDC_SEPOLIA, maxTimeoutSeconds: 300, extra: { name: "USDC", version: "2" } }],
    error: "Payment required.",
    recipient: SELLER, amount, token_address: USDC_SEPOLIA, chain_id: chainId, eip712_domain: { name: "USDC", version: "2", chainId, verifyingContract: USDC_SEPOLIA },
  };
}

export async function signedReceipt(core: Record<string, unknown>, key: `0x${string}` = SIGNER_KEY, tamper = false) {
  const r = { v: "XDR-1", tool_version: "1", tier: "paid", ...core } as any;
  const canon = [r.v, r.tool, r.tool_version, r.input_hash, r.output_hash, r.payer, r.recipient, r.amount, r.nonce, r.ts, r.tier].join("|");
  const digest = keccak256(stringToBytes(canon));
  const sig = await secpSign({ hash: digest, privateKey: key, to: "hex" });
  r.signature = sig;
  if (tamper) r.amount = String(Number(r.amount) + 1);
  return r;
}

/** Mock fetch: catalog GET, then unpaid POST → 402, paid POST (X-PAYMENT) → 200 with a signed receipt. */
export function mockFetch(opts: { amount?: string; chainId?: number; freeFirst?: boolean; signerKey?: `0x${string}`; tamper?: boolean; onPaid?: (hdr: string, body: any) => void } = {}) {
  const amount = opts.amount ?? "999";
  const calls: { url: string; init?: RequestInit }[] = [];
  const f = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const h = (init?.headers ?? {}) as Record<string, string>;
    if (url.endsWith("/.well-known/mcp.json")) return new Response(JSON.stringify(catalog), { status: 200, headers: { "content-type": "application/json" } });
    if (url.includes("/v1/price")) return new Response(JSON.stringify({ endpoint: url, current_quote: { amount: amount, asset: "USDC" }, kind: "quoted" }), { status: 200 });
    const body = JSON.parse(String(init?.body ?? "{}"));
    const tool = /\/v1\/tools\/([^/]+)\/call/.exec(url)?.[1] ?? "unknown";
    const xp = h["X-PAYMENT"] ?? h["x-payment"];
    if (!xp) {
      if (opts.freeFirst) {
        const result = { valid: true };
        const rec = await signedReceipt({ tool, input_hash: kh(body.input), output_hash: kh(result), payer: "free:1.2.3.4", recipient: SELLER, amount: "0", nonce: "0x01", ts: 1, tier: "free" }, opts.signerKey);
        return new Response(JSON.stringify({ tool, result, tier: "free", settlement: { settled: false, reason: "free tier" }, receipt: rec }), { status: 200 });
      }
      return new Response(JSON.stringify(challenge402(amount, opts.chainId)), { status: 402, headers: { "content-type": "application/json" } });
    }
    const payload = JSON.parse(Buffer.from(xp, "base64").toString("utf8"));
    opts.onPaid?.(xp, payload);
    const a = payload.payload.authorization;
    if (a.value !== amount) return new Response(JSON.stringify({ error: { code: "INSUFFICIENT_PAYMENT", message: "value != price", retryable: false } }), { status: 402 });
    const result = { valid: true, normalized: "GB82WEST12345698765432" };
    const rec = await signedReceipt({ tool, input_hash: kh(body.input), output_hash: kh(result), payer: a.from, recipient: a.to, amount: a.value, nonce: a.nonce, ts: 1700000000, tier: "paid" }, opts.signerKey, opts.tamper);
    return new Response(JSON.stringify({ tool, result, tier: "paid", settlement: { settled: true, network: "base-sepolia", tx: "0xabc" }, receipt: rec }), { status: 200 });
  }) as unknown as typeof fetch;
  return { fetch: f, calls };
}

export { toHex };
