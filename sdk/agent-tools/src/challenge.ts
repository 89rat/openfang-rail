import type { Challenge } from "./types.js";

const b64decode = (s: string): string =>
  typeof atob === "function" ? atob(s) : Buffer.from(s, "base64").toString("utf8");
export const b64encode = (s: string): string =>
  typeof btoa === "function" ? btoa(s) : Buffer.from(s, "utf8").toString("base64");

const NETWORK_TO_CHAIN: Record<string, number> = { base: 8453, "base-sepolia": 84532, "eip155:8453": 8453, "eip155:84532": 84532 };

function chainFromNetwork(n: unknown): number | undefined {
  if (typeof n !== "string") return undefined;
  if (n in NETWORK_TO_CHAIN) return NETWORK_TO_CHAIN[n];
  const m = /^eip155:(\d+)$/.exec(n);
  return m ? Number(m[1]) : undefined;
}

function isIntString(s: unknown): s is string { return typeof s === "string" && /^\d+$/.test(s); }

/**
 * Parse a 402 in this order: PAYMENT-REQUIRED header (x402 v2, base64 JSON) →
 * body.accepts[0] (x402 v1) → legacy flat fields (price.amount / amount, recipient, chain_id).
 * Throws when no dialect yields a complete challenge. Never invents a value.
 */
export function parseChallenge(status: number, headers: Headers, body: unknown): Challenge {
  if (status !== 402) throw new Error(`parseChallenge: status ${status} is not 402`);
  const candidates: unknown[] = [];
  const hdr = headers.get("PAYMENT-REQUIRED") || headers.get("payment-required");
  if (hdr) { try { candidates.push(JSON.parse(b64decode(hdr))); } catch { /* ignore malformed header */ } }
  candidates.push(body);

  for (const c of candidates) {
    const o = (c ?? {}) as Record<string, any>;
    const a = Array.isArray(o.accepts) ? o.accepts[0] : undefined;
    if (a && typeof a === "object") {
      const amount = isIntString(a.amount) ? a.amount : isIntString(a.maxAmountRequired) ? a.maxAmountRequired : undefined;
      const chainId = chainFromNetwork(a.network);
      const name = a.extra?.name, version = a.extra?.version;
      if (amount && a.payTo && a.asset && chainId && name && version) {
        return { amountMinor: amount, recipient: a.payTo, tokenAddress: a.asset, chainId, eip712: { name: String(name), version: String(version) },
          nonce: typeof o.nonce === "string" ? (o.nonce as `0x${string}`) : undefined,
          expiresAt: typeof o.expires_at === "number" ? o.expires_at : undefined,
          maxTimeoutSeconds: typeof a.maxTimeoutSeconds === "number" ? a.maxTimeoutSeconds : undefined, raw: c };
      }
    }
  }
  // legacy flat shape (code402 v1 wire, older rails)
  const o = (body ?? {}) as Record<string, any>;
  const amount = isIntString(o.price?.amount) ? o.price.amount : isIntString(o.amount) ? o.amount : undefined;
  const tokenAddress = o.price?.token_address ?? o.token_address ?? o.eip712_domain?.verifyingContract;
  const chainId = o.network?.chain_id ?? o.chain_id ?? o.eip712_domain?.chainId;
  const name = o.eip712?.name ?? o.eip712_domain?.name, version = o.eip712?.version ?? o.eip712_domain?.version;
  if (amount && o.recipient && tokenAddress && typeof chainId === "number" && name && version) {
    return { amountMinor: amount, recipient: o.recipient, tokenAddress, chainId, eip712: { name: String(name), version: String(version) },
      nonce: typeof o.nonce === "string" ? (o.nonce as `0x${string}`) : undefined, expiresAt: typeof o.expires_at === "number" ? o.expires_at : undefined, raw: body };
  }
  throw new Error("parseChallenge: 402 did not carry a complete payment challenge (need amount, payTo/recipient, asset, chain, EIP-712 name+version)");
}
