import { b64encode, parseChallenge } from "./challenge.js";
import { verifyReceipt } from "./receipt.js";
import { CapExceededError, ChainNotAllowedError, NoSignerError, ToolError } from "./types.js";
import type { Authorization, CallResult, Catalog, CatalogTool, Challenge, ClientOptions, Receipt } from "./types.js";

const TRANSFER_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

function randomNonce(): `0x${string}` {
  const b = new Uint8Array(32);
  if (!globalThis.crypto?.getRandomValues) throw new Error("code402: WebCrypto unavailable (Node >= 18 required)");
  globalThis.crypto.getRandomValues(b);
  return ("0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")) as `0x${string}`;
}

function toMinor(v: string | number | bigint | undefined): bigint {
  if (v === undefined) return 0n;
  if (typeof v === "bigint") return v;
  if (typeof v === "number") { if (!Number.isInteger(v) || v < 0) throw new Error("maxAmountMinor must be a non-negative integer (minor units)"); return BigInt(v); }
  if (!/^\d+$/.test(v)) throw new Error("maxAmountMinor must be an integer string (minor units)");
  return BigInt(v);
}

export interface Code402Client {
  readonly baseUrl: string;
  readonly maxAmountMinor: string;
  /** Live catalog from /.well-known/mcp.json (cached). Never hardcoded. */
  catalog(): Promise<Catalog>;
  tools(): Promise<CatalogTool[]>;
  /** The full loop: POST → (402 → cap → sign → retry) → verify receipt. */
  callTool<T = unknown>(tool: string, input: Record<string, unknown>, opts?: { idempotencyKey?: string; maxAmountMinor?: string | number | bigint }): Promise<CallResult<T>>;
  /** One unpaid POST; returns the parsed challenge or null on a free-tier 200. Never signs. */
  quote(tool: string, input: Record<string, unknown>): Promise<Challenge | null>;
  /** Free price lookup against the public x402 price index. */
  checkPrice(q: { url?: string; tool?: string }): Promise<unknown>;
}

export function createCode402Client(o: ClientOptions): Code402Client {
  const baseUrl = o.baseUrl.replace(/\/+$/, "");
  const fetchFn = o.fetch ?? globalThis.fetch;
  if (!fetchFn) throw new Error("no fetch available; pass options.fetch");
  const now = o.now ?? (() => Date.now());
  const cap = toMinor(o.maxAmountMinor);
  const validity = o.validitySeconds ?? 300;
  const ttl = o.catalogTtlMs ?? 300_000;
  const priceIndexUrl = (o.priceIndexUrl ?? "https://index.code402.dev").replace(/\/+$/, "");
  let cached: { at: number; catalog: Catalog } | null = null;

  async function catalog(): Promise<Catalog> {
    if (cached && now() - cached.at < ttl) return cached.catalog;
    const r = await fetchFn(`${baseUrl}/.well-known/mcp.json`, { headers: { accept: "application/json" } });
    if (!r.ok) throw new Error(`catalog fetch failed: ${r.status}`);
    const c = (await r.json()) as Catalog;
    if (!Array.isArray(c.tools)) throw new Error("catalog has no tools[]");
    cached = { at: now(), catalog: c };
    return c;
  }

  function callUrl(tool: string, t?: CatalogTool): string {
    const path = t?.call?.replace(/^POST\s+/i, "") ?? `/v1/tools/${tool}/call`;
    return path.startsWith("http") ? path : `${baseUrl}${path}`;
  }

  async function post(url: string, body: unknown, headers: Record<string, string>) {
    const r = await fetchFn(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json", ...headers }, body: JSON.stringify(body) });
    let json: any = null;
    try { json = await r.json(); } catch { json = null; }
    return { status: r.status, headers: r.headers, json };
  }

  function raise(status: number, json: any): never {
    const e = json?.error ?? {};
    throw new ToolError(status, e.code ?? "HTTP_" + status, e.message ?? "request failed", e.retryable ?? (status >= 500 || status === 429), json);
  }

  async function sign(ch: Challenge, tool: string, capForCall: bigint): Promise<string> {
    if (!o.account) throw new NoSignerError(tool);
    const asked = BigInt(ch.amountMinor);
    if (asked > capForCall) throw new CapExceededError(ch.amountMinor, capForCall.toString(), tool);
    if (ch.chainId === 8453 && !o.allowMainnet) throw new ChainNotAllowedError(ch.chainId);
    if (ch.chainId !== 8453 && ch.chainId !== 84532) throw new ChainNotAllowedError(ch.chainId);
    const nowSec = Math.floor(now() / 1000);
    let validBefore = nowSec + validity;
    if (ch.expiresAt && ch.expiresAt < validBefore) validBefore = ch.expiresAt;
    const authorization: Authorization = {
      from: o.account.address, to: ch.recipient, value: ch.amountMinor, validAfter: "0", validBefore: String(validBefore), nonce: ch.nonce ?? randomNonce(),
    };
    const signature = await o.account.signTypedData({
      domain: { name: ch.eip712.name, version: ch.eip712.version, chainId: ch.chainId, verifyingContract: ch.tokenAddress },
      types: TRANSFER_TYPES as unknown as Record<string, { name: string; type: string }[]>,
      primaryType: "TransferWithAuthorization",
      message: { ...authorization, value: BigInt(authorization.value), validAfter: 0n, validBefore: BigInt(validBefore) },
    });
    const payload = { x402Version: 1, scheme: "exact", network: `eip155:${ch.chainId}`, payload: { signature, authorization } };
    return b64encode(JSON.stringify(payload));
  }

  async function finish<T>(tool: string, input: Record<string, unknown>, json: any, paid: boolean, cat: Catalog): Promise<CallResult<T>> {
    const receipt: Receipt | undefined = json?.receipt;
    const signer = o.receiptSigner ?? cat.receipts?.receipt_signing_address;
    const receiptVerification = await verifyReceipt(receipt, signer, { input, output: json?.result });
    return { tool, result: json?.result as T, tier: json?.tier ?? (paid ? "paid" : "free"), paid, amountMinor: receipt?.amount ?? (paid ? "?" : "0"), receipt, receiptVerification, settlement: json?.settlement, raw: json };
  }

  return {
    baseUrl,
    maxAmountMinor: cap.toString(),
    catalog,
    tools: async () => (await catalog()).tools,

    async quote(tool, input) {
      const cat = await catalog();
      const r = await post(callUrl(tool, cat.tools.find((t) => t.name === tool)), { input }, {});
      if (r.status === 402) return parseChallenge(402, r.headers, r.json);
      if (r.status === 200) return null;
      raise(r.status, r.json);
    },

    async callTool(tool, input, opts = {}) {
      const cat = await catalog();
      const spec = cat.tools.find((t) => t.name === tool);
      if (!spec) throw new Error(`code402: unknown tool "${tool}" (catalog has: ${cat.tools.map((t) => t.name).join(", ")})`);
      const url = callUrl(tool, spec);
      const body = opts.idempotencyKey ? { input, idempotency_key: opts.idempotencyKey } : { input };
      const hdrs: Record<string, string> = opts.idempotencyKey ? { "idempotency-key": opts.idempotencyKey } : {};
      const first = await post(url, body, hdrs);
      if (first.status === 200) return finish(tool, input, first.json, false, cat);
      if (first.status !== 402) raise(first.status, first.json);
      const ch = parseChallenge(402, first.headers, first.json);
      const capForCall = opts.maxAmountMinor !== undefined ? (toMinor(opts.maxAmountMinor) < cap ? toMinor(opts.maxAmountMinor) : cap) : cap;
      const xPayment = await sign(ch, tool, capForCall);
      const second = await post(url, body, { ...hdrs, "X-PAYMENT": xPayment });
      if (second.status !== 200) raise(second.status, second.json);
      return finish(tool, input, second.json, true, cat);
    },

    async checkPrice(q) {
      const u = new URL(`${priceIndexUrl}/v1/price`);
      if (q.url) u.searchParams.set("url", q.url);
      if (q.tool) u.searchParams.set("tool", q.tool);
      const r = await fetchFn(u.toString(), { headers: { accept: "application/json" } });
      const json = await r.json().catch(() => null);
      if (!r.ok) raise(r.status, json);
      return json;
    },
  };
}
