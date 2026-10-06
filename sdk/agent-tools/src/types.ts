/** Minimal shapes. Money is ALWAYS an integer string in minor units (USDC: 6 decimals). */

export interface CatalogTool {
  name: string;
  title?: string;
  description: string;
  call: string; // e.g. "POST /v1/tools/iban-check/call"
  input_schema?: JsonSchema; // legacy snake_case shape
  inputSchema?: JsonSchema; // MCP camelCase shape served by the live rail
  output_schema?: JsonSchema;
  outputSchema?: JsonSchema;
  price_usdc?: number; // floor hint only — the 402 is authoritative
  price_usdc_ceiling?: number;
  example_request?: { input: Record<string, unknown> };
}

export interface Catalog {
  name: string;
  description?: string;
  tools: CatalogTool[];
  receipts?: { receipt_signing_address?: string; format?: string };
  payment?: Record<string, unknown>;
  pricing?: Record<string, unknown>;
}

export type JsonSchema = {
  type?: string;
  properties?: Record<string, JsonSchema & { description?: string; enum?: unknown[] }>;
  required?: string[];
  items?: JsonSchema;
  description?: string;
  [k: string]: unknown;
};

/** What we need out of a 402, whatever dialect the server spoke. */
export interface Challenge {
  amountMinor: string; // integer string
  recipient: `0x${string}`;
  tokenAddress: `0x${string}`;
  chainId: number;
  eip712: { name: string; version: string };
  nonce?: `0x${string}`; // legacy servers pin a nonce; x402 v1/v2 let the payer choose one
  expiresAt?: number; // unix seconds
  maxTimeoutSeconds?: number;
  raw: unknown;
}

export interface Authorization {
  from: `0x${string}`;
  to: `0x${string}`;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: `0x${string}`;
}

export interface Receipt {
  v: string;
  tool: string;
  tool_version: string;
  input_hash: string;
  output_hash: string;
  payer: string;
  recipient: string;
  amount: string;
  nonce: string;
  ts: number;
  tier: string;
  /**
   * Streaming fields. The worker appends `successor|stream_state` to the canonical string whenever
   * either is set (documented in /.well-known/mcp.json under `receipts.canonical`). They were absent
   * from this type and from canonical(), which made every live receipt fail verification — see
   * receipt.ts for the measurement.
   */
  successor?: string;
  stream_state?: string;
  signature?: string;
  signer?: string;
}

export interface ReceiptVerification {
  verified: boolean;
  reason: string;
  recovered?: string;
  expected?: string;
}

export interface CallResult<T = unknown> {
  tool: string;
  result: T;
  tier: "free" | "paid" | string;
  paid: boolean;
  amountMinor: string; // "0" on the free tier
  receipt?: Receipt;
  receiptVerification?: ReceiptVerification;
  settlement?: { settled: boolean; network?: string; tx?: string; reason?: string };
  raw: unknown;
}

/** viem-style local account: `address` + `signTypedData`. */
export interface TypedDataSigner {
  address: `0x${string}`;
  signTypedData(args: {
    domain: { name: string; version: string; chainId: number; verifyingContract: `0x${string}` };
    types: Record<string, { name: string; type: string }[]>;
    primaryType: string;
    message: Record<string, unknown>;
  }): Promise<`0x${string}`>;
}

export interface ClientOptions {
  baseUrl: string;
  /** viem LocalAccount (privateKeyToAccount) or anything with address + signTypedData. Omit for free-tier only. */
  account?: TypedDataSigner;
  /** Hard client-side cap per call, in minor units. Never signs above it. Default "0" = pay nothing. */
  maxAmountMinor?: string | number | bigint;
  /** Allow chain 8453 (Base mainnet). Default false: only Base Sepolia 84532 is signed. */
  allowMainnet?: boolean;
  /** Voucher validity window in seconds (validBefore = now + this). Default 300. */
  validitySeconds?: number;
  /** Optional receipt signer override. Default: read from the catalog's receipts.receipt_signing_address. */
  receiptSigner?: string;
  /** Injected fetch (tests). Default globalThis.fetch. */
  fetch?: typeof fetch;
  /** Injected clock (tests). Default Date.now. */
  now?: () => number;
  /** Price-index origin for the free check_price tool. Default https://index.code402.dev (UNVERIFIED until deployed). */
  priceIndexUrl?: string;
  /** Catalog cache TTL ms. Default 300000. */
  catalogTtlMs?: number;
}

export class CapExceededError extends Error {
  constructor(public readonly askedMinor: string, public readonly capMinor: string, public readonly tool: string) {
    super(`code402: ${tool} asked ${askedMinor} minor units but maxAmountMinor is ${capMinor}; refusing to sign`);
    this.name = "CapExceededError";
  }
}
export class ChainNotAllowedError extends Error {
  constructor(public readonly chainId: number) {
    super(`code402: chain ${chainId} not allowed (set allowMainnet: true for 8453)`);
    this.name = "ChainNotAllowedError";
  }
}
export class NoSignerError extends Error {
  constructor(tool: string) {
    super(`code402: ${tool} requires payment but no account was configured`);
    this.name = "NoSignerError";
  }
}
export class ToolError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string, public readonly retryable: boolean, public readonly body: unknown) {
    super(`code402: ${code} (${status}): ${message}`);
    this.name = "ToolError";
  }
}
