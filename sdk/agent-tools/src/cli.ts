#!/usr/bin/env node
// code402 — one CLI for every code402 service surface. Enterprise rules:
//  - keys ONLY from env (never argv, never logged, never stored, format-checked)
//  - spend cap defaults to 0; mainnet needs explicit opt-in; idempotent retries supported
//  - HTTPS-only origins; every network call has a timeout; no telemetry, ever
//  - results on stdout, errors on stderr; exit 0 ok / 1 service failure / 2 usage
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createCode402Client } from "./client.js";
import { verifyReceipt } from "./receipt.js";
import type { TypedDataSigner } from "./types.js";

export const VERSION = "0.2.0";
const DEFAULT_BASE = "https://hcrb.in";
const MAX_INPUT_BYTES = 1_000_000;
const DEFAULT_TIMEOUT_MS = 30_000;

// ---------- enterprise helpers (exported for tests) ----------

export function assertHttpsBase(u: string): string {
  let url: URL;
  try { url = new URL(u); } catch { throw new Error(`base URL is not a valid URL: ${u}`); }
  if (url.protocol !== "https:") throw new Error(`base URL must be HTTPS, got ${url.protocol}// — refusing plain-HTTP payment traffic`);
  return url.toString().replace(/\/+$/, "");
}

export function assertKeyFormat(k: string): `0x${string}` {
  if (!/^0x[0-9a-fA-F]{64}$/.test(k)) throw new Error("CODE402_PRIVATE_KEY must be 0x followed by 64 hex chars (secp256k1 private key)");
  return k as `0x${string}`;
}

export function parseJsonArg(s: string | undefined, what: string): Record<string, unknown> {
  if (s === undefined) return {};
  if (s.length > MAX_INPUT_BYTES) throw new Error(`${what} exceeds ${MAX_INPUT_BYTES} bytes — refusing oversized input`);
  let v: unknown;
  try { v = JSON.parse(s); } catch { throw new Error(`${what} is not valid JSON`); }
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error(`${what} must be a JSON object`);
  return v as Record<string, unknown>;
}

export function timedFetch(ms: number): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit) =>
    fetch(input, { ...init, signal: init?.signal ?? AbortSignal.timeout(ms) })) as typeof fetch;
}

// ---------- CLI ----------

const BASE = assertHttpsBase(process.env.CODE402_BASE_URL ?? DEFAULT_BASE);
const NEEDLE_HOME = process.env.NEEDLE3_HOME ?? "C:/.claude/models/needle3";

const usage = `code402 v${VERSION} — one CLI for every code402 service (server: ${BASE})

  RAIL (63 paid tools, x402 USDC on Base)
  code402 tools                                    list the live catalog
  code402 quote <tool> '<input-json>'              show the price (402 challenge), never signs
  code402 call  <tool> '<input-json>' [--max-minor N] [--mainnet] [--idempotency-key K]
                                                   pay per call (CODE402_PRIVATE_KEY in env)
  code402 <tool> '<input-json>'                    shorthand: pays if a key is set, else quotes
  code402 verify <receipt.json>                    verify a receipt offline against the catalog signer

  LOCAL (offline, ours)
  code402 extract "<text>" [--tools schema.json]   needle3 structured extraction, on-device (vault)

  STOREFRONT
  code402 shop                                     list UCP commercial-feed SKUs

  MISC
  code402 version | help                           global flags: --json, --timeout <ms>

  keys: CODE402_PRIVATE_KEY stays in YOUR environment — never an argument, never stored.
  cap defaults to 0 minor units: every payment is an explicit opt-in. No telemetry, ever.`;

function getFlags(args: string[]): { flags: Map<string, string>; bools: Set<string>; pos: string[] } {
  const flags = new Map<string, string>(), bools = new Set<string>(), pos: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === "--json" || a === "--mainnet") bools.add(a);
    else if (a === "--max-minor" || a === "--timeout" || a === "--idempotency-key" || a === "--tools") flags.set(a, args[++i] ?? "");
    else if (a.startsWith("--")) throw new Error(`unknown flag ${a}`);
    else pos.push(a);
  }
  return { flags, bools, pos };
}

function out(data: unknown, json: boolean) {
  if (json || typeof data !== "string") console.log(JSON.stringify(data, null, json ? 2 : 2));
  else console.log(data);
}

async function main() {
  const [cmd0, ...rest0] = process.argv.slice(2);
  const { flags, bools, pos } = getFlags(rest0);
  const json = bools.has("--json");
  const timeout = Number(flags.get("--timeout") ?? DEFAULT_TIMEOUT_MS);
  if (!Number.isInteger(timeout) || timeout < 1000 || timeout > 300_000) throw new Error("--timeout must be 1000..300000 ms");
  const fetchT = timedFetch(timeout);
  const client = createCode402Client({ baseUrl: BASE, maxAmountMinor: 0, fetch: fetchT });
  const cmd = cmd0 ?? "help";

  if (cmd === "help" || cmd === "--help" || cmd === "-h") { console.log(usage); return; }
  if (cmd === "version" || cmd === "--version") { console.log(VERSION); return; }

  if (cmd === "tools") {
    const tools = await client.tools();
    if (json) return out(tools.map((t) => t.name), true);
    console.log(`${tools.length} tools on ${BASE}:`);
    for (const t of tools) console.log(`  ${t.name}`);
    return;
  }

  if (cmd === "shop") {
    const r = await fetchT(`${BASE}/api/autonomous/commercial/feed`, { headers: { accept: "application/json" } });
    if (!r.ok) throw new Error(`feed fetch failed: HTTP ${r.status}`);
    const feed = (await r.json()) as { totalOrders?: number; orders?: any[] };
    if (json) return out(feed, true);
    console.log(`${feed.totalOrders ?? feed.orders?.length ?? 0} SKU(s) on the UCP commercial feed:`);
    for (const o of feed.orders ?? []) console.log(`  $${o.amountUsdc}  ${o.targetName}  [${o.dealId}]\n      ${o.description}`);
    return;
  }

  if (cmd === "score") {
    const [origin] = pos;
    if (!origin) throw new Error("usage: code402 score <https://origin>");
    const { scoreOrigin } = await import("./score.js");
    const card = await scoreOrigin(origin, ((u: string, init?: RequestInit) => fetch(u, { ...init, signal: init?.signal ?? AbortSignal.timeout(timeout) })) as never);
    if (json) return out(card, true);
    console.log(`Agent-Ready Scorecard — ${card.origin}`);
    console.log(`score ${card.score}/100 · grade ${card.grade} · probed ${card.probed_at.slice(0, 10)}`);
    for (const c of card.checks) console.log(`  ${c.ok ? "✓" : "✗"} ${c.label.padEnd(34)} ${c.detail}`);
    if (card.top_fix) console.log(`\ntop fix: ${card.top_fix}`);
    console.log(`\n${card.scope}`);
    return;
  }

  if (cmd === "verify") {
    const [file] = pos;
    if (!file) throw new Error("usage: code402 verify <receipt.json>");
    const receipt = JSON.parse(readFileSync(file, "utf8"));
    const cat = await client.catalog();
    const v = await verifyReceipt(receipt, cat.receipts?.receipt_signing_address);
    out(v, true);
    if (!v.verified) process.exit(1);
    return;
  }

  if (cmd === "extract") {
    const text = pos.join(" ");
    if (!text) throw new Error('usage: code402 extract "<text to extract from>" [--tools schema.json]');
    if (text.length > 32_000) throw new Error("extract input exceeds 32,000 chars");
    const exe = resolve(NEEDLE_HOME, "runtime", "win-x86_64", "needle.exe");
    const model = resolve(NEEDLE_HOME, "needle3.cact");
    const schema = flags.get("--tools") ?? resolve(NEEDLE_HOME, "tools.invoice.json");
    for (const p of [exe, model, schema]) if (!existsSync(p)) throw new Error(`needle3 vault file missing: ${p} (set NEEDLE3_HOME)`);
    const stdout = execFileSync(exe, ["--model", model, "--tools", schema, "--prompt", text, "--max", "200"], { timeout: 120_000, maxBuffer: 4 * 1024 * 1024, encoding: "utf8" });
    const line = stdout.trim().split("\n").pop() ?? "";
    out(JSON.parse(line), true);
    return;
  }

  // rail: quote / call / shorthand
  let tool: string | undefined;
  let mode: "quote" | "call" | "auto" = "auto";
  if (cmd === "quote" || cmd === "call") { mode = cmd; [tool] = pos; }
  else tool = cmd;
  if (!tool) throw new Error("no tool given");
  const input = parseJsonArg(mode === "auto" ? pos[0] : pos[1], "tool input");

  const catalog = await client.catalog();
  const spec = catalog.tools.find((t) => t.name === tool) ?? catalog.tools.find((t) => t.name === tool!.replace(/-/g, "_"));
  if (!spec) throw new Error(`unknown tool "${tool}" — run \`code402 tools\` for the live catalog`);

  const key = process.env.CODE402_PRIVATE_KEY;
  const wantsPay = mode === "call" || (mode === "auto" && !!key);

  if (!wantsPay) {
    const ch = await client.quote(spec.name, input);
    if (!ch) { console.log("free tier — no charge for this call right now"); return; }
    out(ch, true);
    if (mode === "auto") console.error("hint: set CODE402_PRIVATE_KEY to pay and execute");
    return;
  }

  if (!key) throw new Error("CODE402_PRIVATE_KEY is not set — paying requires your own key (never an argument, never stored)");
  const { privateKeyToAccount } = await import("viem/accounts");
  const paying = createCode402Client({
    baseUrl: BASE,
    account: privateKeyToAccount(assertKeyFormat(key)) as unknown as TypedDataSigner,
    maxAmountMinor: flags.get("--max-minor") ?? "0",
    allowMainnet: bools.has("--mainnet"),
    fetch: fetchT,
  });
  const idem = flags.get("--idempotency-key");
  const r = await paying.callTool(spec.name, input, idem ? { idempotencyKey: idem } : {});
  const rv = r.receiptVerification;
  out({ tier: r.tier, paid: r.paid, amountMinor: r.amountMinor, receiptVerified: rv?.verified ?? false, receiptNote: rv?.reason ?? "no receipt verification performed", result: r.result }, true);
  if (!rv?.verified) process.exit(1);
}

const invokedAsScript = process.argv[1] ? resolve(process.argv[1]) === fileURLToPath(import.meta.url) : false;
if (invokedAsScript) main().catch((e) => { console.error(`error: ${e.message}`); process.exit(e.message?.startsWith("usage:") ? 2 : 1); });
