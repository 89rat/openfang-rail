// Live smoke battery against PRODUCTION. Maps what the deployed build actually
// supports (endpoints, tools, MCP, payment negatives, receipts, free tier).
// Payment-negative probes carry X-PAYMENT (never consume the free tier) and
// sign with a throwaway key (no funds) — they cannot settle anything.
// Usage: node qa_live.mjs [baseURL]     (default: the prod worker URL)
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

const BASE = process.argv[2] || "https://rail.akrivis.in";
const te = new TextEncoder();
const hb = (h) => { h = h.replace(/^0x/, ""); const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; };
const bh = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0), o = new Uint8Array(n); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };
const wAddr = (h) => { const b = hb(h), w = new Uint8Array(32); w.set(b, 12); return w; };
const wU = (v) => { let x = v; const w = new Uint8Array(32); for (let i = 31; i >= 0; i--) { w[i] = Number(x & 0xffn); x >>= 8n; } return w; };
const H = (s) => keccak_256(te.encode(s));

// discovered from the live x402.json before any paid probe — nothing hardcoded
let USDC = "", RECIP = "", DOMNAME = "USD Coin", CHAIN = 8453;

const req = async (path, { method = "GET", body, headers = {} } = {}) => {
  const r = await fetch(BASE + path, { method, headers: { "content-type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const txt = await r.text(); let b; try { b = JSON.parse(txt); } catch { b = txt; }
  return { s: r.status, b, h: Object.fromEntries(r.headers) };
};

let ok = 0, n = 0; const t = (name, cond, note) => { n++; if (cond) ok++; else console.log("  FAIL  " + name + (note ? `  (${note})` : "")); };
const info = (name, val) => console.log(`  · ${name}: ${typeof val === "string" ? val : JSON.stringify(val)}`);

// ---- throwaway payer (no funds — can never settle; proves checks only) ----
const PAYER_PK = crypto.getRandomValues(new Uint8Array(32));
const PAYER = "0x" + bh(keccak_256(secp256k1.getPublicKey(PAYER_PK, false).slice(1)).slice(12));
function signVoucher({ value = "590", to = RECIP, validAfter = "0", nonce } = {}) {
  const now = Math.floor(Date.now() / 1000);
  nonce = nonce ?? "0x" + bh(crypto.getRandomValues(new Uint8Array(32)));
  const m = { from: PAYER, to, value, validAfter, validBefore: String(now + 300), nonce };
  const dom = keccak_256(cat(H("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"), H(DOMNAME), H("2"), wU(BigInt(CHAIN)), wAddr(USDC)));
  const sh = keccak_256(cat(H("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"), wAddr(m.from), wAddr(m.to), wU(BigInt(m.value)), wU(BigInt(m.validAfter)), wU(BigInt(m.validBefore)), hb(m.nonce)));
  const sig = secp256k1.sign(keccak_256(cat(new Uint8Array([0x19, 0x01]), dom, sh)), PAYER_PK);
  return { ...m, signature: "0x" + bh(sig.toCompactRawBytes()) + (sig.recovery + 27).toString(16).padStart(2, "0") };
}
const xpay = (v) => Buffer.from(JSON.stringify(v)).toString("base64");

// ---- receipt recovery (XDR-1) ----
const canon = (o) => [o.v, o.tool, o.tool_version, o.input_hash, o.output_hash, o.payer, o.recipient, o.amount, o.nonce, o.ts, o.tier].join("|");
const recoverSigner = (o) => { const s = hb(o.signature); let v = s[64]; if (v >= 27) v -= 27; const sig = new secp256k1.Signature(BigInt("0x" + bh(s.slice(0, 32))), BigInt("0x" + bh(s.slice(32, 64)))).addRecoveryBit(v); return "0x" + bh(keccak_256(sig.recoverPublicKey(keccak_256(te.encode(canon(o)))).toRawBytes(false).slice(1)).slice(12)); };

const run = async () => {
  console.log(`live battery -> ${BASE}\n`);
  // ---------- discovery ----------
  let r = await req("/health");
  t("health 200 + ok", r.s === 200 && r.b.ok === true);
  info("deployed tools", r.b.tools.join(", "));
  info("receipt_signer", r.b.receipt_signer);
  r = await req("/.well-known/x402.json");
  USDC = r.b.token_address; RECIP = r.b.recipient; CHAIN = r.b.network.chain_id; DOMNAME = r.b.eip712_domain.name;
  t("x402.json production/base/mainnet USDC", r.b.environment === "production" && CHAIN === 8453 && /8335/.test(USDC));
  info("advertised price_minor", r.b.price_minor);
  info("settlement", r.b.settlement);
  r = await req("/.well-known/mcp.json");
  t("mcp.json tools listed", Array.isArray(r.b.tools) && r.b.tools.length >= 7);
  info("mcp.json pricing", r.b.pricing);
  info("per-tool prices in manifest", r.b.tools.every(x => x.price_usdc !== undefined) ? "yes" : "NO (flat build)");
  r = await req("/llms.txt");
  t("llms.txt 200", r.s === 200 && /openfang-rail/.test(String(r.b)));
  r = await req("/");
  info("GET / (homepage)", r.s === 200 ? "200 (homepage served)" : `${r.s}`);
  r = await req("/openapi.json");
  info("GET /openapi.json", r.s === 200 ? `200 (${Object.keys(r.b.paths || {}).length} paths)` : `${r.s}`);
  { const res = await fetch(BASE + "/mcp", { method: "OPTIONS" }); t("OPTIONS /mcp -> 204 + CORS", res.status === 204 && res.headers.get("access-control-allow-origin") === "*"); }
  { const res = await fetch(BASE + "/mcp", { method: "GET" }); info("GET /mcp", `${res.status} (${res.headers.get("allow") ?? "no allow header"})`); }

  // ---------- REST tools (free tier) ----------
  const cases = [
    ["iban-check", { iban: "GB82 WEST 1234 5698 7654 32" }, (b) => b.result.valid === true],
    ["lei-check", { lei: "529900T8BM49AURSDO55" }, (b) => b.result.valid === true],
    ["vat-mod97-check", { vat_number: "BE0417497106" }, (b) => b.result.valid === true],
    ["company-number-format", { company_number: "12345678" }, (b) => b.result.valid === true],
    ["rent-deposit-guard", { deposit_iban: "GB82WEST12345698765432", property_country: "DE", deposit_before_viewing: true }, (b) => b.result.band === "high"],
    ["rental-listing-risk", { payment_irreversible: true, price_below_market_pct: 45 }, (b) => b.result.risk_score > 0],
    ["rental-verdict", { deposit_iban: "DE89370400440532013000", property_country: "DE" }, (b) => b.result.verdict === "clear"],
  ];
  for (const [tool, input, okFn] of cases) {
    const rr = await req(`/v1/tools/${tool}/call`, { method: "POST", body: { input } });
    const good = rr.s === 200 && okFn(rr.b) && rr.b.receipt && recoverSigner(rr.b.receipt).toLowerCase() === rr.b.receipt.signer.toLowerCase();
    t(`REST ${tool} + receipt recovers`, good, `status ${rr.s}`);
  }
  r = await req("/v1/tools/batch-validate/call", { method: "POST", body: { input: { items: [{ tool: "iban-check", value: "GB82 WEST 1234 5698 7654 32" }] } } });
  info("batch-validate on prod", r.s === 200 ? "deployed" : `${r.s} (not deployed)`);

  // ---------- input validation (no quota consumed) ----------
  t("missing required -> 400", (await req("/v1/tools/rental-verdict/call", { method: "POST", body: { input: { property_country: "DE" } } })).s === 400);
  t("non-object input -> 400", (await req("/v1/tools/iban-check/call", { method: "POST", body: { input: "GB82" } })).s === 400);
  t("unknown tool -> 404", (await req("/v1/tools/nope/call", { method: "POST", body: { input: { x: 1 } } })).s === 404);

  // ---------- MCP protocol ----------
  const mcp = (method, params, id = 1) => req("/mcp", { method: "POST", body: { jsonrpc: "2.0", id, method, ...(params ? { params } : {}) } });
  r = await mcp("initialize");
  t("mcp initialize", r.s === 200 && r.b.result.serverInfo.name === "openfang-rail");
  r = await mcp("ping"); t("mcp ping", r.b?.result && Object.keys(r.b.result).length === 0);
  r = await mcp("tools/list");
  t("mcp tools/list >=7 with schemas", r.b.result.tools.length >= 7 && r.b.result.tools.every(x => x.inputSchema));
  r = await mcp("tools/call", { name: "lei-check", arguments: { lei: "529900T8BM49AURSDO55" } });
  t("mcp tools/call ok", r.b.result.isError === false && /"valid":true/.test(r.b.result.content[0].text));
  r = await mcp("tools/call", { name: "nope", arguments: {} });
  t("mcp unknown tool -> error", r.b.error !== undefined);

  // ---------- payment negatives (X-PAYMENT present: no free-tier consumption) ----------
  const ibanBody = { input: { iban: "GB82 WEST 1234 5698 7654 32" } };
  const pay = async (voucher) => req("/v1/tools/iban-check/call", { method: "POST", body: ibanBody, headers: { "X-PAYMENT": typeof voucher === "string" ? voucher : xpay(voucher) } });
  r = await pay(signVoucher({ value: "1" })); t("paid: wrong amount -> PRICE_MISMATCH", r.b.error?.code === "PRICE_MISMATCH", `got ${r.b.error?.code ?? r.s}`);
  r = await pay(signVoucher({ to: "0x0000000000000000000000000000000000000009" })); t("paid: wrong recipient -> RECIPIENT_MISMATCH", r.b.error?.code === "RECIPIENT_MISMATCH");
  r = await pay(signVoucher({ validAfter: String(Math.floor(Date.now() / 1000) + 3600) })); t("paid: not-yet-valid -> EXPIRED", r.b.error?.code === "EXPIRED");
  r = await pay({ ...signVoucher(), signature: "0x" + "00".repeat(65) }); t("paid: bad signature -> BAD_SIGNATURE", r.b.error?.code === "BAD_SIGNATURE");
  r = await pay("!!!not-base64!!!"); t("paid: non-base64 -> MALFORMED_PAYMENT", r.b.error?.code === "MALFORMED_PAYMENT", `got ${r.b.error?.code ?? r.s}`);
  r = await pay({ from: PAYER, to: RECIP, value: "abc", validAfter: "0", validBefore: "9999999999", nonce: "0x" + "11".repeat(32), signature: "0x" + "22".repeat(65) });
  info("non-numeric value on PROD", r.s === 402 ? "clean 402" : `HTTP ${r.s} (500 = uncaught BigInt throw — fixed in local source)`);
  { const v = signVoucher(); const std = { x402Version: 1, scheme: "exact", network: "base", payload: { signature: v.signature, authorization: { from: v.from, to: v.to, value: v.value, validAfter: v.validAfter, validBefore: v.validBefore, nonce: v.nonce } } };
    r = await pay(std);
    info("STANDARD x402 wrapper on PROD", r.s === 200 ? "accepted" : `HTTP ${r.s} ${r.b.error?.code ?? ""} (standard x402 clients cannot pay this build)`);
  }
  r = await pay(signVoucher());
  info("valid unfunded voucher (flat)", `HTTP ${r.s} ${r.b.error?.code ?? ""} ${r.b.error?.message ?? ""} (expected: facilitator balance rejection)`);

  // ---------- free-tier boundary + 402 shape ----------
  let last, calls = 0;
  for (let i = 0; i < 25; i++) { last = await req("/v1/tools/iban-check/call", { method: "POST", body: ibanBody }); calls++; if (last.s === 402) break; }
  if (last.s === 402) {
    info(`free tier exhausted after ${calls} extra calls`);
    t("402: mainnet challenge (8453/USD Coin/mainnet USDC)", last.b.chain_id === 8453 && last.b.eip712_domain?.name === "USD Coin" && last.b.token_address === USDC);
    t("402: recipient + ttl", last.b.recipient === RECIP && (last.b.challenge_ttl_seconds ?? 0) > 0);
    info("402 amount (per-tool on this build)", last.b.amount);
    info("402 standard accepts[] present", Array.isArray(last.b.accepts) ? "yes" : "NO (legacy shape only)");
  } else info(`free tier NOT exhausted after ${calls} calls (last status ${last.s})`);

  console.log(`\n${ok}/${n} live checks passed`);
};
run().catch(e => { console.error("LIVE HARNESS ERROR:", e); process.exit(2); });
