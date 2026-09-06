// openfang-rail — honest x402 paid-tool worker (Workers-native).
//
// Sells DETERMINISTIC validators (IBAN/LEI/VAT/UK-company). No scraping.
// - Payment: EIP-3009 voucher bound to (recipient, amount, nonce), single-use.
//   Proven in redteam/{verify_test,noble_verify,redteam}.mjs.
// - Signed receipts: every result carries an XDR-1 receipt signed with the
//   operator's key; anyone can recover the signer and verify offline. Proven in
//   redteam/receipt_test.mjs (4/4, tamper-rejecting).
// - Free tier: first FREE_CALLS_PER_DAY per IP are free (zero-friction on-ramp);
//   above that, the paid x402 path kicks in.
//
// Rule 0: the Promoter deploys, sets RECIPIENT + RECEIPT_SIGNING_KEY (a Secret),
// holds all keys. The worker never holds funds; the voucher authorizes a
// payer->recipient USDC transfer, submitted on-chain by a facilitator.

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

import { consolePage } from "./console";
import { signPage } from "./sign";

export interface Env {
  NONCES: KVNamespace;                 // replay guard + free-tier counters
  CHAIN_ID: string;
  USDC_ADDRESS: string;
  USDC_DOMAIN_NAME: string;            // "USDC" (sepolia) | "USD Coin" (mainnet)
  RECIPIENT: string;
  PRICE_MINOR: string;
  LAUNCH_MODE: string;                 // "true" => zero take-rate launch
  FREE_CALLS_PER_DAY: string;          // e.g. "20"; "0" disables the free tier
  RECEIPT_SIGNING_KEY: string;         // Secret: 32-byte hex — a DEDICATED, non-fund key
  // Delegation binding (all PUBLIC — no private key here):
  AUTHORIZED_BY: string;               // your wallet, e.g. 0x417da74c...
  ATTESTATION: string;                 // the exact string your wallet signed (contains the receipt-signer address)
  ATTESTATION_SIG: string;             // your wallet's EIP-191 signature over ATTESTATION
  // Settlement (optional): an x402 facilitator that submits the payer-signed
  // EIP-3009 transfer on-chain (gas-sponsored). Non-custodial — funds move
  // payer->RECIPIENT directly; the worker never holds them. Unset => verify-only
  // (testnet demo). REQUIRED on mainnet (CHAIN_ID 8453) or paid calls return 503.
  FACILITATOR_URL?: string;            // e.g. https://facilitator.example/  (worker calls {URL}/settle)
  FACILITATOR_AUTH?: string;           // Secret: optional Authorization header value (e.g. "Bearer <token>"); omit for no-auth facilitators
  // Optional failover chain (comma-separated, tried in order on network errors /
  // HTTP 5xx only — payer-specific failures like insufficient_balance are
  // terminal everywhere and are NOT retried elsewhere). Overrides FACILITATOR_URL.
  FACILITATOR_URLS?: string;
  // Dynamic pricing (reverse/Dutch): idle price decays exponentially to the
  // per-tool floor; every SETTLED sale bumps it up, capped. Buyers can snipe the
  // floor by watching GET /health (live prices) or just retrying the 402.
  PRICE_MAX_MULT: string;              // ceiling multiple over floor (e.g. "5")
  PRICE_BUMP: string;                  // sale bump factor (e.g. "1.5")
  PRICE_TAU_SECONDS: string;           // idle decay time constant (e.g. "1800")
  // Public Base RPC for the on-chain tools (default: publicnode). Used by the
  // RPC-backed tools (settlement-history-check, balance-check, erc20-balance,
  // tx-activity, block-info); every other tool stays offline/deterministic.
  RPC_URL?: string;
  REGISTRY_URL?: string;               // optional: cross-link the marketplace in llms.txt/homepage
}

// ---------- byte helpers ----------
const te = new TextEncoder();
const hb = (h: string) => { h = h.replace(/^0x/, ""); const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; };
const bh = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const cat = (...a: Uint8Array[]) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };
const wAddr = (h: string) => { const b = hb(h); const w = new Uint8Array(32); w.set(b, 12); return w; };
const wU = (v: bigint) => { let x = v; const w = new Uint8Array(32); for (let i = 31; i >= 0; i--) { w[i] = Number(x & 0xffn); x >>= 8n; } return w; };
const addrFromPriv = (k: Uint8Array) => "0x" + bh(keccak_256(secp256k1.getPublicKey(k, false).slice(1)).slice(12));

// ---------- EIP-712 / EIP-3009 verification ----------
const DOMAIN_TH = keccak_256(te.encode("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
const TA_TH = keccak_256(te.encode("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"));
function domainSep(name: string, version: string, chainId: bigint, contract: string) {
  return keccak_256(cat(DOMAIN_TH, keccak_256(te.encode(name)), keccak_256(te.encode(version)), wU(chainId), wAddr(contract)));
}
interface Voucher { from: string; to: string; value: string; validAfter: string; validBefore: string; nonce: string; signature: string; }
function voucherDigest(dom: Uint8Array, m: Voucher) {
  const sh = keccak_256(cat(TA_TH, wAddr(m.from), wAddr(m.to), wU(BigInt(m.value)), wU(BigInt(m.validAfter)), wU(BigInt(m.validBefore)), hb(m.nonce)));
  return keccak_256(cat(new Uint8Array([0x19, 0x01]), dom, sh));
}
function recover(dig: Uint8Array, sigHex: string): string | null {
  try {
    const s = hb(sigHex); if (s.length !== 65) return null;
    let v = s[64]; if (v >= 27) v -= 27; if (v !== 0 && v !== 1) return null;
    const sig = new secp256k1.Signature(BigInt("0x" + bh(s.slice(0, 32))), BigInt("0x" + bh(s.slice(32, 64)))).addRecoveryBit(v);
    return "0x" + bh(keccak_256(sig.recoverPublicKey(dig).toRawBytes(false).slice(1)).slice(12));
  } catch { return null; }
}

// ---------- XDR-1 signed receipt (proven in redteam/receipt_test.mjs) ----------
interface ReceiptCore { v: string; tool: string; tool_version: string; input_hash: string; output_hash: string; payer: string; recipient: string; amount: string; nonce: string; ts: number; tier: string; }
const canon = (r: ReceiptCore) => [r.v, r.tool, r.tool_version, r.input_hash, r.output_hash, r.payer, r.recipient, r.amount, r.nonce, r.ts, r.tier].join("|");
function signReceipt(core: ReceiptCore, keyHex: string) {
  const key = hb(keyHex);
  const sig = secp256k1.sign(keccak_256(te.encode(canon(core))), key);
  const v = (sig.recovery + 27).toString(16).padStart(2, "0");
  return { ...core, signature: "0x" + bh(sig.toCompactRawBytes()) + v, signer: addrFromPriv(key) };
}
const kh = (s: string) => "0x" + bh(keccak_256(te.encode(s)));

// ---------- deterministic validators (offline; structure+checksum only) ----------
function mod97(n: string): number { let r = 0; for (let i = 0; i < n.length; i++) r = (r * 10 + (n.charCodeAt(i) - 48)) % 97; return r; }
function toNum(s: string): string | null { let o = ""; for (const ch of s) { const c = ch.charCodeAt(0); if (c >= 48 && c <= 57) o += ch; else if (c >= 65 && c <= 90) o += (c - 55); else return null; } return o; }
function vIBAN(x: string) { const i = x.replace(/\s+/g, "").toUpperCase(); if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(i)) return f("iban", "malformed"); const n = toNum(i.slice(4) + i.slice(0, 4)); if (n === null) return f("iban", "illegal char"); const ok = mod97(n) === 1; return { tool: "iban-check", valid: ok, normalized: i, country: i.slice(0, 2), reason: ok ? "checksum valid" : "checksum failed", scope: "structure+checksum only" }; }
function vLEI(x: string) { const l = x.replace(/\s+/g, "").toUpperCase(); if (!/^[A-Z0-9]{18}[0-9]{2}$/.test(l)) return f("lei", "malformed"); const n = toNum(l); if (n === null) return f("lei", "illegal char"); const ok = mod97(n) === 1; return { tool: "lei-check", valid: ok, normalized: l, reason: ok ? "checksum valid" : "checksum failed", scope: "structure+checksum only" }; }
function vVAT(x: string) { let v = x.replace(/\s+/g, "").toUpperCase(); if (v.startsWith("BE")) v = v.slice(2); if (!/^0[0-9]{9}$/.test(v)) return f("vat_number", "malformed (BE mod-97)"); const ok = parseInt(v.slice(8, 10), 10) === 97 - (parseInt(v.slice(0, 8), 10) % 97); return { tool: "vat-mod97-check", valid: ok, normalized: "BE" + v, reason: ok ? "checksum valid" : "checksum failed", scope: "BE mod-97 only; NOT VIES/other EU formats" }; }
function vUK(x: string) { const n = x.replace(/\s+/g, "").toUpperCase(); const ok = /^([0-9]{8}|[A-Z]{2}[0-9]{6})$/.test(n); return { tool: "company-number-format", valid: ok, normalized: n, reason: ok ? "format valid" : "malformed", scope: "format only; NOT existence" }; }
function f(field: string, reason: string) { return { valid: false, reason, field, scope: "structure+checksum only" }; }

// ---------- batch tier: many checks, ONE payment, ONE signed receipt ----------
// Flat price for up to BATCH_MAX validator checks per call. Honest math on our own
// posted prices: 50 singles = $0.50; one batch = $0.05 (10x cheaper per check at
// full batch) — and 1 round trip + 1 voucher + 1 settlement instead of 50.
const BATCH_MAX = 50;
const BATCH_FNS: Record<string, (v: string) => unknown> = {
  "iban-check": (v) => vIBAN(v), "lei-check": (v) => vLEI(v),
  "vat-mod97-check": (v) => vVAT(v), "company-number-format": (v) => vUK(v),
  "swift-bic-check": (v) => vSWIFT(v), "aba-routing-check": (v) => vABA(v),
  "ein-format-check": (v) => vEIN(v), "ifsc-check": (v) => vIFSC(v),
  "abn-check": (v) => vABN(v), "luhn-check": (v) => vLuhn(v),
  "isbn-check": (v) => vISBN(v), "e164-check": (v) => vE164(v), "sedol-check": (v) => vSEDOL(v),
};
function vBatch(input: any) {
  const items = Array.isArray(input?.items) ? input.items : null;
  if (!items || items.length === 0) return { tool: "batch-validate", count: 0, results: [], error: `items[] required (1-${BATCH_MAX} of {tool, value})`, scope: "batch of deterministic checks" };
  if (items.length > BATCH_MAX) return { tool: "batch-validate", count: 0, results: [], error: `too many items (max ${BATCH_MAX} per call)`, scope: "batch of deterministic checks" };
  const results = items.map((it: any, i: number) => {
    const fn = BATCH_FNS[String(it?.tool ?? "")];
    if (!fn) return { i, tool: it?.tool ?? null, valid: false, reason: `unknown tool (allowed: ${Object.keys(BATCH_FNS).join(", ")})` };
    return { i, ...(fn(String(it?.value ?? "")) as object) };
  });
  const valid_count = results.filter((r: any) => r.valid === true).length;
  return { tool: "batch-validate", count: results.length, valid_count, invalid_count: results.length - valid_count, results, scope: "structure+checksum only; same engines as the single-check tools" };
}

// ---------- rental due-diligence (deterministic, explainable; ported from rental/rental.mjs, 12/12 tested) ----------
const cc = (s: any) => String(s ?? "").trim().toUpperCase().slice(0, 2);
const rBand = (s: number) => (s >= 50 ? "high" : s >= 25 ? "elevated" : "low");
const rRec = (s: number) => (s >= 50 ? "do not pay; verify landlord and property independently first" : s >= 25 ? "proceed with caution; insist on in-person viewing and a traceable payment" : "no strong fraud signals in supplied inputs; still verify ownership, never pay before viewing");
function rentDepositGuard(input: any) {
  const iban: any = vIBAN(String(input?.deposit_iban ?? ""));
  const propCC = cc(input?.property_country);
  const flags: any[] = [];
  if (!iban.valid) flags.push({ flag: "deposit_iban_invalid", weight: 30, note: `deposit IBAN ${iban.reason}` });
  if (iban.valid && propCC && iban.country !== propCC) flags.push({ flag: "deposit_country_mismatch", weight: 25, note: `deposit IBAN is ${iban.country}, property is ${propCC}` });
  if (input?.deposit_before_viewing === true) flags.push({ flag: "deposit_before_viewing", weight: 30, note: "deposit demanded before a viewing" });
  const score = Math.min(100, flags.reduce((s, x) => s + x.weight, 0));
  return { tool: "rent-deposit-guard", deposit_iban_valid: iban.valid, iban_country: iban.country ?? null, property_country: propCC || null, country_match: iban.valid && propCC ? iban.country === propCC : null, risk_score: score, band: rBand(score), flags, scope: "IBAN structure+checksum and country alignment only; NOT ownership/existence" };
}
const LISTING_RULES: [string, number, string][] = [
  ["payment_irreversible", 25, "paid via crypto/gift card/wire-only (no chargeback)"],
  ["contact_moves_offplatform", 15, "pushed off the listing platform"],
  ["landlord_abroad_cannot_meet", 15, "landlord 'abroad', cannot show in person"],
  ["no_in_person_viewing", 20, "no in-person/video viewing before payment"],
  ["urgency_pressure", 10, "pressure to secure today"],
  ["photos_reverse_image_hit", 20, "listing photos found elsewhere (stolen)"],
  ["identity_docs_requested_upfront", 10, "full ID/bank docs demanded before viewing"],
];
function rentalListingRisk(input: any) {
  const flags: any[] = [];
  for (const [key, weight, note] of LISTING_RULES) if (input?.[key] === true) flags.push({ flag: key, weight, note });
  const pct = Number(input?.price_below_market_pct);
  if (Number.isFinite(pct) && pct >= 20) { const w = Math.min(25, Math.round((pct - 20) / 2) + 10); flags.push({ flag: "price_below_market", weight: w, note: `asking rent ~${pct}% below market` }); }
  const score = Math.min(100, flags.reduce((s, x) => s + x.weight, 0));
  return { tool: "rental-listing-risk", risk_score: score, band: rBand(score), flags_fired: flags, recommendation: rRec(score), scope: "explainable rule engine over caller-supplied signals; deterministic, no ML, no scraping" };
}
function landlordEntity(input: any) {
  if (input?.landlord_lei != null) { const r: any = vLEI(String(input.landlord_lei)); return { checked: true, kind: "lei", valid: r.valid, reason: r.reason }; }
  if (input?.landlord_company_no != null) { const r: any = vUK(String(input.landlord_company_no)); return { checked: true, kind: "uk_company_no", valid: r.valid, reason: r.reason }; }
  return { checked: false, valid: null, reason: "no landlord entity id supplied" };
}
function rentalVerdict(input: any) {
  const deposit: any = rentDepositGuard(input); const listing: any = rentalListingRisk(input); const entity: any = landlordEntity(input);
  let score = Math.max(deposit.risk_score, listing.risk_score);
  const allFlags: any[] = [...deposit.flags, ...listing.flags_fired];
  if (entity.checked && !entity.valid) { score = Math.min(100, score + 15); allFlags.push({ flag: "landlord_entity_unverified", weight: 15, note: entity.reason }); }
  const top = allFlags.slice().sort((a, b) => b.weight - a.weight).slice(0, 3).map((x) => x.flag);
  return { tool: "rental-verdict", verdict: score >= 50 ? "high-risk" : score >= 25 ? "caution" : "clear", risk_score: score, band: rBand(score), components: { deposit, listing, landlord_entity: entity }, flags: allFlags, summary: `${rBand(score)} risk (${score}/100)` + (top.length ? ` — top: ${top.join(", ")}` : " — no red flags in supplied inputs"), scope: "deterministic due-diligence over checksum facts + caller signals; a decision aid, not a guarantee" };
}

// ---------- more deterministic validators (same discipline: offline, structure+checksum only) ----------
function vSWIFT(x: string) { const s = x.replace(/[\s-]+/g, "").toUpperCase(); const ok = /^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(s); return { tool: "swift-bic-check", valid: ok, normalized: s, country: ok ? s.slice(4, 6) : undefined, reason: ok ? "BIC/SWIFT format valid (ISO 9362 structure)" : "malformed", scope: "structure only; NOT bank existence or live network membership" }; }
function vABA(x: string) { const d = x.replace(/\D/g, ""); if (!/^\d{9}$/.test(d)) return f("aba_routing", "malformed (9 digits required)"); let sum = 0; for (let i = 0; i < 9; i++) sum += Number(d[i]) * [3, 7, 1][i % 3]; const ok = sum % 10 === 0; return { tool: "aba-routing-check", valid: ok, normalized: d, country: "US", reason: ok ? "ABA mod-10 checksum valid (3,7,1 weights)" : "checksum failed", scope: "checksum only; NOT ABA registry membership (some valid-structure numbers are unassigned)" }; }
function vEIN(x: string) { const e = x.replace(/[\s-]+/g, "").toUpperCase(); const ok = /^\d{9}$/.test(e); return { tool: "ein-format-check", valid: ok, normalized: ok ? e.slice(0, 2) + "-" + e.slice(2) : e, country: "US", reason: ok ? "EIN format valid (NN-NNNNNNN)" : "malformed (9 digits required)", scope: "format only; the IRS publishes NO public EIN checksum and NOT existence" }; }
function vIFSC(x: string) { const s = x.replace(/\s+/g, "").toUpperCase(); const ok = /^[A-Z]{4}0[A-Z0-9]{6}$/.test(s); return { tool: "ifsc-check", valid: ok, normalized: s, country: "IN", reason: ok ? "IFSC format valid (BBBB0NNNNNN; 5th char always 0)" : "malformed", scope: "RBI structure only; NOT branch existence" }; }
function vABN(x: string) { const d = x.replace(/\D/g, ""); if (!/^\d{11}$/.test(d)) return f("abn", "malformed (11 digits required)"); const w = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19]; let sum = (Number(d[0]) - 1) * 10; for (let i = 1; i < 11; i++) sum += Number(d[i]) * w[i - 1]; const ok = sum % 89 === 0; return { tool: "abn-check", valid: ok, normalized: d, country: "AU", reason: ok ? "ABN mod-89 checksum valid" : "checksum failed", scope: "checksum only; NOT ABR registration status" }; }
function vLuhn(x: string) { const d = x.replace(/[\s-]+/g, ""); if (!/^\d{12,19}$/.test(d)) return f("number", "malformed (12-19 digits required)"); let sum = 0, alt = false; for (let i = d.length - 1; i >= 0; i--) { let n = Number(d[i]); if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; } const ok = sum % 10 === 0; return { tool: "luhn-check", valid: ok, normalized: d, reason: ok ? "Luhn mod-10 checksum valid" : "checksum failed", scope: "checksum only; NOT card validity, brand, or account status — never submit real card numbers" }; }
function vISBN(x: string) { const s = x.replace(/[\s-]+/g, "").toUpperCase(); if (/^\d{9}[\dX]$/.test(s)) { let sum = 0; for (let i = 0; i < 10; i++) sum += (s[i] === "X" ? 10 : Number(s[i])) * (i + 1); const ok = sum % 11 === 0; return { tool: "isbn-check", valid: ok, normalized: s, reason: ok ? "ISBN-10 mod-11 checksum valid" : "checksum failed", scope: "checksum only; NOT registration or in-print status" }; } if (/^\d{13}$/.test(s)) { let sum = 0; for (let i = 0; i < 13; i++) sum += Number(s[i]) * (i % 2 === 0 ? 1 : 3); const ok = sum % 10 === 0; return { tool: "isbn-check", valid: ok, normalized: s, reason: ok ? "ISBN-13 mod-10 checksum valid (1,3 weights)" : "checksum failed", scope: "checksum only; NOT registration or in-print status" }; } return f("isbn", "malformed (ISBN-10 or ISBN-13 required)"); }
function vE164(x: string) { const s = x.replace(/[\s()\-.]/g, ""); const ok = /^\+[1-9]\d{7,14}$/.test(s); return { tool: "e164-check", valid: ok, normalized: s, reason: ok ? "E.164 structure valid (+CC, 8-15 total digits, no leading 0)" : "malformed", scope: "structure only; NOT country-code assignment, number allocation, or reachability" }; }
function vSEDOL(x: string) { const s = x.replace(/\s+/g, "").toUpperCase(); if (!/^[0-9B-Z1-9]{7}$/.test(s) || /[AEIOU]/.test(s.slice(0, 6))) return f("sedol", "malformed (7 chars, digits + consonants B-Z only)"); const val = (c: string) => (c.charCodeAt(0) <= 57 ? Number(c) : c.charCodeAt(0) - 55); let sum = 0; const w = [1, 3, 1, 7, 3, 9]; for (let i = 0; i < 6; i++) sum += val(s[i]) * w[i]; const ok = (10 - (sum % 10)) % 10 === val(s[6]); return { tool: "sedol-check", valid: ok, normalized: s, reason: ok ? "SEDOL mod-10 checksum valid (1,3,1,7,3,9 weights)" : "checksum failed", scope: "checksum only; NOT security existence or reference-data match" }; }

// ---------- vendor-onboarding-pack: one call, one receipt, the whole ID sweep ----------
// The named outcome buyers search for: "screen this vendor's identifiers" —
// IBAN + LEI + VAT + UK company number in one signed response.
function vPack(input: any) {
  const parts: [string, string, (v: string) => any][] = [["iban", "iban", vIBAN], ["lei", "lei", vLEI], ["vat_number", "vat_number", vVAT], ["company_number", "company_number", vUK]];
  const results = parts.filter(([k]) => input?.[k] != null && input?.[k] !== "").map(([k, field, fn]) => { const r: any = fn(String(input[k])); return { field: k, valid: r.valid === true, reason: r.reason, ...(r.normalized ? { normalized: r.normalized } : {}), ...(r.country ? { country: r.country } : {}) }; });
  if (!results.length) return { tool: "vendor-onboarding-pack", checked_count: 0, all_valid: false, results: [], error: "supply at least one of: iban, lei, vat_number, company_number", scope: "bundled deterministic identifier checks; one call, one payment, one receipt" };
  const all = results.every((r) => r.valid);
  return { tool: "vendor-onboarding-pack", checked_count: results.length, all_valid: all, verdict: all ? "all supplied identifiers structurally valid" : "one or more identifiers failed", results, scope: "structure+checksum only per identifier; NOT registry existence, sanctions, or beneficial ownership" };
}

// ---------- settlement-history-check: the ONE tool that looks on-chain ----------
// Lane-3 (counterparty proof), honestly scoped: counts USDC transfers sent/received
// by an address over a recent on-chain window via a public RPC. NOT full history,
// NOT solvency, NOT intent. Preflighted BEFORE payment so an RPC outage never
// charges a payer for nothing.
const DEFAULT_RPC = "https://base-rpc.publicnode.com";
const ERC20_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
async function rpcCall(url: string, method: string, params: unknown[]): Promise<any> {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j: any = await r.json().catch(() => null);
  if (!j || j.error || j.result === undefined) throw new Error("rpc error");
  return j.result;
}
async function rpcUp(url: string): Promise<boolean> { try { await rpcCall(url, "eth_blockNumber", []); return true; } catch { return false; } }
// EIP-1271 boundary: a contract wallet (smart account) signs with isValidSignature,
// which is not secp256k1-recoverable, so `from` has code and its signature can only be
// judged on-chain. Fail closed: an unreadable/absent code result is treated as "not a
// contract", so the EOA recovery path below remains the strict default.
async function isContract(env: Env, address: string): Promise<boolean> {
  try {
    const code = await rpcCall(env.RPC_URL || DEFAULT_RPC, "eth_getCode", [address, "latest"]);
    return typeof code === "string" && code !== "0x" && code.length > 2;
  } catch { return false; }
}
async function vSettlementHistory(x: string, env: Env) {
  const a = x.replace(/\s+/g, "").toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(a)) return { tool: "settlement-history-check", valid: false, reason: "malformed EVM address (0x + 40 hex)", scope: "on-chain USDC activity over a recent window" };
  const rpc = env.RPC_URL || DEFAULT_RPC;
  const usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".toLowerCase();
  const tip = parseInt(await rpcCall(rpc, "eth_blockNumber", []), 16);
  const from = "0x" + Math.max(0, tip - 86400).toString(16); // ~48h at 2s blocks
  const padded = "0x" + a.slice(2).padStart(64, "0");
  const agg = (logs: any[]) => { let vol = 0n; for (const l of logs) vol += BigInt(l.data); return { count: logs.length, volume_usdc: Number(vol) / 1e6, sample_txs: logs.slice(0, 5).map((l) => l.transactionHash) }; };
  const [outLogs, inLogs] = await Promise.all([
    rpcCall(rpc, "eth_getLogs", [{ fromBlock: from, toBlock: "latest", address: usdc, topics: [ERC20_TRANSFER, padded] }]),
    rpcCall(rpc, "eth_getLogs", [{ fromBlock: from, toBlock: "latest", address: usdc, topics: [ERC20_TRANSFER, null, padded] }]),
  ]);
  return { tool: "settlement-history-check", valid: true, address: a, window: "~48h of recent blocks (86400)", usdc_sent: agg(Array.isArray(outLogs) ? outLogs : []), usdc_received: agg(Array.isArray(inLogs) ? inLogs : []), rpc: rpc.replace(/^https:\/\//, "").split("/")[0], scope: "recent-window on-chain USDC transfer counts/volume via a public RPC; NOT full lifetime history, NOT solvency, NOT proof of good conduct — absence of activity is not evidence of anything" };
}

// ---------- on-chain intelligence tools (RPC-backed, same discipline as above) ----------
// balance-check / erc20-balance / tx-activity / block-info: honest, point-in-time
// reads against a public RPC. Like settlement-history-check they are preflighted
// BEFORE payment (see RPC_TOOLS in processCall) so an upstream outage 503s for
// free and never charges a payer for nothing. NOT batchable: unlike the offline
// validators, each of these needs live RPC state per input.
const RPC_TOOLS = new Set(["settlement-history-check", "balance-check", "erc20-balance", "tx-activity", "block-info"]);
const BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"; // Base mainnet USDC
const BALANCE_OF_SEL = "0x70a08231"; // balanceOf(address)
const DECIMALS_SEL = "0x313ce567";   // decimals()
// Fallback decimals for well-known tokens when a contract does not expose
// decimals() (rare). Anything unknown assumes 18; provenance is always reported.
const COMMON_DECIMALS: Record<string, number> = {
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": 6,  // USDC (Base)
  "0x4200000000000000000000000000000000000006": 18, // WETH (Base)
  "0x50c5725949a6f0c72e6c4a641774d973ae808220": 18, // DAI (Base)
  "0xcbb7c0000ab88b473b1f5afd9ef808440eed33bf": 8,  // cbBTC (Base)
};
const isAddr = (v: unknown) => /^0x[0-9a-fA-F]{40}$/.test(String(v ?? "").trim());
const normAddr = (v: unknown) => String(v ?? "").trim().toLowerCase();
const rpcHost = (url: string) => url.replace(/^https:\/\//, "").split("/")[0];
const hexBig = (h: unknown): bigint => { try { const s = String(h ?? "0x0"); return BigInt(s === "0x" || s === "" ? "0x0" : s); } catch { return 0n; } };
const fmtUnits = (raw: bigint, d: number) => Number(raw) / Number(10n ** BigInt(d));
// block id -> eth_getBlockByNumber tag ("latest" for absent); null = malformed.
function normBlock(v: unknown): string | null {
  if (v === undefined || v === null || String(v).trim() === "") return "latest";
  const s = String(v).trim().toLowerCase();
  if (["latest", "earliest", "pending", "finalized", "safe"].includes(s)) return s;
  if (/^0x[0-9a-f]+$/.test(s) && s !== "0x") { const n = BigInt(s); return n <= 2n ** 64n ? "0x" + n.toString(16) : null; }
  if (/^[0-9]+$/.test(s)) { const n = BigInt(s); return n <= 2n ** 64n ? "0x" + n.toString(16) : null; }
  return null;
}
const decFallback = (token: string): { d: number; src: string } =>
  COMMON_DECIMALS[token] !== undefined ? { d: COMMON_DECIMALS[token], src: "common token list (decimals() unavailable)" } : { d: 18, src: "assumed (18) — token does not expose decimals()" };
const rpcDown = (tool: string, scope: string) => ({ tool, valid: false, reason: "upstream RPC unavailable — retry later", retryable: true, scope });

async function vBalance(input: any, env: Env) {
  const a = normAddr(input?.address); const token = normAddr(input?.token_address) || BASE_USDC;
  const scope = "point-in-time ETH + one ERC-20 balance at the latest block via a public RPC; NOT proof of ownership or control of the address, NOT solvency, NOT a price feed, NOT financial advice — balances change every block";
  if (!isAddr(a)) return { tool: "balance-check", valid: false, reason: "malformed EVM address (0x + 40 hex)", scope };
  if (!isAddr(token)) return { tool: "balance-check", valid: false, reason: "malformed token_address (0x + 40 hex)", scope };
  const rpc = env.RPC_URL || DEFAULT_RPC;
  try {
    const [wei, raw, decRaw] = await Promise.all([
      rpcCall(rpc, "eth_getBalance", [a, "latest"]),
      rpcCall(rpc, "eth_call", [{ to: token, data: BALANCE_OF_SEL + a.slice(2).padStart(64, "0") }, "latest"]),
      rpcCall(rpc, "eth_call", [{ to: token, data: DECIMALS_SEL }, "latest"]).catch(() => null),
    ]);
    let { d: decimals, src: decimals_source } = decFallback(token);
    const d = decRaw === null ? NaN : Number(hexBig(decRaw));
    if (Number.isInteger(d) && d >= 0 && d <= 77) { decimals = d; decimals_source = "erc20 decimals()"; }
    const eth = hexBig(wei); const bal = hexBig(raw);
    return { tool: "balance-check", valid: true, address: a,
      native: { symbol: "ETH", balance_wei: eth.toString(), balance: fmtUnits(eth, 18) },
      token: { address: token, balance_raw: bal.toString(), decimals, decimals_source, balance: fmtUnits(bal, decimals) },
      rpc: rpcHost(rpc), scope };
  } catch { return rpcDown("balance-check", scope); }
}

async function vErc20(input: any, env: Env) {
  const a = normAddr(input?.address); const token = normAddr(input?.token_address);
  const scope = "raw ERC-20 balanceOf at the latest block via a public RPC; NOT a price feed, NOT financial advice; decimals are read from the token when possible and otherwise assumed (see decimals_source)";
  if (!isAddr(a) || !isAddr(token)) return { tool: "erc20-balance", valid: false, reason: "malformed address/token_address (0x + 40 hex each)", scope };
  let decimals: number | null = null; let decimals_source = "";
  if (input?.decimals !== undefined && input?.decimals !== null && input?.decimals !== "") {
    const d = Number(input.decimals);
    if (!Number.isInteger(d) || d < 0 || d > 77) return { tool: "erc20-balance", valid: false, reason: "decimals must be an integer 0-77", scope };
    decimals = d; decimals_source = "caller-supplied";
  }
  const rpc = env.RPC_URL || DEFAULT_RPC;
  try {
    const raw = await rpcCall(rpc, "eth_call", [{ to: token, data: BALANCE_OF_SEL + a.slice(2).padStart(64, "0") }, "latest"]);
    if (decimals === null) {
      let fb = decFallback(token);
      try {
        const d = Number(hexBig(await rpcCall(rpc, "eth_call", [{ to: token, data: DECIMALS_SEL }, "latest"])));
        if (Number.isInteger(d) && d >= 0 && d <= 77) fb = { d, src: "erc20 decimals()" };
      } catch { /* non-standard token — keep the fallback */ }
      decimals = fb.d; decimals_source = fb.src;
    }
    const bal = hexBig(raw);
    return { tool: "erc20-balance", valid: true, address: a, token_address: token, balance_raw: bal.toString(), decimals, decimals_source, balance: fmtUnits(bal, decimals), rpc: rpcHost(rpc), scope };
  } catch { return rpcDown("erc20-balance", scope); }
}

async function vTxActivity(input: any, env: Env) {
  const a = normAddr(input?.address);
  const scope = "outbound transaction count (nonce) + contract-code check at the latest block via a public RPC; NOT full transaction history, NOT incoming-transfer counts, NOT proof of identity, activity, or good conduct";
  if (!isAddr(a)) return { tool: "tx-activity", valid: false, reason: "malformed EVM address (0x + 40 hex)", scope };
  const rpc = env.RPC_URL || DEFAULT_RPC;
  try {
    const [nonceHex, code] = await Promise.all([
      rpcCall(rpc, "eth_getTransactionCount", [a, "latest"]),
      rpcCall(rpc, "eth_getCode", [a, "latest"]),
    ]);
    const txCount = Number(hexBig(nonceHex));
    const c = String(code ?? "0x").toLowerCase();
    return { tool: "tx-activity", valid: true, address: a, tx_count: txCount, is_contract: c !== "0x" && c !== "",
      first_funded_heuristic: txCount > 0,
      first_funded_note: txCount > 0 ? "nonce > 0: the address has SENT at least one transaction, so it was funded and active at some point" : "nonce 0: the address has never sent a transaction (received-only, or untouched)",
      rpc: rpcHost(rpc), scope };
  } catch { return rpcDown("tx-activity", scope); }
}

async function vBlockInfo(input: any, env: Env) {
  const tag = normBlock(input?.block);
  const scope = "one block header (number, timestamp, tx count, base fee) via a public RPC; NOT a price feed, NOT market data, NOT per-transaction gas paid";
  if (tag === null) return { tool: "block-info", valid: false, reason: "block must be hex (0x…), decimal, or a tag (latest/earliest/pending/finalized/safe)", scope };
  const rpc = env.RPC_URL || DEFAULT_RPC;
  try {
    const b = await rpcCall(rpc, "eth_getBlockByNumber", [tag, false]);
    if (!b || typeof b !== "object") return { tool: "block-info", valid: false, reason: `block '${tag}' not found`, scope };
    const ts = Number(hexBig(b.timestamp));
    return { tool: "block-info", valid: true, block: tag, block_number: Number(hexBig(b.number)), block_number_hex: b.number,
      timestamp: ts, timestamp_iso: new Date(ts * 1000).toISOString(),
      tx_count: Array.isArray(b.transactions) ? b.transactions.length : 0,
      base_fee_per_gas_wei: b.baseFeePerGas ? hexBig(b.baseFeePerGas).toString() : null,
      base_fee_gwei: b.baseFeePerGas ? fmtUnits(hexBig(b.baseFeePerGas), 9) : null,
      rpc: rpcHost(rpc), scope };
  } catch { return rpcDown("block-info", scope); }
}

type ToolSpec = { desc: string; title: string; inputSchema: any; out: any; ex: any; fn: (input: any, env: Env) => any };
const D = (t: any, d: string) => ({ ...t, description: d });
const strSchema = (field: string, d: string) => ({ type: "object", required: [field], properties: { [field]: { type: "string", description: d } } });
const B = { type: "boolean" }; const S = { type: "string" }; const N = { type: "number" };
const VALID_OUT = { type: "object", properties: { tool: S, valid: B, normalized: S, country: S, reason: S, scope: S }, required: ["valid", "reason"] };
const RISK_OUT = { type: "object", properties: { tool: S, risk_score: N, band: { type: "string", enum: ["low", "elevated", "high"] }, flags: { type: "array" }, flags_fired: { type: "array" }, recommendation: S, scope: S }, required: ["risk_score", "band"] };
const VERDICT_OUT = { type: "object", properties: { tool: S, verdict: { type: "string", enum: ["clear", "caution", "high-risk"] }, risk_score: N, band: S, flags: { type: "array" }, components: { type: "object" }, summary: S, scope: S }, required: ["verdict", "risk_score"] };
const TOOLS: Record<string, ToolSpec> = {
  "iban-check": { title: "IBAN check", desc: "Validate an IBAN by ISO 13616 structure and MOD-97-10 checksum (offline, no bank lookup).", inputSchema: strSchema("iban", "IBAN to validate; spaces allowed."), out: VALID_OUT, ex: { iban: "GB82 WEST 1234 5698 7654 32" }, fn: (i) => vIBAN(String(i?.iban ?? "")) },
  "lei-check": { title: "LEI check", desc: "Validate a Legal Entity Identifier (ISO 17442 + ISO 7064 MOD-97-10 check digits).", inputSchema: strSchema("lei", "20-character Legal Entity Identifier."), out: VALID_OUT, ex: { lei: "529900T8BM49AURSDO55" }, fn: (i) => vLEI(String(i?.lei ?? "")) },
  "vat-mod97-check": { title: "VAT check (BE mod-97)", desc: "Structural VAT check (BE mod-97 family).", inputSchema: strSchema("vat_number", "EU VAT id; BE mod-97 checksum (BE prefix optional)."), out: VALID_OUT, ex: { vat_number: "BE0417497106" }, fn: (i) => vVAT(String(i?.vat_number ?? "")) },
  "company-number-format": { title: "UK company-number format", desc: "Validate UK Companies House number format (not existence).", inputSchema: strSchema("company_number", "8 digits, or 2 letters + 6 digits."), out: VALID_OUT, ex: { company_number: "12345678" }, fn: (i) => vUK(String(i?.company_number ?? "")) },
  "rent-deposit-guard": { title: "Rental deposit guard", desc: "Rental deposit safety: IBAN checksum + property/deposit country alignment + pre-viewing flag.", inputSchema: { type: "object", required: ["deposit_iban"], properties: { deposit_iban: D(S, "IBAN the deposit would be paid to."), property_country: D(S, "ISO 3166-1 alpha-2 country of the property, e.g. DE."), deposit_before_viewing: D(B, "True if a deposit is demanded before any viewing.") } }, out: RISK_OUT, ex: { deposit_iban: "GB82WEST12345698765432", property_country: "DE", deposit_before_viewing: true }, fn: (i) => rentDepositGuard(i) },
  "rental-listing-risk": { title: "Rental listing risk", desc: "Explainable rental-fraud risk score over listing red-flag signals (deterministic rule engine).", inputSchema: { type: "object", required: [], properties: { payment_irreversible: D(B, "Paid via crypto/gift-card/wire-only."), contact_moves_offplatform: D(B, "Pushed off the listing platform."), landlord_abroad_cannot_meet: D(B, "Landlord 'abroad', can't meet in person."), no_in_person_viewing: D(B, "No viewing before payment."), urgency_pressure: D(B, "Pressure to secure today."), photos_reverse_image_hit: D(B, "Listing photos found elsewhere (stolen)."), identity_docs_requested_upfront: D(B, "Full ID/bank docs demanded upfront."), price_below_market_pct: D(N, "How far below local market the rent is asked, in percent.") } }, out: RISK_OUT, ex: { payment_irreversible: true, no_in_person_viewing: true, price_below_market_pct: 45 }, fn: (i) => rentalListingRisk(i) },
  "rental-verdict": { title: "Rental verdict", desc: "One combined, signed rental due-diligence verdict: deposit + landlord entity (LEI/company) + listing risk.", inputSchema: { type: "object", required: ["deposit_iban"], properties: { deposit_iban: D(S, "Deposit IBAN."), property_country: D(S, "Property country, ISO alpha-2."), deposit_before_viewing: D(B, "True if a deposit is demanded before any viewing."), landlord_lei: D(S, "Landlord LEI (optional)."), landlord_company_no: D(S, "Landlord UK company number (optional)."), payment_irreversible: D(B, "Payment demanded via crypto/gift-card/wire-only."), contact_moves_offplatform: D(B, "Contact pushed off the listing platform."), no_in_person_viewing: D(B, "No in-person or video viewing before payment."), urgency_pressure: D(B, "Pressure to secure the property today."), price_below_market_pct: D(N, "How far below local market the rent is asked, in percent.") } }, out: VERDICT_OUT, ex: { deposit_iban: "GB82WEST12345698765432", property_country: "DE", deposit_before_viewing: true, landlord_lei: "529900T8BM49AURSDO55" }, fn: (i) => rentalVerdict(i) },
  "batch-validate": { title: "Batch validate (up to 50 checks, one payment)", desc: "Run up to 50 identifier checks (IBAN / LEI / VAT / UK company / SWIFT / ABA / EIN / IFSC / ABN / Luhn / ISBN / E.164 / SEDOL) in ONE paid call: one voucher, one settlement, one signed XDR-1 receipt covering the whole batch. Flat price regardless of count — at 50 items, 10x cheaper per check than single calls.", inputSchema: { type: "object", required: ["items"], properties: { items: { type: "array", minItems: 1, maxItems: 50, description: "List of {tool, value} checks (max 50).", items: { type: "object", required: ["tool", "value"], properties: { tool: { type: "string", enum: ["iban-check", "lei-check", "vat-mod97-check", "company-number-format", "swift-bic-check", "aba-routing-check", "ein-format-check", "ifsc-check", "abn-check", "luhn-check", "isbn-check", "e164-check", "sedol-check"], description: "which validator to run" }, value: { type: "string", description: "the identifier to check" } } } } } }, out: { type: "object", properties: { tool: S, count: N, valid_count: N, invalid_count: N, results: { type: "array" }, scope: S }, required: ["count", "results"] }, ex: { items: [{ tool: "iban-check", value: "GB82 WEST 1234 5698 7654 32" }, { tool: "lei-check", value: "529900T8BM49AURSDO55" }, { tool: "vat-mod97-check", value: "BE0417497106" }] }, fn: (i) => vBatch(i) },
  "swift-bic-check": { title: "SWIFT/BIC check", desc: "Validate a SWIFT/BIC code by ISO 9362 structure (bank code, ISO country, location, optional branch).", inputSchema: strSchema("bic", "SWIFT/BIC code, 8 or 11 characters; spaces/dashes allowed."), out: VALID_OUT, ex: { bic: "DEUTDEFF500" }, fn: (i) => vSWIFT(String(i?.bic ?? "")) },
  "aba-routing-check": { title: "ABA routing check (US)", desc: "Validate a US ABA routing number by its (3,7,1)-weight mod-10 checksum.", inputSchema: strSchema("aba_routing", "9-digit US bank routing number."), out: VALID_OUT, ex: { aba_routing: "021000021" }, fn: (i) => vABA(String(i?.aba_routing ?? "")) },
  "ein-format-check": { title: "EIN format check (US)", desc: "Validate US Employer Identification Number FORMAT (NN-NNNNNNN). No public EIN checksum exists.", inputSchema: strSchema("ein", "US EIN, 9 digits; dashes/spaces allowed."), out: VALID_OUT, ex: { ein: "12-3456789" }, fn: (i) => vEIN(String(i?.ein ?? "")) },
  "ifsc-check": { title: "IFSC check (India)", desc: "Validate an Indian IFSC by RBI structure (BBBB0NNNNNN; 5th character always 0).", inputSchema: strSchema("ifsc", "11-character Indian Financial System Code."), out: VALID_OUT, ex: { ifsc: "HDFC0000123" }, fn: (i) => vIFSC(String(i?.ifsc ?? "")) },
  "abn-check": { title: "ABN check (Australia)", desc: "Validate an Australian Business Number by its mod-89 checksum (11 digits).", inputSchema: strSchema("abn", "11-digit Australian Business Number; spaces allowed."), out: VALID_OUT, ex: { abn: "51 824 753 556" }, fn: (i) => vABN(String(i?.abn ?? "")) },
  "luhn-check": { title: "Luhn check", desc: "Validate any 12-19 digit number by the Luhn mod-10 algorithm (card-style checksums). Never submit real card numbers.", inputSchema: strSchema("number", "12-19 digit number; spaces/dashes allowed."), out: VALID_OUT, ex: { number: "4111111111111111" }, fn: (i) => vLuhn(String(i?.number ?? "")) },
  "isbn-check": { title: "ISBN check", desc: "Validate an ISBN-10 (mod-11) or ISBN-13 (1,3-weight mod-10) checksum.", inputSchema: strSchema("isbn", "ISBN-10 or ISBN-13; dashes/spaces allowed."), out: VALID_OUT, ex: { isbn: "978-0-306-40615-7" }, fn: (i) => vISBN(String(i?.isbn ?? "")) },
  "e164-check": { title: "E.164 phone check", desc: "Validate a phone number's E.164 structure (+CC, 8-15 digits, no leading zero).", inputSchema: strSchema("phone", "International phone number, e.g. +14155552671."), out: VALID_OUT, ex: { phone: "+14155552671" }, fn: (i) => vE164(String(i?.phone ?? "")) },
  "sedol-check": { title: "SEDOL check", desc: "Validate a UK/Ireland security identifier by its (1,3,1,7,3,9)-weight mod-10 checksum.", inputSchema: strSchema("sedol", "7-character SEDOL code."), out: VALID_OUT, ex: { sedol: "B0YBKJ7" }, fn: (i) => vSEDOL(String(i?.sedol ?? "")) },
  "vendor-onboarding-pack": { title: "Vendor onboarding pack", desc: "Screen a vendor's identifiers in ONE signed call: IBAN + LEI + VAT + UK company number — each checksummed, one verdict, one receipt. Half the price of four single checks.", inputSchema: { type: "object", required: [], properties: { iban: D(S, "Vendor IBAN (optional)."), lei: D(S, "Vendor LEI (optional)."), vat_number: D(S, "Vendor VAT number, BE mod-97 (optional)."), company_number: D(S, "Vendor UK company number (optional).") } }, out: { type: "object", properties: { tool: S, checked_count: N, all_valid: B, verdict: S, results: { type: "array" }, scope: S }, required: ["checked_count", "all_valid"] }, ex: { iban: "GB82 WEST 1234 5698 7654 32", lei: "529900T8BM49AURSDO55", vat_number: "BE0417497106", company_number: "12345678" }, fn: (i) => vPack(i) },
  "settlement-history-check": { title: "Settlement history (counterparty proof)", desc: "On-chain counterparty check: USDC transfers SENT and RECEIVED by an address over the last ~48h of Base blocks (counts, volumes, sample tx hashes). Preflighted so you never pay during an RPC outage.", inputSchema: strSchema("address", "EVM address, 0x-prefixed."), out: { type: "object", properties: { tool: S, valid: B, address: S, usdc_sent: { type: "object" }, usdc_received: { type: "object" }, scope: S }, required: ["valid", "address"] }, ex: { address: "0xc59c85e661d34084a7769f955d17fd38254a6235" }, fn: (i, env) => vSettlementHistory(String(i?.address ?? ""), env) },
  "balance-check": { title: "Balance check (ETH + token)", desc: "On-chain balance snapshot: native ETH balance plus one ERC-20 token balance (defaults to USDC on Base), with raw units and decimals provenance. Preflighted so you never pay during an RPC outage.", inputSchema: { type: "object", required: ["address"], properties: { address: D(S, "EVM address, 0x-prefixed."), token_address: D(S, "ERC-20 token contract address (optional; defaults to USDC on Base).") } }, out: { type: "object", properties: { tool: S, valid: B, address: S, native: { type: "object" }, token: { type: "object" }, reason: S, retryable: B, scope: S }, required: ["valid", "address"] }, ex: { address: "0xc59c85e661d34084a7769f955d17fd38254a6235" }, fn: (i, env) => vBalance(i, env) },
  "erc20-balance": { title: "ERC-20 balance", desc: "Raw + formatted ERC-20 balanceOf for an address at any token contract (decimals read on-chain when available; common-list/18 fallback is labeled). Preflighted so you never pay during an RPC outage.", inputSchema: { type: "object", required: ["address", "token_address"], properties: { address: D(S, "Holder EVM address, 0x-prefixed."), token_address: D(S, "ERC-20 token contract address, 0x-prefixed."), decimals: D(N, "Token decimals override (optional; default: on-chain decimals(), else common list, else 18).") } }, out: { type: "object", properties: { tool: S, valid: B, address: S, token_address: S, balance_raw: S, decimals: N, decimals_source: S, balance: N, reason: S, retryable: B, scope: S }, required: ["valid", "address", "token_address"] }, ex: { address: "0xc59c85e661d34084a7769f955d17fd38254a6235", token_address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" }, fn: (i, env) => vErc20(i, env) },
  "tx-activity": { title: "Tx activity (count + contract check)", desc: "On-chain activity snapshot for an address: total outbound transaction count (nonce), whether the address is a contract (eth_getCode), and a first-funded heuristic (nonce > 0). Preflighted so you never pay during an RPC outage.", inputSchema: strSchema("address", "EVM address, 0x-prefixed."), out: { type: "object", properties: { tool: S, valid: B, address: S, tx_count: N, is_contract: B, first_funded_heuristic: B, scope: S }, required: ["valid", "address", "tx_count"] }, ex: { address: "0xc59c85e661d34084a7769f955d17fd38254a6235" }, fn: (i, env) => vTxActivity(i, env) },
  "block-info": { title: "Block info", desc: "Latest (or specified) Base block header: number, timestamp, transaction count, base fee. Preflighted so you never pay during an RPC outage.", inputSchema: { type: "object", required: [], properties: { block: D(S, "Block number as hex (0x…) or decimal, or a tag (latest/earliest/pending/finalized/safe); defaults to latest.") } }, out: { type: "object", properties: { tool: S, valid: B, block: S, block_number: N, timestamp: N, timestamp_iso: S, tx_count: N, base_fee_gwei: N, reason: S, retryable: B, scope: S }, required: ["valid", "block_number"] }, ex: { block: "latest" }, fn: (i, env) => vBlockInfo(i, env) },
};
// Per-tool price, USDC minor units (6 dp): 999=$0.000999, 2000=$0.002, 20000=$0.02, 50000=$0.05. Hybrid:
// high-volume basic checks priced for agent adoption ($0.000999 headline); premium/bundle
// tools keep value pricing (~$0.02–0.05). Tune freely; the 402 challenge quotes the tool's
// price and the paid path enforces exactly it.
const TOOL_PRICE: Record<string, number> = {
  "iban-check": 999, "lei-check": 999, "vat-mod97-check": 999, "company-number-format": 999,
  "rent-deposit-guard": 20000, "rental-listing-risk": 20000, "rental-verdict": 50000,
  "swift-bic-check": 999, "aba-routing-check": 999, "ein-format-check": 999, "ifsc-check": 999,
  "abn-check": 999, "luhn-check": 999, "isbn-check": 999, "e164-check": 999, "sedol-check": 999,
  "vendor-onboarding-pack": 20000, // 4 checks bundled at half the single-call price
  "settlement-history-check": 20000, // on-chain counterparty proof
  "balance-check": 999, // on-chain ETH + token balance snapshot
  "erc20-balance": 999, // on-chain ERC-20 balanceOf
  "tx-activity": 999, // on-chain tx count + contract check
  "block-info": 2000, // on-chain block header lookup
  "batch-validate": 50000, // flat batch tier: up to 50 checks for $0.05
};
const TOOL_VERSION = "1.0.0";

// ---------- dynamic pricing: reverse/Dutch descent + demand bumps ----------
// Pure function of KV state {p, t}: p(now) = floor + (p_last - floor)·e^(-Δt/τ),
// clamped to [floor, floor·mult]. A settled sale writes p_next = clamp(paid·bump).
// Idle -> price glides down to the floor (today's flat prices are the WORST case);
// demand -> price steps up. Best-effort: any KV hiccup falls back to the floor.
const dpFloor = (tool: string, env: Env) => TOOL_PRICE[tool] ?? Number(env.PRICE_MINOR || "999");
const dpNum = (v: string | undefined, d: number) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : d; };
async function quotePrice(tool: string, env: Env): Promise<number> {
  const floor = dpFloor(tool, env);
  try {
    const st = await env.NONCES.get("dp:" + tool);
    if (st) {
      const { p, t } = JSON.parse(st) as { p: number; t: number };
      const dt = Math.floor(Date.now() / 1000) - t;
      const q = floor + (Number(p) - floor) * Math.exp(-dt / dpNum(env.PRICE_TAU_SECONDS, 1800));
      return Math.max(floor, Math.min(floor * dpNum(env.PRICE_MAX_MULT, 5), Math.round(q)));
    }
  } catch { /* pricing state is best-effort — never fail a call over it */ }
  return floor;
}
async function bumpPrice(tool: string, env: Env, paid: number) {
  try {
    const floor = dpFloor(tool, env);
    const p = Math.min(floor * dpNum(env.PRICE_MAX_MULT, 5), Math.max(floor, Math.round(paid * dpNum(env.PRICE_BUMP, 1.5))));
    await env.NONCES.put("dp:" + tool, JSON.stringify({ p, t: Math.floor(Date.now() / 1000) }));
  } catch { /* best-effort */ }
}
// The ONE quote used everywhere (processCall AND the /health ticker): batch rides
// the surge — never cheaper than 5 dynamic single checks.
async function quoteFor(tool: string, env: Env): Promise<number> {
  if (tool === "batch-validate") return Math.max(TOOL_PRICE["batch-validate"] ?? 50000, 5 * (await quotePrice("iban-check", env)));
  return quotePrice(tool, env);
}

const cors = () => ({ "access-control-allow-origin": "*", "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "content-type, accept, authorization, x-payment, mcp-session-id, mcp-protocol-version", "access-control-expose-headers": "mcp-session-id", "access-control-max-age": "86400" });
const j = (o: unknown, status = 200, extra: Record<string, string> = {}) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", ...cors(), ...extra } });
const err = (code: string, message: string, status: number, retryable = false) => j({ error: { code, message, retryable } }, status);
const launchOn = (env: Env) => env.LAUNCH_MODE === "true";
const signerAddr = (env: Env) => { try { return addrFromPriv(hb(env.RECEIPT_SIGNING_KEY)); } catch { return null; } };
// facilitator probes for the console: measured server-side, cached 60s per isolate
const facCache: { at: number; rows: { url: string; role: string; status: string; ms: number | null }[] } = { at: 0, rows: [] };
async function probeFacilitators(env: Env) {
  if (Date.now() - facCache.at < 60000) return facCache.rows;
  const urls = (env.FACILITATOR_URLS || env.FACILITATOR_URL || "").split(",").map(x => x.trim()).filter(Boolean);
  const rows = await Promise.all(urls.map(async (u, i) => {
    const s0 = Date.now(); let ok = false;
    try { const r = await fetch(u.replace(/\/+$/, "") + "/supported", { signal: AbortSignal.timeout(2500) }); ok = r.ok; } catch { ok = false; }
    return { url: u, role: i === 0 ? "primary" : "fallback*", status: ok ? "reachable" : "unreachable", ms: Date.now() - s0 };
  }));
  facCache.at = Date.now(); facCache.rows = rows; return rows;
}

function manifest(env: Env) {
  const freeN = parseInt(env.FREE_CALLS_PER_DAY || "0", 10);
  return { version: "1.1.0", name: "openfang-rail",
    license: "MIT",
    repository: "https://github.com/drjsarat/openfang-rail",
    description: "Deterministic business-identifier validation (IBAN/LEI/VAT/UK) + rental due-diligence (deposit-safety, listing-risk, signed verdict), paid per call via x402 (EIP-3009). No scraping, no ML.",
    pricing: { take_rate_bps: launchOn(env) ? 0 : 25, mode: "dynamic-dutch", price_usdc_per_call: "per-tool, dynamic (see tools[].price_usdc floor + price_usdc_ceiling)",
      rule: `idle price decays exponentially to the per-tool floor (tau=${dpNum(env.PRICE_TAU_SECONDS, 1800)}s); every settled sale bumps it x${dpNum(env.PRICE_BUMP, 1.5)}, capped at x${dpNum(env.PRICE_MAX_MULT, 5)} of the floor; GET /health quotes live prices`,
      free_tier: freeN > 0 ? `${freeN} calls/day per client, then paid` : "none" },
    receipts: { format: "XDR-1", signature_scheme: "secp256k1", receipt_signing_address: signerAddr(env),
      canonical: "keccak256 over `v|tool|tool_version|input_hash|output_hash|payer|recipient|amount|nonce|ts|tier`; recover signer to verify",
      authorization: { authorized_by: env.AUTHORIZED_BY, attestation: env.ATTESTATION, attestation_sig: env.ATTESTATION_SIG,
        verify: "recover receipt signer from the receipt; confirm the attestation names that signer and is EIP-191-signed by authorized_by. Then the receipt is provably authorized by the operator wallet — no fund key ever touches the worker." } },
    payment: { protocol: "x402", network: env.CHAIN_ID === "8453" ? "base" : "base-sepolia", asset: "USDC",
      flow: "free tier, then: 402 challenge -> EIP-3009 X-PAYMENT voucher -> 200 + signed receipt" },
    tools: Object.entries(TOOLS).map(([name, s]) => ({ name, title: s.title, description: s.desc, call: `POST /v1/tools/${name}/call`,
      input_schema: s.inputSchema, output_schema: s.out, price_usdc: (TOOL_PRICE[name] || 0) / 1e6, price_usdc_ceiling: ((TOOL_PRICE[name] || 0) * dpNum(env.PRICE_MAX_MULT, 5)) / 1e6, example_request: { input: s.ex } })) };
}

// ---------- Bazaar discovery extension (x402 official discovery layer) ----------
// Declared on every 402 so supporting facilitators (PayAI does: /discovery/resources)
// catalog each tool for agent search. Soft-drop rules protect us: a field the
// facilitator doesn't validate is discarded, the rest is kept.
const SERVICE_TAGS = ["iban", "identity", "rental", "compliance", "validation"];
const outputExample = (tool: string): Record<string, unknown> => {
  if (tool === "batch-validate") return { count: 2, valid_count: 2, invalid_count: 0, results: [] };
  if (tool === "vendor-onboarding-pack") return { checked_count: 4, all_valid: true, results: [] };
  if (tool === "settlement-history-check") return { valid: true, address: "0x0000000000000000000000000000000000000000", usdc_sent: { count: 0, volume_usdc: 0 }, usdc_received: { count: 1, volume_usdc: 1 } };
  if (tool === "balance-check") return { valid: true, address: "0x0000000000000000000000000000000000000000", native: { symbol: "ETH", balance: 0 }, token: { address: "0x0000000000000000000000000000000000000000", balance: 0, decimals: 6 } };
  if (tool === "erc20-balance") return { valid: true, address: "0x0000000000000000000000000000000000000000", token_address: "0x0000000000000000000000000000000000000000", balance_raw: "0", decimals: 6, balance: 0 };
  if (tool === "tx-activity") return { valid: true, address: "0x0000000000000000000000000000000000000000", tx_count: 0, is_contract: false, first_funded_heuristic: false };
  if (tool === "block-info") return { valid: true, block: "latest", block_number: 0, timestamp: 0, tx_count: 0, base_fee_gwei: 0 };
  if (tool === "rental-verdict") return { verdict: "clear", risk_score: 0, band: "low" };
  if (tool.startsWith("rental") || tool.startsWith("rent-")) return { risk_score: 0, band: "low" };
  return { valid: true, reason: "checksum valid" };
};
function bazaarInfo(spec: ToolSpec) {
  return { bazaar: { info: {
    input: { type: "http", method: "POST", body: spec.ex },
    inputSchema: spec.inputSchema,
    output: { example: outputExample(Object.keys(TOOLS).find(k => TOOLS[k] === spec) ?? ""), schema: spec.out },
  } } };
}

// Core tool processing — shared by the REST route AND the MCP /mcp endpoint.
// Returns {status, body, headers?}; identical free-tier + EIP-3009 payment path.
async function processCall(tool: string, input: any, req: Request, env: Env): Promise<{ status: number; body: any; headers?: Record<string, string> }> {
  const spec = TOOLS[tool];
  if (!spec) return { status: 404, body: { error: { code: "TOOL_NOT_FOUND", message: `unknown tool '${tool}'` } } };
  if (!env.RECEIPT_SIGNING_KEY) return { status: 503, body: { error: { code: "NOT_CONFIGURED", message: "RECEIPT_SIGNING_KEY unset" } } };
  const missing = (((spec.inputSchema && spec.inputSchema.required) as string[]) || []).filter((k) => input?.[k] === undefined || input?.[k] === null || input?.[k] === "");
  if (missing.length) return { status: 400, body: { error: { code: "INPUT_SCHEMA_INVALID", message: `missing required input: ${missing.join(", ")}` } } };
  if (tool === "batch-validate") {
    const its = (input as any)?.items;
    if (!Array.isArray(its) || its.length === 0 || its.length > BATCH_MAX) return { status: 400, body: { error: { code: "INPUT_SCHEMA_INVALID", message: `items must be an array of 1-${BATCH_MAX} {tool, value} objects` } } };
  }
  // RPC-backed tools must preflight BEFORE payment: an upstream outage must
  // 503 for free, never charge a payer for nothing. Address-shaped inputs are
  // validated here too, so a malformed address never triggers an RPC call.
  if (RPC_TOOLS.has(tool)) {
    const av = input?.address, tv = input?.token_address;
    if (av !== undefined && av !== null && String(av) !== "" && !isAddr(av)) return { status: 400, body: { error: { code: "INPUT_SCHEMA_INVALID", message: "address must be 0x + 40 hex" } } };
    if (tv !== undefined && tv !== null && String(tv) !== "" && !isAddr(tv)) return { status: 400, body: { error: { code: "INPUT_SCHEMA_INVALID", message: "token_address must be 0x + 40 hex" } } };
    if (tool === "erc20-balance" && input?.decimals !== undefined && input?.decimals !== null && input?.decimals !== "") {
      const d = Number(input.decimals);
      if (!Number.isInteger(d) || d < 0 || d > 77) return { status: 400, body: { error: { code: "INPUT_SCHEMA_INVALID", message: "decimals must be an integer 0-77" } } };
    }
    if (tool === "block-info" && normBlock(input?.block) === null) return { status: 400, body: { error: { code: "INPUT_SCHEMA_INVALID", message: "block must be hex (0x…), decimal, or a tag (latest/earliest/pending/finalized/safe)" } } };
    if (!(await rpcUp(env.RPC_URL || DEFAULT_RPC))) return { status: 503, body: { error: { code: "UPSTREAM_RPC_UNAVAILABLE", message: "public RPC unreachable — not charging for this call; retry later", retryable: true } } };
  }
  const chainId = BigInt(env.CHAIN_ID);
  // Live dynamic quote via the single shared pricing path (matches /health).
  const priceStr = String(await quoteFor(tool, env));
  const priceMinor = BigInt(priceStr);
  const recipient = env.RECIPIENT;
  const nowSec = Math.floor(Date.now() / 1000);
  const ref = (new URL(req.url).searchParams.get("ref") || req.headers.get("x-referrer") || "").slice(0, 64);
  // Payment header by client generation: v1 -> X-PAYMENT; v2 official SDK ->
  // PAYMENT-SIGNATURE (base64 {x402Version, payload:{authorization, signature}}).
  // Accept all spellings; the unwrap below handles both payload shapes.
  const xp = req.headers.get("X-PAYMENT") || req.headers.get("PAYMENT-SIGNATURE") || req.headers.get("PAYMENT");
  let tier = "paid", payer = "", amount = priceStr, nonce = "0x", settled = false, settlementTx = "";

  if (!xp) {
    const freeN = parseInt(env.FREE_CALLS_PER_DAY || "0", 10);
    const ip = req.headers.get("cf-connecting-ip") || "unknown";
    const day = new Date().toISOString().slice(0, 10);
    const fk = `free:${ip}:${day}`;
    const used = parseInt((await env.NONCES.get(fk)) || "0", 10);
    if (freeN > 0 && used < freeN) {
      await env.NONCES.put(fk, String(used + 1), { expirationTtl: 86400 });
      tier = "free"; payer = "free:" + ip; amount = "0"; nonce = kh(fk + ":" + used);
    } else {
      const net = env.CHAIN_ID === "8453" ? "base" : "base-sepolia";
      // v2 requirements (what official @x402 clients parse): CAIP-2 network,
      // full resource URL, base64-encoded into the PAYMENT-REQUIRED header.
      const v2Accepts = [{ scheme: "exact", network: "eip155:" + env.CHAIN_ID, amount: priceStr, maxAmountRequired: priceStr, resource: new URL(req.url).toString(), description: `openfang-rail ${tool}`, mimeType: "application/json", payTo: recipient, maxTimeoutSeconds: 300, asset: env.USDC_ADDRESS, extra: { name: env.USDC_DOMAIN_NAME, version: "2" } }];
      const v2Reqs = { x402Version: 2, accepts: v2Accepts, error: "Payment required. Sign the EIP-3009 authorization and retry with the X-PAYMENT header.", extensions: bazaarInfo(spec) };
      const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");
      return { status: 402, headers: {
        "PAYMENT-REQUIRED": b64(v2Reqs),                       // v2: official clients parse this
        "PAYMENT-OPTIONS": JSON.stringify([{ x402Version: 2, scheme: "exact", network: "eip155:" + env.CHAIN_ID }]),
      }, body: {
        // v1 shape kept in the body for older clients (x402-fetch v1, CDP SDK):
        x402Version: 1,
        accepts: [{ scheme: "exact", network: net, maxAmountRequired: priceStr, resource: new URL(req.url).pathname, description: `openfang-rail ${tool}`, mimeType: "application/json", payTo: recipient, maxTimeoutSeconds: 300, asset: env.USDC_ADDRESS, extra: { name: env.USDC_DOMAIN_NAME, version: "2" } }],
        error: v2Reqs.error,
        // Bazaar discovery: catalogs this tool in the official x402 discovery layer
        resource: { url: new URL(req.url).toString(), description: spec.desc, mimeType: "application/json", serviceName: "openfang-rail", tags: SERVICE_TAGS },
        extensions: bazaarInfo(spec),
        // legacy aliases (older/custom clients):
        x402_version: 1, scheme: "eip3009", asset: "USDC", amount: priceStr, token_address: env.USDC_ADDRESS,
        recipient, chain_id: Number(env.CHAIN_ID),
        eip712_domain: { name: env.USDC_DOMAIN_NAME, version: "2", chainId: Number(env.CHAIN_ID), verifyingContract: env.USDC_ADDRESS },
        challenge_ttl_seconds: 300, free_tier_remaining: 0 } };
    }
  } else {
    let vc: Voucher;
    try {
      const parsed: any = JSON.parse(atob(xp));
      const a = parsed?.payload?.authorization;   // standard x402: { x402Version, scheme, network, payload: { signature, authorization } }
      vc = a ? { from: a.from, to: a.to, value: String(a.value), validAfter: String(a.validAfter), validBefore: String(a.validBefore), nonce: a.nonce, signature: parsed.payload.signature } : parsed;
    } catch { return { status: 402, body: { error: { code: "MALFORMED_PAYMENT", message: "X-PAYMENT must be base64 JSON (x402 payload or flat voucher)" } } }; }
    const dom = domainSep(env.USDC_DOMAIN_NAME, "2", chainId, env.USDC_ADDRESS);
    // Non-numeric value/validAfter/validBefore (or missing wrapper fields) must
    // fail CLOSED with a clean 402 — an uncaught BigInt throw here would 500.
    let dig: Uint8Array;
    try { dig = voucherDigest(dom, vc); } catch { return { status: 402, body: { error: { code: "MALFORMED_PAYMENT", message: "voucher numeric fields malformed (value/validAfter/validBefore must be integer strings)" } } }; }
    const signer = recover(dig, vc.signature);
    if (!signer || signer.toLowerCase() !== vc.from.toLowerCase()) {
      // EIP-1271 contract wallets (smart accounts) are not recoverable — defer their
      // signature to the on-chain settlement path (USDC's TransferWithAuthorization
      // validates contract signers via isValidSignature), instead of over-rejecting.
      if (!(await isContract(env, vc.from))) {
        return { status: 402, body: { error: { code: "BAD_SIGNATURE", message: "voucher signature does not recover to `from`" } } };
      }
    }
    // Replay BEFORE price: with dynamic pricing a used voucher may also be
    // stale-priced, but a burned nonce is dead regardless — say REPLAY, so the
    // buyer doesn't re-sign the same dead nonce at the new price.
    const nk = "nonce:" + vc.nonce;
    if (await env.NONCES.get(nk)) return { status: 402, body: { error: { code: "REPLAY", message: "voucher nonce already used" } } };
    if (BigInt(vc.value) !== priceMinor) return { status: 402, body: { error: { code: "PRICE_MISMATCH", message: `must pay exactly ${priceStr} for ${tool} (dynamic price — re-quote via the 402 challenge or GET /health)`, retryable: true } } };
    if (vc.to.toLowerCase() !== recipient.toLowerCase()) return { status: 402, body: { error: { code: "RECIPIENT_MISMATCH", message: "voucher pays the wrong recipient" } } };
    if (!(BigInt(nowSec) >= BigInt(vc.validAfter) && BigInt(nowSec) < BigInt(vc.validBefore))) return { status: 402, body: { error: { code: "EXPIRED", message: "voucher outside its time window", retryable: true } } };

    // Settle on-chain via a facilitator (gas-sponsored, non-custodial): it submits
    // the payer-signed EIP-3009 transfer straight to RECIPIENT. The worker never
    // holds funds. Burn the nonce only AFTER a confirmed settle, so a transient
    // facilitator failure stays safely retryable (double-settle is blocked on-chain
    // by USDC's own authorizationState).
    if (env.FACILITATOR_URL || env.FACILITATOR_URLS) {
      // x402 v2 settle payload (CAIP-2 network ids). Matches standard facilitators.
      // The payer signed `to`+`value`+`nonce`, so the facilitator cannot redirect
      // funds — non-custodial holds even if the facilitator is untrusted (we also
      // checked to===recipient and value===price above).
      const caip = "eip155:" + env.CHAIN_ID;
      const authorization = { from: vc.from, to: vc.to, value: vc.value, validAfter: vc.validAfter, validBefore: vc.validBefore, nonce: vc.nonce };
      const accepted = { scheme: "exact", network: caip, asset: env.USDC_ADDRESS, amount: priceStr, payTo: recipient, maxTimeoutSeconds: 300, extra: { name: env.USDC_DOMAIN_NAME, version: "2" } };
      const paymentPayload = { x402Version: 2, resource: { url: req.url, description: `openfang-rail ${tool}`, mimeType: "application/json" }, accepted, extensions: bazaarInfo(spec), payload: { signature: vc.signature, authorization } };
      // Failover chain: try each facilitator in order; fail over ONLY on network
      // errors / HTTP 5xx. Business failures (insufficient_balance, bad voucher,
      // not-registered) are payer/voucher properties — every facilitator would
      // reject them, so return immediately (retryable at the same facilitator).
      const chain = (env.FACILITATOR_URLS ? env.FACILITATOR_URLS.split(",").map(s => s.trim()).filter(Boolean) : [env.FACILITATOR_URL!]);
      let lastErr: { code: string; message: string; status: number } = { code: "SETTLEMENT_UNAVAILABLE", message: "no facilitator configured", status: 502 };
      let settledOk = false;
      for (const base of chain) {
        try {
          const resp = await fetch(base.replace(/\/$/, "") + "/settle", {
            method: "POST",
            headers: { "content-type": "application/json", ...(env.FACILITATOR_AUTH ? { authorization: env.FACILITATOR_AUTH } : {}) },
            body: JSON.stringify({ paymentPayload, paymentRequirements: accepted }),
            signal: AbortSignal.timeout(15000),
          });
          const sr: any = await resp.json().catch(() => null);
          if (resp.status >= 500) { lastErr = { code: "SETTLEMENT_UNAVAILABLE", message: `${base} -> HTTP ${resp.status}`, status: 502 }; continue; } // try next
          if (!resp.ok || !sr || sr.success !== true) {
            const msg = (sr && (sr.errorReason || sr.errorMessage || sr.error)) || `facilitator returned ${resp.status}`;
            // 4xx = the facilitator understood us and refused this voucher: terminal
            const failHeaders = { "PAYMENT-RESPONSE": Buffer.from(JSON.stringify({ success: false, errorReason: msg, transaction: "", network: "eip155:" + env.CHAIN_ID, payer: vc.from })).toString("base64") };
            return { status: 402, headers: failHeaders, body: { error: { code: "SETTLEMENT_FAILED", message: msg, retryable: true, facilitator: base } } };
          }
          settlementTx = sr.transaction || sr.txHash || ""; settled = true; settledOk = true;
          break;
        } catch { lastErr = { code: "SETTLEMENT_UNAVAILABLE", message: `${base} unreachable`, status: 502 }; continue; }
      }
      if (!settledOk) return { status: lastErr.code === "SETTLEMENT_FAILED" ? 402 : lastErr.status, body: { error: { code: lastErr.code, message: lastErr.message, retryable: true } } };
    } else if (env.CHAIN_ID === "8453") {
      // Mainnet with no facilitator would mean serving a paid call and never
      // collecting. Refuse rather than give it away.
      return { status: 503, body: { error: { code: "SETTLEMENT_NOT_CONFIGURED", message: "mainnet requires FACILITATOR_URL for on-chain settlement" } } };
    }
    await env.NONCES.put(nk, "1", { expirationTtl: 86400 });
    payer = vc.from; nonce = vc.nonce;
    // Demand signal: a settled sale bumps the live price up (capped). Free calls
    // never move the price.
    if (env.FACILITATOR_URL || env.FACILITATOR_URLS) await bumpPrice(tool, env, Number(priceStr));
  }

  const result = await spec.fn(input, env);
  const core: ReceiptCore = { v: "XDR-1", tool, tool_version: TOOL_VERSION,
    input_hash: kh(JSON.stringify(input)), output_hash: kh(JSON.stringify(result)), payer, recipient, amount, nonce, ts: nowSec, tier };
  const receipt = signReceipt(core, env.RECEIPT_SIGNING_KEY);
  const authorization = { authorized_by: env.AUTHORIZED_BY, attestation: env.ATTESTATION, attestation_sig: env.ATTESTATION_SIG };
  const settlement = tier === "free" ? { settled: false, reason: "free tier" }
    : settled ? { settled: true, network: env.CHAIN_ID === "8453" ? "base" : "base-sepolia", tx: settlementTx }
    : { settled: false, reason: "verify-only (no facilitator configured)" };
  // Referral attribution — non-custodial, non-breaking. Record who referred a PAID
  // call so a post-hoc accrual job can pay it out IF/WHEN a take-rate is enabled.
  // No inline payout, no receipt-canonical change. Pays 0 today (LAUNCH_MODE, 0 take-rate).
  if (ref && tier === "paid") { try { await env.NONCES.put("ref:" + ref + ":" + nonce, JSON.stringify({ tool, amount, ts: nowSec }), { expirationTtl: 2592000 }); } catch { /* attribution is best-effort; never fails a call */ } }
  const referral = ref ? { referrer: ref, attributed: tier === "paid", note: "attribution recorded; payback accrues post-hoc only if a take-rate is enabled (currently 0)" } : undefined;
  // v2 clients read PAYMENT-RESPONSE (base64 JSON) to report settlement outcome.
  const successHeaders: Record<string, string> = settled ? { "PAYMENT-RESPONSE": Buffer.from(JSON.stringify({ success: true, transaction: settlementTx, network: "eip155:" + env.CHAIN_ID, payer })).toString("base64") } : {};
  return { status: 200, headers: successHeaders, body: { tool, result, tier, settlement, referral, receipt, authorization } };
}

function x402Manifest(env: Env, req?: Request) {
  const origin = req ? new URL(req.url).origin : "";
  // Standard per-tool resource entries — this is what discovery crawlers
  // (x402scan, Bazaar) parse to find payable endpoints.
  const resources = Object.entries(TOOLS).map(([name, spec]) => ({
    resource: origin ? origin + "/v1/tools/" + name + "/call" : "/v1/tools/" + name + "/call",
    type: "http",
    method: "POST",
    accepts: [{ scheme: "exact", network: "eip155:" + env.CHAIN_ID, amount: String(TOOL_PRICE[name] ?? 999), maxAmountRequired: String(TOOL_PRICE[name] ?? 999), asset: env.USDC_ADDRESS, payTo: env.RECIPIENT, maxTimeoutSeconds: 300, extra: { name: env.USDC_DOMAIN_NAME, version: "2" } }],
    extensions: { bazaar: { info: { input: { type: "http", method: "POST", body: spec.ex }, inputSchema: spec.inputSchema, output: { schema: spec.out } } } },
  }));
  return { x402_version: 1, environment: env.CHAIN_ID === "8453" ? "production" : "staging",
    extensions: ["bazaar"],
    resources,
    asset: "USDC", decimals: 6, network: { name: env.CHAIN_ID === "8453" ? "base" : "base-sepolia", chain_id: Number(env.CHAIN_ID) },
    token_address: env.USDC_ADDRESS, authorization_type: "TransferWithAuthorization (EIP-3009)", signature_scheme: "EIP-712",
    eip712_domain: { name: env.USDC_DOMAIN_NAME, version: "2", chainId: Number(env.CHAIN_ID), verifyingContract: env.USDC_ADDRESS },
    challenge_ttl_seconds: 300, custody: "none", recipient: env.RECIPIENT, price_minor: `dynamic per-tool (floor–x${dpNum(env.PRICE_MAX_MULT, 5)}); the 402 challenge body is authoritative`,
    pricing_mode: "dynamic-dutch", pricing_rule: `idle decay to per-tool floor (tau=${dpNum(env.PRICE_TAU_SECONDS, 1800)}s); settled sales bump the price x${dpNum(env.PRICE_BUMP, 1.5)} (capped); live prices on GET /health`,
    free_tier: `${parseInt(env.FREE_CALLS_PER_DAY || "0", 10)} calls/day per client`,
    settlement: (env.FACILITATOR_URL || env.FACILITATOR_URLS) ? "facilitator (gas-sponsored, on-chain, non-custodial" + (env.FACILITATOR_URLS ? ", failover chain" : "") + ")" : (env.CHAIN_ID === "8453" ? "not configured" : "verify-only (testnet)"),
    notes: "The 402 challenge body is authoritative for recipient, amount, chain, nonce. Payer->seller direct; the rail never holds funds." };
}
function llmsTxt(env: Env) {
  const price = "from $0.000999–0.05 per call, DYNAMIC (idle prices decay toward the floor, demand bumps them up — watch GET /health for live quotes)";
  const freeN = parseInt(env.FREE_CALLS_PER_DAY || "0", 10);
  const market = env.REGISTRY_URL ? `\n\n## Marketplace\n- Listed on the x402 Registry: ${env.REGISTRY_URL} (crawl-verified, sha256-snapshotted)\n- Buyer-side MCP payer (auto-handles the 402 dance): x402-payer` : "";
  return `# openfang-rail\n\n> Deterministic business-identifier validation (IBAN, LEI, VAT, UK company number) and rental due-diligence (deposit-safety, listing-risk, one signed verdict), paid per call via x402 (gasless EIP-3009 USDC on Base). Zero custody, signed receipts, offline + explainable (no ML, no scraping). First ${freeN} calls/day free.\n\n## For agents\n- Discover: GET /.well-known/mcp.json and /.well-known/x402.json\n- MCP: POST /mcp (JSON-RPC 2.0: initialize, tools/list, tools/call)\n- REST: POST /v1/tools/{tool}/call with body {"input":{ … }} (see each tool's input_schema in mcp.json)\n- Free tier first; then a 402 challenge — sign an EIP-3009 voucher, retry with X-PAYMENT.\n- Every result carries a signed XDR-1 receipt; recover the signer to verify offline.\n\n## Tools\n${Object.entries(TOOLS).map(([n, s]) => `- ${n}: ${s.desc}`).join("\n")}\n\nPrice ${price} USDC/call. Non-custodial; payer->seller direct on Base.${market}\n`;
}

function homepage(env: Env, req: Request) {
  const base = new URL(req.url).origin;
  const price = "from $0.000999–0.05 per call, dynamic (idle prices decay toward the floor; demand bumps them up; live quotes on /health)";
  const freeN = parseInt(env.FREE_CALLS_PER_DAY || "0", 10);
  const rows = Object.entries(TOOLS).map(([n, s]) => `<tr><td><code>${n}</code></td><td>${s.desc}</td></tr>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>openfang-rail — deterministic identity & rental checks, paid per call (x402)</title>
<style>body{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;max-width:820px;margin:0 auto;padding:32px 20px;line-height:1.55;color:#16181d;background:#fff}code{background:#f0f2f5;padding:1px 5px;border-radius:4px;font-size:90%}h1{margin:0 0 4px}.muted{color:#5b6472}table{border-collapse:collapse;width:100%;margin:14px 0}td{border:1px solid #e3e6eb;padding:7px 10px;font-size:14px;vertical-align:top}pre{background:#0f1115;color:#e6e9ef;padding:14px;border-radius:8px;overflow-x:auto;font-size:13px}a{color:#b4530a}</style></head>
<body>
<h1>openfang-rail</h1>
<p class="muted">Deterministic business-identifier validation (IBAN, LEI, VAT, UK company no.) and rental due-diligence (deposit-safety, listing-risk, one signed verdict), paid per call via <a href="https://www.x402.org/">x402</a> — gasless EIP-3009 USDC on Base. Non-custodial, signed receipts, offline + explainable (no ML, no scraping). First ${freeN} calls/day free.</p>
<h3>Endpoints</h3>
<ul><li>MCP (Streamable HTTP): <code>POST /mcp</code></li>
<li><a href="/console"><b>Protocol operations console</b></a> — live SOP, pricing sim, handshake trace</li>
<li>Discovery: <a href="/.well-known/mcp.json">/.well-known/mcp.json</a> · <a href="/.well-known/x402.json">/.well-known/x402.json</a> · <a href="/llms.txt">/llms.txt</a></li>
<li>REST: <code>POST /v1/tools/{tool}/call</code></li></ul>
<h3>Tools</h3>
<table><tbody>${rows}</tbody></table>
<h3>Try the free tier</h3>
<pre>curl -s -X POST ${base}/v1/tools/iban-check/call \\
  -H "content-type: application/json" -d '{"input":{"iban":"GB82 WEST 1234 5698 7654 32"}}'</pre>
<p class="muted">Price ${price} USDC/call. Non-custodial — payer&#8594;seller direct on Base; the rail never holds funds. Global edge (Cloudflare Workers) &middot; self-describing MCP + x402 &middot; no registry required.${env.REGISTRY_URL ? ` &middot; <a href="${env.REGISTRY_URL}">Listed on the x402 Registry</a>` : ""}</p>
</body></html>`;
}

function buyPage(env: Env, prices: Record<string, number>) {
  const ex = Object.entries(prices).sort((a,b)=>a[1]-b[1])[0];
  const fmt = (m:number) => "$" + (m/1e6).toFixed(6).replace(/0+$/,"").replace(/.$/,"");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>openfang-rail — pay in 3 lines</title><style>body{font-family:ui-monospace,monospace;max-width:760px;margin:40px auto;padding:0 20px;line-height:1.6;color:#16181d}pre{background:#0f1115;color:#e6e9ef;padding:14px;border-radius:8px;overflow-x:auto;font-size:13px}code{background:#f0f2f5;padding:1px 5px;border-radius:4px}h2{margin-top:28px}</style></head><body>
<h1>Pay in 3 lines</h1>
<p>Any x402 buyer pays automatically. Cheapest tool right now: <b>${ex[0]} at ${fmt(ex[1])}</b> (live dynamic quote).</p>
<h2>1 · Official SDK (recommended)</h2>
<pre>npm i @x402/fetch @x402/evm viem
import { wrapFetchWithPayment } from "@x402/fetch";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
const client = new x402Client();
client.register("eip155:*", new ExactEvmScheme(signer));  // funded wallet
const fetch2 = wrapFetchWithPayment(fetch, client);
await fetch2("${"{base}"}/v1/tools/iban-check/call", { method:"POST",
  headers:{ "content-type":"application/json" },
  body: JSON.stringify({ input:{ iban:"GB82 WEST 1234 5698 7654 32" } }) });
// 402 -> auto-sign -> auto-settle (USDC on Base) -> 200 + signed receipt</pre>
<h2>2 · Any MCP client</h2>
<pre>POST ${"{base}"}/mcp  { "method":"tools/call", "params":{ "name":"iban_check", ... } }
// the 402 challenge comes back inside the tool error — sign, retry with X-PAYMENT</pre>
<h2>3 · Verify what you paid for</h2>
<pre>every 200 carries receipt: { v:"XDR-1", input_hash, output_hash, amount, tx, signer }
recover the signer from ${"{base}"}/.well-known/mcp.json receipt_signing_address</pre>
<p>Prices are dynamic: idle decays to the floor, demand bumps them. Live quotes: <a href="/health">GET /health</a>. Free tier: first 20 calls/day.</p>
</body></html>`;
}

function openapi(env: Env, req: Request) {
  const base = new URL(req.url).origin;
  const paths: Record<string, any> = {};
  for (const [name, s] of Object.entries(TOOLS)) {
    paths[`/v1/tools/${name}/call`] = { post: {
      operationId: name.replace(/-/g, "_"), summary: s.title, description: s.desc,
      requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["input"], properties: { input: s.inputSchema } }, example: { input: s.ex } } } },
      responses: {
        "200": { description: "Result + signed XDR-1 receipt", content: { "application/json": { schema: { type: "object", properties: { tool: { type: "string" }, result: s.out, tier: { type: "string" }, settlement: { type: "object" }, receipt: { type: "object" } } } } } },
        "400": { description: "Invalid input" },
        "402": { description: "Payment required (x402). Sign accepts[0] EIP-3009 authorization and retry with the X-PAYMENT header.", content: { "application/json": { schema: { type: "object", properties: { x402Version: { type: "integer" }, accepts: { type: "array" }, error: { type: "string" } } } } } },
      },
    } };
  }
  return { openapi: "3.1.0",
    info: { title: "openfang-rail", version: "1.1.0", description: "Deterministic business-identifier validation + rental due-diligence, paid per call via x402 (gasless EIP-3009 USDC on Base). Non-custodial, signed receipts. First " + (parseInt(env.FREE_CALLS_PER_DAY || "0", 10)) + " calls/day free." },
    servers: [{ url: base }], paths };
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    // CORS preflight + Streamable-HTTP GET: browser-based MCP/x402 registry validators send these.
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
    if (url.pathname === "/mcp" && req.method === "GET") return new Response(null, { status: 405, headers: { ...cors(), "allow": "POST, OPTIONS" } });
    if (url.pathname === "/" && req.method === "GET") return new Response(homepage(env, req), { headers: { "content-type": "text/html; charset=utf-8", ...cors() } });
    if (url.pathname === "/health") {
      // Live price ticker (the sniping surface): agents poll this for free to
      // time a purchase at the floor instead of probing with billable calls.
      const prices: Record<string, number> = {};
      for (const t of Object.keys(TOOLS)) prices[t] = await quoteFor(t, env);
      return j({ ok: true, launch_zero_take_rate: launchOn(env), receipt_signer: signerAddr(env), tools: Object.keys(TOOLS), prices, pricing: { mode: "dynamic-dutch", floor_to_ceiling_mult: dpNum(env.PRICE_MAX_MULT, 5), decay_tau_seconds: dpNum(env.PRICE_TAU_SECONDS, 1800), sale_bump: dpNum(env.PRICE_BUMP, 1.5), note: "idle price decays to the per-tool floor; each settled sale bumps it up (capped); this endpoint always quotes live" } });
    }
    if (url.pathname === "/ping") return j({ status: "pong", timestamp: new Date().toISOString(), service: "openfang-rail" });
    if (url.pathname === "/.well-known/mcp.json") return j(manifest(env));
    if (url.pathname === "/.well-known/x402.json") return j(x402Manifest(env, req));
    if (url.pathname === "/llms.txt") return new Response(llmsTxt(env), { headers: { "content-type": "text/plain; charset=utf-8", ...cors() } });
    if (url.pathname === "/buy") { const prices: Record<string, number> = {}; for (const t of Object.keys(TOOLS)) prices[t] = await quoteFor(t, env); return new Response(buyPage(env, prices), { headers: { "content-type": "text/html; charset=utf-8", ...cors() } }); }
    if (url.pathname === "/console") {
      const prices: Record<string, number> = {}; const floors: Record<string, number> = {};
      for (const t of Object.keys(TOOLS)) { prices[t] = await quoteFor(t, env); floors[t] = TOOL_PRICE[t] ?? 999; }
      const facilitators = await probeFacilitators(env);
      const data = { origin: url.origin, version: "1.1.0", signer: signerAddr(env), authorizedBy: env.AUTHORIZED_BY || "", attested: !!(env.ATTESTATION_SIG && env.ATTESTATION), recipient: env.RECIPIENT, chain: env.CHAIN_ID === "8453" ? "Base" : "Base Sepolia", tau: dpNum(env.PRICE_TAU_SECONDS, 1800), bump: dpNum(env.PRICE_BUMP, 1.5), mult: dpNum(env.PRICE_MAX_MULT, 5), prices, floors, registryUrl: env.REGISTRY_URL || "(registry not linked)", facilitators, generatedAt: new Date().toISOString().replace("T", " ").slice(0, 19) };
      return new Response(consolePage(data), { headers: { "content-type": "text/html; charset=utf-8", ...cors() } });
    }
    if (url.pathname === "/sign") {
      const prices: Record<string, number> = {}; for (const t of Object.keys(TOOLS)) prices[t] = await quoteFor(t, env);
      const cheapestEntry = Object.entries(prices).sort((a, b) => a[1] - b[1])[0];
      return new Response(signPage({ origin: url.origin, recipient: env.RECIPIENT, usdc: env.USDC_ADDRESS, chainId: Number(env.CHAIN_ID), domainName: env.USDC_DOMAIN_NAME, cheapest: { tool: cheapestEntry[0], price: String(cheapestEntry[1]) } }), { headers: { "content-type": "text/html; charset=utf-8", ...cors() } });
    }
    if (url.pathname === "/.well-known/agent.json" || url.pathname === "/.well-known/agent-card.json") {
      // A2A Agent Card (agent discovery protocol) — generated from the live tool registry
      const skills = Object.entries(TOOLS).map(([name, spec]) => ({ id: name, name: spec.title, description: spec.desc, tags: ["validation", "x402", "base", "mcp"], examples: [spec.ex] }));
      return j({ name: "openfang-rail", description: "Deterministic business-identifier validation (IBAN, LEI, VAT, SWIFT/BIC + more) and rental due-diligence, paid per call via x402 (gasless USDC on Base). Signed offline-verifiable receipts. Free tier 20 calls/day.", url: url.origin + "/mcp", preferredTransport: "StreamableHTTP", protocolVersion: "2024-11-05", version: "1.1.0", provider: { organization: "openfang", url: url.origin }, capabilities: { streaming: false, pushNotifications: false, stateTransitionHistory: false }, defaultInputModes: ["application/json"], defaultOutputModes: ["application/json"], skills, x402: { payment: "USDC on Base per call (EIP-3009)", free_tier: "20 calls/day", manifests: [url.origin + "/.well-known/x402.json", url.origin + "/.well-known/mcp.json"] } });
    }
    if (url.pathname === "/openapi.json") return j(openapi(env, req));

    // MCP streamable-HTTP JSON-RPC endpoint (what Claude Desktop / Cursor / the MCP registry speak)
    if (url.pathname === "/mcp" && req.method === "POST") {
      let rpc: any; try { rpc = await req.json(); } catch { return j({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400); }
      const id = rpc?.id ?? null;
      const method = rpc?.method;
      if (method === "initialize") return j({ jsonrpc: "2.0", id, result: { protocolVersion: rpc?.params?.protocolVersion || "2024-11-05", capabilities: { tools: {}, resources: {}, prompts: {} }, serverInfo: { name: "openfang-rail", version: "1.1.0", license: "MIT" } } });
      if (method === "notifications/initialized") return new Response(null, { status: 204, headers: cors() });
      if (method === "ping") return j({ jsonrpc: "2.0", id, result: { status: "pong", timestamp: new Date().toISOString(), service: "openfang-rail" } });
      if (method === "resources/list") return j({ jsonrpc: "2.0", id, result: { resources: [] } });
      if (method === "resources/templates/list") return j({ jsonrpc: "2.0", id, result: { resourceTemplates: [] } });
      if (method === "prompts/list") return j({ jsonrpc: "2.0", id, result: { prompts: [] } });
      // MCP tool names use snake_case (registry-linter convention); REST/receipts
      // keep the canonical kebab id. tools/call accepts BOTH spellings.
      if (method === "tools/list") return j({ jsonrpc: "2.0", id, result: { tools: Object.entries(TOOLS).map(([name, s]) => {
        const exOut = outputExample(name);
        return {
          name: name.replace(/-/g, "_"),
          title: s.title,
          description: s.desc,
          inputSchema: { ...s.inputSchema, examples: [{ input: s.ex, output: exOut }] },
          outputSchema: { ...s.out, examples: [exOut] },
          examples: [{ input: s.ex, output: exOut }],
          annotations: { title: s.title, readOnlyHint: true, idempotentHint: true, openWorldHint: false }
        };
      }) } });
      if (method === "tools/call") {
        const name = String(rpc?.params?.name ?? "");
        const spec = TOOLS[name] ?? TOOLS[name.replace(/_/g, "-")];
        if (!spec) return j({ jsonrpc: "2.0", id, error: { code: -32601, message: `unknown tool '${name}'` } });
        const toolKey = TOOLS[name] ? name : name.replace(/_/g, "-");
        const args = rpc?.params?.arguments;
        if (!args || typeof args !== "object") return j({ jsonrpc: "2.0", id, error: { code: -32602, message: "expected params.arguments (object)" } });
        const r = await processCall(toolKey, args, req, env);
        // 200 -> normal content; 402/error -> MCP tool error carrying the challenge so the agent can pay & retry
        return j({ jsonrpc: "2.0", id, result: { isError: r.status !== 200, content: [{ type: "text", text: JSON.stringify(r.body) }] } });
      }
      return j({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } });
    }

    // Listability: GET on a tool path (or the tool index) returns a self-describing
    // doc card instead of 404 — crawlers/scanners probe with GET and must not
    // conclude advertised paths are dead. The call itself remains POST.
    const m = url.pathname.match(/^\/v1\/tools\/([^/]+)\/call$/);
    if (req.method === "GET" && m) {
      const tool = decodeURIComponent(m[1]); const spec = TOOLS[tool];
      if (!spec) return err("TOOL_NOT_FOUND", `unknown tool '${tool}'`, 404);
      return j({ tool, title: spec.title, description: spec.desc, method: "POST", call: `/v1/tools/${tool}/call`,
        input_schema: spec.inputSchema, output_schema: spec.out, price_usdc_floor: (TOOL_PRICE[tool] || 0) / 1e6,
        price_note: "dynamic-dutch: live quote via GET /health or the 402 challenge on POST without payment",
        example_request: { input: spec.ex }, docs: `${url.origin}/openapi.json`, mcp: `${url.origin}/mcp` });
    }
    if (req.method === "GET" && url.pathname === "/v1/tools") {
      return j({ tools: Object.keys(TOOLS).map((name) => ({ name, title: TOOLS[name].title, call: `/v1/tools/${name}/call`, docs: `/v1/tools/${name}/call (GET)` })) });
    }
    // REST tool call
    if (req.method === "POST" && m) {
      const tool = decodeURIComponent(m[1]); const spec = TOOLS[tool];
      if (!spec) return err("TOOL_NOT_FOUND", `unknown tool '${tool}'`, 404);
      let payload: any; try { payload = await req.json(); } catch { return err("BAD_JSON", "body must be JSON { input: { … } }", 400); }
      const input = payload?.input;
      if (!input || typeof input !== "object") return err("INPUT_SCHEMA_INVALID", `expected { "input": { … } }`, 400);
      const r = await processCall(tool, input, req, env);
      return j(r.body, r.status, r.headers || {});
    }
    return err("NOT_FOUND", "no such route", 404);
  },
} satisfies ExportedHandler<Env>;
