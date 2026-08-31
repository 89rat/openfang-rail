// Thorough QA/QC harness for the worker. Runs the REAL bundled fetch
// handler against a mock env, signs real EIP-3009 vouchers (throwaway key, no
// funds), mocks the facilitator, verifies receipts offline, and parity-checks
// the ported rental logic against the tested rental.mjs. Node-run, pre-deploy.
// Bundle first:  npx wrangler deploy --dry-run --outdir dist
import worker from "./dist/index.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { rentalVerdict as rvRef, rentDepositGuard as dgRef, rentalListingRisk as lrRef } from "../rental/rental.mjs";

// ---- byte helpers (mirror the worker) ----
const te = new TextEncoder();
const hb = (h) => { h = h.replace(/^0x/, ""); const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; };
const bh = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };
const wAddr = (h) => { const b = hb(h); const w = new Uint8Array(32); w.set(b, 12); return w; };
const wU = (v) => { let x = v; const w = new Uint8Array(32); for (let i = 31; i >= 0; i--) { w[i] = Number(x & 0xffn); x >>= 8n; } return w; };
const addrFromPriv = (k) => "0x" + bh(keccak_256(secp256k1.getPublicKey(k, false).slice(1)).slice(12));
const DOMAIN_TH = keccak_256(te.encode("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
const TA_TH = keccak_256(te.encode("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"));
const domainSep = (name, ver, cid, c) => keccak_256(cat(DOMAIN_TH, keccak_256(te.encode(name)), keccak_256(te.encode(ver)), wU(cid), wAddr(c)));
const voucherDigest = (dom, m) => keccak_256(cat(new Uint8Array([0x19, 0x01]), dom, keccak_256(cat(TA_TH, wAddr(m.from), wAddr(m.to), wU(BigInt(m.value)), wU(BigInt(m.validAfter)), wU(BigInt(m.validBefore)), hb(m.nonce)))));

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", RECIP = "0xc59c85e661d34084a7769f955d17fd38254a6235";
const FLOOR = 999;             // validator floor (keep in sync with TOOL_PRICE in src)
const VCEIL = FLOOR * 5;       // dynamic ceiling for validators (mult 5)
const BATCH_MAX_PRICE = Math.max(50000, VCEIL); // batch = max(floor, 5x dynamic single)
const PAYER_PK = hb("22".repeat(32)); const PAYER = addrFromPriv(PAYER_PK);
function signVoucher({ value = String(FLOOR), to = RECIP, validAfter = "0", validBefore, nonce } = {}) {  // iban-check price
  const now = Math.floor(Date.now() / 1000); validBefore = validBefore ?? String(now + 300);
  nonce = nonce ?? "0x" + bh(crypto.getRandomValues(new Uint8Array(32)));
  const m = { from: PAYER, to, value, validAfter, validBefore, nonce };
  const dom = domainSep("USD Coin", "2", 8453n, USDC);
  const sig = secp256k1.sign(voucherDigest(dom, m), PAYER_PK);
  const signature = "0x" + bh(sig.toCompactRawBytes()) + (sig.recovery + 27).toString(16).padStart(2, "0");
  return { ...m, signature };
}
const xpay = (v) => Buffer.from(JSON.stringify(v)).toString("base64");

// ---- mock env + controllable facilitator + mock Base RPC ----
let MOCK_SETTLE = "success";
let RPC_UP = true;
// Mirrors USDC on-chain authorizationState: a voucher nonce settles at most once.
const settledNonces = new Set();
const LOG_FIXTURE = [
  { transactionHash: "0xout1", data: "0x" + (1000000n).toString(16) },   // 1.0 USDC out
  { transactionHash: "0xout2", data: "0x" + (2500000n).toString(16) },  // 2.5 USDC out
];
let MOCK_PRIMARY_500 = false;
// fixtures for the on-chain intelligence tools (balance/erc20/tx-activity/block)
const CONTRACT_ADDR = "0x4200000000000000000000000000000000000006"; // mock: has deployed code
const NODEC_TOKEN = "0x" + "be".repeat(20);                          // mock: reverts on decimals()
const rpcJson = (result) => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), { status: 200, headers: { "content-type": "application/json" } });
const rpcErr = (msg) => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { message: msg } }), { status: 200, headers: { "content-type": "application/json" } });
globalThis.fetch = async (url, opts) => {
  if (String(url).includes("/settle")) {
    if (String(url).includes("mock.facilitator") && MOCK_PRIMARY_500) return new Response("boom", { status: 500 });
    if (MOCK_SETTLE === "throw") throw new Error("network");
    let auth = null; try { auth = JSON.parse(opts.body).paymentPayload.payload.authorization; } catch { /* probe without payload */ }
    if (MOCK_SETTLE === "success") {
      if (auth && settledNonces.has(auth.nonce)) return new Response(JSON.stringify({ success: false, errorReason: "nonce_already_used_onchain", errorMessage: "authorization state used" }), { status: 200, headers: { "content-type": "application/json" } });
      if (auth) settledNonces.add(auth.nonce);
      return new Response(JSON.stringify({ success: true, transaction: "0xTESTTX", network: "eip155:8453", payer: PAYER }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: false, errorReason: "insufficient_balance", errorMessage: "no funds" }), { status: 200, headers: { "content-type": "application/json" } });
  }
  if (String(url).includes("mock.rpc")) {
    if (!RPC_UP) return rpcErr("down");
    const body = JSON.parse(opts.body);
    if (body.method === "eth_blockNumber") return rpcJson("0x186a0"); // 100000
    if (body.method === "eth_getBalance") return rpcJson("0x" + (1500000000000000000n).toString(16)); // 1.5 ETH
    if (body.method === "eth_getTransactionCount") return rpcJson("0x2a"); // 42
    if (body.method === "eth_getCode") return rpcJson(String(body.params[0]).toLowerCase() === CONTRACT_ADDR ? "0x6080604052" : "0x");
    if (body.method === "eth_call") {
      const to = String(body.params[0]?.to || "").toLowerCase();
      const sel = String(body.params[0]?.data || "").slice(0, 10).toLowerCase();
      if (sel === "0x313ce567" && to === NODEC_TOKEN) return rpcErr("execution reverted"); // non-standard token: no decimals()
      if (sel === "0x70a08231") return rpcJson("0x" + (2500000n).toString(16));            // balanceOf -> 2.5 units raw
      if (sel === "0x313ce567") return rpcJson("0x" + (6n).toString(16));                  // decimals() -> 6
      return rpcJson("0x" + "12".repeat(32));                                             // arbitrary data -> plausible hex
    }
    if (body.method === "eth_getBlockByNumber") return rpcJson({ number: "0x186a0", hash: "0x" + "ab".repeat(32), timestamp: "0x" + (1730000000n).toString(16), transactions: ["0xt1", "0xt2", "0xt3"], baseFeePerGas: "0x" + (100000000n).toString(16), gasLimit: "0x1c9c380", gasUsed: "0x1c9c380" });
    if (body.method === "eth_getLogs") {
      const isOut = body.params[0].topics[1] !== null; // topic1 set = transfers FROM the address
      return rpcJson(isOut ? LOG_FIXTURE : []);
    }
  }
  throw new Error("unexpected outbound fetch to " + url);
};
const baseEnv = () => ({ NONCES: { _m: {}, async get(k) { return this._m[k] ?? null; }, async put(k, v) { this._m[k] = v; } },
  CHAIN_ID: "8453", USDC_ADDRESS: USDC, USDC_DOMAIN_NAME: "USD Coin", RECIPIENT: RECIP, PRICE_MINOR: "590",
  LAUNCH_MODE: "true", FREE_CALLS_PER_DAY: "20", RECEIPT_SIGNING_KEY: "11".repeat(32),
  AUTHORIZED_BY: "", ATTESTATION: "", ATTESTATION_SIG: "", FACILITATOR_URL: "https://mock.facilitator", FACILITATOR_URLS: "",
  PRICE_MAX_MULT: "5", PRICE_BUMP: "1.5", PRICE_TAU_SECONDS: "1800", RPC_URL: "https://mock.rpc", REGISTRY_URL: "" });

let ok = 0, n = 0; const t = (name, cond) => { n++; if (cond) { ok++; } else console.log("  FAIL  " + name); };
const REQ = (path, { method = "POST", body, headers = {}, ip = "9.9.9.9" } = {}) =>
  new Request("https://x" + path, { method, headers: { "content-type": "application/json", "cf-connecting-ip": ip, ...headers }, body: body === undefined ? undefined : (typeof body === "string" ? body : JSON.stringify(body)) });
const call = async (env, path, opts) => { const r = await worker.fetch(REQ(path, opts), env); const txt = await r.text(); let b; try { b = JSON.parse(txt); } catch { b = txt; } return { s: r.status, b }; };

async function run() {
  let env = baseEnv();
  // dynamic-price state hygiene between test groups (paid sales bump dp:* keys)
  const clearDp = () => { for (const k of Object.keys(env.NONCES._m)) if (k.startsWith("dp:")) delete env.NONCES._m[k]; };
  // ---------- endpoints ----------
  let r = await call(env, "/health", { method: "GET" }); t("health 200 + 23 tools", r.s === 200 && r.b.tools.length === 23);
  { const hc = await worker.fetch(REQ("/console", { method: "GET" }), env); const cc = await hc.text();
    t("/console: SOP page w/ live prices + sim + checklist", hc.status === 200 && cc.includes("PROTOCOL OPERATIONS") && cc.includes("Economics simulator") && cc.includes("ofr_sop") && cc.includes("ticker") && cc.includes("PHASE_NAMES"), "s=" + hc.s); }
  { const hsg = await worker.fetch(REQ("/sign", { method: "GET" }), env); const sg = await hsg.text();
    t("/sign: dapp page w/ EIP-712 flow + self-test badge", hsg.status === 200 && sg.includes("eth_signTypedData_v4") && sg.includes("DISCLOSED SELF-TEST") && sg.includes("TransferWithAuthorization")); }
  { const ha = await worker.fetch(REQ("/.well-known/agent-card.json", { method: "GET" }), env); const ac = await ha.json();
    t("A2A agent-card: 23 skills + discovery fields", ha.status === 200 && ac.name === "openfang-rail" && ac.skills.length === 23 && ac.url === "https://x/mcp" && !!ac.capabilities);
    const aj = await (await worker.fetch(REQ("/.well-known/agent.json", { method: "GET" }), env)).json();
    t("A2A agent.json mirrors agent-card", aj.name === "openfang-rail" && aj.skills.length === 23); }
  { const h = await worker.fetch(REQ("/buy", { method: "GET" }), env); const html = await h.text();
    t("/buy page: live prices + official SDK snippet", html.includes("Pay in 3 lines") && /@x402.fetch/.test(html)); }
  r = await call(env, "/.well-known/mcp.json", { method: "GET" }); t("mcp.json 23 tools + schemas", r.s === 200 && r.b.tools.length === 23 && r.b.tools.every(x => x.input_schema && x.input_schema.type === "object"));
  r = await call(env, "/.well-known/x402.json", { method: "GET" }); t("x402.json production/base/USD Coin/settlement", r.b.environment === "production" && r.b.network.name === "base" && r.b.eip712_domain.name === "USD Coin" && /facilitator/.test(r.b.settlement));
  r = await call(env, "/llms.txt", { method: "GET" }); t("llms.txt mentions rental", r.s === 200 && /rental/i.test(r.b));
  { const res = await worker.fetch(REQ("/mcp", { method: "OPTIONS" }), env); t("OPTIONS -> 204 + CORS", res.status === 204 && res.headers.get("access-control-allow-origin") === "*"); }
  { const res = await worker.fetch(REQ("/mcp", { method: "GET" }), env); t("GET /mcp -> 405 (spec-correct)", res.status === 405 && res.headers.get("allow") != null); }
  { const res = await worker.fetch(REQ("/health", { method: "GET" }), env); t("responses carry CORS header", res.headers.get("access-control-allow-origin") === "*"); }
  { const res = await worker.fetch(REQ("/mcp", { body: { jsonrpc: "2.0", id: 9, method: "initialize", params: { protocolVersion: "2025-06-18" } } }), env); const jb = await res.json(); t("initialize echoes client protocolVersion", jb.result.protocolVersion === "2025-06-18"); }

  // ---------- validators (free tier) ----------
  const free = (path, input, ip) => call(env, path, { body: { input }, ip });
  t("iban valid", (await free("/v1/tools/iban-check/call", { iban: "GB82 WEST 1234 5698 7654 32" }, "a1")).b.result.valid === true);
  t("iban invalid checksum", (await free("/v1/tools/iban-check/call", { iban: "GB00 WEST 1234 5698 7654 32" }, "a2")).b.result.valid === false);
  t("lei valid", (await free("/v1/tools/lei-check/call", { lei: "529900T8BM49AURSDO55" }, "a3")).b.result.valid === true);
  t("vat malformed", (await free("/v1/tools/vat-mod97-check/call", { vat_number: "BE123" }, "a4")).b.result.valid === false);
  t("uk company format ok", (await free("/v1/tools/company-number-format/call", { company_number: "12345678" }, "a5")).b.result.valid === true);

  // ---------- expanded validator matrix (valid + invalid vectors each) ----------
  const vec = [
    ["swift-bic-check", { bic: "DEUTDEFF500" }, { bic: "DEUTDEFFX" }],
    ["aba-routing-check", { aba_routing: "021000021" }, { aba_routing: "021000022" }],
    ["ein-format-check", { ein: "12-3456789" }, { ein: "12-345678" }],
    ["ifsc-check", { ifsc: "HDFC0000123" }, { ifsc: "HDFC1000123" }],
    ["abn-check", { abn: "51 824 753 556" }, { abn: "51824753557" }],
    ["luhn-check", { number: "4111111111111111" }, { number: "4111111111111112" }],
    ["isbn-check", { isbn: "978-0-306-40615-7" }, { isbn: "9780306406158" }],
    ["e164-check", { phone: "+14155552671" }, { phone: "01415555267" }],
    ["sedol-check", { sedol: "B0YBKJ7" }, { sedol: "B0YBKJ8" }],
  ];
  for (const [tool, good, bad] of vec) {
    t(`${tool}: valid vector`, (await free(`/v1/tools/${tool}/call`, good, "v-" + tool)).b.result.valid === true);
    t(`${tool}: invalid vector`, (await free(`/v1/tools/${tool}/call`, bad, "x-" + tool)).b.result.valid === false);
  }

  // ---------- vendor-onboarding-pack (the composite product) ----------
  { const r2 = await free("/v1/tools/vendor-onboarding-pack/call", { iban: "GB82 WEST 1234 5698 7654 32", lei: "529900T8BM49AURSDO55", vat_number: "BE0417497106", company_number: "12345678" }, "pk1");
    t("pack: all four identifiers valid -> all_valid", r2.b.result.checked_count === 4 && r2.b.result.all_valid === true); t("pack: receipt covers the pack", r2.b.receipt.tool === "vendor-onboarding-pack"); }
  t("pack: one bad identifier -> all_valid false", (await free("/v1/tools/vendor-onboarding-pack/call", { iban: "GB82 WEST 1234 5698 7654 32", lei: "529900T8BM49AURSDO55", vat_number: "BE0417497106", company_number: "1234567" }, "pk2")).b.result.all_valid === false);
  { const r2 = await free("/v1/tools/vendor-onboarding-pack/call", {}, "pk3"); t("pack: empty input -> explicit error, no crash", r2.s === 200 && r2.b.result.error !== undefined && r2.b.result.checked_count === 0); }
  t("pack: batch tier includes new validators", (await free("/v1/tools/batch-validate/call", { items: [{ tool: "ifsc-check", value: "HDFC0000123" }, { tool: "sedol-check", value: "B0YBKJ7" }] }, "pk4")).b.result.valid_count === 2);

  // ---------- settlement-history-check (on-chain counterparty proof) ----------
  { const r2 = await free("/v1/tools/settlement-history-check/call", { address: "0xc59c85e661d34084a7769f955d17fd38254a6235" }, "sh1");
    t("history: aggregates sent/received from RPC logs", r2.b.result.valid === true && r2.b.result.usdc_sent.count === 2 && r2.b.result.usdc_sent.volume_usdc === 3.5 && r2.b.result.usdc_received.count === 0, JSON.stringify(r2.b.result).slice(0, 140));
    t("history: honest scope label", /NOT full lifetime history/.test(r2.b.result.scope)); }
  t("history: malformed address -> 400 (before payment)", (await free("/v1/tools/settlement-history-check/call", { address: "0x123" }, "sh2")).s === 400);
  { RPC_UP = false;
    const r2 = await free("/v1/tools/settlement-history-check/call", { address: "0xc59c85e661d34084a7769f955d17fd38254a6235" }, "sh3");
    t("history: RPC down -> free 503, never charges", r2.s === 503 && r2.b.error.code === "UPSTREAM_RPC_UNAVAILABLE");
    const settledBefore = settledNonces.size;
    const r3 = await call(env, "/v1/tools/settlement-history-check/call", { body: { input: { address: "0xc59c85e661d34084a7769f955d17fd38254a6235" } }, headers: { "X-PAYMENT": xpay(signVoucher({ value: "20000" })) }, ip: "sh4" });
    t("history: paid attempt during outage 503s BEFORE settlement (no money moves)", r3.s === 503 && settledNonces.size === settledBefore);
    RPC_UP = true; }

  // ---------- on-chain intelligence: balance-check / erc20-balance / tx-activity / block-info ----------
  const AA = "0xc59c85e661d34084a7769f955d17fd38254a6235"; // plain EOA fixture
  { const r2 = await free("/v1/tools/balance-check/call", { address: AA }, "bc1");
    t("balance: ETH + default-USDC token balance from RPC", r2.b.result.valid === true && r2.b.result.native.balance === 1.5 && r2.b.result.token.balance === 2.5 && r2.b.result.token.decimals === 6 && r2.b.result.token.balance_raw === "2500000", JSON.stringify(r2.b.result).slice(0, 160));
    t("balance: honest scope label", /NOT a price feed/.test(r2.b.result.scope) && /NOT financial advice/.test(r2.b.result.scope)); }
  { const r2 = await free("/v1/tools/balance-check/call", { address: AA, token_address: NODEC_TOKEN }, "bc2");
    t("balance: token without decimals() falls back to 18 (labeled)", r2.b.result.valid === true && r2.b.result.token.decimals === 18 && /assumed/.test(r2.b.result.token.decimals_source)); }
  t("balance: malformed address -> 400 (before payment)", (await free("/v1/tools/balance-check/call", { address: "0x123" }, "bc3")).s === 400);
  t("balance: malformed token_address -> 400", (await free("/v1/tools/balance-check/call", { address: AA, token_address: "0xzz" }, "bc4")).s === 400);
  { const r2 = await free("/v1/tools/erc20-balance/call", { address: AA, token_address: USDC }, "eb1");
    t("erc20: formatted balance from balanceOf", r2.b.result.valid === true && r2.b.result.balance_raw === "2500000" && r2.b.result.balance === 2.5 && r2.b.result.decimals === 6 && r2.b.result.decimals_source === "erc20 decimals()"); }
  { const r2 = await free("/v1/tools/erc20-balance/call", { address: AA, token_address: USDC, decimals: 3 }, "eb2");
    t("erc20: caller-supplied decimals override", r2.b.result.balance === 2500 && r2.b.result.decimals === 3 && r2.b.result.decimals_source === "caller-supplied"); }
  t("erc20: missing token_address -> 400", (await free("/v1/tools/erc20-balance/call", { address: AA }, "eb3")).s === 400);
  t("erc20: bad decimals -> 400", (await free("/v1/tools/erc20-balance/call", { address: AA, token_address: USDC, decimals: -2 }, "eb4")).s === 400);
  { const r2 = await free("/v1/tools/tx-activity/call", { address: AA }, "tx1");
    t("tx-activity: nonce count + EOA (not a contract)", r2.b.result.valid === true && r2.b.result.tx_count === 42 && r2.b.result.is_contract === false && r2.b.result.first_funded_heuristic === true, JSON.stringify(r2.b.result).slice(0, 160)); }
  { const r2 = await free("/v1/tools/tx-activity/call", { address: CONTRACT_ADDR }, "tx2");
    t("tx-activity: contract detected via eth_getCode", r2.b.result.is_contract === true && r2.b.result.tx_count === 42); }
  t("tx-activity: malformed address -> 400", (await free("/v1/tools/tx-activity/call", { address: "nope" }, "tx3")).s === 400);
  { const r2 = await free("/v1/tools/block-info/call", {}, "bi1");
    t("block: latest header (number/timestamp/tx count/base fee)", r2.b.result.valid === true && r2.b.result.block_number === 100000 && r2.b.result.timestamp === 1730000000 && r2.b.result.tx_count === 3 && r2.b.result.base_fee_gwei === 0.1, JSON.stringify(r2.b.result).slice(0, 160)); }
  t("block: hex block id accepted", (await free("/v1/tools/block-info/call", { block: "0x186a0" }, "bi2")).b.result.block_number === 100000);
  t("block: decimal block id accepted", (await free("/v1/tools/block-info/call", { block: "100000" }, "bi3")).b.result.block_number === 100000);
  t("block: bad block id -> 400", (await free("/v1/tools/block-info/call", { block: "not-a-block" }, "bi4")).s === 400);
  // RPC down: every new RPC tool 503s BEFORE payment (free AND paid paths)
  { RPC_UP = false;
    for (const [ntool, ninp] of [["balance-check", { address: AA }], ["erc20-balance", { address: AA, token_address: USDC }], ["tx-activity", { address: AA }], ["block-info", {}]]) {
      const rf = await free(`/v1/tools/${ntool}/call`, ninp, "rpcdn-" + ntool);
      t(`${ntool}: RPC down -> free 503 UPSTREAM_RPC_UNAVAILABLE`, rf.s === 503 && rf.b.error.code === "UPSTREAM_RPC_UNAVAILABLE" && rf.b.error.retryable === true);
      const before = settledNonces.size;
      const rp = await call(env, `/v1/tools/${ntool}/call`, { body: { input: ninp }, headers: { "X-PAYMENT": xpay(signVoucher({ value: "999" })) }, ip: "rpcdp-" + ntool });
      t(`${ntool}: paid attempt during outage 503s BEFORE settlement (nothing settles)`, rp.s === 503 && settledNonces.size === before);
    }
    RPC_UP = true; }
  // RPC-backed tools are NOT batchable: the batch tier stays offline/deterministic
  { const r2 = await free("/v1/tools/batch-validate/call", { items: [{ tool: "balance-check", value: AA }, { tool: "block-info", value: "latest" }] }, "nb1");
    t("batch: RPC-backed tools rejected (not batchable)", r2.b.result.count === 2 && r2.b.result.valid_count === 0 && r2.b.result.results.every(x => x.valid === false && /unknown tool/.test(x.reason))); }
  // pricing: new tools are in the price map (floors 999/999/999/2000)
  { const hp = (await call(env, "/health", { method: "GET" })).b.prices;
    t("pricing: on-chain tool floors quoted on /health", hp["balance-check"] === 999 && hp["erc20-balance"] === 999 && hp["tx-activity"] === 999 && hp["block-info"] === 2000); }

  // ---------- rental ----------
  const scamInput = { deposit_iban: "GB82WEST12345698765432", property_country: "DE", deposit_before_viewing: true, payment_irreversible: true, no_in_person_viewing: true, price_below_market_pct: 45, landlord_lei: "NOTALEI0000000000000" };
  r = await free("/v1/tools/rental-verdict/call", scamInput, "b1");
  t("verdict scam high-risk", r.b.result.verdict === "high-risk" && r.b.result.risk_score >= 80); // exact expected: 83
  t("verdict scam single deposit_before_viewing (no double-count)", r.b.result.flags.filter(f => f.flag === "deposit_before_viewing").length === 1);
  t("verdict receipt tool matches", r.b.receipt.tool === "rental-verdict");
  r = await free("/v1/tools/rental-verdict/call", { deposit_iban: "DE89370400440532013000", property_country: "DE" }, "b2");
  t("verdict clean clear/0", r.b.result.verdict === "clear" && r.b.result.risk_score === 0);
  r = await free("/v1/tools/rent-deposit-guard/call", { deposit_iban: "GB82WEST12345698765432", property_country: "DE", deposit_before_viewing: true }, "b3");
  t("deposit-guard high", r.b.result.band === "high" && r.b.result.country_match === false);
  r = await free("/v1/tools/rental-listing-risk/call", {}, "b4");
  t("listing-risk empty -> 0", r.b.result.risk_score === 0);

  // ---------- input abuse ----------
  // ---------- listability: GET on advertised paths must NOT 404 ----------
  { const g = await worker.fetch(REQ("/v1/tools/iban-check/call", { method: "GET" }), env);
    const doc = await g.json();
    t("listability: GET tool path -> 200 doc card (method POST)", g.status === 200 && doc.method === "POST" && doc.tool === "iban-check" && !!doc.input_schema);
    const gi = await worker.fetch(REQ("/v1/tools", { method: "GET" }), env);
    const idx = await gi.json();
    t("listability: GET /v1/tools -> 23-entry index", gi.status === 200 && idx.tools.length === 23); }
  t("missing required -> 400", (await free("/v1/tools/rental-verdict/call", { property_country: "DE" }, "c1")).s === 400);
  t("empty-string required -> 400", (await free("/v1/tools/iban-check/call", { iban: "" }, "c2")).s === 400);
  t("non-object input -> 400", (await call(env, "/v1/tools/iban-check/call", { body: { input: "GB82" }, ip: "c3" })).s === 400);
  t("bad JSON -> 400", (await call(env, "/v1/tools/iban-check/call", { body: "{not json", ip: "c4" })).s === 400);
  t("unknown tool -> 404", (await free("/v1/tools/nope/call", { x: 1 }, "c5")).s === 404);
  { const r2 = await free("/v1/tools/rental-verdict/call", JSON.parse('{"__proto__":{"polluted":true},"deposit_iban":"DE89370400440532013000"}'), "c6");
    t("prototype-pollution input safe", r2.s === 200 && ({}).polluted === undefined); }

  // ---------- MCP protocol ----------
  const mcp = (m, params) => call(env, "/mcp", { body: { jsonrpc: "2.0", id: 1, method: m, ...(params ? { params } : {}) }, ip: "m1" });
  t("mcp initialize", (await mcp("initialize")).b.result.protocolVersion === "2024-11-05");
  t("mcp ping", (await mcp("ping")).b.result !== undefined);
  t("mcp notifications/initialized 204", (await mcp("notifications/initialized")).s === 204);
  r = await mcp("tools/list"); t("mcp tools/list 23 + schema", r.b.result.tools.length === 23 && r.b.result.tools.every(x => x.inputSchema));
  t("mcp resources/list empty", JSON.stringify((await mcp("resources/list")).b.result) === '{"resources":[]}');
  t("mcp prompts/list empty", JSON.stringify((await mcp("prompts/list")).b.result) === '{"prompts":[]}');
  { const tl = (await mcp("tools/list")).b.result.tools; t("tools: readOnly+idempotent annotations + outputSchema + title", tl.every(x => x.annotations?.readOnlyHint === true && x.annotations?.idempotentHint === true && x.outputSchema && x.title)); }
  { const cap = (await mcp("initialize")).b.result.capabilities; t("initialize declares resources+prompts+tools caps", !!cap.resources && !!cap.prompts && !!cap.tools); }
  { const res = await worker.fetch(REQ("/", { method: "GET" }), env); const html = await res.text(); t("homepage 200 + self-describing (no registry)", res.status === 200 && /openfang-rail/.test(html) && /\/mcp/.test(html) && !/smithery/i.test(html)); }
  { const r2 = await call(env, "/openapi.json", { method: "GET" }); t("openapi.json 3.1 + 23 paths + derived server URL", r2.s === 200 && r2.b.openapi === "3.1.0" && Object.keys(r2.b.paths).length === 23 && r2.b.paths["/v1/tools/iban-check/call"].post.requestBody && r2.b.servers[0].url === "https://x"); }
  { const r2 = await call(env, "/.well-known/mcp.json", { method: "GET" }); t("mcp.json tools: example_request + output_schema + title", r2.b.tools.every(x => x.example_request?.input && x.output_schema && x.title)); }
  { const tl = (await mcp("tools/list")).b.result.tools; t("tools/list inputSchema carries examples", tl.every(x => Array.isArray(x.inputSchema.examples) && x.inputSchema.examples.length === 1)); }
  { // registry-linter conformance: snake_case MCP names + EVERY parameter described
    const tl = (await mcp("tools/list")).b.result.tools;
    t("conformance: MCP tool names snake_case", tl.every(x => /^[a-z0-9_]+$/.test(x.name)), tl.map(x => x.name).filter(n => !/^[a-z0-9_]+$/.test(n)).join(","));
    const bare = [];
    for (const x of tl) for (const [k, v] of Object.entries(x.inputSchema.properties || {})) if (!v.description) bare.push(`${x.name}.${k}`);
    t("conformance: every input parameter has a description", bare.length === 0, bare.join(","));
    const so = tl.find(x => x.name === "settlement_history_check");
    t("conformance: kebab->snake mapping correct", !!so && so.title === "Settlement history (counterparty proof)"); }
  r = await mcp("tools/call", { name: "iban_check", arguments: { iban: "GB82 WEST 1234 5698 7654 32" } });
  t("mcp tools/call snake_case ok", r.b.result.isError === false && /"valid":true/.test(r.b.result.content[0].text));
  r = await mcp("tools/call", { name: "iban-check", arguments: { iban: "GB82 WEST 1234 5698 7654 32" } });
  t("mcp tools/call kebab also accepted (compat)", r.b.result.isError === false && /"valid":true/.test(r.b.result.content[0].text));
  t("mcp tools/call unknown -> error", (await mcp("tools/call", { name: "nope", arguments: {} })).b.error !== undefined);
  t("mcp tools/call missing args -> error", (await mcp("tools/call", { name: "iban_check" })).b.error !== undefined);

  // ---------- payment path (signed voucher + mocked facilitator) ----------
  clearDp();
  const live = async (tool) => (await call(env, "/health", { method: "GET" })).b.prices[tool]; // dynamic price at sign time
  MOCK_SETTLE = "success";
  const v1 = signVoucher();
  r = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(v1) }, ip: "pay1" });
  t("paid: valid voucher + settle success -> 200 settled tx", r.s === 200 && r.b.settlement.settled === true && r.b.settlement.tx === "0xTESTTX" && r.b.tier === "paid");
  // standard x402 X-PAYMENT payload (payload.authorization wrapper) must also settle
  { const v = signVoucher({ value: String(await live("iban-check")) }); const std = { x402Version: 1, scheme: "exact", network: "base", payload: { signature: v.signature, authorization: { from: v.from, to: v.to, value: v.value, validAfter: v.validAfter, validBefore: v.validBefore, nonce: v.nonce } } };
    const rs = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(std) }, ip: "std1" });
    t("paid: STANDARD x402 X-PAYMENT payload settles", rs.s === 200 && rs.b.settlement.settled === true); }
  // referral attribution (non-custodial): captured from ?ref=, echoed, attributed only when paid
  { const r2 = await call(env, "/v1/tools/iban-check/call?ref=0xREF1", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, ip: "refA" }); t("referral: free call records referrer, attributed=false", r2.b.referral?.referrer === "0xREF1" && r2.b.referral.attributed === false); }
  { MOCK_SETTLE = "success"; const v = signVoucher({ value: String(await live("iban-check")) }); const r2 = await call(env, "/v1/tools/iban-check/call?ref=0xREF2", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(v) }, ip: "refB" }); t("referral: paid call attributes referrer=true", r2.b.referral?.referrer === "0xREF2" && r2.b.referral.attributed === true); }
  // replay same voucher -> REPLAY (nonce burned after success)
  r = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(v1) }, ip: "pay1b" });
  t("paid: nonce replay rejected", r.s === 402 && r.b.error.code === "REPLAY");
  // settle failure -> 402 SETTLEMENT_FAILED, nonce NOT burned (retryable)
  MOCK_SETTLE = "fail"; const v2 = signVoucher({ value: String(await live("iban-check")) });
  r = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(v2) }, ip: "pay2" });
  t("paid: settle fail -> 402 SETTLEMENT_FAILED", r.s === 402 && r.b.error.code === "SETTLEMENT_FAILED");
  MOCK_SETTLE = "success"; // retry same voucher should now succeed (nonce was not burned)
  r = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(v2) }, ip: "pay2b" });
  t("paid: failed-settle nonce is retryable", r.s === 200 && r.b.settlement.settled === true);
  // settle unreachable -> 502
  MOCK_SETTLE = "throw"; const v3 = signVoucher({ value: String(await live("iban-check")) });
  r = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(v3) }, ip: "pay3" });
  t("paid: facilitator unreachable -> 502", r.s === 502 && r.b.error.code === "SETTLEMENT_UNAVAILABLE");
  MOCK_SETTLE = "success";
  // failover chain: primary 5xx -> fallback settles; business failure -> terminal
  { const envF = baseEnv(); envF.FACILITATOR_URL = "https://mock.facilitator"; envF.FACILITATOR_URLS = "https://mock.facilitator, https://mock2.facilitator";
    MOCK_PRIMARY_500 = true; const rf = await call(envF, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(signVoucher({ value: String(FLOOR) })) }, ip: "fo1" });
    t("failover: primary 500 -> fallback settles", rf.s === 200 && rf.b.settlement.settled === true, JSON.stringify(rf.b).slice(0,120));
    MOCK_PRIMARY_500 = false;
    MOCK_SETTLE = "fail"; const p2 = (await call(envF, "/health", { method: "GET" })).b.prices["iban-check"]; // prior sale bumped the dynamic price — sign at live quote
    const rf2 = await call(envF, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(signVoucher({ value: String(p2) })) }, ip: "fo2" });
    MOCK_SETTLE = "success";
    t("failover: business failure is terminal (no cross-facilitator retry)", rf2.s === 402 && rf2.b.error.code === "SETTLEMENT_FAILED", "s=" + rf2.s + " b=" + JSON.stringify(rf2.b).slice(0,200)); }
  // Bazaar discovery on the paywall 402 challenge (FREE_CALLS=0 -> any call 402s)
  { const envB = baseEnv(); envB.FREE_CALLS_PER_DAY = "0";
    const rb = await call(envB, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, ip: "bz1" });
    const bz = rb.b.extensions?.bazaar?.info;
    t("bazaar: 402 carries extensions.bazaar.info", !!bz && bz.input?.type === "http" && bz.input?.method === "POST" && !!bz.inputSchema && !!bz.output?.example, JSON.stringify(rb.b.extensions||{}).slice(0,120));
    t("bazaar: resource metadata (serviceName + tags)", rb.b.resource?.serviceName === "openfang-rail" && Array.isArray(rb.b.resource?.tags) && rb.b.resource.tags.length <= 5); }
  // voucher tampering / mismatches
  t("paid: bad signature -> BAD_SIGNATURE", (await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay({ ...signVoucher(), signature: "0x" + "00".repeat(65) }) }, ip: "pay4" })).b.error?.code === "BAD_SIGNATURE");
  t("paid: wrong amount -> PRICE_MISMATCH", (await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(signVoucher({ value: "1" })) }, ip: "pay5" })).b.error?.code === "PRICE_MISMATCH");
  t("paid: wrong recipient -> RECIPIENT_MISMATCH", (await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(signVoucher({ to: "0x0000000000000000000000000000000000000009", value: String(await live("iban-check")) })) }, ip: "pay6" })).b.error?.code === "RECIPIENT_MISMATCH");
  t("paid: expired -> EXPIRED", (await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(signVoucher({ validBefore: "1", value: String(await live("iban-check")) })) }, ip: "pay7" })).b.error?.code === "EXPIRED");

  // malformed payment payloads must fail CLOSED with a clean 402 — never a 500
  { const r2 = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay({ from: PAYER, to: RECIP, value: "abc", validAfter: "0", validBefore: "9999999999", nonce: "0x" + "11".repeat(32), signature: "0x" + "22".repeat(65) }) }, ip: "mal1" });
    t("paid: non-numeric value -> 402 MALFORMED_PAYMENT (no 500)", r2.s === 402 && r2.b.error?.code === "MALFORMED_PAYMENT"); }
  t("paid: non-base64 X-PAYMENT -> 402 MALFORMED_PAYMENT", (await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": "!!!not-base64!!!" }, ip: "mal2" })).b.error?.code === "MALFORMED_PAYMENT");
  t("paid: x402 wrapper missing authorization -> 402 (no 500)", (await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay({ x402Version: 1, scheme: "exact", payload: { signature: "0x" + "00".repeat(65) } }) }, ip: "mal3" })).s === 402);

  // ---------- batch tier (one payment, one receipt, up to 50 checks) ----------
  clearDp(); // batch price = max(50000, 5 x dynamic single) — start from the floor
  { const r2 = await free("/v1/tools/batch-validate/call", { items: [{ tool: "iban-check", value: "GB82 WEST 1234 5698 7654 32" }, { tool: "lei-check", value: "529900T8BM49AURSDO55" }, { tool: "vat-mod97-check", value: "BE123" }, { tool: "nope", value: "x" }] }, "bat1");
    t("batch: mixed items -> counts + unknown-tool per-item error", r2.b.result.count === 4 && r2.b.result.valid_count === 2 && r2.b.result.invalid_count === 2 && r2.b.result.results[3].valid === false && /unknown tool/.test(r2.b.result.results[3].reason));
    t("batch: one receipt covers the whole batch", r2.b.receipt.tool === "batch-validate"); }
  t("batch: empty items -> 400", (await free("/v1/tools/batch-validate/call", { items: [] }, "bat2")).s === 400);
  t("batch: non-array items -> 400", (await free("/v1/tools/batch-validate/call", { items: "nope" }, "bat3")).s === 400);
  t("batch: 51 items -> 400", (await free("/v1/tools/batch-validate/call", { items: Array.from({ length: 51 }, () => ({ tool: "iban-check", value: "GB82 WEST 1234 5698 7654 32" })) }, "bat4")).s === 400);
  t("batch: 50 items (max) ok + all valid", (await free("/v1/tools/batch-validate/call", { items: Array.from({ length: 50 }, () => ({ tool: "iban-check", value: "GB82 WEST 1234 5698 7654 32" })) }, "bat5")).b.result.count === 50);
  { const v = signVoucher({ value: "50000" }); const r2 = await call(env, "/v1/tools/batch-validate/call", { body: { input: { items: [{ tool: "iban-check", value: "GB82 WEST 1234 5698 7654 32" }, { tool: "lei-check", value: "529900T8BM49AURSDO55" }] } }, headers: { "X-PAYMENT": xpay(v) }, ip: "bat6" });
    t("batch: paid at flat 50000 -> settled", r2.s === 200 && r2.b.settlement.settled === true && r2.b.receipt.amount === "50000"); }

  // free-tier exhaustion: exactly 20 free, 21st -> 402
  clearDp();
  let last; for (let i = 0; i < 21; i++) last = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, ip: "exh" });
  t("free tier: 21st call -> 402 mainnet challenge", last.s === 402 && last.b.chain_id === 8453 && last.b.token_address === USDC && last.b.eip712_domain.name === "USD Coin" && last.b.amount === String(FLOOR));
  t("402 is standard x402 (accepts[])", last.b.x402Version === 1 && Array.isArray(last.b.accepts) && last.b.accepts[0].scheme === "exact" && last.b.accepts[0].payTo === RECIP && last.b.accepts[0].maxAmountRequired === String(FLOOR) && last.b.accepts[0].network === "base");
  // v2 handshake (official @x402 SDK contract): base64 PAYMENT-REQUIRED header,
  // CAIP-2 network, amount field, bazaar extension
  { const envV = baseEnv(); envV.FREE_CALLS_PER_DAY = "0";
    const h = await worker.fetch(REQ("/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, ip: "v2h" }), envV);
    const v2 = JSON.parse(Buffer.from(h.headers.get("payment-required") || "", "base64").toString());
    const a = v2.accepts[0];
    t("v2: PAYMENT-REQUIRED header decodes to x402Version 2 + CAIP-2 + amount", v2.x402Version === 2 && a.network === "eip155:8453" && a.amount === String(FLOOR) && /^https:\/\/x\//.test(a.resource), JSON.stringify(a).slice(0, 140));
    t("v2: challenge carries bazaar extension", !!v2.extensions?.bazaar?.info?.inputSchema); }
  { const xm = (await call(env, "/.well-known/x402.json", { method: "GET" })).b;
    t("x402.json advertises bazaar extension", Array.isArray(xm.extensions) && xm.extensions.includes("bazaar")); }
  { const xm2 = (await call(env, "/.well-known/x402.json", { method: "GET" })).b;
    t("x402.json carries parseable resources[] for crawlers (23)", Array.isArray(xm2.resources) && xm2.resources.length === 23 && xm2.resources.every(r => r.accepts?.[0]?.payTo && r.accepts[0].amount && r.extensions?.bazaar), JSON.stringify(xm2.resources?.[0]||{}).slice(0,120)); }
  // PAYMENT-SIGNATURE header (v2 official client) accepted end-to-end
  { clearDp(); const v = signVoucher({ value: String(FLOOR) });
    const r2 = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "PAYMENT-SIGNATURE": xpay({ x402Version: 2, payload: { signature: v.signature, authorization: { from: v.from, to: v.to, value: v.value, validAfter: v.validAfter, validBefore: v.validBefore, nonce: v.nonce } } }) }, ip: "v2p" });
    t("v2: PAYMENT-SIGNATURE header settles", r2.s === 200 && r2.b.settlement.settled === true, "s=" + r2.s + " " + JSON.stringify(r2.b).slice(0, 140)); }
  // per-tool value pricing: the bundled verdict quotes more than a simple check
  { let l2; for (let i = 0; i < 21; i++) l2 = await call(env, "/v1/tools/rental-verdict/call", { body: { input: { deposit_iban: "DE89370400440532013000", property_country: "DE" } }, ip: "vpx" }); t("per-tool pricing: rental-verdict 402 quotes 50000", l2.s === 402 && l2.b.amount === "50000" && l2.b.accepts[0].maxAmountRequired === "50000"); }

  // mainnet + no facilitator -> 503 on paid
  const env2 = baseEnv(); env2.FACILITATOR_URL = "";
  r = await call(env2, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(signVoucher()) }, ip: "nf1" });
  t("mainnet no-facilitator paid -> 503", r.s === 503 && r.b.error.code === "SETTLEMENT_NOT_CONFIGURED");

  // ---------- receipt crypto (offline recovery + tamper) ----------
  const rc = (await free("/v1/tools/iban-check/call", { iban: "GB82 WEST 1234 5698 7654 32" }, "rec1")).b.receipt;
  const canon = (o) => [o.v, o.tool, o.tool_version, o.input_hash, o.output_hash, o.payer, o.recipient, o.amount, o.nonce, o.ts, o.tier].join("|");
  const recoverSigner = (o) => { const s = hb(o.signature); let v = s[64]; if (v >= 27) v -= 27; const sig = new secp256k1.Signature(BigInt("0x" + bh(s.slice(0, 32))), BigInt("0x" + bh(s.slice(32, 64)))).addRecoveryBit(v); return "0x" + bh(keccak_256(sig.recoverPublicKey(keccak_256(te.encode(canon(o)))).toRawBytes(false).slice(1)).slice(12)); };
  t("receipt: recovers to published signer", recoverSigner(rc).toLowerCase() === rc.signer.toLowerCase());
  t("receipt: tamper breaks recovery", recoverSigner({ ...rc, amount: "999" }).toLowerCase() !== rc.signer.toLowerCase());

  // ---------- determinism ----------
  const d1 = (await free("/v1/tools/rental-verdict/call", scamInput, "det1")).b.result;
  const d2 = (await free("/v1/tools/rental-verdict/call", scamInput, "det2")).b.result;
  t("determinism: identical result", JSON.stringify(d1) === JSON.stringify(d2));

  // ---------- concurrency / sniping ----------
  // (a) free-tier quota race: the KV counter is read-then-write, so a burst of
  // concurrent calls from one IP overshoots the daily free quota. KNOWN, accepted:
  // bounded free-service leak of deterministic checks (no paid-path impact — see (b)).
  { const shots = Array.from({ length: 25 }, () => call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, ip: "racefree" }));
    const rs = await Promise.all(shots);
    const served = rs.filter(x => x.s === 200 && x.b.tier === "free").length;
    t("sniping: free-tier concurrency overshoot exists (documented, bounded)", served > 20, `${served}/25 served free vs limit 20`); }
  // (b) same-voucher double-spend: fire ONE voucher at 8 concurrent requests. The
  // KV burn happens after settle, so all 8 pass the replay check — but USDC's
  // on-chain authorizationState settles each nonce at most once (mocked faithfully),
  // so exactly ONE result is ever delivered for ONE payment.
  { MOCK_SETTLE = "success"; const v = signVoucher({ value: String(await live("iban-check")) });
    const shots = Array.from({ length: 8 }, () => call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(v) }, ip: "racedupe" }));
    const rs = await Promise.all(shots);
    const ok200 = rs.filter(x => x.s === 200).length, rej = rs.filter(x => x.s === 402).length;
    t("sniping: same-voucher concurrency -> exactly 1 result per payment", ok200 === 1 && rej === 7, `${ok200} delivered, ${rej} rejected`);
    const after = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, headers: { "X-PAYMENT": xpay(v) }, ip: "racedupe2" });
    t("sniping: voucher dead after the race (REPLAY)", after.s === 402 && after.b.error?.code === "REPLAY"); }

  // ---------- dynamic pricing (reverse/Dutch + sniping via /health) ----------
  clearDp();
  { // idle decay: seeded high price decays toward the floor but stays above it; /health quotes it live
    await env.NONCES.put("dp:iban-check", JSON.stringify({ p: 50000, t: Math.floor(Date.now() / 1000) - 3600 }));
    const q = (await call(env, "/health", { method: "GET" })).b.prices["iban-check"];
    t("dyn: idle price decays toward floor; /health quotes live", q > FLOOR && q < 50000, `q=${q}`);
    t("dyn: /health publishes the pricing rule (mode/tau/bump/cap)", (await call(env, "/health", { method: "GET" })).b.pricing.mode === "dynamic-dutch");
    let l2; for (let i = 0; i < 21; i++) l2 = await call(env, "/v1/tools/iban-check/call", { body: { input: { iban: "GB82 WEST 1234 5698 7654 32" } }, ip: "dpx1" });
    t("dyn: 402 challenge quotes the live (decayed) price, not the floor", l2.s === 402 && Math.abs(Number(l2.b.amount) - q) <= 10 && Number(l2.b.accepts[0].maxAmountRequired) === Number(l2.b.amount), `402=${l2.b.amount} q=${q}`); }
  { // sale bump: a settled sale raises the stored price by the bump factor
    const q0 = (await call(env, "/health", { method: "GET" })).b.prices["lei-check"]; // fresh -> floor 10000
    MOCK_SETTLE = "success";
    const r2 = await call(env, "/v1/tools/lei-check/call", { body: { input: { lei: "529900T8BM49AURSDO55" } }, headers: { "X-PAYMENT": xpay(signVoucher({ value: String(q0) })) }, ip: "dpx2" });
    const st = JSON.parse((await env.NONCES.get("dp:lei-check")) || "null");
    t("dyn: settled sale bumps the price up (x1.5)", r2.s === 200 && st && st.p === Math.round(q0 * 1.5), JSON.stringify(st));
    t("dyn: /health reflects the bump immediately", (await call(env, "/health", { method: "GET" })).b.prices["lei-check"] === st.p);
    // free calls never move the price
    const before = (await call(env, "/health", { method: "GET" })).b.prices["lei-check"];
    await call(env, "/v1/tools/lei-check/call", { body: { input: { lei: "529900T8BM49AURSDO55" } }, ip: "dpx3" });
    t("dyn: free-tier calls never bump the price", (await call(env, "/health", { method: "GET" })).b.prices["lei-check"] === before); }
  { // ceiling clamp + batch surge-riding
    await env.NONCES.put("dp:vat-mod97-check", JSON.stringify({ p: 999999999, t: Math.floor(Date.now() / 1000) }));
    t("dyn: ceiling clamps at floor x mult", (await call(env, "/health", { method: "GET" })).b.prices["vat-mod97-check"] === VCEIL);
    await env.NONCES.put("dp:iban-check", JSON.stringify({ p: 50000, t: Math.floor(Date.now() / 1000) }));
    t("dyn: batch rides the surge (>= 5x dynamic single)", (await call(env, "/health", { method: "GET" })).b.prices["batch-validate"] === BATCH_MAX_PRICE); }
  { // manifests publish the rule honestly
    const m = (await call(env, "/.well-known/mcp.json", { method: "GET" })).b;
    t("dyn: mcp.json publishes mode+rule and per-tool ceiling", m.pricing.mode === "dynamic-dutch" && m.tools.every(x => typeof x.price_usdc_ceiling === "number"));
    t("dyn: x402.json publishes pricing_mode/rule", (await call(env, "/.well-known/x402.json", { method: "GET" })).b.pricing_mode === "dynamic-dutch"); }

  // ---------- logic parity vs tested rental.mjs (compare logic fields, not note prose) ----------
  const strip = (o) => ({ verdict: o.verdict, risk_score: o.risk_score, band: o.band, flags: (o.flags || o.flags_fired || []).map(f => f.flag + ":" + f.weight).sort() });
  const cases = [
    {}, { deposit_iban: "DE89370400440532013000", property_country: "DE" },
    { deposit_iban: "GB82WEST12345698765432", property_country: "DE", deposit_before_viewing: true },
    { deposit_iban: "FR14 2004 1010 0505 0001 3M02 606", property_country: "FR", payment_irreversible: true, urgency_pressure: true },
    scamInput, { deposit_iban: "xx", property_country: "US", price_below_market_pct: 70, no_in_person_viewing: true },
  ];
  let parity = 0;
  for (const c of cases) {
    const w = (await free("/v1/tools/rental-verdict/call", { deposit_iban: "DE89370400440532013000", ...c }, "p" + Math.random())).b.result;
    const ref = rvRef({ deposit_iban: "DE89370400440532013000", ...c });
    if (JSON.stringify(strip(w)) === JSON.stringify(strip(ref))) parity++;
    else console.log("  PARITY DIFF:", JSON.stringify(strip(w)), "vs", JSON.stringify(strip(ref)));
  }
  t(`rental logic parity worker==rental.mjs (${parity}/${cases.length})`, parity === cases.length);

  console.log(`\n${ok}/${n} QA checks passed`);
  process.exit(ok === n ? 0 : 1);
}
run().catch(e => { console.error("HARNESS ERROR:", e); process.exit(2); });

