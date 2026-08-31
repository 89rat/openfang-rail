// prove-sale (source) — self-contained EIP-3009 prover. Bundled to prove/prove-sale.mjs
// with @noble inlined, so the end user needs NO npm install — just `node prove-sale.mjs`.
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

const RAIL = process.env.RAIL || "https://rail.akrivis.in";
const RPC = process.env.BASE_RPC || "https://mainnet.base.org";
const RECIPIENT = "0xc59c85e661d34084a7769f955d17fd38254a6235";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const VALUE = 590n;
const CHAIN_ID = 8453n;
const COUNT = Math.max(1, parseInt(process.env.COUNT || "3", 10));
const PROBES = [
  { tool: "iban-check", input: { iban: "GB82 WEST 1234 5698 7654 32" } },
  { tool: "rental-verdict", input: { deposit_iban: "GB82WEST12345698765432", property_country: "DE", deposit_before_viewing: true, payment_irreversible: true, no_in_person_viewing: true, price_below_market_pct: 45 } },
  { tool: "lei-check", input: { lei: "529900T8BM49AURSDO55" } },
];

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

const pkHex = process.env.PAYER_PRIVATE_KEY;
if (!pkHex || !/^0x?[0-9a-fA-F]{64}$/.test(pkHex.startsWith("0x") ? pkHex : "0x" + pkHex)) {
  console.error("ERROR: set PAYER_PRIVATE_KEY to a 32-byte (64 hex char) Base-mainnet wallet key holding a few cents of USDC.");
  console.error('  Windows:  set PAYER_PRIVATE_KEY=0x....   then:  node prove-sale.mjs');
  process.exit(1);
}
const PK = hb(pkHex.startsWith("0x") ? pkHex : "0x" + pkHex);
const PAYER = addrFromPriv(PK);

function signVoucher() {
  const now = Math.floor(Date.now() / 1000);
  const m = { from: PAYER, to: RECIPIENT, value: VALUE.toString(), validAfter: "0", validBefore: String(now + 300), nonce: "0x" + bh(crypto.getRandomValues(new Uint8Array(32))) };
  const sig = secp256k1.sign(voucherDigest(domainSep("USD Coin", "2", CHAIN_ID, USDC), m), PK);
  m.signature = "0x" + bh(sig.toCompactRawBytes()) + (sig.recovery + 27).toString(16).padStart(2, "0");
  return m;
}
async function rpc(method, params) { const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) }); return (await r.json()).result; }
async function balanceOf(addr) { try { const data = "0x70a08231" + "0".repeat(24) + addr.replace(/^0x/, "").toLowerCase(); const res = await rpc("eth_call", [{ to: USDC, data }, "latest"]); return res ? BigInt(res) : null; } catch { return null; } }
async function settleOnce(p) {
  const v = signVoucher();
  const res = await fetch(`${RAIL}/v1/tools/${p.tool}/call`, { method: "POST", headers: { "content-type": "application/json", "X-PAYMENT": Buffer.from(JSON.stringify(v)).toString("base64") }, body: JSON.stringify({ input: p.input }) });
  const body = await res.json().catch(() => ({}));
  return { ok: res.status === 200 && body?.settlement?.settled === true, status: res.status, tx: body?.settlement?.tx, body };
}

(async () => {
  console.log("Payer    :", PAYER);
  console.log("Recipient:", RECIPIENT);
  if (COUNT > 25) console.log(`\n⚠️  ${COUNT} self-paid settlements is WASH TRADING — proves nothing past ~10 and is a delisting red flag. Real volume comes from external payers.\n`);
  console.log(`Proving ${COUNT} settlement(s) at ${(Number(VALUE) / 1e6).toFixed(6)} USDC each via PayAI (gas-sponsored)…\n`);
  const before = await balanceOf(RECIPIENT);
  let ok = 0;
  for (let i = 0; i < COUNT; i++) {
    const p = PROBES[i % PROBES.length];
    process.stdout.write(`  [${i + 1}/${COUNT}] ${p.tool} … `);
    try { const r = await settleOnce(p); if (r.ok) { ok++; console.log("settled  tx " + r.tx); } else console.log(`not settled (${r.status}) ${JSON.stringify(r.body?.error || r.body).slice(0, 150)}`); }
    catch (e) { console.log("error: " + e.message); }
  }
  const after = await balanceOf(RECIPIENT);
  console.log(`\n${ok}/${COUNT} settlements confirmed on-chain.`);
  if (before != null && after != null) { const d = Number(after - before) / 1e6; console.log(`Payout wallet USDC: ${Number(before) / 1e6} -> ${Number(after) / 1e6}  (delta +${d.toFixed(6)})`); console.log(d > 0 ? "That delta is real revenue in your wallet." : "(net-zero: payer == recipient self-test — still proves settlement fired)"); }
  console.log(ok === COUNT ? "\nThe loop works, repeatedly. Paste this to the assistant." : "\nSome settlements did not confirm — paste this output and we debug it. No funds move on a failed settle.");
  process.exit(ok === COUNT ? 0 : 1);
})();
