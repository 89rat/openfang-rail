// /sign — the disclosed SELF-TEST purchase, signed inside the buyer's own wallet.
// Open this page in a WALLET app's dApp browser (Binance Web3 wallet, MetaMask
// mobile, Trust...). The wallet injects window.ethereum, signs the EIP-3009
// voucher via eth_signTypedData_v4 (key never leaves the wallet), and the page
// submits it to the rail. Label: DISCLOSED SELF-TEST — never a "customer".

export interface SignData {
  origin: string;
  recipient: string;
  usdc: string;
  chainId: number;
  domainName: string;
  cheapest: { tool: string; price: string };
}

export function signPage(d: SignData): string {
  const dataJson = JSON.stringify(d).replace(/</g, "\\u003c").replace(/'/g, "\\u0027");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>openfang-rail — sign the self-test</title>
<style>
body{background:#0a0c10;color:#c9d4e3;font-family:ui-monospace,Consolas,monospace;font-size:14px;line-height:1.6;padding:26px 18px;max-width:520px;margin:0 auto}
h1{font-size:16px;color:#fff;letter-spacing:1px} .acc{color:#39d98a}.warn{color:#ffb454}.dim{color:#6b7a90}
button{width:100%;padding:15px;font-size:15px;font-family:inherit;border:none;border-radius:10px;cursor:pointer;margin:8px 0}
.c{background:#39d98a;color:#04140c;font-weight:bold}.s{background:#4da3ff;color:#04140c;font-weight:bold}
button:disabled{opacity:.4}
.card{background:#10141b;border:1px solid #1d2430;border-radius:10px;padding:14px;margin:12px 0}
#log{background:#07090d;border:1px solid #1d2430;border-radius:8px;padding:12px;min-height:120px;white-space:pre-wrap;word-break:break-all;font-size:12.5px;margin-top:12px}
.l{color:#39d98a}.e{color:#ff6b6b}.d{color:#6b7a90}
.badge{display:inline-block;background:#ffb454;color:#231500;font-size:11px;font-weight:bold;padding:3px 10px;border-radius:5px;letter-spacing:1px}
</style></head><body>
<span class="badge">DISCLOSED SELF-TEST</span>
<h1>openfang-rail — sign &amp; pay</h1>
<p class="dim">This buys ONE call from <b>your wallet</b> (${esc(d.origin)} rail, USDC on Base). It is an operator self-test, <b>never a customer sale</b>. The signature happens inside your wallet; your key never leaves it.</p>
<div class="card" id="st">❓ connect your wallet first</div>
<button class="c" id="connect">1 · CONNECT WALLET</button>
<button class="s" id="pay" disabled>2 · SIGN &amp; PAY ${esc(d.cheapest.price)} USDC → ${esc(d.cheapest.tool)}</button>
<div id="log" class="dim">waiting…</div>
<p class="dim" style="font-size:11px">EIP-3009 TransferWithAuthorization · domain: ${esc(d.domainName)} v2 · chainId ${d.chainId} · settles payer→recipient directly; this rail never holds funds.</p>
<script>
const D = JSON.parse('${dataJson}');
const log = (m, cls) => { const el = document.getElementById("log"); const p = document.createElement("div"); p.className = cls || ""; p.textContent = m; el.appendChild(p); };
const USDC = D.usdc, RECIP = D.recipient, CID = "0x" + D.chainId.toString(16);
let acct = null;
const st = document.getElementById("st");
function setSt(t) { st.innerHTML = t; }
async function getProvider() {
  if (window.ethereum) return window.ethereum;
  throw new Error("no injected wallet found — open this page inside your wallet app's dApp browser");
}
document.getElementById("connect").onclick = async () => {
  try {
    const p = await getProvider();
    const accounts = await p.request({ method: "eth_requestAccounts" });
    acct = accounts[0];
    const cid = await p.request({ method: "eth_chainId" });
    if (Number(cid) !== D.chainId) {
      log("wrong chain (" + Number(cid) + ") — switching to Base…", "d");
      try { await p.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CID }] }); }
      catch (e) { await p.request({ method: "wallet_addEthereumChain", params: [{ chainId: CID, chainName: "Base", nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 }, rpcUrls: ["https://base-rpc.publicnode.com"], blockExplorerUrls: ["https://basescan.org"] }] }); }
    }
    const balHex = await p.request({ method: "eth_call", params: [{ to: USDC, data: "0x70a08231" + acct.slice(2).toLowerCase().padStart(64, "0") }, "latest"] });
    const bal = Number(BigInt(balHex)) / 1e6;
    setSt('✅ <span class="acc">' + acct + "</span><br>USDC on Base: " + bal + " · chain: Base ✓");
    document.getElementById("pay").disabled = false;
    log("wallet connected: " + acct, "l");
  } catch (e) { log("connect failed: " + (e.message || e), "e"); setSt("❌ connect failed"); }
};
document.getElementById("pay").onclick = async () => {
  try {
    const p = await getProvider();
    const now = Math.floor(Date.now() / 1000);
    const voucher = {
      types: { EIP712Domain: [{ name: "name", type: "string" }, { name: "version", type: "string" }, { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" }], TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] },
      primaryType: "TransferWithAuthorization",
      domain: { name: D.domainName, version: "2", chainId: D.chainId, verifyingContract: D.usdc },
      message: { from: acct, to: D.recipient, value: D.cheapest.price, validAfter: String(now - 60), validBefore: String(now + 300), nonce: "0x" + [...crypto.getRandomValues(new Uint8Array(32))].map(x => x.toString(16).padStart(2, "0")).join("") }
    };
    log("requesting signature from your wallet…", "d");
    const sig = await p.request({ method: "eth_signTypedData_v4", params: [acct, JSON.stringify(voucher)] });
    log("signed ✓ — submitting to the rail…", "l");
    const payload = { x402Version: 2, scheme: "exact", network: "eip155:" + D.chainId, payload: { signature: sig, authorization: voucher.message } };
    const r = await fetch(D.origin + "/v1/tools/" + D.cheapest.tool + "/call", { method: "POST", headers: { "content-type": "application/json", "X-PAYMENT": btoa(JSON.stringify(payload)) }, body: JSON.stringify({ input: D.cheapest.example }) });
    const b = await r.json();
    if (r.status === 200 && b.settlement && b.settlement.settled) {
      log("✅ SETTLED — tx: " + (b.settlement.tx || "(see receipt)") , "l");
      log("receipt signer: " + (b.receipt && b.receipt.signer) + " · amount: " + (b.receipt && b.receipt.amount) + " · tier: " + b.tier, "l");
      log("DISCLOSED SELF-TEST COMPLETE — loop proven with real settlement.", "l");
      document.getElementById("st").innerHTML = '✅ <span class="acc">SELF-TEST SETTLED</span><br>tx: ' + (b.settlement.tx || "?");
    } else {
      log("HTTP " + r.status + ": " + JSON.stringify(b).slice(0, 220), "e");
    }
  } catch (e) { log("pay failed: " + (e.message || e), "e"); }
};
function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }
</script></body></html>`;
}
function esc(s: unknown) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }
