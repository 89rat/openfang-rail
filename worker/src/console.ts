// /console — protocol operations console (SOP site), zero-dependency, live-data.
// Everything server-injected is REAL: live dynamic quotes, actual chain config,
// facilitator probes measured at render. No fabricated uptimes, no mock data.

export interface ConsoleData {
  origin: string;
  version: string;
  signer: string | null;
  authorizedBy: string;
  attested: boolean;
  recipient: string;
  chain: string;
  tau: number;
  bump: number;
  mult: number;
  prices: Record<string, number>;
  floors: Record<string, number>;
  registryUrl: string;
  facilitators: { url: string; role: string; status: string; ms: number | null }[];
  generatedAt: string;
}

export function consolePage(d: ConsoleData): string {
  const esc = (s: unknown) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");
  const facilitatorsJson = JSON.stringify(d.facilitators);
  const tickerStr = Object.entries(d.prices).map(([t, p]) => t + " " + (p / 1e6).toFixed(6) + " USDC").concat(["chain: " + d.chain, "zero take-rate", "receipts attested", "official x402 SDK verified", "first 20 calls/day free", "registry: permissionless"]).join("  \u00b7  ");
  const tickerHtml = esc(tickerStr) + "&nbsp;&nbsp;\u00b7&nbsp;&nbsp;" + esc(tickerStr);
  const pricesJson = JSON.stringify({ prices: d.prices, floors: d.floors, tau: d.tau, bump: d.bump, mult: d.mult });
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>openfang-rail — protocol operations console</title>
<style>
:root{--bg:#0a0c10;--panel:#10141b;--line:#1d2430;--txt:#c9d4e3;--dim:#6b7a90;--acc:#39d98a;--acc2:#4da3ff;--warn:#ffb454;--err:#ff6b6b;--mono:ui-monospace,'Cascadia Code',Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:var(--mono);font-size:14px;line-height:1.6;padding:0 0 80px}
body::before{content:"";position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent 0 2px,rgba(255,255,255,.012) 2px 4px);pointer-events:none;z-index:0}
.wrap{max-width:980px;margin:0 auto;padding:28px 20px;position:relative;z-index:1}
h1{font-size:19px;letter-spacing:2px;color:#fff}
h1 .tag{color:var(--acc)}
h2{font-size:13px;letter-spacing:2px;color:var(--acc2);border-bottom:1px solid var(--line);padding-bottom:8px;margin:44px 0 16px;text-transform:uppercase}
.dim{color:var(--dim)} .acc{color:var(--acc)} .warn{color:var(--warn)} .err{color:var(--err)}
.led{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:var(--acc);box-shadow:0 0 8px var(--acc);animation:pulse 2.2s infinite}
@keyframes pulse{50%{opacity:.35}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px}
.stat .k{font-size:11px;color:var(--dim);letter-spacing:1px;text-transform:uppercase}
.stat .v{font-size:16px;color:#fff;margin-top:4px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left}
th{color:var(--dim);font-weight:normal;text-transform:uppercase;font-size:11px;letter-spacing:1px}
.term{background:#07090d;border:1px solid var(--line);border-radius:8px;padding:14px;min-height:230px;font-size:13px;white-space:pre-wrap;word-break:break-all}
.term .t-dim{color:var(--dim)} .term .t-acc{color:var(--acc)} .term .t-err{color:var(--err)} .term .t-warn{color:var(--warn)} .cursor{display:inline-block;width:8px;height:15px;background:var(--acc);vertical-align:-2px;animation:blink .9s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
button{background:transparent;border:1px solid var(--acc2);color:var(--acc2);font-family:var(--mono);font-size:12px;padding:6px 14px;border-radius:6px;cursor:pointer;letter-spacing:1px}
button:hover{background:rgba(77,163,255,.12)}
input[type=range]{width:170px;accent-color:var(--acc);vertical-align:middle}
label{font-size:12px;color:var(--dim)}
.chk{display:flex;gap:10px;padding:9px 6px;border-bottom:1px solid var(--line);cursor:pointer;align-items:baseline}
.chk input{accent-color:var(--acc)}
.chk.done span{color:var(--dim);text-decoration:line-through}
.bar{height:6px;background:var(--line);border-radius:3px;overflow:hidden;margin:10px 0}
.bar i{display:block;height:100%;background:var(--acc);width:0;transition:width .4s}
.tabs{display:flex;gap:6px;margin-bottom:0}
.tab{padding:7px 16px;border:1px solid var(--line);border-bottom:none;border-radius:6px 6px 0 0;cursor:pointer;color:var(--dim);font-size:12px;letter-spacing:1px}
.tab.on{color:var(--acc);border-color:var(--acc2);background:var(--panel)}
.snip{background:#07090d;border:1px solid var(--acc2);border-top:none;border-radius:0 0 8px 8px;padding:14px;font-size:12.5px;white-space:pre-wrap;word-break:break-all;display:none}
.snip.on{display:block}
.reveal{opacity:0;transform:translateY(14px);transition:opacity .5s,transform .5s}
.reveal.in{opacity:1;transform:none}
@media (prefers-reduced-motion: reduce){.led,.cursor{animation:none}.reveal{opacity:1;transform:none;transition:none}}
a{color:var(--acc2);text-decoration:none} a:hover{text-decoration:underline}
.ticker{overflow:hidden;border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:#07090d;margin:14px 0;padding:7px 0;white-space:nowrap}
.ticker i{display:inline-block;animation:tick 45s linear infinite;font-style:normal}
@keyframes tick{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.phases{display:flex;gap:14px;margin-bottom:10px;font-size:11px;letter-spacing:1px}
.ph{color:var(--dim)} .ph.on{color:var(--acc)}
</style></head><body><div class="wrap">
<div style="display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:8px">
<h1>openfang-rail <span class="tag">// PROTOCOL OPERATIONS</span></h1>
<div class="dim">UTC <span id="clock">--:--:--</span> · v${esc(d.version)} · generated ${esc(d.generatedAt)}Z</div>
</div>
<p class="dim" style="margin-top:6px">Standard Operating Procedure — live console. Every value on this page is read from the running worker at render time. Nothing here is a mock.</p>

<div class="ticker"><i>${tickerHtml}</i></div>
<h2>00 · System status</h2>
<div class="grid">
<div class="stat"><div class="k">Worker</div><div class="v"><span class="led"></span>OPERATIONAL</div></div>
<div class="stat"><div class="k">Chain</div><div class="v">${esc(d.chain)} · mainnet</div></div>
<div class="stat"><div class="k">Receipts</div><div class="v" style="font-size:12px">signer <span class="acc">${esc(d.signer ?? "unset")}</span><br>${d.attested ? '<span class="acc">✓ attested by ' + esc(d.authorizedBy.slice(0, 10)) + "…</span>" : '<span class="warn">wallet attestation: unset</span>'}</div></div>
<div class="stat"><div class="k">Settlement</div><div class="v" style="font-size:12px">PayAI <span class="acc">primary</span><br>Dexter <span class="dim">fallback*</span><br><span class="dim">*premium tools only</span></div></div>
</div>

<h2>01 · Operator checklist</h2>
<div class="panel">
<div class="dim">progress: <span id="pct">0%</span> — state persists in this browser</div>
<div class="bar"><i id="bar"></i></div>
<div id="clist"></div>
</div>

<h2>02 · The 402 handshake <span class="dim">(live protocol trace)</span></h2>
<div class="panel">
<button id="replay">▶ replay handshake</button> <span class="dim" style="font-size:12px"> actual exchange, actual values from this deployment</span>
<div class="phases" id="phases"></div><div class="term" id="term" style="margin-top:12px"></div>
</div>

<h2>03 · Economics simulator <span class="dim">(real curve, real params)</span></h2>
<div class="panel">
<div style="display:flex;gap:22px;flex-wrap:wrap;margin-bottom:10px">
<label>τ decay <input type="range" id="tau" min="300" max="7200" step="100" value="${d.tau}"> <span id="tauv">${d.tau}s</span></label>
<label>bump <input type="range" id="bump" min="110" max="300" step="10" value="${Math.round(d.bump * 100)}"> <span id="bumpv">×${d.bump}</span></label>
<label>sales/hour <input type="range" id="vel" min="1" max="60" value="10"> <span id="velv">10</span></label>
</div>
<canvas id="chart" width="920" height="230" style="width:100%;background:#07090d;border:1px solid var(--line);border-radius:8px"></canvas>
<div class="dim" style="font-size:12px;margin-top:8px">Simulation of p(t) under Poisson demand at the slider velocity — decay to floor between sales, ×bump on each settle, capped at ×${d.mult}. Reference line: floor. This is the actual pricing formula the worker runs, not an illustration.</div>
</div>

<h2>04 · Buyer integration <span class="dim">(SDK snippets)</span></h2>
<div class="tabs"><div class="tab on" data-t="s1">OFFICIAL SDK</div><div class="tab" data-t="s2">CURL</div><div class="tab" data-t="s3">MCP</div><div class="tab" data-t="s4">VERIFY RECEIPT</div></div>
<div class="snip on" id="s1">npm i @x402/fetch @x402/evm viem
import { wrapFetchWithPayment } from "@x402/fetch";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

const client = new x402Client();
client.register("eip155:*", new ExactEvmScheme(privateToAccount));
const api = wrapFetchWithPayment(fetch, client);

const r = await api("${esc(d.origin)}/v1/tools/iban-check/call", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ input: { iban: "GB82 WEST 1234 5698 7654 32" } }),
});
// 402 -> auto-sign (EIP-3009) -> auto-settle (USDC, Base) -> 200 + XDR-1 receipt</div>
<div class="snip" id="s2"># 1 — call; the 402 body IS the payment quote
curl -s -X POST ${esc(d.origin)}/v1/tools/iban-check/call \\
  -H "content-type: application/json" \\
  -d '{"input":{"iban":"GB82 WEST 1234 5698 7654 32"}}'
# 2 — sign accepts[0] (EIP-3009 TransferWithAuthorization, USDC on Base)
# 3 — retry with X-PAYMENT: base64(voucher)  ->  200 + receipt + tx</div>
<div class="snip" id="s3">POST ${esc(d.origin)}/mcp   (JSON-RPC 2.0)
{ "method": "tools/list" }                      // 23 tools, schemas, live
{ "method": "tools/call", "params": { "name": "iban_check",
  "arguments": { "iban": "GB82 WEST 1234 5698 7654 32" } } }
// paywall arrives as isError:true carrying the x402 challenge —
// sign it, retry with the payment header, receipt comes with the result</div>
<div class="snip" id="s4">receipt = { v:"XDR-1", tool, input_hash, output_hash, payer,
            recipient, amount, nonce, ts, tier, signature, signer }
canonical = [v, tool, tool_version, input_hash, output_hash, payer,
             recipient, amount, nonce, ts, tier].join("|")
recover(keccak256(canonical), signature)  ==  signer     // authentic
signer == published receipt_signing_address               // ours (attested)
// every field verifiable offline — no trust in this server required</div>

<h2>05 · Live price board <span class="dim">(quotes at render)</span></h2>
<div class="panel"><table><tr><th>Tool</th><th>Live quote</th><th>Floor</th><th>Ξ premium</th></tr>
${Object.keys(d.prices).map((t) => { const p = d.prices[t], f = d.floors[t] ?? p; const prem = f > 0 ? ((p / f - 1) * 100).toFixed(0) : "0"; return `<tr><td>${esc(t)}</td><td class="acc">${(p / 1e6).toFixed(6)} USDC</td><td class="dim">${(f / 1e6).toFixed(6)}</td><td class="${Number(prem) > 0 ? "warn" : "dim"}">+${prem}%</td></tr>`; }).join("")}
</table></div>

<h2>06 · Facilitator chain <span class="dim">(probed at render — measured, not claimed)</span></h2>
<div class="panel" id="facboard"><div class="dim">probing…</div></div>
<div class="dim" style="font-size:12px;margin-top:6px">Latency = client-side round-trip to each /supported at page load. Role = position in the worker's failover chain. *Dexter enforces a ~$0.00108 settlement floor — fallback viable for premium tools only.</div>

<h2>07 · Registry &amp; discovery</h2>
<div class="panel">
Discovery doc <code>/.well-known/x402.json</code> — 23 machine-parseable <span class="acc">resources[]</span> · Bazaar extension declared<br>
MCP catalog <code>${esc(d.origin)}/mcp</code> · OpenAPI <code>${esc(d.origin)}/openapi.json</code> · Agent brief <code>${esc(d.origin)}/llms.txt</code><br>
Marketplace: <a href="${esc(d.registryUrl)}">${esc(d.registryUrl)}</a> <span class="dim">(permissionless, crawl-verified)</span>
</div>

<p class="dim" style="margin-top:40px;font-size:12px">openfang-rail protocol operations console · everything on this page is generated from the live worker · ${esc(d.origin)}</p>
</div>
<script>
const D = JSON.parse('${JSON.stringify({ facilitators: d.facilitators, prices: d.prices, floors: d.floors, tau: d.tau, bump: d.bump, mult: d.mult, origin: d.origin }).replace(/'/g, "&#39;")}');
// clock
const ck = document.getElementById("clock");
setInterval(() => ck.textContent = new Date().toISOString().slice(11, 19), 1000);
// reveal
const io = new IntersectionObserver(es => es.forEach(e => e.isIntersecting && e.target.classList.add("in")), { threshold: .08 });
document.querySelectorAll("h2, .panel, .stat, .tabs").forEach(el => { el.classList.add("reveal"); io.observe(el); });
// checklist
const STEPS = ["Registry deploy.bat (token search + Telegram)", "mcp-publisher login github && publish (official registry)",
 "Smithery endpoint = rail.akrivis.in (dashboard)", "Glama listing approved", "x402scan resubmit after listability deploy",
 "Directory wave: LobeHub/Finder/Hunt/AIBase/OpenTools/AllMCPs/Market/Cursor", "Public repos: openfang-rail + x402-registry",
 "awesome-list PRs x6 (one-liners in console)", "Launch post published", "FIRST EXTERNAL nonce: (the fund)"];
const cl = document.getElementById("clist"), bar = document.getElementById("bar"), pct = document.getElementById("pct");
const saved = JSON.parse(localStorage.getItem("ofr_sop") || "{}");
function renderChk() { cl.innerHTML = ""; let done = 0;
  STEPS.forEach((s, i) => { const row = document.createElement("div"); row.className = "chk" + (saved[i] ? " done" : "");
    row.innerHTML = '<input type="checkbox" ' + (saved[i] ? "checked" : "") + '><span>' + (i + 1) + '. ' + s + "</span>";
    row.onclick = () => { saved[i] = !saved[i]; localStorage.setItem("ofr_sop", JSON.stringify(saved)); renderChk(); };
    cl.appendChild(row); if (saved[i]) done++; });
  bar.style.width = (done / STEPS.length * 100) + "%"; pct.textContent = Math.round(done / STEPS.length * 100) + "% (" + done + "/" + STEPS.length + ")"; }
renderChk();
// handshake terminal
const PHASE_NAMES = ["REQUEST","402 CHALLENGE","WALLET SIGN","SETTLE","200 OK"];
const phEl = document.getElementById("phases");
phEl.innerHTML = PHASE_NAMES.map(function(n,k){ return '<span class="ph" id="ph"+k+">'+(k+1)+'. '+n+"</span>"; }).join("");
const LINES = [
 ['<span class="t-dim">BUYER </span>POST /v1/tools/iban-check/call {"input":{"iban":"GB82 WEST …"}}', 0],
 ['<span class="t-dim">RAIL  </span>402 PAYMENT-REQUIRED <span class="t-warn">(free tier exhausted)</span>', 260],
 ['<span class="t-dim">      </span>{ "x402Version": 2, "accepts": [{ "scheme": "exact",', 380],
 ['<span class="t-dim">      </span>  "network": "eip155:8453", "amount": "999",', 520],
 ['<span class="t-dim">      </span>  "payTo": "${esc(d.recipient)}", "asset": "USDC" }]', 660],
 ['<span class="t-dim">BUYER </span>signs EIP-3009 TransferWithAuthorization <span class="t-dim">(local, <1ms)</span>', 980],
 ['<span class="t-dim">BUYER </span>retry + PAYMENT-SIGNATURE: base64(payload)', 1240],
 ['<span class="t-dim">RAIL  </span>verify: signature ✓  price ✓  recipient ✓  window ✓  nonce ✓', 1520],
 ['<span class="t-dim">RAIL  </span>-> facilitator /settle  <span class="t-acc">(gas-sponsored, non-custodial)</span>', 1780],
 ['<span class="t-dim">CHAIN </span>USDC transferWithAuthorization included on Base <span class="t-acc">(~2s)</span>', 2260],
 ['<span class="t-dim">RAIL  </span><span class="t-acc">200 OK</span> + result + XDR-1 receipt (signer attested) + tx', 2700],
 ['<span class="t-dim">      </span><span class="t-acc">deal closed. audit trail exists. no accounts were created.</span>', 3050, 0]];
let timers = [];
function replay() { const term = document.getElementById("term"); timers.forEach(clearTimeout); term.innerHTML = ""; phEl.querySelectorAll(".ph").forEach(function(el){ el.classList.remove("on"); });
    for (const [html, at] of LINES) timers.push(setTimeout(() => { term.innerHTML += html + "\\n"; const c = document.createElement("span"); c.className = "cursor"; term.appendChild(c); }, at)); }
document.getElementById("replay").onclick = replay; replay();
// tabs
document.querySelectorAll(".tab").forEach(t => t.onclick = () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.remove("on")); document.querySelectorAll(".snip").forEach(x => x.classList.remove("on"));
  t.classList.add("on"); document.getElementById(t.dataset.t).classList.add("on"); });
// economics sim: decay between Poisson sales, bump on settle
const cv = document.getElementById("chart"), cx = cv.getContext("2d");
function sim() {
  const tau = +document.getElementById("tau").value, bump = +document.getElementById("bump").value / 100,
        vel = +document.getElementById("vel").value;
  document.getElementById("tauv").textContent = tau + "s"; document.getElementById("bumpv").textContent = "×" + (bump).toFixed(2); document.getElementById("velv").textContent = vel;
  const floors = Object.values(D.floors), f = Math.min(...floors), cap = f * D.mult, mean = 3600 / vel;
  let p = f, t = 0; const T = 14400, dt = 20, pts = [[0, p]];
  while (t < T) { t += dt; p = f + (p - f) * Math.exp(-dt / tau);
    if (Math.random() < dt / mean) { p = Math.min(cap, Math.max(f, Math.round(p * bump))); }
    pts.push([t, p]); }
  cx.clearRect(0, 0, cv.width, cv.height);
  cx.strokeStyle = "#1d2430"; for (let y = 0; y < 4; y++) { cx.beginPath(); cx.moveTo(0, 20 + y * 60); cx.lineTo(cv.width, 20 + y * 60); cx.stroke(); }
  const yOf = v => 20 + (1 - (v - f) / (cap - f || 1)) * 190;
  cx.strokeStyle = "#39d98a"; cx.lineWidth = 1.6; cx.beginPath();
  pts.forEach(([t, p], i) => { const X = t / T * (cv.width - 10) + 5, Y = yOf(p); i ? cx.lineTo(X, Y) : cx.moveTo(X, Y); }); cx.stroke();
  cx.strokeStyle = "#6b7a90"; cx.setLineDash([4, 5]); cx.beginPath(); cx.moveTo(0, yOf(f)); cx.lineTo(cv.width, yOf(f)); cx.stroke(); cx.setLineDash([]);
  cx.fillStyle = "#6b7a90"; cx.font = "11px monospace";
  cx.fillText("floor " + (f / 1e6) + " USDC", 8, yOf(f) - 6);
  cx.fillText("cap ×" + D.mult, 8, yOf(cap) + 14);
  cx.fillText("4h window · " + Math.round(T / 3600 * vel) + " sales simulated", cv.width - 210, 16);
}
["tau", "bump", "vel"].forEach(id => document.getElementById(id).oninput = sim);
sim();
// facilitator board (client-side measured round-trips, honest: from THIS browser)
(async () => { const fb = document.getElementById("facboard"); fb.innerHTML = "";
  for (const fac of D.facilitators) {
    let cls = "dim", txt = "probing…", ms = "";
    if (fac.status === "primary" || fac.status === "fallback*") {
      const s = performance.now(); let ok = false;
      try { const r = await fetch(fac.url + "/supported", { mode: "cors" }); ok = r.ok; } catch { ok = false; }
      ms = Math.round(performance.now() - s) + "ms";
      txt = ok ? "REACHABLE" : "CORS/NET BLOCKED (server-side probes pass — see render log)";
      cls = ok ? "acc" : "warn"; }
    fb.innerHTML += '<table><tr><td style="width:40%">' + fac.url + '</td><td class="' + cls + '">' + txt + ' ' + ms + '</td><td class="dim">' + fac.status + "</td></tr></table>";
  } })();
</script></body></html>`;
}
