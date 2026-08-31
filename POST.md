# Launch post (draft) — the self-pricing API for agents

**Title options:**
1. "I built an API that bids against itself: prices fall while it's idle, rise when you buy"
2. "A marketplace where agents pay agents, per call, with on-chain receipts — no accounts, no API keys"
3. "openfang-rail: deterministic checks from $0.001/call, and a receipt your auditor can verify offline"

---

**Body (short version, for X/fosstodon/Reddit r/*):**

We just shipped the full loop for agentic commerce — seller side, marketplace, and buyer side:

🔧 **The rail** — 19 deterministic tools (IBAN, LEI, VAT, SWIFT/BIC, ABA, IFSC, ABN, SEDOL… + rental-fraud verdicts + vendor-onboarding packs). Pure functions, no ML, no scraping. $0.001–$0.05/call at the floor (live Dutch-quoted) via x402: your agent gets a 402, signs an EIP-3009 voucher (gasless, USDC on Base), gets the answer **plus a signed receipt** it can verify offline.

📉 **It prices itself.** Reverse-Dutch: idle prices decay to the floor; every settled sale bumps them up (×1.5, capped at 5×). Live ticker on GET /health — snipe the floor if you like. The rule is published in the manifest; nothing hidden.

🛒 **The marketplace** — a permissionless registry (https://x402-registry.akrivis.workers.dev): POST your service URL, it crawl-verifies your x402 manifests (sha256-snapshotted), re-checks every 6h, dead services drop out. No accounts, no approval, no fee. Agents search it over MCP.

💳 **The buyer side** — x402-payer: a stdio MCP client with a hard per-call spending cap that pays any listed service automatically and verifies receipts. Your key never leaves the process.

Everything is non-custodial (payer→seller direct), every claim has a runnable test (111/111 harness, exploit tables in SECURITY.md), and the payment core rejects replay/underpay/wrong-recipient/tamper — proven, not asserted.

Try it free (20 calls/day): curl -X POST https://rail.akrivis.in/v1/tools/iban-check/call -H "content-type: application/json" -d '{"input":{"iban":"GB82 WEST 1234 5698 7654 32"}}'

---

**Follow-up post (day 3):** the first real sale — receipt JSON + on-chain tx link.
"That's it. That's the whole business. An agent paid another agent for a computation and both got proofs."
