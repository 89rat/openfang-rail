# openfang-rail — Independent Trust, Pre-Payment Risk & XDR-1 Receipt Layer for Agent Payments

> **Non-Custodial Commerce. 0 Middlemen. 100% Proof.**  
> Operated by **JUANA LIMITED** (UK Company No. `14043409`) · Live at **[https://code402.dev](https://code402.dev)** & **[https://hcrb.in](https://hcrb.in)**

**`openfang-rail`** is the production surface of the **Code402 / HCRB** independent verification and receipt layer for autonomous agent payments ([x402](https://www.x402.org/) & [Model Context Protocol](https://modelcontextprotocol.io/)).

When an AI agent pays an API or supplier, the payment rail moves the tokens—but **who verifies the counterparty, enforces pre-payment spend policy, and proves that the paid output matched the request?**

We hold the **proof**, never the **money**:
- **Zero Platform Custody (`$0.00`)**: Payments settle peer-to-peer from buyer wallet to seller wallet via gasless EIP-3009 (`TransferWithAuthorization`) in USDC/EURC on Base (`8453`), Polygon (`137`), Arbitrum (`42161`), and Avalanche (`43114`), or via 25-currency Stripe Checkout prepaid keys (`ck_live_...`).
- **Every Call Receipted (`XDR-1`)**: Every execution returns a deterministic, keccak-256 + `secp256k1` signed **XDR-1 receipt** binding `input_hash`, `output_hash`, `payer`, `recipient`, `amount`, and `nonce`.
- **Verify Free, Forever**: Anyone can verify any XDR-1 receipt offline (`npx -y @code402/verify-mcp@latest`) or via the free stateless verifier at **[https://verify.code402.dev](https://verify.code402.dev)** (`GET https://hcrb.in/verify`).

---

## Architecture: 4 Trust Layers Across 57 Live MCP Tools

Machine catalog: [`https://hcrb.in/.well-known/mcp.json`](https://hcrb.in/.well-known/mcp.json) · x402 discovery: [`https://hcrb.in/.well-known/x402.json`](https://hcrb.in/.well-known/x402.json) · A2A Agent Card: [`https://hcrb.in/.well-known/agent-card.json`](https://hcrb.in/.well-known/agent-card.json) · OpenAPI 3.1: [`https://hcrb.in/openapi.json`](https://hcrb.in/openapi.json)

| Layer | Core Capabilities & Live Tools | Price (Live `/health` Quote) |
| :--- | :--- | :--- |
| **1. XDR-1 Receipts & 3-Way Reconciliation** | `receipt-verify` (`GET /verify`), `check-price`, `reconcile` (`POST /commerce/reconcile` — stateless 3-way Order/Payment/Delivery matching), Exception Cure (`POST /v1/reconcile/cure`) | `receipt-verify` & `check-price`: **Free forever**<br>`reconcile`: **`$0.05 USDC`** (`50,000` minor) |
| **2. Facilitator-Adjacent Pre-Payment Risk & Policy** | `aci-trust-lookup`, `simulate-spend-sentinel`, `pre-disbursement-guard`, `token-contract-risk`, `balance-check`, `erc20-balance`, `tx-activity` | **`$0.005 – $0.05 USDC`** (`5,000 – 50,000` minor) |
| **3. Global Counterparty & Statutory Verification (12 Registries)** | `iban-check` (ISO 13616 MOD-97), `lei-check` (ISO 17442 + GLEIF), `vat-mod97-check` (EU VIES), `swift-bic-check` (ISO 9362), `company-number-format` (UK Companies House), `aba-routing-check`, `ein-format-check`, `gstin-check`, `ifsc-check`, `abn-check`, `uscc-check` (CN), `cnpj-check` (BR), `kra-pin-check` (KE), `sanctions-address-screen` (OFAC/UK FCDO/EU/UN exact-match), Regional Supplier Packs (`india-supplier-check`, `china-supplier-check`, `japan-supplier-check`, `latam-supplier-check`, `gulf-supplier-check`, `africa-supplier-check`) | Single check: **`$0.005 USDC`** (`5,000` minor)<br>Sanctions / Supplier Pack: **`$0.02 USDC`** (`20,000` minor) |
| **4. Enterprise ISO 20022, Swift CBPR+ & ERP Accounting** | `iso20022-validate`, `iso20022-to-x402-intent`, `POST /iso20022/repair-party` (Swift CBPR+ `<PstlAdr>` + LEI cure), `POST /iso20022/mt101-to-pain001`, `POST /iso20022/tx-to-camt054` (on-chain `txHash` → SAP/NetSuite `camt.054.001.08` XML), `/batch-cure` | Per-call: **`$0.005 – $0.05 USDC`**<br>Batch Cure (500 rows): **`£79 / $99`**<br>Fixed Validation Run: **`$250`** |

> **Scope & Honesty Note**: Identifier and sanctions tools perform deterministic structural, checksum, and snapshot exact-match checks with signed provenance receipts. They are engineering decision and reconciliation controls, not legal compliance determinations or guarantees of account ownership.

---

## Quickstart

### 1. Free-Tier Call (First 5 Calls/Day per Caller — Zero Keys, Zero Accounts)

```bash
curl -s -X POST https://hcrb.in/v1/tools/iban-check/call \
  -H "content-type: application/json" \
  -d '{"input":{"iban":"GB82WEST12345698765432"}}'
```

### 2. Connect Any MCP Client (Claude Desktop, Claude Code, Cursor, Windsurf)

Registered in the Official MCP Registry as `io.github.89rat/code402`, `io.github.89rat/openfang-rail`, and `io.github.89rat/code402-verify-mcp`:

```json
{
  "mcpServers": {
    "code402-clearinghouse": {
      "type": "streamable-http",
      "url": "https://hcrb.in/mcp"
    }
  }
}
```

### 3. How Conditional x402 Settlement & XDR-1 Receipts Work

1. **Challenge (`HTTP 402`)**: Beyond the free tier, `POST /v1/tools/{tool}/call` returns `HTTP 402` (`PAYMENT-REQUIRED`) with an authoritative x402 v2 quote (`amount` in minor units, `payTo`, chain ID, single-use nonce, and 5-minute expiry).
2. **Pre-Settlement Hold Guard (`HTTP 409 PAYMENT_RETRY_HELD`)**: The agent signs an EIP-3009 `TransferWithAuthorization` and retries with `PAYMENT-SIGNATURE` (or `X-PAYMENT`). If an upstream facilitator returns an ambiguous `5xx`, the rail holds the retry (`409 PAYMENT_RETRY_HELD`) so single-use EIP-3009 nonces are never burned without confirmed execution.
3. **Signed XDR-1 Receipt**: Once verified, the response returns the deterministic output plus a signed **XDR-1 receipt** (`v|tool|tool_version|input_hash|output_hash|payer|recipient|amount|nonce|ts|tier`).
4. **Offline or Stateless Verification**:
   ```bash
   # Verify offline on your own machine (zero network calls):
   npx -y @code402/verify-mcp@latest

   # Or verify via the free stateless endpoint:
   curl -s "https://hcrb.in/verify?receipt=<url-encoded-receipt-json>"
   ```

---

## The Code402 / HCRB Open-Source Stack

| Repository | Role in the Stack |
| :--- | :--- |
| **[`89rat/openfang-rail`](https://github.com/89rat/openfang-rail)** | Production 57-tool Verification, Pre-Payment Risk & Reconciliation Rail (`https://hcrb.in` · `https://code402.dev`) |
| **[`89rat/code402-verify-mcp`](https://github.com/89rat/code402-verify-mcp)** | Local-first & hosted (`https://verify.code402.dev`) XDR-1 cryptographic receipt verifier (`keccak256` + `secp256k1` recovery) |
| **[`89rat/code402-facilitator-embed`](https://github.com/89rat/code402-facilitator-embed)** | Zero-dependency ESM embed kit (`preflightPayee` + `offline-verify.mjs`) for x402 facilitators, payout switches, and AP platforms |
| **[`89rat/x402-conformance`](https://github.com/89rat/x402-conformance)** | Executable 0–100 protocol conformance & challenge verifier for any x402 endpoint |
| **[`89rat/x402-payer-skill`](https://github.com/89rat/x402-payer-skill)** | Autonomous x402 EIP-3009 payer skill with payTo/amount pinning and rolling spend caps |
| **[`89rat/langchain-code402`](https://github.com/89rat/langchain-code402)** | `DynamicStructuredTools` adapter for LangChain, Vercel AI SDK, and OpenAI function calling |

---

## Repository Layout

- [`worker/`](worker/) — Cloudflare Worker serving the REST API, `streamable-http` MCP server (`POST /mcp`), `.well-known` discovery manifests, and verification harness (`qa.mjs`, `qa_live.mjs`, `worker/redteam/`).
- [`engine/`](engine/) — Rust (`workers-rs`) WebAssembly compute plane for deterministic checksums, batch XDR-1 receipt verification, and `secp256k1` signer recovery.
- [`well-known/`](well-known/) — Machine-readable discovery manifests (`/.well-known/x402.json`, `/.well-known/mcp.json`, `/.well-known/agent-card.json`).

## License

[MIT](LICENSE) © 2026 JUANA LIMITED (UK Company No. 14043409)
