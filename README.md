# openfang-rail — code402 / HCRB tools rail

Deterministic business-identifier validation (IBAN, LEI, VAT, SWIFT-BIC, company numbers and more) plus seven paid revenue modules, paid per call via [x402](https://www.x402.org/) — EIP-3009 USDC on Base. Non-custodial, no accounts, no API keys: agents pay directly from their wallets, and every result carries a signed, offline-verifiable XDR-1 receipt.

**Live endpoint:** https://hcrb.in (aliases: `rail.hcrb.in`, `api.code402.dev`, `rail.akrivis.in` — same rail).

**Catalog:** 24 public tools (default card) + 7 paid revenue-module tools (`?catalog=modules`) + an experimental card. Machine catalog: [`/.well-known/mcp.json`](https://hcrb.in/.well-known/mcp.json) · Agent instructions: [`/llms.txt`](https://hcrb.in/llms.txt).

## Endpoints

| Path | What it is |
|---|---|
| `POST /mcp` | MCP server (JSON-RPC 2.0: `initialize`, `tools/list`, `tools/call`) |
| `POST /v1/tools/{tool}/call` | REST entry point, body `{"input": { ... }}` |
| `POST /v1/modules/{...}` | the seven revenue modules (e.g. `/v1/modules/commerce/accelerate-payout`) |
| `GET /.well-known/x402.json` | x402 discovery (payment kinds, assets) |
| `GET /.well-known/mcp.json` | MCP discovery (tool schemas, receipt signer, catalogs) |
| `GET /llms.txt` | agent-facing integration guide incl. evaluation paths |
| `GET /health` | live tool list and build attestation |
| `GET /status` | service status and settlement treasury |
| `https://verify.code402.dev` | free standalone XDR-1 receipt verifier |

## Quickstart (HTTP)

```bash
# eligible tools: first 5 calls/day per client are free — no payment needed
curl -s https://hcrb.in/v1/tools/iban-check/call \
  -H 'content-type: application/json' \
  -d '{"input":{"iban":"GB82WEST12345698765432"}}'
```

After the free allowance the API answers `402` with an x402 v2 payment challenge (the `PAYMENT-REQUIRED` header). Sign the exact quoted amount with your wallet, resend with `PAYMENT-SIGNATURE` (or legacy `X-PAYMENT`), and the response carries the settlement result plus a signed receipt. Any x402-capable client handles this loop; our SDK is [`@code-402/agent-tools`](https://www.npmjs.com/package/@code-402/agent-tools) (LangChain, Vercel AI SDK, OpenAI function calling).

## Prices

Every price is quoted live by the 402 challenge — inspect it before signing; never sign more than the quoted amount, to a different recipient, or on a different chain. The seven revenue modules quote in the $0.005–0.01 USDC range at the micro tier (measured 2026-10-19).

## Receipts

Every paid result carries an XDR-1 receipt: a canonical, keccak-hashed field set signed by the rail's key (published in `/.well-known/mcp.json` and `/.well-known/jwks.json`). Verify offline, or free at `https://verify.code402.dev` / `POST /v1/receipt/verify`. A valid signature proves integrity under that signer, not the truth of a business claim or settlement.

## Repository layout

- [`worker/`](worker/) — the Cloudflare Worker serving the API, MCP endpoint, discovery files, console and playground (`worker/src/`), plus QA harness (`qa.mjs`, `qa_live.mjs`) and a red-team suite (`worker/redteam/`)
- [`engine/`](engine/) — Rust (workers-rs) compute plane: batch XDR-1 receipt verification (`/verify-batch`), key recovery, and a measured benchmark endpoint; deployed via GitHub Actions
- [`well-known/`](well-known/) — the discovery documents served at `/.well-known/*`
- [`mcp-bridge.mjs`](mcp-bridge.mjs) — zero-dependency stdio↔HTTP bridge for MCP hosts that only speak stdio (Docker: `docker build -t openfang-rail .`)

## License

[MIT](LICENSE)
