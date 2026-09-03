# openfang-rail

Deterministic business-identity validation (IBAN, LEI, VAT, UK company number) and rental due-diligence checks, paid per call via [x402](https://www.x402.org/) — gasless EIP-3009 USDC on Base. Non-custodial, no accounts, no API keys: agents pay directly from their wallets, and every result carries a signed, offline-verifiable XDR-1 receipt.

**Live endpoint:** https://rail.akrivis.in · 28 tools · first N calls/day free, then from $0.000999/call (dynamic — idle prices decay toward the floor, demand bumps them; live quotes at [`/health`](https://rail.akrivis.in/health)).

**Canonical branded endpoint:** https://code402.dev — same 28 tools, separately deployed. Both origins settle USDC on Base and share the per-client free-tier quota; pick either.

## Endpoints

| Path | What it is |
|---|---|
| `POST /mcp` | MCP server (JSON-RPC 2.0: `initialize`, `tools/list`, `tools/call`) |
| `POST /v1/tools/{tool}/call` | REST entry point, body `{"input": { ... }}` |
| `GET /.well-known/x402.json` | x402 discovery (resources, prices, example inputs) |
| `GET /.well-known/mcp.json` | MCP discovery (tool schemas, receipt signer) |
| `GET /.well-known/agent.json` | A2A agent card |
| `GET /health` | live quotes + tool count |
| `GET /playground` | browser form: try any tool on the free tier |
| `GET /leaderboard`, `GET /profile/{address}` | buyer stats (on-chain identity only — no signups) |

## Quickstart (HTTP)

```bash
# free tier — no payment needed
curl -s https://rail.akrivis.in/v1/tools/iban-check/call \
  -H 'content-type: application/json' \
  -d '{"input":{"iban":"GB82WEST12345698765432"}}'
```

When the free tier is exhausted the API answers `402` with a payment challenge (EIP-3009 `TransferWithAuthorization` for USDC on Base). Sign the voucher with your wallet, retry with the payment header, and the response includes the settlement result plus a signed receipt. Any x402 client library handles this dance; the canonical flow is documented at the [x402 protocol](https://www.x402.org/).

## Quickstart (stdio / Docker)

The rail is a hosted HTTP MCP endpoint. `mcp-bridge.mjs` is a zero-dependency stdio↔HTTP bridge for hosts that only speak MCP over stdio (Glama, Docker MCP Toolkit, desktop client configs):

```bash
docker build -t openfang-rail .
docker run -i --rm openfang-rail
```

```json
{
  "mcpServers": {
    "openfang-rail": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "openfang-rail"]
    }
  }
}
```

The container holds no secrets and no local state — it proxies protocol traffic to the hosted endpoint, whose free tier applies. Point it elsewhere with `MCP_ENDPOINT`.

## Receipts

Every tool result carries an XDR-1 receipt: a canonical, keccak-hashed field set signed by the rail's key (published in `/.well-known/mcp.json`). Anyone can verify a receipt offline — no trust in the server needed after the fact. See [`worker/RECEIPTS.md`](worker/RECEIPTS.md).

## Repository layout

- [`worker/`](worker/) — the Cloudflare Worker serving the API, MCP endpoint, discovery files, console and playground (`worker/src/`), plus QA harness (`qa.mjs`, `qa_live.mjs`) and a red-team suite (`worker/redteam/`)
- [`engine/`](engine/) — Rust (workers-rs) compute plane: batch XDR-1 receipt verification (`/verify-batch`), key recovery, and a measured benchmark endpoint; deployed via GitHub Actions
- [`well-known/`](well-known/) — the discovery documents served at `/.well-known/*`

## License

[MIT](LICENSE)
