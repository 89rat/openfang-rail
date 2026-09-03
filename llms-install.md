# llms-install.md — openfang-rail

openfang-rail is a **remote MCP server**. There is nothing to compile or install
from this repository for normal use — pick one of the two connection options.

## Option 1 — connect directly (recommended, zero setup)

- **Transport:** Streamable HTTP
- **URL:** `https://code402.dev/mcp`
- **Auth:** none. Free tier per client per day; exhausted tools answer HTTP 402
  and accept x402 payments (EIP-3009 USDC on Base). A client that doesn't pay
  simply stays on the free tier — no keys, no signup.

Handshake: POST JSON-RPC 2.0 `initialize` → `notifications/initialized` →
`tools/list` (28 deterministic tools) → `tools/call`.

REST equivalent: `POST https://code402.dev/v1/tools/{tool}/call` with body
`{"input": { ... }}` — input schemas per tool in
`https://code402.dev/.well-known/mcp.json`.

## Option 2 — local stdio container (for hosts that require stdio)

```bash
docker build -t openfang-rail https://github.com/89rat/openfang-rail.git
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

The container is a zero-dependency bridge to the hosted endpoint; it holds no
secrets and no local state. Point it elsewhere with the `MCP_ENDPOINT` env var.

## Verification

- Discovery: `/.well-known/x402.json`, `/.well-known/mcp.json`, `/.well-known/agent.json`
- Live quotes + tool list: `GET https://code402.dev/health`
- Every result carries a signed XDR-1 receipt that verifies offline (see
  `worker/RECEIPTS.md`); the receipt signer is published in `/.well-known/mcp.json`.
