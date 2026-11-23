# openfang-rail / code402 MCP stdio bridge.
# The rail itself is a hosted HTTP MCP endpoint (https://hcrb.in/mcp);
# this image wraps the zero-dependency stdio<->HTTP bridge in mcp-bridge.mjs so
# stdio-only MCP hosts (Glama, Docker MCP Toolkit, desktop configs) can talk
# to it. No secrets, no local state; published synthetic fixtures run free.
FROM node:20-alpine
LABEL org.opencontainers.image.title="code402 / openfang-rail MCP bridge" \
      org.opencontainers.image.description="stdio-to-HTTP MCP bridge to Code402 / HCRB (https://hcrb.in/mcp): 58 deterministic verification, ISO 20022, and agent utility tools paid per call via x402 on Base, with signed XDR-1 receipts" \
      org.opencontainers.image.source="https://github.com/89rat/openfang-rail" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY mcp-bridge.mjs .
ENV NODE_ENV=production \
    MCP_ENDPOINT=https://hcrb.in/mcp
ENTRYPOINT ["node", "mcp-bridge.mjs"]
