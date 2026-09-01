# openfang-rail MCP stdio bridge.
# The rail itself is a hosted HTTP MCP endpoint (https://rail.akrivis.in/mcp);
# this image wraps the zero-dependency stdio<->HTTP bridge in mcp-bridge.mjs so
# stdio-only MCP hosts (Glama, Docker MCP Toolkit, desktop configs) can talk
# to it. No secrets, no local state; the hosted endpoint's free tier applies.
FROM node:20-alpine
LABEL org.opencontainers.image.title="openfang-rail MCP bridge" \
      org.opencontainers.image.description="stdio-to-HTTP MCP bridge to openfang-rail: deterministic identity (IBAN/LEI/VAT/GB company) and rental due-diligence checks paid per call via x402, with signed verifiable receipts" \
      org.opencontainers.image.source="https://github.com/89rat/openfang-rail" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY mcp-bridge.mjs .
ENV NODE_ENV=production \
    MCP_ENDPOINT=https://rail.akrivis.in/mcp
ENTRYPOINT ["node", "mcp-bridge.mjs"]
