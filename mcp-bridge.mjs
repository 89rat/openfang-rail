#!/usr/bin/env node
/**
 * MCP stdio <-> Streamable-HTTP bridge for openfang-rail.
 *
 * Speaks newline-delimited JSON-RPC on stdin, forwards each message to the
 * hosted MCP endpoint over HTTP, and forwards responses (plain JSON or
 * SSE `data:` frames) back on stdout. Lets stdio-only MCP hosts (Glama,
 * Docker MCP Toolkit, desktop client configs) talk to the hosted rail with
 * no local state and no secrets — protocol traffic only; free-tier limits
 * of the hosted endpoint apply.
 *
 * Env: MCP_ENDPOINT (default https://code402.dev/mcp)
 */
import readline from "node:readline";

const ENDPOINT = process.env.MCP_ENDPOINT || "https://code402.dev/mcp";

let sessionId = null;

function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

async function forward(raw) {
  let msgId = null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") msgId = parsed.id ?? null;
  } catch {}

  try {
    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        ...(sessionId ? { "mcp-session-id": sessionId } : {}),
      },
      body: raw,
    });
    const sid = res.headers.get("mcp-session-id");
    if (sid) sessionId = sid;
    if (res.status === 202 || res.status === 204) return; // notification accepted

    const ctype = res.headers.get("content-type") || "";
    const text = await res.text();

    if (ctype.includes("text/event-stream")) {
      let emitted = false;
      for (const frame of text.split("\n")) {
        const line = frame.trim();
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim();
        if (!data || data === "[DONE]") continue;
        try { emit(JSON.parse(data)); emitted = true; } catch {}
      }
      if (!emitted && msgId != null) {
        emit({ jsonrpc: "2.0", id: msgId, error: { code: -32603, message: `upstream SSE returned no data (HTTP ${res.status})` } });
      }
      return;
    }

    if (text) {
      try { emit(JSON.parse(text)); return; } catch {}
    }
    if (msgId != null) {
      emit({ jsonrpc: "2.0", id: msgId, error: { code: -32603, message: `upstream HTTP ${res.status}` } });
    }
  } catch (e) {
    if (msgId != null) {
      emit({ jsonrpc: "2.0", id: msgId, error: { code: -32603, message: String((e && e.message) || e) } });
    }
  }
}

let pending = 0;
function maybeExit() {
  if (rl.closed && pending === 0) process.exit(0);
}
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on("line", (line) => {
  const raw = line.trim();
  if (!raw) return;
  pending++;
  forward(raw).catch(() => {}).finally(() => { pending--; maybeExit(); });
});
rl.on("close", maybeExit);
