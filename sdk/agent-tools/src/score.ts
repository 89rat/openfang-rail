// score.ts — the Agent-Ready Scorecard. Deterministic HTTP probes that grade how
// discoverable and machine-payable an origin is for autonomous agents.
// Honesty contract: presence checks measured live, labeled with the probe date;
// these are discovery-surface checks, NOT quality or security audits.
export interface ScoreCheck {
  id: string;
  label: string;
  weight: number;
  ok: boolean;
  detail: string;
}

export interface Scorecard {
  origin: string;
  probed_at: string;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  checks: ScoreCheck[];
  top_fix: string | null;
  scope: string;
}

interface FetchLike {
  (input: string, init?: { signal?: AbortSignal; method?: string; headers?: Record<string, string>; body?: string }): Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;
}

const CHECKS: { id: string; label: string; path: string; weight: number; fix: string }[] = [
  { id: "x402-manifest", label: "x402 discovery manifest", path: "/.well-known/x402.json", weight: 18, fix: "publish /.well-known/x402.json so agents can price you" },
  { id: "mcp-manifest", label: "MCP catalog manifest", path: "/.well-known/mcp.json", weight: 14, fix: "publish /.well-known/mcp.json (MCP-native agents read it first)" },
  { id: "mcp-endpoint", label: "MCP server endpoint", path: "/mcp", weight: 12, fix: "serve an MCP endpoint at /mcp (streamable HTTP)" },
  { id: "agent-card", label: "A2A agent card", path: "/.well-known/agent.json", weight: 10, fix: "publish an A2A agent card at /.well-known/agent.json" },
  { id: "openapi", label: "OpenAPI spec (ChatGPT/Actions)", path: "/openapi.json", weight: 8, fix: "publish /openapi.json so GPT Actions and codegen agents can call you" },
  { id: "llms-txt", label: "llms.txt", path: "/llms.txt", weight: 8, fix: "publish /llms.txt describing your machine surface" },
  { id: "ucp", label: "UCP commerce profile", path: "/.well-known/ucp", weight: 8, fix: "publish /.well-known/ucp for Google/UCP agent commerce" },
  { id: "ai-plugin", label: "ChatGPT plugin manifest", path: "/.well-known/ai-plugin.json", weight: 6, fix: "publish /.well-known/ai-plugin.json" },
  { id: "robots", label: "robots.txt crawler access", path: "/robots.txt", weight: 5, fix: "publish /robots.txt allowing agent crawlers" },
  { id: "sitemap", label: "sitemap.xml", path: "/sitemap.xml", weight: 3, fix: "publish /sitemap.xml" },
  { id: "security-txt", label: "security.txt", path: "/.well-known/security.txt", weight: 3, fix: "publish /.well-known/security.txt" },
  { id: "proof-page", label: "public proof page (live measured evidence)", path: "/proof", weight: 6, fix: "publish a /proof page with live measured metrics — citable evidence for agents and humans" },
];

const grade = (s: number): Scorecard["grade"] => (s >= 85 ? "A" : s >= 70 ? "B" : s >= 50 ? "C" : s >= 30 ? "D" : "F");

export async function scoreOrigin(origin: string, fetchFn: FetchLike, now = new Date()): Promise<Scorecard> {
  const base = origin.replace(/\/+$/, "");
  if (!base.startsWith("https://")) throw new Error("origin must be an https:// URL");
  const checks: ScoreCheck[] = [];
  for (const c of CHECKS) {
    let ok = false;
    let detail = "";
    try {
      const r = await fetchFn(base + c.path, { signal: AbortSignal.timeout(10_000) });
      const ct = r.headers.get("content-type") ?? "";
      if (r.status === 200) {
        ok = true;
        detail = `200 · ${ct.split(";")[0]}`;
      } else {
        detail = `HTTP ${r.status}`;
      }
    } catch (e) {
      detail = `unreachable: ${(e as Error).message.slice(0, 60)}`;
    }
    checks.push({ id: c.id, label: c.label, weight: c.weight, ok, detail });
  }

  // Bonus probe: does a real x402 challenge answer 402? (via the MCP manifest, if any)
  const mcpCheck = checks.find((c) => c.id === "mcp-manifest");
  if (mcpCheck?.ok) {
    try {
      const r = await fetchFn(base + "/.well-known/mcp.json", { signal: AbortSignal.timeout(10_000) });
      const cat = JSON.parse(await r.text());
      const tool = cat?.tools?.find?.((t: { name?: string }) => t?.name && t.name !== "receipt-verify" && t.name !== "receipt_verify");
      if (tool) {
        // The estate convention: REST paths are hyphenated (measured: underscore
        // paths 404 for some tools). Use the declared call path, else hyphen-normalize.
        const name = String(tool.name).replace(/_/g, "-");
        const path = (tool.call ?? `/v1/tools/${name}/call`).replace(/^POST\s+/i, "");
        const url = path.startsWith("http") ? path : base + path;
        const resp = await fetchFn(url, { signal: AbortSignal.timeout(15_000), method: "POST", headers: { "content-type": "application/json", "x-force-402": "true" }, body: JSON.stringify({ input: {} }) });
        if (resp.status === 402) {
          checks.push({ id: "x402-challenge", label: "live 402 payment challenge", weight: 5, ok: true, detail: `402 from ${tool.name}` });
        } else {
          checks.push({ id: "x402-challenge", label: "live 402 payment challenge", weight: 5, ok: false, detail: `expected 402, got ${resp.status}` });
        }
      }
    } catch {
      checks.push({ id: "x402-challenge", label: "live 402 payment challenge", weight: 5, ok: false, detail: "probe failed" });
    }
  }

  const total = checks.reduce((s, c) => s + c.weight, 0);
  const got = checks.filter((c) => c.ok).reduce((s, c) => s + c.weight, 0);
  const score = Math.round((got / total) * 100);
  const firstFail = checks.find((c) => !c.ok);
  const fixMap = new Map(CHECKS.map((c) => [c.id, c.fix]));
  return {
    origin: base,
    probed_at: now.toISOString(),
    score,
    grade: grade(score),
    checks,
    top_fix: firstFail ? fixMap.get(firstFail.id) ?? "make your paid endpoints answer a proper x402 402 challenge" : null,
    scope: `presence checks via HTTP probes on ${now.toISOString().slice(0, 10)} — discovery-surface only, not a quality or security audit`,
  };
}
