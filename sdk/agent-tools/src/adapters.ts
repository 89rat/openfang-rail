import type { Code402Client } from "./client.js";
import type { CatalogTool, JsonSchema } from "./types.js";

/** Framework-neutral tool shape. Every adapter is a thin projection of this. */
export interface PlainTool {
  name: string;
  description: string;
  parameters: JsonSchema;
  free: boolean;
  /** Floor price hint, minor units as string, or "0" when free. The 402 is authoritative. */
  priceFloorMinor: string;
  execute(args: Record<string, unknown>): Promise<unknown>;
}

const usdcToMinor = (n: number | undefined): string => (n === undefined ? "0" : Math.round(n * 1e6).toString());
const safeName = (s: string) => s.replace(/[^a-zA-Z0-9_]/g, "_");

function describe(t: CatalogTool): string {
  const price = t.price_usdc !== undefined ? ` Paid per call via x402: floor ${usdcToMinor(t.price_usdc)} USDC minor units${t.price_usdc_ceiling !== undefined ? ` (ceiling ${usdcToMinor(t.price_usdc_ceiling)})` : ""}; the live 402 quote is authoritative and is capped by maxAmountMinor.` : "";
  return `${t.description}${price}`;
}

export const CHECK_PRICE_SCHEMA: JsonSchema = {
  type: "object",
  properties: {
    url: { type: "string", description: "Full URL of an x402 endpoint to look up" },
    tool: { type: "string", description: "Tool name (e.g. iban-check) to look up" },
  },
};

/** Build the plain tool list from the live catalog + the free check_price tool. */
export async function toPlainTools(client: Code402Client, opts: { includeCheckPrice?: boolean; prefix?: string } = {}): Promise<PlainTool[]> {
  const prefix = opts.prefix ?? "code402_";
  const tools = (await client.tools()).map<PlainTool>((t) => ({
    name: prefix + safeName(t.name),
    description: describe(t),
    // The live rail serves the MCP camelCase inputSchema; legacy sellers use
    // input_schema. Either is accepted; the framework schema never comes back empty.
    parameters: t.inputSchema ?? t.input_schema ?? { type: "object", properties: {} },
    free: false,
    priceFloorMinor: usdcToMinor(t.price_usdc),
    execute: async (args) => {
      const r = await client.callTool(t.name, args ?? {});
      return { result: r.result, tier: r.tier, paid: r.paid, amount_minor: r.amountMinor, receipt_verified: r.receiptVerification?.verified ?? false, receipt_reason: r.receiptVerification?.reason, settlement: r.settlement };
    },
  }));
  // The live catalog already serves check_price (it is one of the 23 tools on the default card), so
  // adding it unconditionally produced TWO entries with the same name. Measured 2026-10-06:
  // toPlainTools() returned 24 tools with code402_check_price twice, and toVercelAITools() — which
  // keys its output object by name — silently collapsed them to 23, so the adapters disagreed on the
  // catalogue size. Add the tool only when the catalog does not already provide it.
  const checkPriceName = prefix + "check_price";
  if (opts.includeCheckPrice !== false && !tools.some((t) => t.name === checkPriceName)) {
    tools.unshift({
      name: checkPriceName,
      description: "FREE. Look up what an x402 endpoint currently quotes in its 402 challenge (current quote, 7/30-day min/median/max, percentile among indexed endpoints) from the public x402 price index. Quoted != settled.",
      parameters: CHECK_PRICE_SCHEMA,
      free: true,
      priceFloorMinor: "0",
      execute: (args) => client.checkPrice({ url: args.url as string | undefined, tool: args.tool as string | undefined }),
    });
  }
  return tools;
}

// ---------- OpenAI function calling ----------
export interface OpenAIFunctionSpec { type: "function"; function: { name: string; description: string; parameters: JsonSchema } }

export async function toOpenAIFunctions(client: Code402Client, opts?: { includeCheckPrice?: boolean; prefix?: string }) {
  const tools = await toPlainTools(client, opts);
  const specs: OpenAIFunctionSpec[] = tools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } }));
  const byName = new Map(tools.map((t) => [t.name, t]));
  /** Dispatch a tool_call: {name, arguments (JSON string or object)} → JSON string result. */
  async function dispatch(call: { name: string; arguments: string | Record<string, unknown> }): Promise<string> {
    const t = byName.get(call.name);
    if (!t) throw new Error(`unknown tool ${call.name}`);
    const args = typeof call.arguments === "string" ? (JSON.parse(call.arguments || "{}") as Record<string, unknown>) : call.arguments ?? {};
    return JSON.stringify(await t.execute(args));
  }
  return { tools: specs, dispatch, plain: tools };
}

// ---------- Vercel AI SDK (`ai` tool() shape) ----------
/** Returns objects matching the `ai` package's tool shape: { description, parameters (zod or JSON schema), execute }.
 *  If `zod` and `ai` are installed, pass `jsonSchema` from "ai" as opts.jsonSchema to wrap parameters; otherwise raw JSON Schema is used. */
export async function toVercelAITools(client: Code402Client, opts: { includeCheckPrice?: boolean; prefix?: string; jsonSchema?: (s: JsonSchema) => unknown } = {}) {
  const tools = await toPlainTools(client, opts);
  const wrap = opts.jsonSchema ?? ((s: JsonSchema) => s);
  const out: Record<string, { description: string; parameters: unknown; execute: (args: Record<string, unknown>) => Promise<unknown> }> = {};
  for (const t of tools) out[t.name] = { description: t.description, parameters: wrap(t.parameters), execute: (args) => t.execute(args) };
  return out;
}

// ---------- LangChain (DynamicStructuredTool-compatible) ----------
/** Returns plain objects with {name, description, schema (JSON schema), func}. If you have @langchain/core, pass its
 *  `DynamicStructuredTool` class (and optionally a zod converter) to get real StructuredTool instances. */
export async function toLangChainTools(
  client: Code402Client,
  opts: { includeCheckPrice?: boolean; prefix?: string; DynamicStructuredTool?: new (f: { name: string; description: string; schema: unknown; func: (a: Record<string, unknown>) => Promise<string> }) => unknown; schema?: (s: JsonSchema) => unknown } = {},
) {
  const tools = await toPlainTools(client, opts);
  const toSchema = opts.schema ?? ((s: JsonSchema) => s);
  const fields = tools.map((t) => ({ name: t.name, description: t.description, schema: toSchema(t.parameters), func: async (a: Record<string, unknown>) => JSON.stringify(await t.execute(a)) }));
  if (opts.DynamicStructuredTool) return fields.map((f) => new opts.DynamicStructuredTool!(f));
  return fields;
}
