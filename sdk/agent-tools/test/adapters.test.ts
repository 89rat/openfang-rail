import { describe, expect, it } from "vitest";
import { toPlainTools, toVercelAITools, toOpenAIFunctions } from "../src/adapters.js";
import type { Code402Client } from "../src/client.js";

/**
 * The live catalog already serves `check_price` (one of the 23 tools on the default card), and the
 * adapters used to add their own unconditionally. Measured 2026-10-06 against https://hcrb.in:
 * toPlainTools() returned 24 entries with `code402_check_price` twice, while toVercelAITools() —
 * which keys its result object by name — collapsed the pair to 23. So the three adapters reported
 * different catalogue sizes for the same service.
 */
function stubClient(toolNames: string[]): Code402Client {
  const tools = toolNames.map((name) => ({ name, description: `desc ${name}`, inputSchema: { type: "object", properties: {} } }));
  return {
    baseUrl: "https://hcrb.in",
    maxAmountMinor: "0",
    catalog: async () => ({ tools } as never),
    tools: async () => tools as never,
    callTool: async () => ({ result: {}, tier: "free", paid: false } as never),
    quote: async () => null,
    checkPrice: async () => ({}),
  };
}

describe("catalogue adapters", () => {
  it("adds check_price when the catalog does not already serve it", async () => {
    const tools = await toPlainTools(stubClient(["iban_check", "lei_check"]));
    const names = tools.map((t) => t.name);
    expect(names).toContain("code402_check_price");
    expect(names).toHaveLength(3);
    expect(new Set(names).size).toBe(names.length);
  });

  it("does not duplicate check_price when the catalog already serves it", async () => {
    const names = (await toPlainTools(stubClient(["iban_check", "check_price", "receipt_verify"]))).map((t) => t.name);
    expect(names.filter((n) => n === "code402_check_price")).toHaveLength(1);
    expect(names).toHaveLength(3);
  });

  it("still honours includeCheckPrice: false", async () => {
    const names = (await toPlainTools(stubClient(["iban_check"]), { includeCheckPrice: false })).map((t) => t.name);
    expect(names).toEqual(["code402_iban_check"]);
  });

  it("reports the same catalogue size from every adapter", async () => {
    const client = stubClient(["iban_check", "check_price", "receipt_verify"]);
    const plain = await toPlainTools(client);
    const vercel = await toVercelAITools(client, { jsonSchema: (s) => s });
    const openai = await toOpenAIFunctions(client);
    expect(Object.keys(vercel)).toHaveLength(plain.length);
    expect(openai.tools).toHaveLength(plain.length);
    expect(new Set(plain.map((t) => t.name)).size).toBe(plain.length);
  });
});
