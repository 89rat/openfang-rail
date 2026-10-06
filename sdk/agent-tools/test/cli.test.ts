import { describe, it, expect } from "vitest";
import { assertHttpsBase, assertKeyFormat, parseJsonArg, timedFetch, VERSION } from "../src/cli.js";

describe("enterprise CLI guards", () => {
  it("accepts the package version shape", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
  it("HTTPS-only: plain http origins are refused for payment traffic", () => {
    expect(assertHttpsBase("https://hcrb.in")).toBe("https://hcrb.in");
    expect(() => assertHttpsBase("http://hcrb.in")).toThrow(/HTTPS/);
    expect(() => assertHttpsBase("not-a-url")).toThrow(/valid URL/);
  });
  it("keys are format-checked before any use (0x + 64 hex)", () => {
    const k = "0x" + "ab".repeat(32);
    expect(assertKeyFormat(k)).toBe(k);
    expect(() => assertKeyFormat("0x1234")).toThrow(/64 hex/);
    expect(() => assertKeyFormat("ab".repeat(32))).toThrow(/64 hex/);
  });
  it("input JSON must be an object, under the size cap", () => {
    expect(parseJsonArg('{"a":1}', "t")).toEqual({ a: 1 });
    expect(parseJsonArg(undefined, "t")).toEqual({});
    expect(() => parseJsonArg("[1,2]", "t")).toThrow(/object/);
    expect(() => parseJsonArg("{bad", "t")).toThrow(/valid JSON/);
    expect(() => parseJsonArg(" ".repeat(1_000_001), "t")).toThrow(/exceeds/);
  });
  it("timedFetch always attaches a timeout signal", async () => {
    const f = timedFetch(5000);
    let seen: AbortSignal | null = null;
    const stub = ((_: any, init?: RequestInit) => { seen = init?.signal ?? null; return Promise.resolve(new Response("{}")); }) as typeof fetch;
    const orig = globalThis.fetch;
    globalThis.fetch = stub;
    try { await f("https://example.com", {}); } finally { globalThis.fetch = orig; }
    expect(seen).not.toBeNull();
  });
});

describe("Agent-Ready Scorecard", () => {
  it("grades an origin from deterministic probes (mocked fetch)", async () => {
    const { scoreOrigin } = await import("../src/score.js");
    const good = new Set(["/.well-known/x402.json", "/.well-known/mcp.json", "/mcp", "/robots.txt"]);
    const fetchFn = async (url: string) => {
      const p = new URL(url).pathname;
      if (good.has(p)) return { status: 200, headers: { get: () => "application/json" }, text: async () => '{"tools":[]}' };
      return { status: 404, headers: { get: () => "text/plain" }, text: async () => "nf" };
    };
    const card = await scoreOrigin("https://example.com", fetchFn as never, new Date("2026-09-21"));
    expect(card.checks.length).toBeGreaterThanOrEqual(11);
    expect(card.checks.find((c) => c.id === "x402-manifest")?.ok).toBe(true);
    expect(card.checks.find((c) => c.id === "agent-card")?.ok).toBe(false);
    expect(card.top_fix).toBeTruthy();
    expect(card.score).toBeGreaterThan(0);
    expect(card.score).toBeLessThan(100);
    expect(["A", "B", "C", "D", "F"]).toContain(card.grade);
  });
  it("rejects non-https origins", async () => {
    const { scoreOrigin } = await import("../src/score.js");
    await expect(scoreOrigin("http://example.com", (() => { throw new Error("no fetch"); }) as never)).rejects.toThrow(/https/);
  });
});
