import { describe, it, expect } from "vitest";
import { recoverTypedDataAddress } from "viem";
import { createCode402Client, CapExceededError, ChainNotAllowedError, NoSignerError, parseChallenge, verifyReceipt, toOpenAIFunctions, toVercelAITools, toLangChainTools, toPlainTools } from "../src/index.js";
import { mockFetch, payer, receiptSigner, challenge402, signedReceipt, kh, SELLER, USDC_SEPOLIA, PAYER_KEY, catalog } from "./helpers.js";

const BASE = "https://seller.example";

describe("402 → cap → sign → retry → receipt", () => {
  it("pays a 402 within the cap and verifies the receipt", async () => {
    let seen: any = null;
    const m = mockFetch({ amount: "999", onPaid: (_h, p) => (seen = p) });
    const c = createCode402Client({ baseUrl: BASE, account: payer, maxAmountMinor: "5000", fetch: m.fetch, now: () => 1700000000000 });
    const r = await c.callTool("iban-check", { iban: "GB82 WEST 1234 5698 7654 32" });
    expect(r.paid).toBe(true);
    expect(r.amountMinor).toBe("999");
    expect(r.receiptVerification?.verified).toBe(true);
    expect(r.receiptVerification?.recovered?.toLowerCase()).toBe(receiptSigner.address.toLowerCase());
    // two POSTs to the tool + one catalog fetch
    expect(m.calls.filter((x) => x.url.includes("/call")).length).toBe(2);
    // the voucher really was signed by the payer over the challenge's domain
    const a = seen.payload.authorization;
    expect(a.to.toLowerCase()).toBe(SELLER);
    expect(a.value).toBe("999");
    expect(Number(a.validBefore)).toBe(1700000000 + 300);
    const rec = await recoverTypedDataAddress({
      domain: { name: "USDC", version: "2", chainId: 84532, verifyingContract: USDC_SEPOLIA },
      types: { TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] },
      primaryType: "TransferWithAuthorization",
      message: { from: a.from, to: a.to, value: BigInt(a.value), validAfter: BigInt(a.validAfter), validBefore: BigInt(a.validBefore), nonce: a.nonce },
      signature: seen.payload.signature,
    });
    expect(rec.toLowerCase()).toBe(payer.address.toLowerCase());
  });

  it("refuses to sign above maxAmountMinor (no second request is sent)", async () => {
    const m = mockFetch({ amount: "20000" });
    const c = createCode402Client({ baseUrl: BASE, account: payer, maxAmountMinor: "5000", fetch: m.fetch });
    await expect(c.callTool("rent-deposit-guard", { deposit_iban: "x" })).rejects.toBeInstanceOf(CapExceededError);
    expect(m.calls.filter((x) => x.url.includes("/call")).length).toBe(1);
  });

  it("per-call cap can only tighten the client cap", async () => {
    const m = mockFetch({ amount: "999" });
    const c = createCode402Client({ baseUrl: BASE, account: payer, maxAmountMinor: "500", fetch: m.fetch });
    await expect(c.callTool("iban-check", { iban: "x" }, { maxAmountMinor: "5000" })).rejects.toBeInstanceOf(CapExceededError);
  });

  it("default cap is 0: pays nothing", async () => {
    const m = mockFetch({ amount: "1" });
    const c = createCode402Client({ baseUrl: BASE, account: payer, fetch: m.fetch });
    await expect(c.callTool("iban-check", { iban: "x" })).rejects.toBeInstanceOf(CapExceededError);
  });

  it("mainnet is refused unless allowMainnet", async () => {
    const m = mockFetch({ amount: "999", chainId: 8453 });
    const c = createCode402Client({ baseUrl: BASE, account: payer, maxAmountMinor: "5000", fetch: m.fetch });
    await expect(c.callTool("iban-check", { iban: "x" })).rejects.toBeInstanceOf(ChainNotAllowedError);
  });

  it("no account → NoSignerError on a 402; free-tier 200 still works", async () => {
    const m = mockFetch({ amount: "999" });
    const c = createCode402Client({ baseUrl: BASE, maxAmountMinor: "5000", fetch: m.fetch });
    await expect(c.callTool("iban-check", { iban: "x" })).rejects.toBeInstanceOf(NoSignerError);
    const free = mockFetch({ freeFirst: true });
    const c2 = createCode402Client({ baseUrl: BASE, fetch: free.fetch });
    const r = await c2.callTool("iban-check", { iban: "x" });
    expect(r.paid).toBe(false);
    expect(r.amountMinor).toBe("0");
    expect(r.receiptVerification?.verified).toBe(true);
  });

  it("receipt from the wrong signer fails verification", async () => {
    const m = mockFetch({ amount: "999", signerKey: PAYER_KEY });
    const c = createCode402Client({ baseUrl: BASE, account: payer, maxAmountMinor: "5000", fetch: m.fetch });
    const r = await c.callTool("iban-check", { iban: "x" });
    expect(r.receiptVerification?.verified).toBe(false);
    expect(r.receiptVerification?.reason).toMatch(/does not match/);
  });

  it("tampered receipt fails verification", async () => {
    const m = mockFetch({ amount: "999", tamper: true });
    const c = createCode402Client({ baseUrl: BASE, account: payer, maxAmountMinor: "5000", fetch: m.fetch });
    const r = await c.callTool("iban-check", { iban: "x" });
    expect(r.receiptVerification?.verified).toBe(false);
  });

  it("quote() never signs", async () => {
    const m = mockFetch({ amount: "999" });
    const c = createCode402Client({ baseUrl: BASE, fetch: m.fetch });
    const q = await c.quote("iban-check", { iban: "x" });
    expect(q?.amountMinor).toBe("999");
    expect(q?.chainId).toBe(84532);
  });
});

describe("parseChallenge dialects", () => {
  it("prefers the PAYMENT-REQUIRED header (v2)", () => {
    const v2 = { x402Version: 2, accepts: [{ scheme: "exact", network: "eip155:8453", amount: "777", payTo: SELLER, asset: USDC_SEPOLIA, extra: { name: "USD Coin", version: "2" } }] };
    const h = new Headers({ "PAYMENT-REQUIRED": Buffer.from(JSON.stringify(v2)).toString("base64") });
    const ch = parseChallenge(402, h, challenge402("999"));
    expect(ch.amountMinor).toBe("777");
    expect(ch.chainId).toBe(8453);
    expect(ch.eip712.name).toBe("USD Coin");
  });
  it("falls back to legacy flat fields", () => {
    const legacy = { price: { amount: "5000", token_address: USDC_SEPOLIA }, recipient: SELLER, network: { chain_id: 84532 }, eip712: { name: "USDC", version: "2" }, nonce: "0x11", expires_at: 5 };
    const ch = parseChallenge(402, new Headers(), legacy);
    expect(ch.amountMinor).toBe("5000");
    expect(ch.nonce).toBe("0x11");
  });
  it("rejects float amounts / incomplete challenges", () => {
    expect(() => parseChallenge(402, new Headers(), { accepts: [{ maxAmountRequired: "0.001", payTo: SELLER, asset: USDC_SEPOLIA, network: "base", extra: { name: "USDC", version: "2" } }] })).toThrow();
  });
});

describe("verifyReceipt", () => {
  it("passes on a valid receipt with matching hashes", async () => {
    const input = { iban: "x" }, output = { valid: true };
    const r = await signedReceipt({ tool: "iban-check", input_hash: kh(input), output_hash: kh(output), payer: payer.address, recipient: SELLER, amount: "999", nonce: "0x01", ts: 1 });
    expect((await verifyReceipt(r, receiptSigner.address, { input, output })).verified).toBe(true);
    expect((await verifyReceipt(r, receiptSigner.address, { input: { iban: "y" }, output })).verified).toBe(false);
    expect((await verifyReceipt(undefined, receiptSigner.address)).verified).toBe(false);
    expect((await verifyReceipt(r, undefined)).verified).toBe(false);
  });
});

describe("adapters (catalog-driven, never hardcoded)", () => {
  it("propagates the live MCP inputSchema (camelCase) to every framework adapter", async () => {
    const liveShape = {
      ...catalog,
      tools: catalog.tools.map((t) => ({
        ...t,
        inputSchema: { type: "object", required: ["iban"], properties: { iban: { type: "string" } } },
        input_schema: undefined,
      })),
    };
    const fetch = (async (url: string) => {
      if (url.endsWith("/.well-known/mcp.json")) return new Response(JSON.stringify(liveShape), { status: 200, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify(challenge402("999")), { status: 402, headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
    const c = createCode402Client({ baseUrl: BASE, account: payer, maxAmountMinor: "5000", fetch });
    const expected = liveShape.tools[0].inputSchema;
    const plain = await toPlainTools(c, { includeCheckPrice: false });
    expect(plain[0].parameters).toEqual(expected);
    const oai = await toOpenAIFunctions(c);
    expect(oai.tools.find((t) => t.function.name === "code402_iban_check")!.function.parameters).toEqual(expected);
    const v = await toVercelAITools(c, { includeCheckPrice: false });
    expect((v.code402_iban_check!.parameters as unknown)).toEqual(expected);
    const lc = (await toLangChainTools(c, { includeCheckPrice: false })) as any[];
    expect(lc[0].schema).toEqual(expected);
  });

  it("OpenAI function specs + dispatch, with free check_price first", async () => {
    const m = mockFetch({ amount: "999" });
    const c = createCode402Client({ baseUrl: BASE, account: payer, maxAmountMinor: "5000", fetch: m.fetch, priceIndexUrl: "https://index.example" });
    const { tools, dispatch } = await toOpenAIFunctions(c);
    expect(tools.map((t) => t.function.name)).toEqual(["code402_check_price", "code402_iban_check", "code402_rent_deposit_guard"]);
    expect(tools[1]!.function.description).toMatch(/floor 999/);
    const out = JSON.parse(await dispatch({ name: "code402_iban_check", arguments: JSON.stringify({ iban: "x" }) }));
    expect(out.paid).toBe(true);
    expect(out.receipt_verified).toBe(true);
    const price = JSON.parse(await dispatch({ name: "code402_check_price", arguments: { tool: "iban-check" } }));
    expect(price.kind).toBe("quoted");
  });
  it("Vercel AI + LangChain shapes", async () => {
    const m = mockFetch({ amount: "999" });
    const c = createCode402Client({ baseUrl: BASE, account: payer, maxAmountMinor: "5000", fetch: m.fetch });
    const v = await toVercelAITools(c, { includeCheckPrice: false });
    expect(Object.keys(v)).toEqual(["code402_iban_check", "code402_rent_deposit_guard"]);
    expect(typeof v.code402_iban_check!.execute).toBe("function");
    const lc = (await toLangChainTools(c, { includeCheckPrice: false })) as any[];
    expect(lc[0].name).toBe("code402_iban_check");
    expect(JSON.parse(await lc[0].func({ iban: "x" })).paid).toBe(true);
    class Fake { constructor(public f: any) {} }
    const inst = (await toLangChainTools(c, { DynamicStructuredTool: Fake as any })) as Fake[];
    expect(inst[0]).toBeInstanceOf(Fake);
  });
});
