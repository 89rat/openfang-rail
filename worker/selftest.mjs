// selftest.mjs — the disclosed SELF-TEST purchase.
// Buys the cheapest tool on the LIVE rail with a funded key YOU provide via env.
// This is verification spend, not a customer: label it as self-test everywhere, forever.
// Usage:  EVM_PRIVATE_KEY=0x... node selftest.mjs
import { wrapFetchWithPayment, x402HTTPClient } from "@x402/fetch";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";
import { writeFileSync } from "node:fs";

const BASE = process.env.RAIL_URL || "https://rail.akrivis.in";
if (!process.env.EVM_PRIVATE_KEY) { console.error("set EVM_PRIVATE_KEY (a funded wallet, ~$0.05 USDC on Base)"); process.exit(1); }
process.env.EVM_PRIVATE_KEY = process.env.EVM_PRIVATE_KEY.startsWith("0x") ? process.env.EVM_PRIVATE_KEY : "0x" + process.env.EVM_PRIVATE_KEY;
const acct = privateKeyToAccount(process.env.EVM_PRIVATE_KEY);
console.log("SELF-TEST purchaser:", acct.address);
console.log("this is a DISCLOSED self-test — never present it as a customer sale\n");

const client = new x402Client();
client.register("eip155:*", new ExactEvmScheme(acct));
const api = wrapFetchWithPayment(fetch, client);
const httpClient = new x402HTTPClient(client);

const r = await api(BASE + "/v1/tools/iban-check/call", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ input: { iban: "GB82 WEST 1234 5698 7654 32" } }),
});
const result = await httpClient.processResponse(r);
console.log("HTTP:", r.status, "| paymentStatus:", result.paymentStatus);
const out = { at: new Date().toISOString(), http: r.status, paymentStatus: result.paymentStatus, body: result.body, header: result.header ?? null, note: "DISCLOSED SELF-TEST PURCHASE — operator wallet, not a customer" };
writeFileSync("selftest-receipt.json", JSON.stringify(out, null, 2));
console.log("saved: selftest-receipt.json");
if (result.paymentStatus === "settled") {
  const b = result.body ?? {};
  console.log("\nSETTLED ✓  tx:", b.settlement?.tx ?? "(see header)");
  console.log("receipt signer:", b.receipt?.signer, "| tier:", b.tier, "| amount:", b.receipt?.amount);
  console.log("\nDISCLOSED SELF-TEST COMPLETE — the loop is proven with real settlement.");
} else {
  console.log("\nnot settled — see paymentStatus/body above (insufficient funds is the usual cause)");
}
