// Example: code402 tools inside OpenAI function calling. Testnet by default.
// Set ALLOW_MAINNET=1 only when you mean to spend real USDC on Base.
import { privateKeyToAccount } from "viem/accounts";
import { createCode402Client, toOpenAIFunctions } from "@code402/agent-tools";

const ALLOW_MAINNET = process.env.ALLOW_MAINNET === "1";
if (!process.env.PAYER_PRIVATE_KEY) throw new Error("set PAYER_PRIVATE_KEY (a dedicated, low-balance agent wallet — never a main wallet)");

const client = createCode402Client({
  baseUrl: process.env.CODE402_URL ?? "https://hcrb.in",
  account: privateKeyToAccount(process.env.PAYER_PRIVATE_KEY),
  maxAmountMinor: process.env.MAX_MINOR ?? "5000", // 0.005 USDC hard cap per call
  allowMainnet: ALLOW_MAINNET,
});

const { tools, dispatch } = await toOpenAIFunctions(client);
console.log(tools.map((t) => t.function.name));
// ... pass `tools` to chat.completions.create({ tools }), then for each tool_call:
// const content = await dispatch({ name: call.function.name, arguments: call.function.arguments });
console.log(await dispatch({ name: "code402_iban_check", arguments: { iban: "GB82 WEST 1234 5698 7654 32" } }));
