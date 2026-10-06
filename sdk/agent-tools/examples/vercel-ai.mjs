// Example: Vercel AI SDK. `jsonSchema` from "ai" wraps our JSON Schema parameters.
import { jsonSchema } from "ai";
import { privateKeyToAccount } from "viem/accounts";
import { createCode402Client, toVercelAITools } from "@code402/agent-tools";

const ALLOW_MAINNET = process.env.ALLOW_MAINNET === "1";
const client = createCode402Client({
  baseUrl: "https://hcrb.in",
  account: privateKeyToAccount(process.env.PAYER_PRIVATE_KEY),
  maxAmountMinor: "5000",
  allowMainnet: ALLOW_MAINNET,
});
export const tools = await toVercelAITools(client, { jsonSchema });
// generateText({ model, tools, prompt: "Is GB82 WEST 1234 5698 7654 32 a valid IBAN?" })
