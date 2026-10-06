// Example: LangChain. Pass the real DynamicStructuredTool class to get StructuredTool instances.
import { DynamicStructuredTool } from "@langchain/core/tools";
import { privateKeyToAccount } from "viem/accounts";
import { createCode402Client, toLangChainTools } from "@code402/agent-tools";

const ALLOW_MAINNET = process.env.ALLOW_MAINNET === "1";
const client = createCode402Client({
  baseUrl: "https://hcrb.in",
  account: privateKeyToAccount(process.env.PAYER_PRIVATE_KEY),
  maxAmountMinor: "5000",
  allowMainnet: ALLOW_MAINNET,
});
// schema: JSON Schema is accepted by recent @langchain/core; convert with json-schema-to-zod if your version needs zod.
export const tools = await toLangChainTools(client, { DynamicStructuredTool });
