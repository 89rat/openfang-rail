# @code-402/agent-tools

code402's x402 pay-per-call tools (IBAN / LEI / VAT / rental due-diligence / on-chain checks …) in your agent's toolbelt — LangChain, Vercel AI SDK, or OpenAI function calling — with a hard client-side spend cap and offline receipt verification. The tool list is read live from `/.well-known/mcp.json`; nothing is hardcoded.

## Quickstart (5 lines)

```js
import { privateKeyToAccount } from "viem/accounts";
import { createCode402Client, toOpenAIFunctions } from "@code-402/agent-tools";
const client = createCode402Client({ baseUrl: "https://hcrb.in", account: privateKeyToAccount(process.env.PAYER_PRIVATE_KEY), maxAmountMinor: "5000" });
const { tools, dispatch } = await toOpenAIFunctions(client);   // also: toVercelAITools(), toLangChainTools()
console.log(await dispatch({ name: "code402_iban_check", arguments: { iban: "GB82 WEST 1234 5698 7654 32" } }));
```

Free tier first (the seller's `/.well-known/mcp.json` states the current allowance); after that every call is the loop below.

## What happens on a call

1. `POST /v1/tools/{tool}/call` with `{input}` — unpaid.
2. `200` → done (free tier). `402` → parse the challenge (`PAYMENT-REQUIRED` header, `accepts[0]`, or legacy flat fields).
3. **Cap check**: if the quoted amount is above `maxAmountMinor`, throw `CapExceededError`. Nothing is signed.
4. Sign an EIP-3009 `TransferWithAuthorization` (EIP-712) from your wallet **to the recipient named in the 402**, for exactly the quoted amount, valid ≤ 300 s.
5. Retry with `X-PAYMENT: base64(JSON)`; return `{result, receipt, settlement, receiptVerification}`.
6. Recover the XDR-1 receipt signer and compare with the catalog's `receipts.receipt_signing_address`; also check `input_hash`/`output_hash` against what you sent and got.

## Cap semantics

- `maxAmountMinor` is an **integer string in USDC minor units** (6 decimals): `"5000"` = 0.005 USDC. Default `"0"` = never pay.
- The cap is enforced **before** signing, per call. A per-call `maxAmountMinor` can only tighten the client cap, never loosen it.
- Base mainnet (chain 8453) is refused unless `allowMainnet: true`. Base Sepolia (84532) is the default. Anything else is refused.

## The 402 is authoritative

Catalog prices (`price_usdc`, `price_usdc_ceiling`) are floor/ceiling hints for the model; the live 402 challenge is the only price this client will sign — never more, never to a different recipient, never on a different chain. Use `client.quote(tool, input)` to see a challenge without paying.

## Custody

None. The voucher you sign is a direct payer → seller USDC transfer; this library holds no funds, has no server, sends nothing anywhere except the seller's URL and (for `check_price`) the public price index. Use a dedicated low-balance agent wallet. No keys are stored or logged.

## Free tool: `check_price`

`code402_check_price {url|tool}` queries the public x402 price index (`/v1/price`): current 402 quote, 7/30-day min/median/max, percentile among indexed endpoints. Quoted ≠ settled.

## Adapters

| Function | Returns |
|---|---|
| `toOpenAIFunctions(client)` | `{tools: [{type:"function", function:{name, description, parameters}}], dispatch(call)}` |
| `toVercelAITools(client, {jsonSchema})` | `{ [name]: {description, parameters, execute} }` (pass `jsonSchema` from `ai`) |
| `toLangChainTools(client, {DynamicStructuredTool})` | `DynamicStructuredTool[]`, or plain `{name, description, schema, func}` without the class |
| `toPlainTools(client)` | the framework-neutral shape the others project from |

Peer deps: `viem` (required for signing/recovery); `ai`, `@langchain/core`, `zod` optional.

## Develop

```
npm install && npm run typecheck && npm test   # vitest, mocked fetch (402 then 200), cap refusal, receipt pass/fail
```

MIT. No latency or volume figures are stated because none are measured by this package.
