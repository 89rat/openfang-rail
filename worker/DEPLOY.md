# openfang-rail — go live (Scenario A: zero take-rate, testnet first)

Rule 0: every step here is **yours** to run — your Cloudflare account, your wallet,
your keys. I prepared and verified the code; I don't deploy or hold keys.

## What's verified and ready
- `src/index.ts` — validators + **correct** EIP-3009 verification (amount+recipient+nonce, single-use), pure `@noble` (Workers-native, bundles clean at ~88KB).
- Payment logic proven: `redteam/noble_verify.mjs` and `redteam/verify_test.mjs` (6/6 each), `redteam/redteam.mjs` (broken-vs-correct exploit table). See `SECURITY.md`.
- `LAUNCH_MODE=true` = zero take-rate: full price → seller, rail skims nothing. Stated in the manifest and every receipt.

## Deploy (Base Sepolia — testnet, ~10 min)
```bash
cd openfang-rail/worker
npm install
npx wrangler kv namespace create NONCES        # paste the id into wrangler.jsonc
# edit wrangler.jsonc: set RECIPIENT to YOUR testnet payout wallet (0x...)
npx wrangler deploy                             # -> https://openfang-rail.<subdomain>.workers.dev
```
Smoke test (no payment → 402 challenge):
```bash
curl -s -X POST https://YOUR-WORKER/v1/tools/iban-check/call \
  -H "content-type: application/json" -d '{"input":{"iban":"GB82 WEST 1234 5698 7654 32"}}' | jq
# expect HTTP 402 + an EIP-3009 challenge (recipient, amount, domain, nonce, TTL)
```

## The one honest gap between "verifies" and "collects"
This worker **verifies and authorizes** payment; it does not itself move USDC.
An EIP-3009 voucher is gasless for the payer, but **someone must submit it on-chain**:
- **Option 1 (self-relay):** a tiny script calls `USDC.transferWithAuthorization(voucher)` on Base — needs a gas wallet (your key → Rule 0). This is the fastest path to your first real settlement.
- **Option 2 (facilitator):** hand the voucher to a public x402 facilitator (e.g. Coinbase's) that submits it. Zero gas ops for you.

Until one of these is wired, the worker proves the *authorization* half of the loop. The first **real settlement** = a voucher submitted and confirmed on-chain.

## Before you EVER flip to mainnet (non-negotiable)
1. **OFAC/sanctions screen the payer address** before real-money volume (doctrine gate G6). Not built here — add it or gate mainnet behind it.
2. Change `wrangler.jsonc`: `CHAIN_ID=8453`, `USDC_ADDRESS=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, `USDC_DOMAIN_NAME="USD Coin"`, RECIPIENT = your **mainnet** wallet.
3. Keep `LAUNCH_MODE=true` (Scenario A) — real payments to real sellers, you skim nothing, ~$37 of forgone fee per 3M calls. Do NOT full-refund (wash-trading trap).

## The go-live truth
Deploying this makes the rail **discoverable and able to take a verified payment**.
"Live" in the sense that matters is still one thing: **one external agent signs a
voucher and it settles on-chain, payer→seller, no human.** That first settlement —
not the deploy — is the milestone. Everything here is built and verified to make
that possible; it hasn't happened yet.
