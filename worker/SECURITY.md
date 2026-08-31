# openfang-rail — payment security (the trust artifact)

Trust is earned by reproducing the attack and showing the fix, not by asserting
"secure." This documents both, with runnable proof.

## The bug in the common "day-1 worker" pattern

Many pasted x402 workers verify payment like this:

```ts
const receipt = await waitForTransactionReceipt({ hash: paymentSignature });
if (receipt.status === "success") { /* deliver the paid resource */ }
```

That checks only that *some* transaction succeeded. It never checks **amount,
recipient, token, or single-use**. Result: total bypass.

## Reproduced exploits (`redteam/redteam.mjs`, runnable)

| Exploit | tx-hash-trust (BROKEN) | EIP-3009 (CORRECT) |
|---|---|---|
| Replay one $0.005 tx x3 → unlimited free calls | ACCEPT / ACCEPT / ACCEPT | ACCEPT / **REPLAY** |
| Underpay $0.000001, claim the $0.005 service | ACCEPT | **PRICE_MISMATCH** |
| Present a tx that paid a total stranger | ACCEPT | **RECIPIENT_MISMATCH** |
| Legit exact payment | ACCEPT | ACCEPT |

BROKEN "ACCEPT" on any exploit row = free service / stolen calls.

## The fix (shipped in `src/index.ts`, proven in `redteam/verify_test.mjs`, 6/6)

Verify an **EIP-3009 TransferWithAuthorization voucher** bound to the request:

1. signature must recover to `from` (viem `verifyTypedData`);
2. `value` must equal the exact quoted amount (else `PRICE_MISMATCH`);
3. `to` must equal the seller's published recipient (else `RECIPIENT_MISMATCH`);
4. `now` must be within `[validAfter, validBefore)` (else `EXPIRED`);
5. `nonce` must be unused — stored in KV, single-use (else `REPLAY`).

Non-custodial: the voucher authorizes a payer→recipient USDC transfer; a
facilitator submits it on-chain. The worker never holds funds.

## Run it yourself

```
cd worker/redteam
npm i viem
node verify_test.mjs   # 6/6: valid accepted; replay/underpay/wrong-recipient/expiry/tamper rejected
node redteam.mjs       # side-by-side: broken accepts every exploit, correct rejects them
```

## Deploy discipline

Testnet first (`wrangler.jsonc` targets Base Sepolia). A payment bug on Sepolia
costs test money; the same bug on mainnet is real. Flip to mainnet only after
one real external settlement proves the loop. The broken verifier is kept ONLY
as a red-team target — it is never the production payment gate.

## Concurrency & sniping (qa.mjs, runnable)

The sequential exploits above say nothing about RACES. Reproduced and classified:

| Sniping vector | Status | Proof |
|---|---|---|
| **Stale/cheap price replay** — quote a cheap challenge, pay it later for a pricier call | **impossible** | every call re-quotes and enforces the exact current per-tool price (`PRICE_MISMATCH`); amount is signed into the voucher |
| **Replay / double-spend** — submit one voucher twice, or fire it at N concurrent requests | **impossible** | worker burns the nonce after settle, and USDC's on-chain `authorizationState` settles each nonce at most once; 8 concurrent same-voucher requests → exactly **1** result delivered, 7 rejected, voucher dead (`REPLAY`) |
| **Free-tier quota race** — burst concurrent calls from one IP (KV counter is read-then-write) | **real, accepted** | 25 concurrent → >20 served free. Bounded: deterministic checks, ~zero marginal cost, no paid-path weakening. Tighten with an edge WAF rate-limit rule on `/v1/tools/*` + `/mcp` (dashboard, Rule 0) or a Durable-Object counter if it ever matters |
| **IP rotation** — fresh quota per IP | **inherent** | any per-IP free tier has this; the free tier is an on-ramp, not a moat |
| **Facilitator settle-and-deny** — malicious facilitator settles on-chain but reports failure | **no fund risk** | the voucher is payer→recipient signed (`to`/`value`/`nonce`); nobody can redirect funds. Payer can prove payment on-chain by nonce. Mitigation: reputable facilitator + the receipt/tx audit trail |
| **Underpriced-build window** — buying $0.02–0.05 tools at a stale flat price before a pricing redeploy lands | **operational** | closes the moment the per-tool build is deployed; exposure ≈ 0 pre-listings |
| **Price-state manipulation** — self-dealing sales to pump the dynamic price at rivals | **self-harming** | every pump is a real paid sale (bumps cost the pumper money); ceiling caps at 5× floor; τ-decay restores the floor; the floor is the pre-dynamic price, so the worst case for buyers = the old flat price |
| **Stale-quote sniping** — hold a floor-price voucher and redeem it later within its window | **by design** | voucher `validBefore` ≤ ~5 min bounds it; price moves only on real sales, so a sniper is a buyer who paid the then-current price — exactly the reverse/Dutch intent |

Run the races: `node qa.mjs` (73 checks; see "concurrency / sniping").
