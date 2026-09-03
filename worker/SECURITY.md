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
| **Replay / double-spend** — submit one voucher twice, or fire it at N concurrent requests | **impossible** | replay protection is TWO-LAYERED, and the chain is the authority: KV (NONCES) is only a fast-path pre-check; the authoritative single-use guard is USDC's on-chain `authorizationState`, which settles each `(payer, nonce)` at most once. Because delivery is gated on *synchronous successful settlement* (nonce is burned only AFTER the settle confirms), even a cross-region KV race where two requests both pass the pre-check cannot duplicate delivery — both race to settle, exactly one wins on-chain, the loser gets `SETTLEMENT_FAILED` and delivers nothing. 8 concurrent same-voucher requests → exactly **1** result delivered, 7 rejected. The Durable-Object nonce-registry pattern is unnecessary here precisely because of this gating; it would become mandatory only if delivery ever preceded settlement (e.g., streaming-credit models — which are custody-adjacent and out of scope by design) |
| **Free-tier quota race** — burst concurrent calls from one IP (KV counter is read-then-write) | **real, accepted** | 25 concurrent → >20 served free. Bounded: deterministic checks, ~zero marginal cost, no paid-path weakening. Tighten with an edge WAF rate-limit rule on `/v1/tools/*` + `/mcp` (dashboard, Rule 0) or a Durable-Object counter if it ever matters |
| **IP rotation** — fresh quota per IP | **inherent** | any per-IP free tier has this; the free tier is an on-ramp, not a moat |
| **Facilitator settle-and-deny** — malicious facilitator settles on-chain but reports failure | **no fund risk** | the voucher is payer→recipient signed (`to`/`value`/`nonce`); nobody can redirect funds. Payer can prove payment on-chain by nonce. Mitigation: reputable facilitator + the receipt/tx audit trail |
| **Underpriced-build window** — buying $0.02–0.05 tools at a stale flat price before a pricing redeploy lands | **operational** | closes the moment the per-tool build is deployed; exposure ≈ 0 pre-listings |
| **Price-state manipulation** — self-dealing sales to pump the dynamic price at rivals | **self-harming** | every pump is a real paid sale (bumps cost the pumper money); ceiling caps at 5× floor; τ-decay restores the floor; the floor is the pre-dynamic price, so the worst case for buyers = the old flat price |
| **Stale-quote sniping** — hold a floor-price voucher and redeem it later within its window | **by design** | voucher `validBefore` ≤ ~5 min bounds it; price moves only on real sales, so a sniper is a buyer who paid the then-current price — exactly the reverse/Dutch intent |

Run the races: `node qa.mjs` (73 checks; see "concurrency / sniping").

## Regulatory posture (non-custodial)

This section states the design's regulatory boundary. It is architectural intent,
not a legal opinion — nothing here substitutes for counsel before real-money volume.

| Boundary | Design | Why it holds |
|---|---|---|
| **No custody, ever** | The worker verifies and relays; it never holds, pools, or intermediates USDC. The EIP-3009 voucher is signed payer→recipient and submitted by a third-party facilitator. | The worker lacks the power to initiate, redirect, or retain a transfer — the `to`/`value`/`nonce` are signed into the voucher by the payer. |
| **Money-transmitter (MSB) boundary** | Positioned as software/network access, not a transmitter. | FinCEN 2019 guidance (FIN-2019-G001) excludes providers of communication/software/network access that take no independent custody or control of funds. We neither custody nor exercise discretion over the value path. |
| **OFAC / sanctions screen** | A settle-layer screen (the G6 facilitator) drops sanctioned counterparties before relay. | Non-custodial actors still bear strict liability for facilitating sanctioned transfers. **Caveat:** the denylist is a compiled snapshot — it stales by design and needs a regeneration cadence before volume invitations. |
| **SEC / CFTC boundary** | Settlement is restricted to spot metered digital services, priced 1:1 in USDC. | No futures/options/derivative-style bids are matched, so the pricing mechanism stays a metered SaaS agreement, not an ATS / broker-dealer / SEF. |
| **Travel Rule (FATF)** | Per-call amounts ($0.001–$0.05) sit far below the $3,000 / €1,000 threshold; settlement is unhosted-to-unhosted. | The platform is not a VASP intermediary for these transfers and holds no originator/beneficiary KYC obligation for them. |
| **IRS broker (1099-DA)** | The platform never takes custody, executes no sweeps, and keeps no off-chain ledger of user funds. | Non-custodial software that cannot determine customer identity, cost basis, or unhosted-wallet ownership falls outside the broker definition. |

The entire payment lifecycle is anchored to peer-to-peer on-chain signatures; the
worker's only role is to verify a voucher and deliver a receipt.
