# XDR-1 Conditional Settlement Receipts — Open Specification (`v1.0`)

**Status:** Deployed in Production (`https://hcrb.in` · `https://verify.code402.dev`)  
**Reference Verifier:** [`@code402/verify-mcp`](https://github.com/89rat/code402-verify-mcp) (`npx -y @code402/verify-mcp@latest`)  
**Facilitator Embed:** [`89rat/code402-facilitator-embed`](https://github.com/89rat/code402-facilitator-embed)  
**Steward:** JUANA LIMITED (UK Company No. `14043409`) · `hello@code402.dev`

---

## 1. Problem Statement: The Verify-vs-Settle Gap in Autonomous Agent Payments

In HTTP `402` ([x402](https://www.x402.org/)) agent-to-API transactions, payments settle on-chain via EIP-3009 (`TransferWithAuthorization`) in USDC or EURC. Once an on-chain transfer settles, it is irreversible.

Empirical evaluation of x402 payment flows exposes three structural failure modes when payment verification and service delivery are uncoupled:
1. **Unconfirmed Facilitator Ambiguity (Nonce Burn / Unpaid Delivery)**: If an upstream facilitator times out or returns `HTTP 5xx` during settlement, a naive seller either releases the paid payload without confirmed settlement or rejects the request after the single-use EIP-3009 `nonce` is already in flight.
2. **Delivery Tampering / Substitution**: A standard blockchain transaction receipt (`txHash`) proves only that wallet $A$ transferred amount $M$ to wallet $B$ at timestamp $T$. It does **not** prove which tool was invoked, what input parameters were supplied (`input_hash`), or what payload was returned (`output_hash`).
3. **Non-Custodial Boundary**: Holding buyer funds in a platform-controlled account introduces balance-sheet custody risk, whereas peer-to-peer EIP-3009 transfers keep funds strictly between buyer and seller.

**XDR-1 Conditional Settlement Receipts** solve all three problems **with `$0.00` platform-held funds**: the platform never holds customer funds, holds retries on ambiguous facilitator state (`HTTP 409 PAYMENT_RETRY_HELD`), and cryptographically binds `input_hash`, `output_hash`, `payer`, `recipient`, `amount`, and `nonce` into an offline-verifiable receipt.

---

## 2. Non-Custodial Two-Phase Conditional Settlement Protocol

```
Buyer Agent                     Seller / Code402 Rail                 Facilitator / Chain (Base 8453)
-----------                     ---------------------                 -------------------------------
1. POST /v1/tools/{tool}/call ------>
   (unpaid)
                                <---- HTTP 402 Payment Required
                                      (amount, payTo, chainId,
                                       nonce, validBefore)

2. Pin challenge (payTo + amount),
   sign EIP-3009 authorization
   POST /v1/tools/{tool}/call ------>
   Header: PAYMENT-SIGNATURE          3. Validate EIP-3009 fields &
                                         single-use nonce lock
                                      4. Forward to Facilitator ----------> Verify & Settle EIP-3009
                                                                            (Payer -> Seller direct)
                                         [If Facilitator returns 5xx /
                                          ambiguous state]:
                                      <-- HTTP 409 PAYMENT_RETRY_HELD
                                          (Nonce preserved; output held;
                                           zero funds held by rail)

                                         [If Settlement Confirmed]:
                                      5. Compute input_hash & output_hash
                                      6. Sign canonical XDR-1 Receipt
                                <---- HTTP 200 OK
                                      { result, receipt (XDR-1) }

7. Verify offline (0 network calls):
   keccak256(canonReceipt) +
   secp256k1.recoverPublicKey === signer
```

### Key Protocol Invariants
- **Invariant 1 — Zero Platform Custody (`$0.00`)**: The EIP-3009 `TransferWithAuthorization` `to` (`payTo`) address is always the seller's wallet. The verifier/rail never takes possession of funds.
- **Invariant 2 — Ambiguous Facilitator Hold (`HTTP 409 PAYMENT_RETRY_HELD`)**: When the final facilitator in the failover chain returns an ambiguous `5xx` or network timeout, the rail returns `409 PAYMENT_RETRY_HELD` instead of `402` or `200`. The single-use EIP-3009 nonce remains held in durable state until on-chain settlement state is resolved, preventing both double-charges and unpaid payload release.
- **Invariant 3 — Free, Stateless Offline Verification Forever**: Verifying an XDR-1 receipt requires only `keccak256` and `secp256k1` public-key recovery against the signer published in `/.well-known/mcp.json` (`receipt_signing_address`). Hosted verification at `https://verify.code402.dev` (`GET https://hcrb.in/verify`) is free forever.

---

## 3. XDR-1 Wire Format & Canonical Digest

### 3.1 Core Fields (`ReceiptCore`)

Field order in the canonical string is strict and wire-critical:

| Position | Field | Type | Description |
|---:|---|---|---|
| `1` | `v` | `string` | Protocol version identifier (`"XDR-1"`). |
| `2` | `tool` | `string` | Canonical tool or endpoint identifier (e.g., `"iban-check"`). |
| `3` | `tool_version` | `string` | Semantic version or build identifier of the executing tool. |
| `4` | `input_hash` | `string` | `0x`-prefixed lowercase hex digest of the canonicalized request input. |
| `5` | `output_hash` | `string` | `0x`-prefixed lowercase hex digest of the canonicalized response output. |
| `6` | `payer` | `string` | `0x`-prefixed Ethereum/EVM address of the EIP-3009 payer (or tier identifier). |
| `7` | `recipient` | `string` | `0x`-prefixed Ethereum/EVM `payTo` recipient address. |
| `8` | `amount` | `string` | Integer minor units settled (e.g., `"5000"` for `$0.005000 USDC`). Never floating-point. |
| `9` | `nonce` | `string` | Single-use challenge/authorization nonce bound to this execution. |
| `10` | `ts` | `number` | Unix epoch timestamp (seconds or milliseconds as emitted). |
| `11` | `tier` | `string` | Execution tier (e.g., `"paid"`, `"free"`, `"prepaid"`). |
| `12` *(opt)* | `successor` | `string` | Optional hash-chain successor pointer (`""` if unset when `stream_state` is present). |
| `13` *(opt)* | `stream_state` | `string` | Stream lifecycle state (defaults to `"active"` when appended). |

### 3.2 Canonical Serialization (`canonReceipt`)

The canonical string is constructed by joining positions `1..11` with the ASCII pipe character (`|`, `0x7C`). If either `successor` or `stream_state` is present, two additional pipe-separated slots are appended (`successor || ""` and `stream_state || "active"`):

```typescript
export function canonReceipt(r: ReceiptCore): string {
  const parts = [
    r.v,
    r.tool,
    r.tool_version,
    r.input_hash,
    r.output_hash,
    r.payer,
    r.recipient,
    r.amount,
    r.nonce,
    r.ts,
    r.tier,
  ];
  if (r.successor || r.stream_state) {
    parts.push(r.successor || "", r.stream_state || "active");
  }
  return parts.join("|");
}
```

### 3.3 Digest & `secp256k1` Signature (`digestReceipt` & `verifyReceipt`)

1. **Digest**: Raw `keccak256` over the UTF-8 bytes of `canonReceipt(r)` (no EIP-191 prefix on the receipt digest itself; EIP-191 is used only for the separate operator key-binding attestation):
   $$\text{digest} = \text{keccak256}(\text{UTF8}(\text{canonReceipt}(r)))$$
2. **Signature**: 65-byte compact `secp256k1` signature formatted as `"0x" + r_hex(64) + s_hex(64) + v_hex(2)`, where `v` $\in \{27, 28\}$ (`0x1b`, `0x1c`).
3. **Verification**: Recover the uncompressed secp256k1 public key $P$ from $(\text{digest}, r, s, v - 27)$, compute `"0x" + keccak256(P[1..65])[12..32]`, and compare case-insensitively to `receipt.signer` and the domain's published `receipt_signing_address`.

---

## 4. Stateless 3-Way Reconciliation (`POST /commerce/reconcile`)

For enterprise accounts-payable (AP), marketplace payouts, and multi-agent workflows, an XDR-1 receipt combines with the purchase order and on-chain transfer in a stateless 3-way match:

```bash
curl -s -X POST https://hcrb.in/commerce/reconcile \
  -H "content-type: application/json" \
  -d '{
    "order":    { "id": "po_2026_104", "amount_minor": "5000", "input_hash": "0x..." },
    "payment":  { "tx_hash": "0x...", "payer": "0x...", "recipient": "0x...", "amount_minor": "5000" },
    "delivery": { "receipt": { "v": "XDR-1", "input_hash": "0x...", "output_hash": "0x...", "signature": "0x...", "signer": "0x..." } }
  }'
```

The endpoint verifies:
1. **Cryptographic Receipt Validity**: `verifyReceipt(delivery.receipt, expectedSigner) === true`.
2. **Amount & Counterparty Conservation**: `order.amount_minor === payment.amount_minor === delivery.receipt.amount` (strict integer minor-unit equality).
3. **Input/Output Commitment Integrity**: `order.input_hash === delivery.receipt.input_hash`.

---

## 5. Adopting XDR-1 in Your MCP Server or Facilitator

1. **Verify Receipts Locally (MCP / CLI)**:
   ```bash
   npx -y @code402/verify-mcp@latest
   ```
2. **Embed in an x402 Facilitator or Payout Switch**:
   Copy [`code402-facilitator-embed.mjs`](https://github.com/89rat/code402-facilitator-embed) (zero dependencies) to gate beneficiary payouts on a valid XDR-1 preflight receipt.
3. **Audit Your x402 Endpoint Conformance**:
   ```bash
   npx github:89rat/x402-conformance https://your-endpoint.example
   ```
