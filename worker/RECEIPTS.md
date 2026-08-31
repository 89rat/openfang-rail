# Signed receipts, cryptographically bound to your wallet (no fund key exposed)

Every result carries an XDR-1 receipt signed by a **dedicated receipt key**, and
that key is authorized by a one-time attestation signed by **your wallet
0xc59c85e661d34084a7769f955d17fd38254a6235**. Anyone can verify the full chain
offline: receipt → receipt-signer → authorized-by-your-wallet. Your fund key
never touches the worker.

Proven: `redteam/attest_test.mjs` (3/3 — chain verifies, forged signer rejected,
wrong-wallet attestation rejected) and `redteam/receipt_test.mjs` (4/4).

## One-time setup (Rule 0 — you run these; I never see a private key)

1) Generate the DEDICATED receipt key (holds no funds — a leak only lets someone
   forge receipts, which you then rotate; your USDC is never at risk):
```
openssl rand -hex 32              # -> RECEIPT_SIGNING_KEY
```

2) Derive its address (the receipt-signer). Any of your tools work; e.g. with
   the delivered helper:
```
node -e 'import("@noble/curves/secp256k1").then(async m=>{import("@noble/hashes/sha3").then(h=>{const k=Buffer.from(process.argv[1],"hex");const pub=m.secp256k1.getPublicKey(k,false).slice(1);console.log("0x"+Buffer.from(h.keccak_256(pub)).slice(12).toString("hex"))})})' <RECEIPT_SIGNING_KEY>
```
   Call the result SIGNER (e.g. 0xabc…).

3) Build the EXACT attestation string (lowercase both addresses):
```
openfang-rail: I authorize receipt-signer <SIGNER> to issue XDR-1 receipts on my behalf. authorized_by=0xc59c85e661d34084a7769f955d17fd38254a6235
```

4) Sign that string with your wallet 0x417d… using personal_sign (EIP-191) —
   in MetaMask/your wallet UI or `personal_sign`. This is the ONLY thing your
   fund wallet does, and it moves no money. Copy the signature -> ATTESTATION_SIG.

5) Set the worker config:
```
wrangler secret put RECEIPT_SIGNING_KEY      # the hex from step 1 (secret)
# vars in wrangler.jsonc (all public):
#   AUTHORIZED_BY   = 0xc59c85e661d34084a7769f955d17fd38254a6235
#   ATTESTATION     = "<the exact string from step 3>"
#   ATTESTATION_SIG = "<the signature from step 4>"
```

## Verify any receipt (anyone, no trust)
```
node redteam/verify-receipt.mjs '<the full JSON response from a call>'
# -> { verified: true, receipt_signer, authorized_by, checks: {...} }
```

## Why this is the safe answer to "tie receipts to my wallet"
- You cannot sign with an address; signing needs a private key.
- Putting your FUND key (0x417d…) in the worker would risk your USDC on any
  compromise. Never do that.
- Instead: a throwaway receipt key signs; your wallet signs a one-time
  authorization. Receipts are provably yours; the fund key stays offline.
- Rotate: generate a new receipt key + re-sign the attestation. No fund exposure.
