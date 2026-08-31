import { privateKeyToAccount } from "viem/accounts";
import { verifyTypedData } from "viem";

// Base Sepolia USDC domain
const CHAIN_ID = 84532;
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const DOMAIN = { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC };
const TYPES = { TransferWithAuthorization: [
  { name: "from", type: "address" }, { name: "to", type: "address" },
  { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" },
  { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
]};

// ---- the verifier the worker uses (the CORRECT path) ----
const usedNonces = new Set();
async function verifyVoucher(v, expected, now) {
  // 1. signature must recover to `from`
  const ok = await verifyTypedData({ address: v.from, domain: DOMAIN, types: TYPES,
    primaryType: "TransferWithAuthorization", message: v, signature: v.signature });
  if (!ok) return "BAD_SIGNATURE";
  // 2. must pay the exact quoted amount
  if (BigInt(v.value) !== BigInt(expected.amount)) return "PRICE_MISMATCH";
  // 3. must pay the seller's published recipient (anti-misdirection)
  if (v.to.toLowerCase() !== expected.recipient.toLowerCase()) return "RECIPIENT_MISMATCH";
  // 4. time window
  if (!(BigInt(now) >= BigInt(v.validAfter) && BigInt(now) < BigInt(v.validBefore))) return "EXPIRED";
  // 5. single-use nonce (replay guard)
  if (usedNonces.has(v.nonce)) return "REPLAY";
  usedNonces.add(v.nonce);
  return "ACCEPT";
}

const payer = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const RECIPIENT = "0x2222222222222222222222222222222222222222";
const now = 1_800_000_000n;
async function makeVoucher(overrides = {}) {
  const m = { from: payer.address, to: RECIPIENT, value: 5000n,
    validAfter: 0n, validBefore: 2_000_000_000n,
    nonce: "0x" + "9f".repeat(32), ...overrides };
  const signature = await payer.signTypedData({ domain: DOMAIN, types: TYPES,
    primaryType: "TransferWithAuthorization", message: m });
  return { ...m, signature };
}

let pass=0, fail=0;
const chk=(n,got,want)=>{const ok=got===want;console.log(`${ok?"PASS":"FAIL"}  ${n}  (${got})`);ok?pass++:fail++;};

// valid voucher, exact amount 5000, correct recipient -> ACCEPT
chk("valid voucher accepted", await verifyVoucher(await makeVoucher(), {amount:5000n, recipient:RECIPIENT}, now), "ACCEPT");
// replay the SAME nonce -> REPLAY (the bug in the pasted worker: infinite reuse)
chk("replay same nonce rejected", await verifyVoucher(await makeVoucher(), {amount:5000n, recipient:RECIPIENT}, now), "REPLAY");
// underpayment: voucher pays 1, quote 5000 -> PRICE_MISMATCH (the pasted worker would accept ANY tx)
chk("underpayment rejected", await verifyVoucher(await makeVoucher({value:1n, nonce:"0x"+"11".repeat(32)}), {amount:5000n, recipient:RECIPIENT}, now), "PRICE_MISMATCH");
// pays a DIFFERENT recipient -> RECIPIENT_MISMATCH
chk("wrong recipient rejected", await verifyVoucher(await makeVoucher({to:"0x3333333333333333333333333333333333333333", nonce:"0x"+"22".repeat(32)}), {amount:5000n, recipient:RECIPIENT}, now), "RECIPIENT_MISMATCH");
// expired window -> EXPIRED
chk("expired voucher rejected", await verifyVoucher(await makeVoucher({validBefore:100n, nonce:"0x"+"33".repeat(32)}), {amount:5000n, recipient:RECIPIENT}, now), "EXPIRED");
// tampered amount but same signature (attacker edits value after signing) -> BAD_SIGNATURE
const good = await makeVoucher({nonce:"0x"+"44".repeat(32)});
chk("post-sign tamper rejected", await verifyVoucher({...good, value:1n}, {amount:1n, recipient:RECIPIENT}, now), "BAD_SIGNATURE");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
