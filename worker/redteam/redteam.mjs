import { privateKeyToAccount } from "viem/accounts";
import { verifyTypedData } from "viem";

// ============================================================================
// A model of Base state: a few real transactions the chain would confirm.
// ============================================================================
const SELLER = "0x2222222222222222222222222222222222222222";
const CHAIN = {
  // a legit $0.005 payment to the seller
  "0xGOOD": { status: "success", to: SELLER, valueMinor: 5000n },
  // an attacker's $0.000001 payment to the SELLER (underpayment)
  "0xDUST": { status: "success", to: SELLER, valueMinor: 1n },
  // an attacker's payment to SOMEONE ELSE entirely (unrelated tx)
  "0xELSEWHERE": { status: "success", to: "0x9999999999999999999999999999999999999999", valueMinor: 9_000_000n },
};

// ============================================================================
// BROKEN verifier — the pasted worker's logic: "any successful tx = paid".
// ============================================================================
function brokenVerify(txHash) {
  const rcpt = CHAIN[txHash];
  if (!rcpt) return "NO_TX";
  if (rcpt.status === "success") return "ACCEPT";   // <-- the entire check
  return "REVERTED";
}

// ============================================================================
// CORRECT verifier — EIP-3009 voucher bound to (recipient, amount, nonce).
// ============================================================================
const CHAIN_ID = 84532, USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const DOMAIN = { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC };
const TYPES = { TransferWithAuthorization: [
  {name:"from",type:"address"},{name:"to",type:"address"},{name:"value",type:"uint256"},
  {name:"validAfter",type:"uint256"},{name:"validBefore",type:"uint256"},{name:"nonce",type:"bytes32"}]};
const used = new Set();
async function correctVerify(v, expect, now) {
  const ok = await verifyTypedData({ address:v.from, domain:DOMAIN, types:TYPES,
    primaryType:"TransferWithAuthorization", message:v, signature:v.signature });
  if (!ok) return "BAD_SIGNATURE";
  if (BigInt(v.value)!==BigInt(expect.amount)) return "PRICE_MISMATCH";
  if (v.to.toLowerCase()!==expect.recipient.toLowerCase()) return "RECIPIENT_MISMATCH";
  if (!(BigInt(now)>=BigInt(v.validAfter)&&BigInt(now)<BigInt(v.validBefore))) return "EXPIRED";
  if (used.has(v.nonce)) return "REPLAY";
  used.add(v.nonce); return "ACCEPT";
}
const payer = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
async function voucher(o={}) {
  const m={from:payer.address,to:SELLER,value:5000n,validAfter:0n,validBefore:2_000_000_000n,nonce:"0x"+"9f".repeat(32),...o};
  return {...m, signature: await payer.signTypedData({domain:DOMAIN,types:TYPES,primaryType:"TransferWithAuthorization",message:m})};
}
const now=1_800_000_000n, EXP={amount:5000n,recipient:SELLER};

console.log("=== RED TEAM: exploits vs the two verifiers ===\n");
const rows = [];

// Exploit 1: replay one paid tx for unlimited free calls
{
  const b1=brokenVerify("0xGOOD"), b2=brokenVerify("0xGOOD"), b3=brokenVerify("0xGOOD");
  const v=await voucher(); const c1=await correctVerify(v,EXP,now); const c2=await correctVerify(await voucher(),EXP,now); // 2nd reuses same nonce
  rows.push(["Replay one tx x3 (free calls)", `${b1}/${b2}/${b3}`, `${c1}/${c2}`]);
}
// Exploit 2: pay $0.000001 dust, claim the $0.005 service
rows.push(["Underpayment ($0.000001)", brokenVerify("0xDUST"),
  await correctVerify(await voucher({value:1n,nonce:"0x"+"11".repeat(32)}),EXP,now)]);
// Exploit 3: present a tx that paid SOMEONE ELSE
rows.push(["Present unrelated tx (paid a stranger)", brokenVerify("0xELSEWHERE"),
  await correctVerify(await voucher({to:"0x9999999999999999999999999999999999999999",nonce:"0x"+"22".repeat(32)}),EXP,now)]);
// Baseline: a genuine correct payment
rows.push(["Legit exact payment", brokenVerify("0xGOOD"),
  await correctVerify(await voucher({nonce:"0x"+"44".repeat(32)}),EXP,now)]);

const pad=(s,n)=>String(s).padEnd(n);
console.log(pad("EXPLOIT",42)+pad("tx-hash-trust (BROKEN)",26)+"EIP-3009 (CORRECT)");
console.log("-".repeat(90));
for(const [e,b,c] of rows) console.log(pad(e,42)+pad(b,26)+c);
console.log("\nBROKEN 'ACCEPT' on an exploit = free service / stolen calls.");
console.log("CORRECT rejects every exploit and accepts only the exact, single-use, correctly-addressed payment.");
