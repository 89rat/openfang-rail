// openfang-rail self-relay. Turns a verified X-PAYMENT voucher into an on-chain
// settlement: calls USDC.transferWithAuthorization(...) on Base. The PAYER is
// gasless; the RELAYER (this script, your gas wallet) pays the tiny gas.
//
// Rule 0: RELAYER_KEY is YOUR gas wallet key, read from env — never in code,
// never shown to the assistant. Usage:
//   RELAYER_KEY=0x... node settle.mjs '<base64 X-PAYMENT voucher>'
import { createWalletClient, createPublicClient, http, encodeFunctionData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base, baseSepolia } from "viem/chains";

const CHAINS = {
  "84532": { chain: baseSepolia, usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", rpc: "https://base-sepolia-rpc.publicnode.com" },
  "8453":  { chain: base,        usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", rpc: "https://base-rpc.publicnode.com" },
};
const ABI = [{ type:"function", name:"transferWithAuthorization", stateMutability:"nonpayable",
  inputs:[{name:"from",type:"address"},{name:"to",type:"address"},{name:"value",type:"uint256"},
    {name:"validAfter",type:"uint256"},{name:"validBefore",type:"uint256"},{name:"nonce",type:"bytes32"},
    {name:"v",type:"uint8"},{name:"r",type:"bytes32"},{name:"s",type:"bytes32"}], outputs:[] }];

export function voucherToCall(v, usdc) {
  const s = v.signature.replace(/^0x/,"");
  const r = "0x"+s.slice(0,64), ss = "0x"+s.slice(64,128); let vv = parseInt(s.slice(128,130),16); if (vv < 27) vv += 27;
  const data = encodeFunctionData({ abi: ABI, functionName: "transferWithAuthorization",
    args: [v.from, v.to, BigInt(v.value), BigInt(v.validAfter), BigInt(v.validBefore), v.nonce, vv, r, ss] });
  return { to: usdc, data };
}

async function main() {
  const cfg = CHAINS[process.env.CHAIN_ID || "84532"];
  const voucher = JSON.parse(atob(process.argv[2]));
  const call = voucherToCall(voucher, cfg.usdc);
  if (!process.env.RELAYER_KEY) { console.log("DRY: would submit", call.to, call.data.slice(0,42)+"…  (set RELAYER_KEY to broadcast)"); return; }
  const account = privateKeyToAccount(process.env.RELAYER_KEY);
  const pub = createPublicClient({ chain: cfg.chain, transport: http(cfg.rpc) });
  const wallet = createWalletClient({ account, chain: cfg.chain, transport: http(cfg.rpc) });
  const tx = await wallet.sendTransaction({ to: call.to, data: call.data });
  console.log("submitted:", tx);
  const rcpt = await pub.waitForTransactionReceipt({ hash: tx });
  console.log("settled in block", rcpt.blockNumber, "status", rcpt.status, "-> payer->seller USDC moved on-chain");
}
if (import.meta.url === `file://${process.argv[1]}`) main().catch(e => { console.error("relay error:", e.message); process.exit(1); });
