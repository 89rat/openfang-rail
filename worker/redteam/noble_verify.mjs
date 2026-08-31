import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { privateKeyToAccount } from "viem/accounts"; // only to PRODUCE a viem-signed voucher for cross-check

const enc = new TextEncoder();
const hexToBytes = (h) => { h=h.replace(/^0x/,""); const o=new Uint8Array(h.length/2); for(let i=0;i<o.length;i++)o[i]=parseInt(h.substr(i*2,2),16); return o; };
const bytesToHex = (b) => [...b].map(x=>x.toString(16).padStart(2,"0")).join("");
const concat = (...a)=>{const n=a.reduce((s,x)=>s+x.length,0);const o=new Uint8Array(n);let k=0;for(const x of a){o.set(x,k);k+=x.length;}return o;};
const word_addr = (h)=>{const b=hexToBytes(h);const w=new Uint8Array(32);w.set(b,12);return w;};
const word_u = (v)=>{let x=BigInt(v);const w=new Uint8Array(32);for(let i=31;i>=0;i--){w[i]=Number(x&0xffn);x>>=8n;}return w;};

const DOMAIN_TYPEHASH = keccak_256(enc.encode("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
const TA_TYPEHASH = keccak_256(enc.encode("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"));

function domainSeparator(name, version, chainId, verifyingContract) {
  return keccak_256(concat(DOMAIN_TYPEHASH, keccak_256(enc.encode(name)), keccak_256(enc.encode(version)), word_u(chainId), word_addr(verifyingContract)));
}
function digest(dom, m) {
  const structHash = keccak_256(concat(TA_TYPEHASH, word_addr(m.from), word_addr(m.to), word_u(m.value), word_u(m.validAfter), word_u(m.validBefore), hexToBytes(m.nonce)));
  return keccak_256(concat(new Uint8Array([0x19,0x01]), dom, structHash));
}
function recoverAddr(dig, sigHex) {
  const s = hexToBytes(sigHex); // 65 bytes r||s||v
  const r = s.slice(0,32), ss = s.slice(32,64); let v = s[64]; if (v>=27) v-=27;
  const sig = new secp256k1.Signature(BigInt("0x"+bytesToHex(r)), BigInt("0x"+bytesToHex(ss))).addRecoveryBit(v);
  const pub = sig.recoverPublicKey(dig).toRawBytes(false).slice(1); // drop 0x04
  return "0x"+bytesToHex(keccak_256(pub).slice(12));
}

const CHAIN_ID=84532, USDC="0x036CbD53842c5426634e7929541eC2318f3dCF7e", NAME="USDC";
const dom = domainSeparator(NAME,"2",CHAIN_ID,USDC);
const SELLER="0x2222222222222222222222222222222222222222";
const used=new Set();
function nobleVerify(v, expect, now) {
  const addr = recoverAddr(digest(dom, v), v.signature).toLowerCase();
  if (addr !== v.from.toLowerCase()) return "BAD_SIGNATURE";
  if (BigInt(v.value)!==BigInt(expect.amount)) return "PRICE_MISMATCH";
  if (v.to.toLowerCase()!==expect.recipient.toLowerCase()) return "RECIPIENT_MISMATCH";
  if (!(BigInt(now)>=BigInt(v.validAfter)&&BigInt(now)<BigInt(v.validBefore))) return "EXPIRED";
  if (used.has(v.nonce)) return "REPLAY"; used.add(v.nonce); return "ACCEPT";
}

// produce vouchers with viem (real EIP-712 signatures) and verify with NOBLE (cross-impl check)
const payer = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const TYPES={TransferWithAuthorization:[{name:"from",type:"address"},{name:"to",type:"address"},{name:"value",type:"uint256"},{name:"validAfter",type:"uint256"},{name:"validBefore",type:"uint256"},{name:"nonce",type:"bytes32"}]};
const D={name:NAME,version:"2",chainId:CHAIN_ID,verifyingContract:USDC};
async function voucher(o={}){const m={from:payer.address,to:SELLER,value:5000n,validAfter:0n,validBefore:2_000_000_000n,nonce:"0x"+"9f".repeat(32),...o};return{...m,signature:await payer.signTypedData({domain:D,types:TYPES,primaryType:"TransferWithAuthorization",message:m})};}
const now=1_800_000_000n, EXP={amount:5000n,recipient:SELLER};
let pass=0,fail=0;const chk=(n,g,w)=>{const ok=g===w;console.log(`${ok?"PASS":"FAIL"}  ${n} (${g})`);ok?pass++:fail++;};

chk("noble verifies a viem-signed voucher", nobleVerify(await voucher(),EXP,now), "ACCEPT");
chk("replay rejected", nobleVerify(await voucher(),EXP,now), "REPLAY");
chk("underpay rejected", nobleVerify(await voucher({value:1n,nonce:"0x"+"11".repeat(32)}),EXP,now), "PRICE_MISMATCH");
chk("wrong recipient rejected", nobleVerify(await voucher({to:"0x3333333333333333333333333333333333333333",nonce:"0x"+"22".repeat(32)}),EXP,now), "RECIPIENT_MISMATCH");
chk("expired rejected", nobleVerify(await voucher({validBefore:100n,nonce:"0x"+"33".repeat(32)}),EXP,now), "EXPIRED");
const good=await voucher({nonce:"0x"+"44".repeat(32)}); chk("post-sign tamper rejected", nobleVerify({...good,value:1n},{amount:1n,recipient:SELLER},now), "BAD_SIGNATURE");
console.log(`\n${pass} passed, ${fail} failed  (noble impl matches viem, Workers-native, no node built-ins)`);
process.exit(fail?1:0);
