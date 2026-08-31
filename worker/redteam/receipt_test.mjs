import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
const te=new TextEncoder();
const hb=(h)=>{h=h.replace(/^0x/,"");const o=new Uint8Array(h.length/2);for(let i=0;i<o.length;i++)o[i]=parseInt(h.substr(i*2,2),16);return o;};
const bh=(b)=>[...b].map(x=>x.toString(16).padStart(2,"0")).join("");
const addrFromPriv=(k)=>{const pub=secp256k1.getPublicKey(k,false).slice(1);return "0x"+bh(keccak_256(pub).slice(12));};

// Canonical receipt string — FIXED field order (no JSON key-order ambiguity).
function canon(r){return [r.v,r.tool,r.tool_version,r.input_hash,r.output_hash,r.payer,r.recipient,r.amount,r.nonce,r.ts,r.tier].join("|");}
function signReceipt(core, privHex){
  const digest=keccak_256(te.encode(canon(core)));
  const sig=secp256k1.sign(digest, hb(privHex));
  const v=sig.recovery+27;
  return { ...core, signature:"0x"+bh(sig.toCompactRawBytes())+v.toString(16).padStart(2,"0"), signer: addrFromPriv(hb(privHex)) };
}
// Third-party verifier: recover signer from receipt, must equal claimed signer.
function verifyReceipt(rc){
  const digest=keccak_256(te.encode(canon(rc)));
  const s=hb(rc.signature); let v=s[64]; if(v>=27)v-=27;
  const sig=new secp256k1.Signature(BigInt("0x"+bh(s.slice(0,32))),BigInt("0x"+bh(s.slice(32,64)))).addRecoveryBit(v);
  const pub=sig.recoverPublicKey(digest).toRawBytes(false).slice(1);
  const rec="0x"+bh(keccak_256(pub).slice(12));
  return rec.toLowerCase()===rc.signer.toLowerCase();
}

const KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const core={ v:"XDR-1", tool:"iban-check", tool_version:"1.0.0",
  input_hash:"0x"+bh(keccak_256(te.encode("GB82WEST12345698765432"))),
  output_hash:"0x"+bh(keccak_256(te.encode('{"valid":true}'))),
  payer:"0x1111111111111111111111111111111111111111",
  recipient:"0xc59c85e661d34084a7769f955d17fd38254a6235",
  amount:"5000", nonce:"0x"+"9f".repeat(32), ts:1800000000, tier:"paid" };

let pass=0,fail=0;const chk=(n,c)=>{console.log(`${c?"PASS":"FAIL"}  ${n}`);c?pass++:fail++;};
const rc=signReceipt(core,KEY);
chk("receipt verifies (recovered signer == claimed)", verifyReceipt(rc));
chk("signer address is deterministic from key", rc.signer===addrFromPriv(hb(KEY)));
// tamper: change the result the seller claims -> verification fails
chk("tampered output rejected", !verifyReceipt({...rc, output_hash:"0x"+bh(keccak_256(te.encode('{"valid":false}')))}));
// tamper: change amount -> fails
chk("tampered amount rejected", !verifyReceipt({...rc, amount:"1"}));
console.log(`\nsigner (publish this as receipt_signing_address): ${rc.signer}`);
console.log(`${pass} passed, ${fail} failed`); process.exit(fail?1:0);
