import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { privateKeyToAccount } from "viem/accounts";   // simulate the wallet (MetaMask personal_sign = EIP-191)
const te=new TextEncoder();
const hb=(h)=>{h=h.replace(/^0x/,"");const o=new Uint8Array(h.length/2);for(let i=0;i<o.length;i++)o[i]=parseInt(h.substr(i*2,2),16);return o;};
const bh=(b)=>[...b].map(x=>x.toString(16).padStart(2,"0")).join("");
const addrFromPriv=(k)=>"0x"+bh(keccak_256(secp256k1.getPublicKey(k,false).slice(1)).slice(12));
const cat=(...a)=>{const n=a.reduce((s,x)=>s+x.length,0);const o=new Uint8Array(n);let k=0;for(const x of a){o.set(x,k);k+=x.length;}return o;};

// ---- receipt signing (dedicated key, raw keccak) ----
const canon=(r)=>[r.v,r.tool,r.tool_version,r.input_hash,r.output_hash,r.payer,r.recipient,r.amount,r.nonce,r.ts,r.tier].join("|");
function signReceipt(core,k){const d=keccak_256(te.encode(canon(core)));const s=secp256k1.sign(d,k);const v=(s.recovery+27).toString(16).padStart(2,"0");return {...core,signature:"0x"+bh(s.toCompactRawBytes())+v,signer:addrFromPriv(k)};}
function recoverRaw(digest,sigHex){const s=hb(sigHex);let v=s[64];if(v>=27)v-=27;const sig=new secp256k1.Signature(BigInt("0x"+bh(s.slice(0,32))),BigInt("0x"+bh(s.slice(32,64)))).addRecoveryBit(v);return "0x"+bh(keccak_256(sig.recoverPublicKey(digest).toRawBytes(false).slice(1)).slice(12));}

// ---- EIP-191 (personal_sign) recover — how the WALLET's attestation is verified ----
function eip191Digest(msg){const p=te.encode("\x19Ethereum Signed Message:\n"+msg.length);return keccak_256(cat(p,te.encode(msg)));}
function recover191(msg,sigHex){return recoverRaw(eip191Digest(msg),sigHex);}

// keys: dedicated receipt signer, and a wallet standing in for 0x417d
const RECEIPT_KEY=hb("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const receiptSigner=addrFromPriv(RECEIPT_KEY);
const wallet=privateKeyToAccount("0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba");
const WALLET=wallet.address;

// the one-time authorization the WALLET signs offline (EIP-191)
const attestation=`openfang-rail: I authorize receipt-signer ${receiptSigner.toLowerCase()} to issue XDR-1 receipts on my behalf. authorized_by=${WALLET.toLowerCase()}`;
const attSig=await wallet.signMessage({message:attestation});   // <- what Dr J does once in his wallet

// third-party verifier: receipt -> signer -> authorized-by-wallet
function verifyChain(rc, att, attSig, expectedWallet){
  const recSigner=recoverRaw(keccak_256(te.encode(canon(rc))), rc.signature);
  if(recSigner.toLowerCase()!==rc.signer.toLowerCase()) return "RECEIPT_SIG_BAD";
  // the attestation must name THIS receipt signer, and be signed by the expected wallet
  if(!att.toLowerCase().includes(rc.signer.toLowerCase())) return "SIGNER_NOT_IN_ATTESTATION";
  const attSigner=recover191(att, attSig);
  if(attSigner.toLowerCase()!==expectedWallet.toLowerCase()) return "ATTESTATION_NOT_BY_WALLET";
  return "AUTHORIZED_BY_"+expectedWallet;
}

const core={v:"XDR-1",tool:"iban-check",tool_version:"1.0.0",input_hash:"0x"+bh(keccak_256(te.encode("GB82WEST12345698765432"))),output_hash:"0x"+bh(keccak_256(te.encode('{"valid":true}'))),payer:"0x1111111111111111111111111111111111111111",recipient:WALLET,amount:"5000",nonce:"0x"+"9f".repeat(32),ts:1800000000,tier:"paid"};
const rc=signReceipt(core,RECEIPT_KEY);

let pass=0,fail=0;const chk=(n,g,w)=>{const ok=g===w;console.log(`${ok?"PASS":"FAIL"}  ${n}  (${g})`);ok?pass++:fail++;};
chk("full chain: receipt -> signer -> authorized by wallet", verifyChain(rc,attestation,attSig,WALLET), "AUTHORIZED_BY_"+WALLET);
// forged: attacker signs a receipt with a DIFFERENT key not in the attestation
const evil=hb("0x0000000000000000000000000000000000000000000000000000000000000abc");
const forged=signReceipt(core,evil);
chk("forged signer rejected (not authorized)", verifyChain(forged,attestation,attSig,WALLET), "SIGNER_NOT_IN_ATTESTATION");
// tampered attestation signature (someone else signed the authorization)
const other=privateKeyToAccount("0x1111111111111111111111111111111111111111111111111111111111111111");
const badAttSig=await other.signMessage({message:attestation});
chk("attestation not by the real wallet rejected", verifyChain(rc,attestation,badAttSig,WALLET), "ATTESTATION_NOT_BY_WALLET");
console.log(`\nreceipt_signer to publish: ${receiptSigner}`);
console.log(`wallet (authorized_by): ${WALLET}`);
console.log(`${pass} passed, ${fail} failed`);process.exit(fail?1:0);
