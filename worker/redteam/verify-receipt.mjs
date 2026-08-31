// Usage: node verify-receipt.mjs '<the full JSON response from a paid/free call>'
// Verifies: receipt -> receipt-signer -> authorized by the operator wallet. No trust required.
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
const te=new TextEncoder();
const hb=(h)=>{h=h.replace(/^0x/,"");const o=new Uint8Array(h.length/2);for(let i=0;i<o.length;i++)o[i]=parseInt(h.substr(i*2,2),16);return o;};
const bh=(b)=>[...b].map(x=>x.toString(16).padStart(2,"0")).join("");
const cat=(...a)=>{const n=a.reduce((s,x)=>s+x.length,0);const o=new Uint8Array(n);let k=0;for(const x of a){o.set(x,k);k+=x.length;}return o;};
const canon=(r)=>[r.v,r.tool,r.tool_version,r.input_hash,r.output_hash,r.payer,r.recipient,r.amount,r.nonce,r.ts,r.tier].join("|");
function recoverRaw(dig,sigHex){const s=hb(sigHex);let v=s[64];if(v>=27)v-=27;const sig=new secp256k1.Signature(BigInt("0x"+bh(s.slice(0,32))),BigInt("0x"+bh(s.slice(32,64)))).addRecoveryBit(v);return "0x"+bh(keccak_256(sig.recoverPublicKey(dig).toRawBytes(false).slice(1)).slice(12));}
const eip191=(m)=>keccak_256(cat(te.encode("\x19Ethereum Signed Message:\n"+m.length),te.encode(m)));

const resp=JSON.parse(process.argv[2]);
const rc=resp.receipt, auth=resp.authorization;
const recSigner=recoverRaw(keccak_256(te.encode(canon(rc))), rc.signature);
const attSigner=recoverRaw(eip191(auth.attestation), auth.attestation_sig);
const checks={
  receipt_signature_valid: recSigner.toLowerCase()===rc.signer.toLowerCase(),
  signer_named_in_attestation: auth.attestation.toLowerCase().includes(rc.signer.toLowerCase()),
  attestation_by_operator: attSigner.toLowerCase()===auth.authorized_by.toLowerCase(),
};
const ok=Object.values(checks).every(Boolean);
console.log(JSON.stringify({ verified: ok, receipt_signer: recSigner, authorized_by: auth.authorized_by, checks }, null, 2));
process.exit(ok?0:1);
