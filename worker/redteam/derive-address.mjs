// Derive the Ethereum address (receipt-signer) from a 32-byte hex private key.
// Usage: node derive-address.mjs <hexkey>
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
const k = (process.argv[2]||"").replace(/^0x/,"");
if (k.length !== 64) { console.error("need a 32-byte hex key"); process.exit(1); }
const key = Uint8Array.from(k.match(/../g).map(b=>parseInt(b,16)));
const pub = secp256k1.getPublicKey(key, false).slice(1);
const addr = "0x" + [...keccak_256(pub).slice(12)].map(x=>x.toString(16).padStart(2,"0")).join("");
console.log(addr);
