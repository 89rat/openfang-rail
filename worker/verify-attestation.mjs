// Verify the operator wallet's EIP-191 attestation signature BEFORE deploy.
// Usage: node verify-attestation.mjs <0x-signature>
// Exit 0 = valid (signed by 0x417da74c...0d58 over the exact ATTESTATION string).
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

const ATTESTATION = "openfang-rail: I authorize receipt-signer 0xae851dde8a04c9e6a3a675c6679b5e53b148c118 to issue XDR-1 receipts on my behalf. authorized_by=0xc59c85e661d34084a7769f955d17fd38254a6235";
const EXPECTED = "0xc59c85e661d34084a7769f955d17fd38254a6235";
const RECEIPT_SIGNER = "0xae851dde8a04c9e6a3a675c6679b5e53b148c118";

const te = new TextEncoder();
const hb = (h) => { h = h.replace(/^0x/, ""); const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; };
const bh = (b) => [...b].map(x => x.toString(16).padStart(2, "0")).join("");
const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };

function recoverRaw(digest, sigHex) {
  const s = hb(sigHex); let v = s[64]; if (v >= 27) v -= 27;
  const sig = new secp256k1.Signature(BigInt("0x" + bh(s.slice(0, 32))), BigInt("0x" + bh(s.slice(32, 64)))).addRecoveryBit(v);
  return "0x" + bh(keccak_256(sig.recoverPublicKey(digest).toRawBytes(false).slice(1)).slice(12));
}
function eip191Digest(msg) { const p = te.encode("\x19Ethereum Signed Message:\n" + msg.length); return keccak_256(cat(p, te.encode(msg))); }

const sig = process.argv[2] || "";
if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) { console.error("need a 65-byte 0x signature"); process.exit(1); }
if (!ATTESTATION.toLowerCase().includes(RECEIPT_SIGNER)) { console.error("FAIL: attestation does not name the receipt signer"); process.exit(1); }
const recovered = recoverRaw(eip191Digest(ATTESTATION), sig);
console.log("recovered signer:", recovered);
if (recovered.toLowerCase() !== EXPECTED.toLowerCase()) { console.error("FAIL: not signed by", EXPECTED); process.exit(1); }
console.log("PASS: attestation is validly signed by the operator wallet");
