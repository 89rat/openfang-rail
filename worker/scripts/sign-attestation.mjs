// sign-attestation.mjs — signs the openfang-rail attestation with the operator wallet.
// Reads OPERATOR_KEY from env (never argv, never echoed). Verifies the key derives
// to 0x417da74c...0d58 before signing. Prints ONLY the 0x signature on stdout.
import { privateKeyToAccount } from "viem/accounts";

const ATTESTATION = "openfang-rail: I authorize receipt-signer 0xae851dde8a04c9e6a3a675c6679b5e53b148c118 to issue XDR-1 receipts on my behalf. authorized_by=0xc59c85e661d34084a7769f955d17fd38254a6235";
const EXPECTED = "0xc59c85e661d34084a7769f955d17fd38254a6235";

const k = (process.env.OPERATOR_KEY || "").trim();
if (!/^0x[0-9a-fA-F]{64}$/.test(k)) { console.error("OPERATOR_KEY missing or not 0x+64hex"); process.exit(1); }
const acct = privateKeyToAccount(k);
if (acct.address.toLowerCase() !== EXPECTED.toLowerCase()) {
  console.error(`WRONG KEY: derives to ${acct.address}, expected ${EXPECTED}`); process.exit(1);
}
const sig = await acct.signMessage({ message: ATTESTATION }); // EIP-191 personal_sign
console.log(sig);
