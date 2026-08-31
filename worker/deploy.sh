#!/usr/bin/env bash
# openfang-rail — guided deploy. Rule 0: YOU run this; it uses YOUR Cloudflare
# login and YOUR keys. The assistant never sees them.
set -e
cd "$(dirname "$0")"
echo "== 1/5 install =="; npm install
echo "== 2/5 Cloudflare login (opens browser) =="; npx wrangler login
echo "== 3/5 create KV namespace NONCES =="; npx wrangler kv namespace create NONCES
echo ">> paste the id above into wrangler.jsonc (replace <REPLACE_WITH_KV_ID>), then press Enter"; read _
echo "== 4/5 receipt signing (see RECEIPTS.md) =="
echo ">> generate a DEDICATED receipt key:  openssl rand -hex 32"
echo ">> then:  npx wrangler secret put RECEIPT_SIGNING_KEY"
echo ">> and set AUTHORIZED_BY / ATTESTATION / ATTESTATION_SIG vars in wrangler.jsonc (RECEIPTS.md step 3-5)"
echo ">> press Enter when done"; read _
echo "== 5/5 deploy =="; npx wrangler deploy
echo "DONE. Smoke test:"
echo '  curl -s -X POST https://openfang-rail.<you>.workers.dev/v1/tools/iban-check/call -H "content-type: application/json" -d '"'"'{"input":{"iban":"GB82 WEST 1234 5698 7654 32"}}'"'"''
