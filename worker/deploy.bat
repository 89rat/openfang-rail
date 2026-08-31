@echo off
REM ============================================================================
REM  openfang-rail - near-one-shot deploy for Windows.
REM  Rule 0: YOU run this. It uses YOUR Cloudflare login. The assistant never
REM  sees your keys. The ONLY interactive step is the Cloudflare browser login;
REM  everything else (KV, secret, deploy) is automatic.
REM  Prereq: Node.js (npm/npx) installed.
REM ============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"
echo(
echo ===============================================
echo   openfang-rail deploy  (verified worker)
echo ===============================================
echo(

echo [1/5] Installing dependencies...
call npm install
if errorlevel 1 goto :err

echo(
echo [2/5] Cloudflare login  (a browser window opens - click Allow)...
call npx wrangler whoami >nul 2>&1 || call npx wrangler login
if errorlevel 1 goto :err

echo(
echo [3/5] Creating KV namespace + wiring it into config (automatic)...
call node scripts\provision-kv.mjs
if errorlevel 1 goto :err

echo(
echo [4/5] Receipt key: generate (dedicated, non-fund) and store as a secret...
for /f "delims=" %%K in ('node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"') do set "RKEY=%%K"
echo   receipt-signer address (publish as receipt_signing_address):
call node redteam\derive-address.mjs !RKEY!
REM  write the key with NO trailing newline, pipe it into wrangler (no paste)
> "%TEMP%\ofr_rkey.txt" <nul set /p=!RKEY!
call npx wrangler secret put RECEIPT_SIGNING_KEY < "%TEMP%\ofr_rkey.txt"
del "%TEMP%\ofr_rkey.txt" 2>nul
if errorlevel 1 goto :err
echo   ^(wallet-binding attestation is optional; add later via RECEIPTS.md^)

echo(
echo [5/5] Deploying to Cloudflare...
call npx wrangler deploy
if errorlevel 1 goto :err

echo(
echo ================= DONE =================
echo Your worker URL is shown just above (the https://openfang-rail... line).
echo Smoke test it (replace YOURURL):
echo   curl -X POST YOURURL/v1/tools/iban-check/call -H "content-type: application/json" -d "{\"input\":{\"iban\":\"GB82 WEST 1234 5698 7654 32\"}}"
echo(
echo Paste the URL to the assistant to verify it live. Then list it (GTM-LISTINGS.md).
goto :done

:err
echo(
echo *** A step failed - see the error above. Copy the last lines to the assistant. ***

:done
echo(
pause
endlocal
