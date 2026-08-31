@echo off
REM Redeploy the worker. KV, receipt-key secret, account, and login are already
REM configured from the first deploy, so this just pushes the updated config +
REM src/index.ts. THIS DEPLOY GOES LIVE ON BASE MAINNET with on-chain settlement
REM via the PayAI facilitator (permissionless, no whitelist, gas-sponsored, non-custodial).
REM Paid calls now move REAL USDC. Rule 0: you run it.
setlocal
cd /d "%~dp0"
echo Updating dependencies...
call npm install
echo(
echo Deploying updated worker (Base MAINNET + on-chain settlement)...
call npx wrangler deploy
echo(
echo Done. Live on Base mainnet: the free tier serves, and paid calls settle
echo REAL USDC via https://facilitator.payai.network (gas-sponsored, non-custodial).
echo Paste the URL to the assistant to re-verify live and prove the first sale.
pause
endlocal
