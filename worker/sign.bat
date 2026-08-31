@echo off
REM Serves the attestation signing page on localhost so MetaMask can inject.
REM Sign with the OPERATOR wallet 0x417d...0d58. Ctrl+C here when done.
cd /d "%~dp0"
start "" http://localhost:8402/sign-attestation.html
node -e "require('http').createServer((q,s)=>{require('fs').readFile('sign-attestation.html',(e,d)=>{if(e){s.statusCode=404;s.end('missing')}else{s.setHeader('content-type','text/html');s.end(d)}})}).listen(8402,()=>console.log('Serving http://localhost:8402 - Ctrl+C to stop'))"
