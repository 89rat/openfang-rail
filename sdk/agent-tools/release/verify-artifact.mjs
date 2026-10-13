// Builtin-only verifier. No extraction, package hooks, signing, credentials or publish calls.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
export const PIN = Object.freeze({ name:'@code-402/agent-tools',version:'0.2.3',prior:'0.2.2',repo:'89rat/openfang-rail',
  repositoryUrl:'git+https://github.com/89rat/openfang-rail.git',ref:'refs/heads/sdk/agent-tools-source',
  sha256:'bb5569507a17bf0643adf1648d6a6d1328114abd67fb79f746cd5c89126c6174',
  integrity:'sha512-A+zUYQkAddOzUP9DGmjth7VONR/Hw5aVUqcedCt/6uOtyBKJvgrCbXI1OzXi1XWeiF+YuAm/96nPhiVci0sZiA==' });
const dir=path.dirname(fileURLToPath(import.meta.url));
const digest=(algorithm,bytes,encoding='hex')=>createHash(algorithm).update(bytes).digest(encoding);
const cstring=bytes=>new TextDecoder('utf-8',{fatal:true}).decode(bytes).split('\0')[0];
const octal=bytes=>{const text=cstring(bytes).trim();if(!/^[0-7]+$/.test(text))throw Error('TAR_NUMBER_INVALID');const value=parseInt(text,8);if(!Number.isSafeInteger(value))throw Error('TAR_NUMBER_UNSAFE');return value;};
export function parseTar(raw){
  const entries=new Map();let offset=0;
  while(offset+512<=raw.length){const h=raw.subarray(offset,offset+512);
    if(h.every(b=>b===0)){if(!raw.subarray(offset).every(b=>b===0))throw Error('TAR_TRAILING_DATA');return entries;}
    let sum=0;for(let i=0;i<512;i++)sum+=(i>=148&&i<156)?32:h[i];if(sum!==octal(h.subarray(148,156)))throw Error('TAR_CHECKSUM');
    const prefix=cstring(h.subarray(345,500)),name=(prefix?prefix+'/':'')+cstring(h.subarray(0,100));
    if(!/^package\/[A-Za-z0-9_.\/-]+$/.test(name)||name.split('/').some(p=>!p||p==='.'||p==='..')||name.includes('\\'))throw Error('TAR_PATH');
    if(h[156]!==0&&h[156]!==48)throw Error('TAR_NOT_REGULAR');
    if(entries.has(name))throw Error('TAR_DUPLICATE');
    const size=octal(h.subarray(124,136));if(size>1048576||offset+512+size>raw.length)throw Error('TAR_SIZE');
    entries.set(name,raw.subarray(offset+512,offset+512+size));offset+=512+Math.ceil(size/512)*512;
  }
  throw Error('TAR_UNTERMINATED');
}
export function assertScope(entries,baseline){
  if(entries.size!==19||baseline.length!==19||new Set(baseline.map(r=>r.path)).size!==19)throw Error('ENTRY_COUNT');
  const changed=[];for(const b of baseline){const bytes=entries.get(b.path);if(!bytes)throw Error('ENTRY_SET');if(digest('sha256',bytes)!==b.sha256)changed.push(b.path);}
  if(changed.sort().join('|')!==['package/dist/receipt.js','package/dist/types.d.ts','package/package.json'].join('|'))throw Error('NON_MINIMAL_FILE_CHANGE');
  const pkg=JSON.parse(entries.get('package/package.json').toString('utf8'));
  if(pkg.name!==PIN.name||pkg.version!==PIN.version||pkg.repository?.url!==PIN.repositoryUrl||pkg.repository?.type!=='git')throw Error('PACKAGE_IDENTITY');
  const source=entries.get('package/dist/receipt.js').toString('utf8');
  const start=source.indexOf('export function canonical('),end=source.indexOf('export const hashJson');
  if(start<0||end<=start)throw Error('CANONICAL_FUNCTION_MISSING');
  const canonical=vm.runInNewContext('('+source.slice(start,end).replace('export ','').trim()+')',{}, {timeout:100});
  const receipt={v:'XDR-1',tool:'iban-check',tool_version:'1',input_hash:'i',output_hash:'o',payer:'p',recipient:'r',amount:'5000',nonce:'n',ts:1,tier:'paid'};
  const core='XDR-1|iban-check|1|i|o|p|r|5000|n|1|paid';
  for(const [extra,expected] of [[{},core],[{stream_state:'active'},core+'||active'],[{successor:'next'},core+'|next|active'],[{successor:'next',stream_state:'closed'},core+'|next|closed'],[{successor:'',stream_state:''},core]]){
    if(canonical({...receipt,...extra})!==expected)throw Error('CANONICAL_RECEIPT_REGRESSION');
  }
  if(!/successor\?: string/.test(entries.get('package/dist/types.d.ts').toString())||!/stream_state\?: string/.test(entries.get('package/dist/types.d.ts').toString()))throw Error('RECEIPT_TYPES_MISSING');
  return {name:pkg.name,version:pkg.version,files:entries.size,changed,repository_url:pkg.repository.url};
}
export function verifyArtifact(bytes,baseline){
  if(digest('sha256',bytes)!==PIN.sha256||'sha512-'+digest('sha512',bytes,'base64')!==PIN.integrity)throw Error('FROZEN_ARTIFACT_CHANGED');
  return {...assertScope(parseTar(gunzipSync(bytes,{maxOutputLength:2097152})),baseline),sha256:PIN.sha256,integrity:PIN.integrity};
}
export function guard(env){
  if(env.GITHUB_REPOSITORY!==PIN.repo||env.GITHUB_REF!==PIN.ref||env.GITHUB_EVENT_NAME!=='workflow_dispatch'||env.GITHUB_RUN_ATTEMPT!=='1'
    ||!/^[a-f0-9]{40}$/.test(env.REVIEWED_RELEASE_COMMIT||'')||env.GITHUB_SHA!==env.REVIEWED_RELEASE_COMMIT)throw Error('REVIEWED_MANUAL_RELEASE_ONLY');
  const [major,minor]=process.versions.node.split('.').map(Number);if(major<22||(major===22&&minor<14))throw Error('NODE_VERSION_UNSUPPORTED');
}
export function validateWorkflow(source){
  if(!/^on:\n  workflow_dispatch:/m.test(source)||/^\s*(?:push|pull_request|schedule|workflow_call):/m.test(source)
    ||!/^permissions: \{\}/m.test(source)||(source.match(/id-token: write/g)||[]).length!==1
    ||/secrets\.|NODE_AUTH_TOKEN|NPM_TOKEN|npm ci|npm run build|npm pack|--provenance\b/.test(source)
    ||!source.includes('persist-credentials: false')||!source.includes('package-manager-cache: false')
    ||!source.includes('npm install --global npm@11.19.1 --ignore-scripts')
    ||!source.includes('github.run_attempt == 1')||!source.includes("github.ref == '"+PIN.ref+"'")
    ||!source.includes('--ignore-scripts --registry https://registry.npmjs.org'))throw Error('WORKFLOW_AUTHORITY_CHANGED');
  const uses=[...source.matchAll(/uses: ([^\s]+)/g)].map(m=>m[1]);
  if(uses.length!==4||uses.some(u=>u!=='actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803'&&u!=='actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38'))throw Error('ACTION_PIN_CHANGED');
  return true;
}
export function registryDecision(latest,version,{after=false}={}){
  if(version){if(version.name!==PIN.name||version.version!==PIN.version||version.dist?.integrity!==PIN.integrity)throw Error('PUBLIC_VERSION_MISMATCH');
    if(latest!==PIN.version)throw Error('VERSION_PRESENT_TAG_DIFFERS_NO_RETAG');return {publish_needed:false,public_verified:true};}
  if(after)throw Error('PUBLISH_OUTCOME_UNCONFIRMED_NO_RESUBMIT');
  if(latest!==PIN.prior)throw Error('LATEST_CHANGED_REQUALIFY');return {publish_needed:true,public_verified:false};
}
async function publicJson(url,allow404=false){
  const r=await fetch(url,{redirect:'error',headers:{accept:'application/json','cache-control':'no-cache'},signal:AbortSignal.timeout(15000)});
  if(r.status===404&&allow404)return null;if(!r.ok)throw Error('REGISTRY_READ_UNAVAILABLE');
  const text=await r.text();if(text.length>1048576)throw Error('REGISTRY_BODY_TOO_LARGE');return JSON.parse(text);
}
async function registryRead(after){
  const root='https://registry.npmjs.org/@code-402%2Fagent-tools';
  const [metadata,version]=await Promise.all([publicJson(root),publicJson(root+'/0.2.3',true)]);
  if(metadata.name!==PIN.name)throw Error('REGISTRY_PACKAGE_CHANGED');
  return registryDecision(metadata['dist-tags']?.latest,version,{after});
}
async function main(){
  const mode=process.argv[2]||'verify';
  if(mode==='guard'){guard(process.env);console.log('Reviewed manual source commit and runner context verified.');return;}
  if(mode==='verify'){const baseline=JSON.parse(fs.readFileSync(path.join(dir,'published-0.2.2-files.json')));
    console.log(JSON.stringify(verifyArtifact(fs.readFileSync(path.join(dir,'agent-tools-0.2.3-candidate.tgz')),baseline)));return;}
  if(mode!=='registry-before'&&mode!=='registry-after')throw Error('UNKNOWN_VERIFY_MODE');
  const result=await registryRead(mode==='registry-after');
  if(process.env.GITHUB_OUTPUT)fs.appendFileSync(process.env.GITHUB_OUTPUT,'publish_needed='+result.publish_needed+'\n');
  console.log(JSON.stringify(result));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{console.error('Release verification failed; do not publish or resubmit until the exact artifact, context and registry outcome are reconciled.');process.exitCode=1;});
