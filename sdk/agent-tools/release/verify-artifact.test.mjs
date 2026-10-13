import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';
import {gunzipSync} from 'node:zlib';import {fileURLToPath} from 'node:url';
import {PIN,verifyArtifact,parseTar,assertScope,guard,registryDecision,validateWorkflow} from './verify-artifact.mjs';
const dir=path.dirname(fileURLToPath(import.meta.url));
const bytes=fs.readFileSync(path.join(dir,'agent-tools-0.2.3-candidate.tgz'));
const baseline=JSON.parse(fs.readFileSync(path.join(dir,'published-0.2.2-files.json')));
const env={GITHUB_REPOSITORY:PIN.repo,GITHUB_REF:PIN.ref,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:'a'.repeat(40),REVIEWED_RELEASE_COMMIT:'a'.repeat(40)};
test('exact reviewed tarball verifies 19 files, only three changes and canonical receipt cases',()=>{assert.equal(verifyArtifact(bytes,baseline).files,19);});
test('one changed byte is rejected before decompression/execution',()=>{const changed=Buffer.from(bytes);changed[20]^=1;assert.throws(()=>verifyArtifact(changed,baseline),/FROZEN_ARTIFACT/);});
test('unrelated adapter change, missing or extra archive entry is rejected',()=>{const entries=parseTar(gunzipSync(bytes));entries.set('package/dist/adapters.js',Buffer.from('changed'));assert.throws(()=>assertScope(entries,baseline),/NON_MINIMAL/);entries.delete('package/LICENSE');assert.throws(()=>assertScope(entries,baseline),/ENTRY_COUNT/);});
test('path traversal, symlink, duplicate and corrupt tar headers fail closed',()=>{
  const raw=gunzipSync(bytes),checksum=h=>{h.fill(32,148,156);let n=0;for(const b of h)n+=b;h.write(n.toString(8).padStart(6,'0')+'\0 ',148,'ascii');};
  for(const [name,type] of [['package/../escape','0'],['package/link','2']]){const altered=Buffer.from(raw);altered.fill(0,0,100);altered.write(name,0,'ascii');altered[156]=type.charCodeAt(0);checksum(altered.subarray(0,512));assert.throws(()=>parseTar(altered),/TAR_PATH|TAR_NOT_REGULAR/);}
  const corrupt=Buffer.from(raw);corrupt[0]^=1;assert.throws(()=>parseTar(corrupt),/CHECKSUM/);
  const size=parseInt(raw.subarray(124,136).toString().replace(/\0/g,'').trim(),8),length=512+Math.ceil(size/512)*512;
  assert.throws(()=>parseTar(Buffer.concat([raw.subarray(0,length),raw])),/DUPLICATE/);
});
test('manual exact repo/ref/commit and first run only',()=>{assert.doesNotThrow(()=>guard(env));for(const key of ['GITHUB_REPOSITORY','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_SHA','GITHUB_RUN_ATTEMPT'])assert.throws(()=>guard({...env,[key]:'wrong'}),/REVIEWED_MANUAL/);});
test('registry preflight only permits absent version at prior latest',()=>{assert.equal(registryDecision('0.2.2',null).publish_needed,true);assert.throws(()=>registryDecision('0.2.4',null),/LATEST_CHANGED/);});
test('already published exact version skips publish; mismatch or other latest never retags',()=>{const version={name:PIN.name,version:PIN.version,dist:{integrity:PIN.integrity}};assert.equal(registryDecision('0.2.3',version).publish_needed,false);assert.throws(()=>registryDecision('0.2.3',{...version,dist:{integrity:'wrong'}}),/MISMATCH/);assert.throws(()=>registryDecision('0.2.4',version),/NO_RETAG/);});
test('post-publish unknown outcome forbids blind resubmission',()=>{assert.throws(()=>registryDecision('0.2.2',null,{after:true}),/NO_RESUBMIT/);});
test('workflow restricts trigger, token authority, exact actions and immutable package publication',()=>{
  const source=fs.readFileSync(path.join(dir,'../../../.github/workflows/publish-agent-tools.yml'),'utf8').replace(/\r\n/g,'\n');
  assert.equal(validateWorkflow(source),true);
  for(const changed of [source.replace('workflow_dispatch:','push:'),source.replace('permissions: {}','permissions: write-all'),source.replace('id-token: write','id-token: read'),source.replace('--ignore-scripts','--run-scripts'),source.replace('checkout@d23441a48e516b6c34aea4fa41551a30e30af803','checkout@v6')])assert.throws(()=>validateWorkflow(changed));
});
