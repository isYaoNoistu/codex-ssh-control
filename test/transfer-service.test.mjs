import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { once } from 'node:events';
import { spawn, spawnSync } from 'node:child_process';
import { PassThrough } from 'node:stream';
import { createHash } from 'node:crypto';
import { TransferService } from '../src/transfer-service.mjs';
const services=new WeakMap();
test('unsupported platform blocks upload, download, manifests, start and resume before remote access',()=>{
 const source=`import os from 'node:os';import path from 'node:path';import fs from 'node:fs';const dir=fs.mkdtempSync(path.join(os.tmpdir(),'unsupported-transfer-'));Object.defineProperty(process,'platform',{value:'darwin'});const {TransferService}=await import(${JSON.stringify(new URL('../src/transfer-service.mjs',import.meta.url).href)});const service=new TransferService({dataDir:dir,spawnRemote:()=>{throw Error('remote access');},authorize:()=>true});try{for(const direction of ['upload','download'])for(const method of ['prepare','planManifest']){try{await service[method]({threadId:'a',host:{id:'h'},direction,localPath:path.join(dir,'a'),localRoot:dir,remotePath:'/tmp/a',remoteRoot:'/tmp',overwrite:'never',expiresAt:Date.now()+60000});throw Error('accepted');}catch(e){if(!/local binary transfer unsupported on this platform/.test(e.message))throw e;}}for(const method of ['start','resume']){try{await service[method]({threadId:'a',planId:'a'.repeat(32),transferId:'a'.repeat(32)});throw Error('accepted');}catch(e){if(!/local binary transfer unsupported on this platform/.test(e.message))throw e;}}}finally{service.close();fs.rmSync(dir,{recursive:true,force:true});}`;
 const result=spawnSync(process.execPath,['--input-type=module','-e',source],{encoding:'utf8',windowsHide:true});assert.equal(result.status,0,result.stderr);
});
const binaryTest=(name,fn)=>test(name,{skip:process.platform==='darwin'?'local binary transfer unsupported on this platform':false},fn);
function tracked(t,options){const service=new TransferService(options);if(!services.has(t))services.set(t,[]);services.get(t).push(service);return service;}
async function fixture(t,authorize=async()=>true){const root=await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()),'transfer-service-'));t.after(async()=>{for(const s of services.get(t)??[])s.close();await fs.rm(root,{recursive:true,force:true});});await fs.writeFile(path.join(root,'input'),'abc');return {root,service:tracked(t,{dataDir:path.join(root,'state'),spawnRemote:()=>{throw new Error('offline');},authorize}),request:{threadId:'chat',host:{id:'fixture'},direction:'upload',localPath:path.join(root,'input'),localRoot:root,remotePath:'/tmp/out',remoteRoot:'/tmp',blockedPaths:[],overwrite:'never',expiresAt:Date.now()+60000}};}
test('prepare freezes source digest; rejected inspect never spawns',async t=>{
 const {service,request}=await fixture(t,async()=>false); await assert.rejects(service.prepare(request),/authoriz/);
});
test('transfer identifiers are owned by their chat and input cannot inject records',async t=>{
 const {service}=await fixture(t); await assert.rejects(service.read({threadId:'other',transferId:'../../x'}),/identifier/);
 await assert.rejects(service.start({threadId:'x',planId:'a'.repeat(32)}),/not found/);
});
test('expired requests fail before remote metadata access',async t=>{
 const {service,request}=await fixture(t);request.expiresAt=Date.now()-1; await assert.rejects(service.prepare(request),/expired/);
});
function fakeRemote(){
 const state={data:Buffer.alloc(0),source:Buffer.from([0,255,3]),committed:false,operations:[]};
 const hash=b=>createHash('sha256').update(b).digest('hex');
 state.spawn=(host,command)=>{
  const encoded=[...command.matchAll(/\"([A-Za-z0-9+/=]+)\"/g)].at(-1)[1];const req=JSON.parse(Buffer.from(encoded,'base64'));state.operations.push(req.operation);
  const child=new EventEmitter();child.stdin=new PassThrough();child.stdout=new PassThrough();child.stderr=new PassThrough();child.kill=()=>{child.stdin.destroy();child.stdout.destroy();child.emit('close',1);};
  setImmediate(async()=>{try{let result;
   if(req.operation==='target')result={snapshot:null};
   else if(req.operation==='inspect')result={snapshot:{dev:'1',ino:'2',size:state.source.length,mtimeNs:'1000000000',ctimeNs:'1000000000',mode:0o600,sha256:hash(state.source)}};
   else if(req.operation==='read'){assert.equal(hash(state.source.subarray(0,req.offset)),req.prefixSha256);child.stdout.end(state.source.subarray(req.offset));child.stderr.end();setImmediate(()=>child.emit('close',0));return;}
   else if(req.operation==='stage')result={offset:state.data.length,prefixSha256:hash(state.data)};
   else if(req.operation==='write'){for await(const chunk of child.stdin)state.data=Buffer.concat([state.data,chunk]);result={offset:state.data.length,prefixSha256:hash(state.data)};}
   else if(req.operation==='commit'){assert.equal(hash(state.data),req.sha256);state.committed=true;result={committed:true};}
   else throw new Error('unexpected '+req.operation);
   child.stdout.end(JSON.stringify({ok:true,result}));child.stderr.end();setImmediate(()=>child.emit('close',0));
  }catch(error){child.stdout.end(JSON.stringify({ok:false,error:error.message}));setImmediate(()=>child.emit('close',1));}});return child;
 };return state;
}
binaryTest('approved immutable source streams and commits; token never leaves internal record',async t=>{
 const stages=[];const {root,request}=await fixture(t);const remote=fakeRemote();const service=tracked(t,{dataDir:path.join(root,'real-state'),spawnRemote:remote.spawn,authorize:async(stage,record)=>{assert.equal(record.remoteToken,undefined);stages.push(stage);return true;}});
 const plan=await service.prepare(request);assert.equal(plan.sha256,createHash('sha256').update('abc').digest('hex'));assert.equal(plan.remoteToken,undefined);
 await assert.rejects(service.start({threadId:'other',planId:plan.planId}),/not found/);
 await service.start({threadId:'chat',planId:plan.planId});const result=await service.wait({threadId:'chat',transferId:plan.planId});assert.equal(result.status,'completed');assert.equal(remote.data.toString(),'abc');assert.deepEqual(stages,['inspect','start','commit']);
});
binaryTest('source changes after approval prevent start and commit revocation retains resumable partial',async t=>{
 const {root,request}=await fixture(t);const remote=fakeRemote();let allowCommit=false;const service=tracked(t,{dataDir:path.join(root,'real-state'),spawnRemote:remote.spawn,authorize:async stage=>stage!=='commit'||allowCommit});
 const stale=await service.prepare(request);await fs.writeFile(request.localPath,'changed');await assert.rejects(service.start({threadId:'chat',planId:stale.planId}),/source changed/);
 await fs.writeFile(request.localPath,'abc');const plan=await service.prepare(request);await service.start({threadId:'chat',planId:plan.planId});const stopped=await service.wait({threadId:'chat',transferId:plan.planId});assert.equal(stopped.status,'interrupted');assert.equal(remote.committed,false);assert.equal(remote.data.length,3);
 allowCommit=true;const restarted=tracked(t,{dataDir:path.join(root,'real-state'),spawnRemote:remote.spawn,authorize:async()=>true});await restarted.resume({threadId:'chat',transferId:plan.planId});assert.equal((await restarted.wait({threadId:'chat',transferId:plan.planId})).status,'completed');assert.equal(remote.operations.filter(x=>x==='write').length,1);
});
test('overwrite capability fails closed before inspection',async t=>{const {service,request}=await fixture(t);await assert.rejects(service.prepare({...request,overwrite:{snapshot:{ino:'1'}}}),/overwrite unsupported/);});
binaryTest('download streams binary into a local staged file and requires commit authorization',async t=>{
 const {root,request}=await fixture(t);const remote=fakeRemote();const stages=[];const service=tracked(t,{dataDir:path.join(root,'state2'),spawnRemote:remote.spawn,authorize:async stage=>{stages.push(stage);return true;}});
 const plan=await service.prepare({...request,direction:'download',localPath:path.join(root,'download')});await service.start({threadId:'chat',planId:plan.planId});const done=await service.wait({threadId:'chat',transferId:plan.planId});assert.equal(done.status,'completed',done.error);assert.deepEqual(await fs.readFile(path.join(root,'download')),remote.source);assert.deepEqual(stages,['inspect','start','commit']);
});
binaryTest('expiry at commit gate prevents remote publication',async t=>{
 const {root,request}=await fixture(t);let now=Date.now();const remote=fakeRemote();const service=tracked(t,{dataDir:path.join(root,'state2'),spawnRemote:remote.spawn,clock:()=>now,authorize:async stage=>{if(stage==='commit')now=request.expiresAt+1;return true;}});
 const plan=await service.prepare(request);await service.start({threadId:'chat',planId:plan.planId});const stopped=await service.wait({threadId:'chat',transferId:plan.planId});assert.equal(stopped.status,'interrupted');assert.match(stopped.error,/expired/);assert.equal(remote.committed,false);
});
binaryTest('cancel while commit approval is pending prevents publication',async t=>{
 const {root,request}=await fixture(t);const remote=fakeRemote();let entered,release;const ready=new Promise(resolve=>entered=resolve),gate=new Promise(resolve=>release=resolve);
 const service=tracked(t,{dataDir:path.join(root,'state2'),spawnRemote:remote.spawn,authorize:async stage=>{if(stage==='commit'){entered();await gate;}return true;}});
 const plan=await service.prepare(request);await service.start({threadId:'chat',planId:plan.planId});await ready;await service.cancel({threadId:'chat',transferId:plan.planId});release();const stopped=await service.wait({threadId:'chat',transferId:plan.planId});assert.equal(stopped.status,'cancelled');assert.equal(remote.committed,false);
});
binaryTest('two services fence concurrent start and cross-instance cancellation is durable',async t=>{
 const {root,request}=await fixture(t);const remote=fakeRemote();let entered,release;const ready=new Promise(resolve=>entered=resolve),gate=new Promise(resolve=>release=resolve);const options={dataDir:path.join(root,'shared-state'),spawnRemote:remote.spawn,authorize:async stage=>{if(stage==='commit'){entered();await gate;}return true;}};
 const first=tracked(t,options),second=tracked(t,options);const plan=await first.prepare(request);
 await first.start({threadId:'chat',planId:plan.planId});await ready;assert.equal((await second.read({threadId:'chat',transferId:plan.planId})).status,'verifying');
 await assert.rejects(second.resume({threadId:'chat',transferId:plan.planId}),/owned|running/);
 await second.cancel({threadId:'chat',transferId:plan.planId});release();assert.equal((await first.wait({threadId:'chat',transferId:plan.planId})).status,'cancelled');assert.equal(remote.committed,false);
});
binaryTest('live process ownership blocks takeover and dead process ownership is recoverable',async t=>{
 const {root,request}=await fixture(t);const remote=fakeRemote();const dataDir=path.join(root,'process-state');const service=tracked(t,{dataDir,spawnRemote:remote.spawn,authorize:async()=>true});const plan=await service.prepare(request);
 const script=`import {TransferService} from ${JSON.stringify(new URL('../src/transfer-service.mjs',import.meta.url).href)};const x=JSON.parse(Buffer.from(process.argv[1],'base64'));const s=new TransferService({dataDir:x.dataDir,spawnRemote:()=>{throw Error('unused')},authorize:async()=>true});const r=await s._claim(x.threadId,x.id);r.status='interrupted';await s._save(r);console.log('claimed');setInterval(()=>{},1000);`;
 const child=spawn(process.execPath,['--input-type=module','-e',script,Buffer.from(JSON.stringify({dataDir,threadId:'chat',id:plan.planId})).toString('base64')],{stdio:['ignore','pipe','pipe'],windowsHide:true});child.stderr.resume();t.after(()=>child.kill());
 await once(child.stdout,'data');await assert.rejects(service.resume({threadId:'chat',transferId:plan.planId}),/owned/);const closed=once(child,'close');child.kill();await closed;
 await service.resume({threadId:'chat',transferId:plan.planId});assert.equal((await service.wait({threadId:'chat',transferId:plan.planId})).status,'completed');
});
binaryTest('fenced stale worker cannot overwrite records after ownership changes',async t=>{
 const {root,request}=await fixture(t);const remote=fakeRemote();const dataDir=path.join(root,'fence-state');const service=tracked(t,{dataDir,spawnRemote:remote.spawn,authorize:async()=>true});const plan=await service.prepare(request);const r=await service._claim('chat',plan.planId);
 service.db.prepare('UPDATE transfers SET owner_token=? WHERE id=?').run('replacement-owner',plan.planId);r.status='completed';await assert.rejects(service._save(r),/ownership lost/);assert.equal((await service.read({threadId:'chat',transferId:plan.planId})).status,'prepared');
});
test('managed local directory creation has its own authorization gate',async t=>{
 const {service,root,request}=await fixture(t,async stage=>stage==='mkdir');const result=await service.createDirectory({threadId:'chat',host:request.host,side:'local',root,path:path.join(root,'nested'),expiresAt:Date.now()+60000});assert.equal(result.created.length,1);
 const denied=tracked(t,{dataDir:path.join(root,'denied'),spawnRemote:()=>{throw Error('must not spawn')},authorize:async()=>false});await assert.rejects(denied.createDirectory({threadId:'chat',host:request.host,side:'local',root,path:path.join(root,'blocked'),expiresAt:Date.now()+60000}),/authoriz/);await assert.rejects(fs.stat(path.join(root,'blocked')),/ENOENT/);
});

binaryTest('renewed resume approval binds the new expiry and rejection preserves the previous plan',async t=>{
 const {root,request}=await fixture(t);const remote=fakeRemote();let acceptResume=false,seen;
 const service=tracked(t,{dataDir:path.join(root,'renew-state'),spawnRemote:remote.spawn,authorize:async(stage,record)=>{
  if(stage==='commit'&&!acceptResume)return false;
  if(stage==='resume'){seen=record;return acceptResume;}
  return true;
 }});
 const plan=await service.prepare(request);await service.start({threadId:'chat',planId:plan.planId});
 assert.equal((await service.wait({threadId:'chat',transferId:plan.planId})).status,'interrupted');
 const expiresAt=request.expiresAt+60000;
 await assert.rejects(service.resume({threadId:'chat',transferId:plan.planId,expiresAt}),/authorization/);
 assert.equal(seen.approvalPayload.expiresAt,expiresAt);
 const rejected=await service.read({threadId:'chat',transferId:plan.planId});assert.equal(rejected.expiresAt,request.expiresAt);assert.equal(rejected.approvalPayload.expiresAt,request.expiresAt);
 acceptResume=true;await service.resume({threadId:'chat',transferId:plan.planId,expiresAt});
 const completed=await service.wait({threadId:'chat',transferId:plan.planId});assert.equal(completed.status,'completed');assert.equal(completed.approvalPayload.expiresAt,expiresAt);
});

test('recursive upload inspection enforces local blocked paths before hashing children',async t=>{
 const {root,request}=await fixture(t);const tree=path.join(root,'tree'),blocked=path.join(tree,'restricted');await fs.mkdir(blocked,{recursive:true});await fs.writeFile(path.join(blocked,'data'),'private');
 const service=tracked(t,{dataDir:path.join(root,'manifest-state'),spawnRemote:()=>{throw new Error('must not spawn');},authorize:async()=>true});
 await assert.rejects(service.planManifest({...request,localPath:tree,localBlockedPaths:[blocked]}),/protected/);
});

binaryTest('revocation during a stream is checked before each following chunk',async t=>{
 const {root,request}=await fixture(t);await fs.writeFile(request.localPath,Buffer.alloc(2*1024*1024,17));const remote=fakeRemote();let revoked=false;
 const service=tracked(t,{dataDir:path.join(root,'lease-state'),spawnRemote:remote.spawn,authorize:async()=>true,validateLease:record=>{
  assert.equal(record.remoteToken,undefined);if(record.status==='streaming'&&record.bytesTransferred>0)revoked=true;
  if(revoked)throw new Error('grant revoked');
 }});
 const plan=await service.prepare(request);await service.start({threadId:'chat',planId:plan.planId});const stopped=await service.wait({threadId:'chat',transferId:plan.planId});
 assert.equal(stopped.status,'interrupted');assert.match(stopped.error,/revoked/);assert.ok(remote.data.length<2*1024*1024);assert.equal(remote.committed,false);
});
