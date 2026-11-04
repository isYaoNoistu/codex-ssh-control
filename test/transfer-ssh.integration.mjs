/** Opt-in disposable real SSH transfer acceptance. No configured user hosts. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { createFixture } from './integration/fixture.mjs';
import { prepareInvocation } from '../src/transport.mjs';
import { TransferService } from '../src/transfer-service.mjs';

test('real SSH interrupted binary upload resumes then downloads with final hash', {skip:process.env.SSH_TRANSFER_INTEGRATION!=='1',timeout:600000}, async()=>{
 const fixture=createFixture();let service;const sample=[];let timer;
 try{
  const size=process.env.SSH_TRANSFER_LARGE_TEST==='1'?500*1024*1024:16*1024*1024;
  const source=path.join(fixture.dir,'artifact.bin');const file=await fs.open(source,'wx');const chunk=Buffer.alloc(256*1024,0xa5);
  try{for(let n=0;n<size;n+=chunk.length)await file.write(chunk,0,Math.min(chunk.length,size-n));}finally{await file.close();}
  let interrupted=false,writes=0;const stages=[];
  const spawnRemote=(host,command)=>{
   const invocation=prepareInvocation(host,command,undefined,{dataDir:fixture.dir});const child=spawn(invocation.file,invocation.args,{stdio:['pipe','pipe','pipe'],windowsHide:true,shell:false});
   const encoded=[...command.matchAll(/\"([A-Za-z0-9+/=]+)\"/g)].at(-1)[1];const request=JSON.parse(Buffer.from(encoded,'base64'));
   if(request.operation==='write'){writes++;if(!interrupted){const original=child.stdin.write.bind(child.stdin);let bytes=0;child.stdin.write=(data,...args)=>{const result=original(data,...args);bytes+=data.length;if(bytes>=4*1024*1024&&!interrupted){interrupted=true;setImmediate(()=>child.kill());}return result;};}}
   return child;
  };
  service=new TransferService({dataDir:fixture.dir,spawnRemote,authorize:async(stage,record)=>{stages.push(stage);assert.equal(record.remoteToken,undefined);return true;}});
  const request={threadId:'fixture-chat',host:fixture.host('tester'),direction:'upload',localPath:source,localRoot:fixture.dir,remotePath:'/tmp/artifact.bin',remoteRoot:'/tmp',overwrite:'never',expiresAt:Date.now()+300000,maxBytes:size};
  const started=Date.now();timer=setInterval(()=>sample.push(process.memoryUsage().rss),50);
  const upload=await service.prepare(request);await service.start({threadId:request.threadId,planId:upload.planId});const stopped=await service.wait({threadId:request.threadId,transferId:upload.planId});assert.equal(stopped.status,'interrupted',stopped.error);assert.ok(interrupted);
  await service.resume({threadId:request.threadId,transferId:upload.planId});const finished=await service.wait({threadId:request.threadId,transferId:upload.planId});assert.equal(finished.status,'completed',finished.error);assert.equal(writes,2);
  const download=await service.prepare({...request,direction:'download',localPath:path.join(fixture.dir,'download.bin')});assert.equal(download.sha256,upload.sha256);await service.start({threadId:request.threadId,planId:download.planId});const downloaded=await service.wait({threadId:request.threadId,transferId:download.planId});assert.equal(downloaded.status,'completed',downloaded.error);assert.equal((await fs.stat(download.localPath)).size,size);
  await service.cleanup({threadId:request.threadId,transferId:upload.planId},r=>{
   assert.equal(r.remoteRoot,request.remoteRoot);assert.equal(r.localRoot,request.localRoot);return r;
  });
  const tree=path.join(fixture.dir,'tree-source');await fs.mkdir(path.join(tree,'nested'),{recursive:true});await fs.writeFile(path.join(tree,'nested','leaf.bin'),Buffer.from([0,255,1]));
  for(const direction of ['upload','download']){
   const manifest=await service.planManifest({...request,direction,localPath:direction==='upload'?tree:path.join(fixture.dir,'tree-download'),remotePath:'/tmp/artifact-tree',maxEntries:8});
   assert.equal(manifest.files.length,1,'private transport receipts must never enter artifact manifests');
   for(const directory of manifest.directoryRequests)await service.createDirectory({...directory,host:request.host});
   for(const entry of manifest.files){const plan=await service.prepare({...entry.request,host:request.host});await service.start({threadId:request.threadId,planId:plan.planId});const status=await service.wait({threadId:request.threadId,transferId:plan.planId});assert.equal(status.status,'completed',status.error);}
  }
  assert.deepEqual(await fs.readFile(path.join(fixture.dir,'tree-download','nested','leaf.bin')),Buffer.from([0,255,1]));
  console.log(JSON.stringify({transport:'Windows OpenSSH to disposable Debian Linux container',bytes:size,elapsedSeconds:(Date.now()-started)/1000,peakClientRssBytes:Math.max(...sample),sha256:upload.sha256,stages}));
 }finally{clearInterval(timer);try{if(service){for(const {record,promise} of service.running.values()){await service.cancel({threadId:record.threadId,transferId:record.transferId});await promise.catch(()=>{});}service.close();}}finally{fixture.cleanup();}}
});
