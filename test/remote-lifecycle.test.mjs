import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectJobPrivate,inspectTransferPrivate} from '../src/remote-lifecycle.mjs';
import {buildTransferCommand} from '../src/transfer-service.mjs';

const job={id:'a'.repeat(32),token:'b'.repeat(64),host:{id:'fixture'},status:'completed',observation:'confirmed'};
const usage={bytes:1200,retainedBytes:150,reclaimedBytes:1050,collected:true};

test('the expanded transfer guard and long approved paths fit into Windows SSH argv',()=>{
  const root='/srv'+('/'+'component'.repeat(24)).repeat(17);
  const command=buildTransferCommand({operation:'collect',root,path:root+'/artifact.jar',token:'a'.repeat(64),
    sha256:'b'.repeat(64),size:1,mode:420,mtimeNs:'1',originalExpiresAt:1,expectedStatus:'completed',overwrite:'never'});
  assert.ok(command.length<31000,'reserve space for the SSH executable, options and destination');
});

test('private job collection authenticates the exact ID and terminal outcome, never submits or signals', async()=>{
  const calls=[];
  const service={execute:async(host,_command,opts)=>{
    calls.push([host.id,JSON.parse(opts.input)]);
    return {exitCode:0,stdout:JSON.stringify(usage)};
  }};
  for(const status of ['unknown','missing','timed_out','submitted','running']) {
    await assert.rejects(inspectJobPrivate(service,{...job,status},true),/confirmed terminal/);
  }
  await assert.rejects(inspectJobPrivate(service,{...job,observation:'unknown'},true),/confirmed terminal/);
  assert.deepEqual(calls,[]);
  assert.deepEqual(await inspectJobPrivate(service,job,true),usage);
  assert.deepEqual(calls,[['fixture',{id:job.id,token:job.token,action:'collect',expectedStatus:'completed'}]]);
});

test('partial, failed and inconsistent helper responses never confirm cleanup', async()=>{
  for(const transport of [{exitCode:1},{exitCode:0,truncated:true},
    {exitCode:0,stdout:JSON.stringify({error:'busy'})},
    {exitCode:0,stdout:JSON.stringify({missing:true,bytes:0,retainedBytes:0,reclaimedBytes:0,collected:true})},
    {exitCode:0,stdout:JSON.stringify({...usage,retainedBytes:140})}]) {
    await assert.rejects(inspectJobPrivate({execute:async()=>transport},job,true));
  }
});

test('transfer maintenance is scoped to private upload state with the original lease deadline', async()=>{
  const r={direction:'upload',status:'cancelled',cancelConfirmed:true,expiresAt:500,remoteToken:'c'.repeat(64)};
  const calls=[];
  const service={clock:()=>1000,_metadata:async(record,action,args)=>{
    calls.push([record.expiresAt,record.remoteToken,action,args]);return usage;
  }};
  for(const status of ['commit_unknown','unknown','interrupted','streaming']) {
    await assert.rejects(inspectTransferPrivate(service,{...r,status},true),/confirmed terminal/);
  }
  await assert.rejects(inspectTransferPrivate(service,{...r,cancelConfirmed:false},true),/confirmed terminal/);
  await assert.rejects(inspectTransferPrivate(service,{...r,cancelConfirmed:false,cleanedAt:123},true),/confirmed terminal/);
  await assert.rejects(inspectTransferPrivate(service,{...r,unresolvedCommit:true},true),/confirmed terminal/);
  const download=await inspectTransferPrivate(service,{...r,direction:'download'},true);
  assert.equal(download.collected,true);assert.equal(download.bytes,0);assert.deepEqual(calls,[]);
  assert.deepEqual(await inspectTransferPrivate(service,r,true),usage);
  assert.deepEqual(calls,[[31000,r.remoteToken,'collect',{expectedStatus:'cancelled',originalExpiresAt:500}]]);
  assert.equal(r.expiresAt,500);
});
