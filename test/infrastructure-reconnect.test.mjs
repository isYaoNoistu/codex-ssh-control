import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {randomUUID} from 'node:crypto';
import {Store} from '../src/store.mjs';
import {createInfrastructureRuntime} from '../src/infrastructure-runtime.mjs';

const probe='SSH_CONTROL_CAPABILITIES_V1='+JSON.stringify({schemaVersion:1,os:'Linux',python:{available:true,version:'3.12.0'},openat2:{available:true,errno:null},processGroups:true,commands:{},sftp:{available:null}});
function setup(t,replies){
 const dataDir=mkdtempSync(join(tmpdir(),'ssh-retry-')),store=new Store(dataDir);let calls=0;
 store.saveHost({id:'fixture',sshAlias:'fixture.invalid',enabled:true});store.grant('owner',['fixture']);
 const runtime=createInfrastructureRuntime({dataDir,store,gate:async(ctx,args,op)=>{
  const token=randomUUID();let p=store.beginNativeOperation(ctx.threadId,'fixture',op,args.explanation??'验证固定只读诊断的连接恢复。',token,store.getPolicy('fixture').revision);
  if(p.status==='pending')p=store.completeNativeApproval(ctx.threadId,p.approval.id,token,'approve');
  if(p.status!=='ready')throw new Error(p.reason);return p;
 },requireActive:(_signal,id,owner)=>store.assertOperationReady(owner,id),finish:(id,r)=>store.finishOperation(id,r),spawnImpl:()=>{
  const child=new EventEmitter();child.stdin=new PassThrough();child.stdout=new PassThrough();child.stderr=new PassThrough();
  child.kill=()=>{child.stdout.end();child.stderr.end();child.emit('close',null);};
  const index=calls++;child.stdin.on('finish',()=>setImmediate(()=>{const r=replies(index,store);child.stdout.end(r.stdout??'');child.stderr.end(r.stderr??'');child.emit('close',r.code??0);}));return child;
 }});
 t.after(async()=>{await runtime.close();store.close();rmSync(dataDir,{recursive:true,force:true});});
 return {store,calls:()=>calls,call:(name,args={})=>runtime.call(name,{threadId:'owner'},{hostId:'fixture',...args},new AbortController().signal)};
}
test('fixed capability query retries a lost connection once and returns confirmed data',async t=>{
 const h=setup(t,i=>i===0?{code:255,stderr:'Broken pipe'}:{stdout:probe});
 assert.equal((await h.call('ssh_capabilities')).capabilities.remote.tasksReady,true);assert.equal(h.calls(),2);
});
test('authentication or fingerprint failure never retries',async t=>{
 const h=setup(t,()=>({code:255,stderr:'Host key verification failed'}));
 await assert.rejects(h.call('ssh_capabilities'));assert.equal(h.calls(),1);
});
test('revocation between diagnostic attempts prevents the reconnect',async t=>{
 const h=setup(t,(_i,s)=>{s.revoke('owner',['fixture']);return {code:255,stderr:'Broken pipe'};});
 await assert.rejects(h.call('ssh_capabilities'),/失效/);assert.equal(h.calls(),1);
});
test('ambiguous task submission is recorded unknown and is never retried',async t=>{
 const h=setup(t,()=>({code:255,stderr:'Broken pipe'})),p=h.store.getPolicy('fixture');
 h.store.savePolicy('owner','fixture',{...p.policy,mode:'approval',jobs:{enabled:true}},p.revision);h.store.grant('owner',['fixture']);
 const {job}=await h.call('ssh_job_submit',{command:'sleep 1',cwd:'/tmp',explanation:'验证提交断线不会执行两次。',idempotencyKey:'one-intent'});
 assert.equal(job.observation,'unknown');assert.equal(h.calls(),1);
});
