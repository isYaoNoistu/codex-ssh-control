import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {DatabaseSync} from 'node:sqlite';
import {Store} from '../src/store.mjs';
import {createInfrastructureRuntime} from '../src/infrastructure-runtime.mjs';

function fixture(t,{maxConcurrent=1,afterGate=()=>{}}={}) {
  const dataDir=mkdtempSync(join(tmpdir(),'ssh-lifecycle-')),localRoot=join(dataDir,'artifacts');mkdirSync(localRoot);
  const store=new Store(dataDir);store.saveHost({id:'fixture',sshAlias:'fixture.invalid',enabled:true});
  const p=store.getPolicy('fixture');
  store.savePolicy('owner','fixture',{...p.policy,mode:'approval',maxConcurrent,
    roots:[{id:'remote',path:'/tmp/artifacts',read:true,write:true}],
    localRoots:[{id:'local',path:localRoot,read:true,write:true}],jobs:{enabled:true},transfers:{enabled:true},
  },p.revision);store.grant('owner',['fixture']);
  const connections=[];
  const runtime=createInfrastructureRuntime({dataDir,store,
    gate:async(ctx,args,operation)=>{
      const token=randomUUID();let permit=store.beginNativeOperation(ctx.threadId,'fixture',operation,'验证任务失败、并发和恢复状态。',token,store.getPolicy('fixture').revision);
      if(permit.status==='pending')permit=store.completeNativeApproval(ctx.threadId,permit.approval.id,token,'approve');
      if(permit.status!=='ready')throw new Error(`${permit.code}: ${permit.reason}`);afterGate(store,operation);return permit;
    },requireActive:(_signal,id,owner)=>store.assertOperationReady(owner,id),finish:(id,r)=>store.finishOperation(id,r),
    spawnImpl:(_file,args)=>{
      const child=new EventEmitter();child.stdin=new PassThrough();child.stdout=new PassThrough();child.stderr=new PassThrough();
      child.kill=()=>{child.stdout.end();child.stderr.end();child.emit('close',1);};
      let input='';child.stdin.on('data',b=>input+=b);
      child.stdin.on('finish',()=>setImmediate(()=>{
        let result;
        if(input){const req=JSON.parse(input);connections.push(req.action);result={status:'running',exitCode:null,log:''};}
        else {const encoded=[...args.at(-1).matchAll(/"([A-Za-z0-9+/=]+)"/g)].at(-1)[1];const req=JSON.parse(Buffer.from(encoded,'base64'));connections.push(req.operation);assert.equal(req.operation,'target');result={ok:true,result:{snapshot:null}};}
        child.stdout.end(JSON.stringify(result));child.stderr.end();child.emit('close',0);
      }));return child;
    },
  });
  t.after(async()=>{await runtime.close();store.close();rmSync(dataDir,{recursive:true,force:true});});
  return {store,localRoot,connections,
    call:(name,args={})=>runtime.call(name,{threadId:'owner'},{hostId:'fixture',...args},new AbortController().signal),
    active:()=>{const db=new DatabaseSync(join(dataDir,'store.sqlite'),{readOnly:true});try{return db.prepare("SELECT * FROM operations WHERE status='active' AND counts_concurrency=1").all();}finally{db.close();}},
  };
}

test('changed source before dispatch releases the permit without leaving a durable transfer slot',{skip:process.platform==='darwin'},async t=>{
  const f=fixture(t),localPath=join(f.localRoot,'artifact.bin');writeFileSync(localPath,'approved');
  const {planId}=await f.call('ssh_transfer_prepare',{direction:'upload',localPath,remotePath:'/tmp/artifacts/new.bin'});
  writeFileSync(localPath,'changed');
  await assert.rejects(f.call('ssh_transfer_start',{planId}),/source changed/);
  assert.equal(f.active().length,0,'no remote mutation was dispatched, so no concurrency slot may remain');
  assert.equal(f.store.getExternalOperation('owner','transfer',planId),null);
  assert.equal((await f.call('ssh_transfer_prepare',{direction:'upload',localPath,remotePath:'/tmp/artifacts/replacement.bin'})).plan.status,'prepared');
  assert.deepEqual(f.connections,['target','target']);
});

test('concurrent conflicting idempotency keys do not strand a phantom job permit',async t=>{
  const f=fixture(t,{maxConcurrent:2});
  const results=await Promise.allSettled(['sleep 1','sleep 2'].map(command=>f.call('ssh_job_submit',{command,cwd:'/tmp',idempotencyKey:'same'})));
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  assert.match(results.find(r=>r.status==='rejected').reason.message,/snapshot mismatch/);
  assert.deepEqual(f.connections,['submit']);
  const {jobs}=await f.call('ssh_job_list');assert.equal(jobs.length,1);
  const active=f.active();assert.equal(active.length,1,'only the task actually submitted may retain a slot');
  assert.equal(active[0].external_id,jobs[0].id);
});

test('revocation after approval but before dispatch releases an unused execution slot',async t=>{
  const f=fixture(t,{afterGate:store=>{store.revoke('owner',['fixture']);store.grant('owner',['fixture']);}});
  await assert.rejects(f.call('ssh_job_submit',{command:'sleep 1',cwd:'/tmp'}),/失效/);
  assert.equal(f.active().length,0);assert.deepEqual(f.connections,[]);
});

test('transfer responses consistently expose the approved host for sidebar authorization controls',{skip:process.platform==='darwin'},async t=>{
  const f=fixture(t),localPath=join(f.localRoot,'artifact.bin');writeFileSync(localPath,'approved');
  const {plan,planId}=await f.call('ssh_transfer_prepare',{direction:'upload',localPath,remotePath:'/tmp/artifacts/new.bin'});
  assert.equal(plan.hostId,'fixture');
  assert.equal((await f.call('ssh_transfer_read',{transferId:planId})).transfer.hostId,'fixture');
  assert.equal((await f.call('ssh_transfer_list')).transfers[0].hostId,'fixture');
});
