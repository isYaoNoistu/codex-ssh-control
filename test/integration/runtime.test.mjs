import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {createFixture} from './fixture.mjs';
import {Store} from '../../src/store.mjs';
import {createInfrastructureRuntime} from '../../src/infrastructure-runtime.mjs';

const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(read,accept,label,timeout=60000){
  const end=Date.now()+timeout;let last;
  do{last=await read();if(accept(last))return last;await delay(40);}while(Date.now()<end);
  throw Error(`${label}: ${JSON.stringify(last)}`);
}

test('governed infrastructure runtime over isolated real SSH',{skip:process.env.SSH_INTEGRATION!=='1',timeout:900000},async t=>{
  const fixture=createFixture(),dataDir=mkdtempSync(join(tmpdir(),'sri-')),localRoot=join(dataDir,'artifacts');
  mkdirSync(localRoot);const store=new Store(dataDir),threadId='runtime-owner',hostId='fixture',approvals=[];
  let runtime;
  t.after(async()=>{try{await runtime?.close();}finally{store.close();try{fixture.cleanup();}finally{rmSync(dataDir,{recursive:true,force:true});}}});
  const docker=args=>{
    const result=spawnSync('docker',args,{encoding:'utf8',windowsHide:true,timeout:30000});
    assert.equal(result.status,0,result.stderr||result.error?.message);return result.stdout;
  };
  docker(['exec',fixture.containers[0],'sh','-c','mkdir -p /home/tester/artifacts && chown tester:tester /home/tester/artifacts && chmod 700 /home/tester/artifacts']);
  store.saveHost({...fixture.host(),enabled:true});
  const initial=store.getPolicy(hostId);
  store.savePolicy(threadId,hostId,{...initial.policy,mode:'approval',maxConcurrent:1,
    roots:[{id:'remote',path:'/home/tester/artifacts',read:true,write:true}],
    localRoots:[{id:'local',path:localRoot,read:true,write:true}],
    jobs:{enabled:true,timeoutSeconds:120,maxOutputKiB:64},
    transfers:{enabled:true,maxBytes:64*1024*1024,timeoutSeconds:180},
  },initial.revision);
  store.grant(threadId,[hostId]);
  const gate=async(ctx,args,operation)=>{
    const token=randomUUID(),id=args.hostId??hostId;
    let permit=store.beginNativeOperation(ctx.threadId,id,operation,args.explanation??'检查隔离测试主机及已授权测试文件。',token,store.getPolicy(id).revision);
    if(permit.status==='pending'){
      approvals.push(structuredClone(permit.approval));
      permit=store.completeNativeApproval(ctx.threadId,permit.approval.id,token,'approve');
    }
    if(permit.status!=='ready')throw Object.assign(new Error(`${permit.code}: ${permit.reason}`),{code:permit.code});
    return permit;
  };
  runtime=createInfrastructureRuntime({dataDir,store,gate,
    requireActive:(signal,operationId,owner)=>{assert.ok(!signal?.aborted);store.assertOperationReady(owner,operationId);},
    finish:(id,result)=>store.finishOperation(id,result),spawnImpl:spawn,
  });
  const call=(name,args={},owner=threadId)=>runtime.call(name,{threadId:owner},{...args},new AbortController().signal);
  const explain='在一次性测试主机验证精确审批和执行结果，不操作用户服务器。';

  await t.test('capability probe and explicit managed mkdir use the real permission gate',async()=>{
    const result=await call('ssh_capabilities',{hostId});
    assert.equal(result.capabilities.remote.tasksReady,true);
    assert.equal(result.capabilities.remote.transfersReady,true);
    await call('ssh_transfer_mkdir',{hostId,side:'remote',root:'/home/tester/artifacts',path:'/home/tester/artifacts/releases',explanation:explain});
    assert.equal(docker(['exec',fixture.containers[0],'stat','-c','%U %a','/home/tester/artifacts/releases']).trim(),'tester 700');
    assert.equal(approvals.at(-1).presentation.operation.kind,'transfer_mkdir');
  });
  await t.test('approved durable jobs expose incremental output and release their single slot',async()=>{
    const {job}=await call('ssh_job_submit',{hostId,command:"printf 'first\\nsecond\\n'; sleep 1; printf 'last\\n'",cwd:'/home/tester/artifacts',explanation:explain,idempotencyKey:'runtime-once'});
    assert.ok(job.id);assert.equal(job.host,undefined);
    const done=await until(async()=> (await call('ssh_job_read',{taskId:job.id,limitBytes:6})).job,j=>j.status==='completed','job completion');
    assert.equal(done.exitCode,0);assert.equal(done.output,'first\n');assert.equal(done.nextCursor,6);assert.equal(done.hasMore,true);
    const tail=(await call('ssh_job_read',{taskId:job.id,cursor:done.nextCursor,refresh:false})).job;
    assert.equal(tail.output,'second\nlast\n');
    await assert.rejects(()=>call('ssh_job_read',{taskId:job.id,refresh:false},'other-chat'));
    const retried=(await call('ssh_job_submit',{hostId,command:"printf 'first\\nsecond\\n'; sleep 1; printf 'last\\n'",cwd:'/home/tester/artifacts',explanation:explain,idempotencyKey:'runtime-once'})).job;
    assert.equal(retried.id,job.id);
    assert.equal(store.getExternalOperation(threadId,'job',job.id).status,'completed');
  });
  await t.test('revocation interrupts binary transfer and reapproval renews the same concurrency slot',async()=>{
    const localPath=join(localRoot,'source.bin'),remotePath='/home/tester/artifacts/releases/runtime.bin';
    const content=Buffer.alloc(32*1024*1024,0x51);writeFileSync(localPath,content);
    const expected=createHash('sha256').update(content).digest('hex');
    const {plan,planId}=await call('ssh_transfer_prepare',{hostId,direction:'upload',localPath,remotePath});
    assert.equal(plan.sha256,expected);assert.equal(plan.size,content.length);
    const started=await call('ssh_transfer_start',{planId,explanation:explain});
    assert.equal(started.transfer.id,planId);
    const original=store.getExternalOperation(threadId,'transfer',planId);
    await until(async()=> (await call('ssh_transfer_read',{transferId:planId})).transfer,r=>r.bytesTransferred>0,'first upload bytes');
    store.revoke(threadId,[hostId]);
    const stopped=await until(async()=> (await call('ssh_transfer_read',{transferId:planId})).transfer,r=>['interrupted','commit_unknown','completed'].includes(r.status),'revoked transfer');
    assert.equal(stopped.status,'interrupted',JSON.stringify(stopped));
    assert.ok(stopped.bytesTransferred<content.length);
    assert.equal(docker(['exec',fixture.containers[0],'sh','-c',`test ! -e ${remotePath} && printf absent`]),'absent');
    await assert.rejects(()=>call('ssh_transfer_resume',{transferId:planId,explanation:explain}));
    await assert.rejects(()=>call('ssh_transfer_read',{transferId:planId},'other-chat'));
    store.grant(threadId,[hostId]);
    const resumed=await call('ssh_transfer_resume',{transferId:planId,explanation:explain});
    assert.ok(resumed.transfer.expiresAt>plan.expiresAt);
    assert.equal(resumed.transfer.approvalPayload.expiresAt,resumed.transfer.expiresAt);
    assert.equal(store.getExternalOperation(threadId,'transfer',planId).id,original.id);
    const db=new DatabaseSync(join(dataDir,'store.sqlite'),{readOnly:true});
    try{assert.equal(db.prepare("SELECT count(*) n FROM operations WHERE status='active' AND counts_concurrency=1").get().n,1);}finally{db.close();}
    const completed=await until(async()=> (await call('ssh_transfer_read',{transferId:planId})).transfer,r=>r.status==='completed'||r.status==='interrupted'||r.status==='commit_unknown','resumed upload');
    assert.equal(completed.status,'completed',JSON.stringify(completed));
    assert.equal(store.getExternalOperation(threadId,'transfer',planId).status,'completed');
    const destination=join(localRoot,'download.bin');
    const download=await call('ssh_transfer_prepare',{hostId,direction:'download',localPath:destination,remotePath});
    await call('ssh_transfer_start',{planId:download.planId,explanation:explain});
    const downloaded=await until(async()=> (await call('ssh_transfer_read',{transferId:download.planId})).transfer,r=>['completed','interrupted','commit_unknown'].includes(r.status),'download');
    assert.equal(downloaded.status,'completed',JSON.stringify(downloaded));
    assert.equal(createHash('sha256').update(readFileSync(destination)).digest('hex'),expected);
    const {manifest}=await call('ssh_transfer_manifest',{hostId,direction:'download',localPath:join(localRoot,'recursive'),remotePath:'/home/tester/artifacts/releases'});
    assert.deepEqual(manifest.files.map(x=>x.relativePath),['runtime.bin']);
    assert.equal(manifest.requiresIndividualApproval,true);
  });
});
