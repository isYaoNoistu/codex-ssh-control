import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync,readFileSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {JobService} from '../src/job-service.mjs';
import {TransferService} from '../src/transfer-service.mjs';
import {LifecycleService} from '../src/lifecycle.mjs';
import {createLocalPartial} from '../src/local-files.mjs';

const day=86400000, host={id:'dev',hostname:'server.invalid',username:'agent',port:22,enabled:true};
function setup(t){
  const dataDir=mkdtempSync(join(tmpdir(),'ssh-retention-'));
  let instant=Date.now(), status='completed',blocked=null,calls=0;
  const jobs=new JobService({dataDir,authorize:()=>true,execute:async()=>{
    calls++;if(blocked)await blocked;
    return {exitCode:0,stdout:JSON.stringify({status,exitCode:0,log:Buffer.from('test output\n').toString('base64')})};
  }});
  const transfers=new TransferService({dataDir,authorize:()=>true,spawnRemote:()=>{throw Error('unexpected SSH');}});
  const opts={dataDir,jobs,transfers,clock:()=>instant};
  const service=new LifecycleService(opts), peer=new LifecycleService(opts);
  t.after(()=>{peer.close();service.close();jobs.close();transfers.close();rmSync(dataDir,{recursive:true,force:true});});
  function seedTransfer(status,extra={},owner=null){
    const id=randomBytes(16).toString('hex');
    const r={transferId:id,threadId:'owner',host,approvalPayload:{hostId:host.id},remoteToken:randomBytes(32).toString('hex'),
      status,createdAt:instant,finishedAt:instant,expiresAt:instant-1,direction:'upload',remotePath:'/srv/artifact',...extra};
    transfers.db.prepare('INSERT INTO transfers(id,thread_id,record,owner_pid,owner_token) VALUES(?,?,?,?,?)').run(id,r.threadId,JSON.stringify(r),owner?process.pid:null,owner);
    return r;
  }
  const request={threadId:'owner',host,operation:{command:'check-fixture',cwd:'/tmp'},idempotencyKey:'once'};
  return {service,peer,jobs,transfers,seedTransfer,dataDir,request,calls:()=>calls,advance:n=>instant+=n*day,setStatus:v=>status=v,
    hold(){let release;blocked=new Promise(r=>release=r);return ()=>{blocked=null;release();};}};
}

test('age archives confirmed output, preserves the cleanup binding and prevents replay even after archive expiry',async t=>{
  const f=setup(t), {id}=await f.jobs.submit({...f.request,sessionId:'launching-session'});
  assert.equal((await f.jobs.submit({...f.request,sessionId:'another-session'})).sessionId,'launching-session');
  assert.equal(f.service.settings().retentionDays,30);
  f.service.configure({retentionDays:2});assert.equal(f.peer.settings().retentionDays,2);
  assert.throws(()=>f.service.configure({retentionDays:0}),/保留/);
  f.advance(1);assert.equal(f.peer.sweep().jobs,0);
  f.advance(2);assert.equal(f.peer.sweep().jobs,1);
  assert.equal(f.jobs.list({threadId:'owner'}).length,0);
  assert.equal((await f.jobs.read({threadId:'owner',taskId:id})).output,'');
  const entries=f.service.listArchives({threadId:'owner',hostId:host.id}).items;
  assert.equal(entries[0].id,id);assert.equal(entries[0].sessionId,'launching-session');assert.doesNotMatch(JSON.stringify(entries),/token|check-fixture.*test output/u);
  assert.equal(f.service.overview().local.outputBytes,0);
  f.advance(50);assert.equal(f.service.sweep().purged,0,'never expire the only cleanup token');
  const options={kind:'job',threadId:'owner',hostId:host.id,id,collect:true};
  await assert.rejects(f.service.remote({...options,threadId:'other'},()=>assert.fail()),/不存在/);
  await assert.rejects(f.service.remote({...options,hostId:'other'},()=>assert.fail()),/所有权/);
  await f.service.remote(options,async r=>{assert.match(r.token,/^[a-f0-9]{64}$/);return {collected:true,retainedBytes:7};});
  assert.equal(f.peer.sweep().purged,1);
  assert.equal(f.service.listArchives().items.length,0);
  assert.equal((await f.jobs.submit(f.request)).id,id);
  await assert.rejects(f.jobs.submit({...f.request,operation:{...f.request.operation,command:'different'}}),/snapshot mismatch/);
  assert.equal(f.calls(),1);
});

test('an in-flight reconciliation blocks retirement; collection is exclusive across SQLite connections',async t=>{
  const f=setup(t),{id}=await f.jobs.submit(f.request);
  const release=f.hold();const reading=f.jobs.reconcile({threadId:'owner',taskId:id});
  f.advance(35);assert.equal(f.peer.sweep().jobs,0);
  release();await reading;
  assert.equal(f.service.sweep().jobs,1);
  let finish,began;
  const started=new Promise(resolve=>began=resolve);
  const opts={kind:'job',id,hostId:host.id,threadId:'owner',collect:true};
  const collecting=f.service.remote(opts,async()=>{began();await new Promise(resolve=>finish=resolve);throw Error('disconnect');});
  await started;
  await assert.rejects(f.peer.remote(opts,()=>assert.fail()),/使用或回收/);
  await assert.rejects(f.jobs.reconcile({threadId:'owner',taskId:id}),/使用或回收/);
  finish();await assert.rejects(collecting,/disconnect/);
  assert.equal(f.peer.listArchives().items[0].remoteCleaned,false);
  assert.equal((await f.peer.remote(opts,async r=>({collected:Boolean(r.token)}))).collected,true);
});

test('unknown, timeout, uncertain cancellation and live transfer workers cannot be collected by age',async t=>{
  const f=setup(t);for(const state of ['unknown','timed_out','missing']){
    f.setStatus(state);await f.jobs.submit({...f.request,idempotencyKey:state});
  }
  for(const state of ['unknown','commit_unknown','interrupted','failed','committing','prepared','cancelled'])f.seedTransfer(state);
  f.seedTransfer('completed',{},'busy');
  const good=f.seedTransfer('completed');
  f.advance(31);
  assert.deepEqual(f.peer.sweep(),{jobs:0,transfers:1,purged:0});
  assert.deepEqual(f.service.listArchives().items.map(r=>r.id),[good.transferId]);
  await assert.rejects(f.transfers.resume({threadId:'owner',transferId:good.transferId}),/归档/);
});

test('a substituted local partial cannot remove the final artifact or consume recovery evidence',async t=>{
  const f=setup(t),target=join(f.dataDir,'artifact');writeFileSync(target,'retain');
  const r=f.seedTransfer('cancelled',{direction:'download',cancelConfirmed:true,localPath:target,localRoot:f.dataDir,partial:{path:target,token:'different'}});
  f.advance(35);assert.equal(f.peer.sweep().transfers,1);
  await assert.rejects(f.service.remote({kind:'transfer',id:r.transferId,hostId:host.id,threadId:'owner',collect:true},async()=>({collected:true,reclaimedBytes:0})),/所有权/);
  assert.equal(readFileSync(target,'utf8'),'retain');assert.equal(f.peer.listArchives().items[0].remoteCleaned,false);
});

test('only a positively verified explicit upload cleanup releases the archived binding',async t=>{
  const f=setup(t),successful=f.seedTransfer('completed'),missing=f.seedTransfer('completed');
  const ambiguous=f.seedTransfer('cancelled',{cleanedAt:Date.now()});
  f.transfers._metadata=async(r)=>r.transferId===successful.transferId?
    {collected:true,bytes:123,retainedBytes:0,reclaimedBytes:123}:
    {collected:true,missing:true,bytes:0,retainedBytes:0,reclaimedBytes:0};
  const cleanup=r=>f.transfers.cleanup({threadId:r.threadId,transferId:r.transferId},record=>record);
  await cleanup(successful);await assert.rejects(cleanup(missing),/not verified/);
  await assert.rejects(cleanup(ambiguous),/confirmed/);
  f.advance(35);
  assert.equal(f.service.sweep().transfers,2);
  const list=f.service.listArchives().items;
  assert.equal(list.find(row=>row.id===successful.transferId).remoteCleaned,true);
  assert.equal(list.find(row=>row.id===missing.transferId).remoteCleaned,false);
  assert.equal(f.service.overview().local.protectedRecords,1);
  assert.equal((await f.transfers._load(missing.threadId,missing.transferId)).remoteToken,missing.remoteToken);
});

test('missing local partial directory retains its cleanup binding and archive',async t=>{
  const f=setup(t),token=randomBytes(32).toString('hex'),target=join(f.dataDir,'artifact');
  const directory=join(f.dataDir,'.ssh-transfer-'+token);
  const partial={token,directory,path:join(directory,'data'),ino:'1',dev:'2',directoryDev:'2',directoryIno:'3'};
  const r=f.seedTransfer('cancelled',{cancelConfirmed:true,direction:'download',remoteToken:token,partial,localPath:target,localRoot:f.dataDir});
  f.advance(35);f.service.sweep();
  const action={kind:'transfer',id:r.transferId,hostId:host.id,threadId:r.threadId,collect:true};
  await assert.rejects(f.peer.remote(action,async()=>({collected:true}),()=>r),{code:'ENOENT'});
  assert.equal(f.service.listArchives().items[0].remoteCleaned,false);
  assert.equal((await f.transfers._load(r.threadId,r.transferId)).remoteToken,token);
});

test('transfer archives identify the session which actually started a prepared plan',{skip:process.platform==='darwin'},async t=>{
  const f=setup(t),r=f.seedTransfer('prepared',{expiresAt:Date.now()+60000,sessionId:'preparation-session'});
  f.transfers._verifySource=async()=>{};
  f.transfers._run=async row=>{row.status='completed';row.finishedAt=Date.now();await f.transfers._save(row);};
  await f.transfers.start({threadId:r.threadId,planId:r.transferId,sessionId:'starting-session'});
  await f.transfers.wait({threadId:r.threadId,transferId:r.transferId});
  f.advance(35);f.peer.sweep();
  assert.equal(f.service.listArchives().items[0].sessionId,'starting-session');
});

test('cancelling an unresolved commit during a new resume keeps its outcome unknown', {skip:process.platform==='darwin'}, async t=>{
  const f=setup(t),r=f.seedTransfer('commit_unknown');
  let finish;
  f.transfers._run=()=>new Promise(resolve=>finish=resolve);
  const op={threadId:r.threadId,transferId:r.transferId};
  await f.transfers.resume({...op,expiresAt:Date.now()+60000});
  assert.equal((await f.transfers.cancel(op)).status,'commit_unknown');
  finish();await f.transfers.wait(op);
  const old=f.seedTransfer('cancelled');
  await assert.rejects(f.transfers.resume({...op,transferId:old.transferId}),/cannot resume/);
  f.advance(60);
  assert.equal(f.service.sweep().transfers,0,'a rejected resume cannot create terminal proof');
});

test('local partial cleanup enforces current exclusions and can recover an interrupted directory removal',{skip:process.platform==='darwin'},async t=>{
  const f=setup(t),target=join(f.dataDir,'final.bin'),token=randomBytes(32).toString('hex');
  const partial=await createLocalPartial(target,f.dataDir,token);writeFileSync(partial.path,'unfinished');
  writeFileSync(target,'published independent artifact');
  const r=f.seedTransfer('cancelled',{direction:'download',cancelConfirmed:true,localPath:target,localRoot:f.dataDir,remoteToken:token,partial});
  f.advance(35);assert.equal(f.service.sweep().transfers,1);
  const op={kind:'transfer',id:r.transferId,hostId:host.id,threadId:'owner',collect:true};
  const done=async()=>({collected:true,bytes:0,retainedBytes:0,reclaimedBytes:0});
  await assert.rejects(f.service.remote(op,done,()=>({localBlockedPaths:[partial.directory]})),/protected/);
  assert.equal(readFileSync(partial.path,'utf8'),'unfinished');
  let checks=0;
  await assert.rejects(f.service.remote(op,done,()=>{if(++checks===3)throw Error('grant revoked before rmdir');}),/revoked/);
  assert.throws(()=>readFileSync(partial.path),{code:'ENOENT'});
  assert.equal(f.service.listArchives().items[0].remoteCleaned,false);
  await f.peer.remote(op,done,()=>({localBlockedPaths:[]}));
  assert.equal(f.peer.listArchives().items[0].remoteCleaned,true);
  assert.equal(readFileSync(target,'utf8'),'published independent artifact');
});
