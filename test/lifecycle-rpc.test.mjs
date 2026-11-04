import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {randomBytes} from 'node:crypto';
import {join} from 'node:path';
import {mkdirSync,writeFileSync,readFileSync,statSync} from 'node:fs';
import {setup,promptText} from './helpers/rpc-harness.mjs';

// Pre-feature fixture: terminal records had updatedAt but no finishedAt.
async function legacyJob(h,overrides={}){
  const host=(await h.call('ssh_status')).structuredContent.state.hosts[0],id=randomBytes(16).toString('hex');
  const old=new Date(Date.now()-40*86400000).toISOString();
  const r={id,threadId:'owner',host,hostId:host.id,identity:id,idempotencyKey:id,token:randomBytes(32).toString('hex'),
    operation:{command:'demo',env:{}},status:'completed',observation:'confirmed',exitCode:0,log:'old output',createdAt:old,updatedAt:old,...overrides};
  const db=new DatabaseSync(join(h.dir,'task-state','jobs.sqlite'));try{
    db.prepare('INSERT INTO jobs VALUES(?,?,?,?,?)').run(id,r.threadId,id,id,JSON.stringify(r));
  }finally{db.close();}
  return r;
}
const req=r=>({hostId:r.hostId,kind:'job',id:r.id,explanation:'核对指定记录的归属和终态，回收其私有输出。'});
test('sidebar-only archival tools paginate terminal legacy records from all chats without contacting SSH',async t=>{
  const h=await setup(t),a=await legacyJob(h),b=await legacyJob(h,{threadId:'prior-session'});
  await legacyJob(h,{observation:'unknown'});await legacyJob(h,{status:'timed_out'});
  for(const [tool,args] of [['overview',{}],['configure',{retentionDays:2}],['sweep',{}],['inspect',req(a)],['collect',req(a)]]){
    assert.equal((await h.call('ssh_lifecycle_'+tool,args)).isError,true,tool+' cannot run without UI capability');
  }
  assert.equal((await h.admin('ssh_lifecycle_configure',{retentionDays:3})).structuredContent.settings.retentionDays,3);
  assert.equal((await h.admin('ssh_lifecycle_sweep')).structuredContent.sweep.jobs,2);
  const page=await h.admin('ssh_lifecycle_overview',{hostId:a.hostId,limit:1});
  assert.equal(page.structuredContent.overview.local.protectedRecords,2);
  const {items,nextCursor}=page.structuredContent.archive;
  const last=(await h.admin('ssh_lifecycle_overview',{hostId:a.hostId,limit:1,cursor:nextCursor})).structuredContent.archive;
  assert.equal(last.nextCursor,null);assert.deepEqual(new Set([items[0].id,last.items[0].id]),new Set([a.id,b.id]));
  assert.equal(await h.count(),0);
});

test('legacy transfer cleanup under god honors revocation and private directory exclusions after native approval',async t=>{
  const h=await setup(t), root=join(h.dir,'artifacts'), localRoot=root.replaceAll('\\','/');
  mkdirSync(root);
  const id=randomBytes(16).toString('hex'), token=randomBytes(32).toString('hex');
  const directory=join(root,'.ssh-transfer-'+token),file=join(directory,'data'),target=join(root,'artifact.bin');
  mkdirSync(directory);writeFileSync(file,'partial');writeFileSync(target,'published');
  const localDir=statSync(directory,{bigint:true}),localFile=statSync(file,{bigint:true});
  const partial={token,directory,path:file,dev:String(localFile.dev),ino:String(localFile.ino),directoryDev:String(localDir.dev),directoryIno:String(localDir.ino)};
  const host=(await h.call('ssh_status')).structuredContent.state.hosts[0],now=Date.now();
  const r={transferId:id,threadId:'owner',host,approvalPayload:{hostId:host.id},remoteToken:token,
    status:'cancelled',cancelConfirmed:true,createdAt:now,finishedAt:now,expiresAt:now-1,direction:'download',remotePath:'/srv/output.bin',
    remoteRoot:'/srv',localPath:target.replaceAll('\\','/'),localRoot,partial};
  const db=new DatabaseSync(join(h.dir,'transfers','transfers.sqlite'));try{
    db.prepare('INSERT INTO transfers(id,thread_id,record) VALUES(?,?,?)').run(id,r.threadId,JSON.stringify(r));
  }finally{db.close();}
  const enabledRoots=[{id:'artifacts',path:localRoot,read:true,write:true}];
  const current=(await h.call('ssh_permissions',{hostId:host.id})).structuredContent.policy;
  const policy={...current.policy,mode:'god',roots:[{id:'srv',path:'/srv',read:true,write:true}],localRoots:enabledRoots,transfers:{...current.policy.transfers,enabled:true}};
  const accept=m=>h.answer(m.id,{action:'accept',content:{confirm:true}});
  h.setElicitation(accept);
  const activate=await h.admin('ssh_policy_save',{hostId:host.id,expectedRevision:current.revision,policy,godAck:{hostId:host.id,expectedRevision:current.revision,confirmed:true}});
  assert.equal(activate.structuredContent.policy.policy.mode,'god');
  const grant=async()=>assert.deepEqual((await h.call('ssh_request_access',{hostIds:[host.id]})).structuredContent.state.grantedHostIds,[host.id]);
  await grant();
  const cleanup=()=>h.call('ssh_transfer_cleanup',{transferId:id,explanation:'测试清理已取消传输的私有文件并保留最终制品。'});
  h.setElicitation(m=>{assert.ok(promptText(m).includes(r.localPath));h.answer(m.id,{action:'decline'});});
  assert.equal((await cleanup()).structuredContent.code,'APPROVAL_DECLINED');
  assert.equal(readFileSync(file,'utf8'),'partial');
  h.setElicitation(accept);
  assert.ok(!(await h.patchPolicy({localRoots:[]})).isError);await grant();
  const prompts=h.prompts.length;
  assert.equal((await cleanup()).structuredContent.code,'TRANSFER_PATH_NOT_ALLOWED');
  assert.equal(h.prompts.length,prompts,'revoked root blocks approval');
  assert.ok(!(await h.patchPolicy({localRoots:[...enabledRoots,{id:'excluded',path:directory,read:false,write:false}]})).isError);await grant();
  const blocked=await cleanup();
  assert.equal(blocked.isError,true);assert.match(blocked.structuredContent.error,/protected local partial/);
  assert.equal(readFileSync(file,'utf8'),'partial');assert.equal(readFileSync(target,'utf8'),'published');
  assert.equal(await h.count(),0);
});

test('remote maintenance validates host, chat and native approval before dispatch',async t=>{
  const h=await setup(t,{initialMode:'readonly'}),r=await legacyJob(h);
  const hst={...r.host,sshAlias:'changed.example.invalid'};
  const mismatched=await legacyJob(h,{host:hst});
  await h.admin('ssh_lifecycle_sweep');
  assert.equal((await h.admin('ssh_lifecycle_inspect',req(r))).isError,true,'no chat grant');
  await h.grants();
  assert.equal((await h.admin('ssh_lifecycle_inspect',req(mismatched))).isError,true,'changed host identity');
  await h.admin('ssh_grant',{hostIds:[r.hostId]},'other');
  assert.equal((await h.admin('ssh_lifecycle_inspect',req(r),'other')).isError,true,'different owner');
  assert.equal(await h.count(),0);
  assert.equal((await h.admin('ssh_lifecycle_inspect',req(r))).structuredContent.measurement.bytes,240);
  assert.equal(await h.count(),1);
  assert.equal((await h.admin('ssh_lifecycle_collect',req(r))).structuredContent.code,'READ_ONLY_MODE');
  await h.patchPolicy({mode:'restricted'});await h.grants();
  h.setElicitation(m=>h.answer(m.id,{action:'decline'}));
  const rejected=await h.admin('ssh_lifecycle_collect',req(r));
  assert.equal(rejected.structuredContent.code,'APPROVAL_DECLINED');assert.equal(await h.count(),1);
  h.setElicitation(m=>{assert.ok(promptText(m).includes(r.id));h.answer(m.id,{action:'accept',content:{confirm:true}});});
  assert.equal((await h.admin('ssh_lifecycle_collect',req(r))).structuredContent.measurement.reclaimedBytes,200);
  assert.equal(await h.count(),2);
  assert.equal((await h.admin('ssh_lifecycle_overview')).structuredContent.archive.items.find(x=>x.id===r.id).remoteCleaned,true);
});
