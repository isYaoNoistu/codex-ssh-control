import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {Store} from '../src/store.mjs';

function setup(t){const dir=mkdtempSync(join(tmpdir(),'ssh-infra-store-'));const s=new Store(dir);s.saveHost({id:'app',sshAlias:'fixture',enabled:true});s.grant('owner',['app']);t.after(()=>{s.close();rmSync(dir,{recursive:true,force:true});});return {s,dir};}
function permit(s,kind='test'){return s.beginNativeOperation('owner','app',{kind},'验证独立测试主机的运行状态。',Math.random().toString(),s.getPolicy('app').revision);}
test('structured connection values compare semantically and changes revoke existing grants',t=>{
  const {s}=setup(t);
  s.saveHost({id:'app',connection:{mode:'native',trustedLocalConfig:true}});
  assert.equal(s.state('owner').grantedHostIds.length,0);
  s.grant('owner',['app']);
  s.saveHost({id:'app',connection:{trustedLocalConfig:true,mode:'native'}});
  assert.deepEqual(s.state('owner').grantedHostIds,['app']);
  s.saveHost({id:'app',connection:null});
  assert.deepEqual(s.state('owner').grantedHostIds,[]);
});
test('durable operations keep concurrency slots across lease expiry and plugin restart',t=>{
  const {s,dir}=setup(t);const p=s.getPolicy('app');s.savePolicy('owner','app',{...p.policy,maxConcurrent:1},p.revision);s.grant('owner',['app']);
  const op=permit(s);assert.equal(op.status,'ready');
  s.trackExternalOperation('owner',op.operationId,'job','remote-task');
  const db=new DatabaseSync(join(dir,'store.sqlite'));db.prepare('UPDATE operations SET expires_at=1 WHERE id=?').run(op.operationId);db.close();
  assert.equal(s.getExternalOperation('owner','job','remote-task').status,'active');
  assert.equal(permit(s).code,'CONCURRENCY_LIMIT');
  s.markOperationUnknown(op.operationId,'连接中断，等待核实');
  assert.equal(s.listHistory().items[0].status,'unknown');
  const second=new Store(dir);
  try { assert.equal(second.getExternalOperation('owner','job','remote-task').id,op.operationId);assert.throws(()=>second.getExternalOperation('other','job','remote-task')); }
  finally { second.close(); }
  s.finishOperation(op.operationId,{status:'completed',exitCode:0});
  assert.equal(permit(s).status,'ready');
});
test('control operations do not deadlock behind the job they must stop or inspect',t=>{
  const {s}=setup(t);const p=s.getPolicy('app');s.savePolicy('owner','app',{...p.policy,maxConcurrent:1},p.revision);s.grant('owner',['app']);
  const op=permit(s);s.trackExternalOperation('owner',op.operationId,'job','remote-task');
  const control=s.beginNativeOperation('owner','app',{kind:'job_control',id:'remote-task',action:'read'},'读取当前聊天任务的状态。','control-prompt',s.getPolicy('app').revision);
  assert.equal(control.status,'ready');
});
test('durable transfer approval cannot be resurrected by revoke and regrant',t=>{
  const {s}=setup(t);const op=permit(s);s.trackExternalOperation('owner',op.operationId,'transfer','upload-one');
  s.assertOperationReady('owner',op.operationId);
  s.revoke('owner',['app']);s.grant('owner',['app']);
  assert.throws(()=>s.assertOperationReady('owner',op.operationId),/失效/);
  assert.throws(()=>s.trackExternalOperation('other',op.operationId,'transfer','upload-two'));
});

function approved(s,threadId,hostId,operation){
  const token=Math.random().toString();
  const pending=s.beginNativeOperation(threadId,hostId,operation,'确认精确文件、目标和时限后继续传输。',token,s.getPolicy(hostId).revision);
  assert.equal(pending.status,'pending',JSON.stringify(pending));
  const ready=s.completeNativeApproval(threadId,pending.approval.id,token,'approve');
  assert.equal(ready.status,'ready',JSON.stringify(ready));
  return ready;
}
function transferFixture(t){
  const {s,dir}=setup(t),p=s.getPolicy('app');
  s.savePolicy('owner','app',{...p.policy,maxConcurrent:1,roots:[{id:'remote',path:'/srv/releases',read:true,write:true}],localRoots:[{id:'local',path:'C:/build',read:true,write:true}],transfers:{enabled:true}},p.revision);
  s.grant('owner',['app']);
  const operation={kind:'transfer',planId:'transfer-one',direction:'upload',localPath:'C:/build/app.jar',localRoot:'C:/build',remotePath:'/srv/releases/app.jar',remoteRoot:'/srv/releases',blockedPaths:[],localBlockedPaths:[],expiresAt:Date.now()+60000,maxBytes:1073741824,size:4096,sha256:'a'.repeat(64),sourceSnapshot:{dev:'1',ino:'2',size:4096,mtimeNs:'1',ctimeNs:'1',mode:420,sha256:'a'.repeat(64)},targetSnapshot:null,overwrite:'never'};
  const original=approved(s,'owner','app',operation);
  s.trackExternalOperation('owner',original.operationId,'transfer',operation.planId,{deadline:operation.expiresAt});
  return {s,dir,operation,original};
}

test('explicit transfer renewal keeps one durable slot and survives finishing the control request',t=>{
  const {s,dir,operation,original}=transferFixture(t);
  const historyId=s.listHistory().items.find(x=>x.operationId===original.operationId).id;
  const before=s.getHistory(historyId).operationSnapshot;
  const db=new DatabaseSync(join(dir,'store.sqlite'));db.prepare('UPDATE operations SET expires_at=1 WHERE id=?').run(original.operationId);db.close();
  const policy=s.getPolicy('app');s.savePolicy('owner','app',{...policy.policy,maxConcurrent:1},policy.revision);s.grant('owner',['app']);
  assert.throws(()=>s.assertOperationReady('owner',original.operationId));
  const transfer={...operation,expiresAt:Date.now()+120000};
  const control=approved(s,'owner','app',{kind:'transfer_control',action:'resume',id:operation.planId,transfer});
  const renewed=s.renewExternalOperation('owner',control.operationId,'transfer',operation.planId,{deadline:transfer.expiresAt});
  assert.equal(renewed.id,original.operationId);
  s.finishOperation(control.operationId,{status:'completed',exitCode:0});
  s.assertOperationReady('owner',original.operationId);
  assert.equal(permit(s).code,'CONCURRENCY_LIMIT');
  const after=s.getHistory(historyId).operationSnapshot;
  assert.deepEqual(after,before);
  assert.ok(s.listAudit().items.some(x=>x.event==='external_operation_renewed'&&x.operationId===original.operationId));
  s.revoke('owner',['app']);s.grant('owner',['app']);
  assert.throws(()=>s.assertOperationReady('owner',original.operationId));
});

test('renewal cannot change the frozen transfer, cross chats, replay, or revive completed work',t=>{
  const {s,operation,original}=transferFixture(t);
  const transfer={...operation,expiresAt:Date.now()+120000};
  const control=approved(s,'owner','app',{kind:'transfer_control',action:'resume',id:operation.planId,transfer});
  assert.throws(()=>s.renewExternalOperation('other',control.operationId,'transfer',operation.planId,{deadline:transfer.expiresAt}));
  assert.throws(()=>s.renewExternalOperation('owner',control.operationId,'job',operation.planId,{deadline:transfer.expiresAt}));
  assert.throws(()=>s.renewExternalOperation('owner',control.operationId,'transfer','not-this-plan',{deadline:transfer.expiresAt}));
  assert.throws(()=>s.renewExternalOperation('owner',control.operationId,'transfer',operation.planId,{deadline:transfer.expiresAt+1}));
  const changed=approved(s,'owner','app',{kind:'transfer_control',action:'resume',id:operation.planId,transfer:{...transfer,remotePath:'/srv/releases/other.jar'}});
  assert.throws(()=>s.renewExternalOperation('owner',changed.operationId,'transfer',operation.planId,{deadline:transfer.expiresAt}));
  s.renewExternalOperation('owner',control.operationId,'transfer',operation.planId,{deadline:transfer.expiresAt});
  assert.throws(()=>s.renewExternalOperation('owner',control.operationId,'transfer',operation.planId,{deadline:transfer.expiresAt}));
  s.finishOperation(original.operationId,{status:'completed',exitCode:0});
  const again=approved(s,'owner','app',{kind:'transfer_control',action:'resume',id:operation.planId,transfer});
  assert.throws(()=>s.renewExternalOperation('owner',again.operationId,'transfer',operation.planId,{deadline:transfer.expiresAt}));
});

test('transfer renewal rejects a newly approved different host or changed connection',t=>{
  const {s,operation}=transferFixture(t),transfer={...operation,expiresAt:Date.now()+120000};
  s.saveHost({id:'other',sshAlias:'second-fixture',enabled:true});
  const p=s.getPolicy('other');s.savePolicy('owner','other',s.getPolicy('app').policy,p.revision);s.grant('owner',['other']);
  const other=approved(s,'owner','other',{kind:'transfer_control',action:'resume',id:operation.planId,transfer});
  assert.throws(()=>s.renewExternalOperation('owner',other.operationId,'transfer',operation.planId,{deadline:transfer.expiresAt}));
  s.saveHost({id:'app',sshAlias:'changed-fixture'});s.grant('owner',['app']);
  const changed=approved(s,'owner','app',{kind:'transfer_control',action:'resume',id:operation.planId,transfer});
  assert.throws(()=>s.renewExternalOperation('owner',changed.operationId,'transfer',operation.planId,{deadline:transfer.expiresAt}));
});
