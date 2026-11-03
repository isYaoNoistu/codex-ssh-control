import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import path from 'node:path';
import {setup,pause,purpose} from './helpers/rpc-harness.mjs';
const args={hostId:'fixture',actionId:'container.stop',args:{name:'example'},explanation:purpose};

test('every remote entry fails closed before SSH and removed queue tools cannot approve',async t=>{
 const h=await setup(t);
 assert.equal((await h.call('ssh_grant',{hostIds:['fixture']})).isError,true);
 for(const [tool,input] of [
  ['ssh_exec',{command:'df -h',explanation:purpose}],['ssh_run_action',{actionId:'disk.usage',explanation:purpose}],['ssh_test_connection',{}],
  ['ssh_list_directory',{path:'/srv/app'}],['ssh_read_file',{path:'/srv/app/a'}],['ssh_write_file',{path:'/srv/app/a',content:'hello',explanation:purpose}],['ssh_delete_file',{path:'/srv/app/a',explanation:purpose}],
 ])assert.equal((await h.call(tool,{hostId:'fixture',...input})).isError,true,tool);
 await h.grants();
 assert.equal((await h.call('ssh_exec',{hostId:'fixture',command:'df -h'})).isError,true,'agent purpose required');
 for(const [tool,input] of [
  ['ssh_exec',{command:'df -h; cat /etc/shadow',explanation:purpose}],['ssh_run_action',{actionId:'service.stop',args:{name:'sshd'},explanation:purpose}],
  ['ssh_read_file',{path:'/root/.ssh/id_rsa'}],['ssh_list_directory',{path:'/srv/app'}],['ssh_write_file',{path:'/srv/app/a',content:'hello',explanation:purpose}],
 ])assert.equal((await h.call(tool,{hostId:'fixture',...input})).isError,true,tool);
 const definitions=(await h.rpc('tools/list',{})).tools;
 for(const name of ['ssh_approval_list','ssh_approval_resolve','ssh_approval_status']) assert.ok(!definitions.some(t=>t.name===name));
 assert.deepEqual(definitions.find(t=>t.name==='ssh_history_get')._meta.ui.visibility,['app']);
 assert.equal(await h.count(),0);
});

test('native prompt explains the action before exact command and accepting continues original call once',async t=>{
 const h=await setup(t);await h.grants();
 let notified;const prompt=new Promise(resolve=>{notified=resolve;});h.setElicitation(notified);
 const executing=h.call('ssh_run_action',args);const message=await prompt;
 assert.equal(await h.count(),0);assert.ok(message.params.message.includes(purpose));
 assert.ok(message.params.message.indexOf(purpose)<message.params.message.indexOf('/usr/bin/docker'));
 assert.match(message.params.message,/example/);assert.match(message.params.message,/fixture/);
 h.answer(message.id,{action:'accept',content:{confirm:true}});
 const response=await executing;assert.ok(response.structuredContent.task);assert.equal(response.structuredContent.approvalRequired,undefined);
 assert.equal(await h.count(),1);
 h.answer(message.id,{action:'accept',content:{confirm:true}});await pause();assert.equal(await h.count(),1);
 const history=(await h.admin('ssh_history_list')).structuredContent.items;
 assert.equal(history.length,1);assert.equal(history[0].status,'completed');
 const entry=(await h.admin('ssh_history_get',{historyId:history[0].id})).structuredContent.entry;
 assert.equal(entry.explanation,purpose);assert.match(entry.command,/docker.* stop .*example/);assert.match(entry.stdout,/fixture command completed/);assert.equal(entry.exitCode,0);
 assert.ok(!Object.hasOwn(entry.hostSnapshot,'identityFile'));
});

test('decline, cancel, missing capability and invalid confirmation never execute or leave approval reusable',async t=>{
 for(const response of [{action:'decline'},{action:'cancel'},{action:'accept',content:{confirm:false}}]){
  await t.test(response.action+JSON.stringify(response.content??{}),async t=>{
   const h=await setup(t);await h.grants();h.setElicitation(m=>h.answer(m.id,response));
   assert.equal((await h.call('ssh_run_action',args)).isError,true);assert.equal(await h.count(),0);
   assert.equal((await h.admin('ssh_history_list')).structuredContent.items.length,0);
   const db=new DatabaseSync(path.join(h.dir,'store.sqlite'));
   try{assert.equal(db.prepare("SELECT COUNT(*) n FROM approvals WHERE status IN ('pending','approved')").get().n,0);}finally{db.close();}
  });
 }
 await t.test('unsupported host',async t=>{const h=await setup(t,{elicitation:false});await h.grants();assert.equal((await h.call('ssh_run_action',args)).isError,true);assert.equal(await h.count(),0);});
});

test('request cancellation terminates native prompt and ignores late accept',async t=>{
 const h=await setup(t);await h.grants();let notify;const prompt=new Promise(resolve=>{notify=resolve;});h.setElicitation(notify);
 const executing=h.call('ssh_run_action',args);const message=await prompt;
 h.cancel(executing.requestId);const result=await executing;assert.equal(result.isError,true);
 h.answer(message.id,{action:'accept',content:{confirm:true}});await pause();assert.equal(await h.count(),0);
 const db=new DatabaseSync(path.join(h.dir,'store.sqlite'));try{assert.equal(db.prepare("SELECT COUNT(*) n FROM approvals WHERE status IN ('pending','approved')").get().n,0);}finally{db.close();}
});

test('changing policy during a native operation prompt invalidates acceptance',async t=>{
 const h=await setup(t);await h.grants();let notify;const prompt=new Promise(resolve=>{notify=resolve;});h.setElicitation(notify);
 const executing=h.call('ssh_run_action',args);const message=await prompt;await h.patchPolicy({maxConcurrent:1});await h.grants();
 h.answer(message.id,{action:'accept',content:{confirm:true}});assert.equal((await executing).isError,true);assert.equal(await h.count(),0);
});

test('same operation in simultaneous native calls requires two distinct user decisions',async t=>{
 const h=await setup(t);await h.grants();let notify;const ready=new Promise(resolve=>{notify=resolve;});const prompts=[];
 h.setElicitation(m=>{prompts.push(m);if(prompts.length===2)notify();});
 const first=h.call('ssh_run_action',args),second=h.call('ssh_run_action',args);await ready;
 assert.notEqual(prompts[0].id,prompts[1].id);h.answer(prompts[0].id,{action:'accept',content:{confirm:true}});h.answer(prompts[1].id,{action:'decline'});
 const results=await Promise.all([first,second]);assert.equal(results.filter(r=>r.structuredContent?.task).length,1);assert.equal(await h.count(),1);
});

test('history contains actual fixed commands, redacts sensitive output and is UI only',async t=>{
 const h=await setup(t);await h.grants();
 const result=await h.call('ssh_exec',{hostId:'fixture',command:'df -h',cwd:'/not-allowed',explanation:'查看文件系统容量，确认是否需要清理空间。'});
 assert.ok(result.structuredContent.task);assert.equal(result.structuredContent.task.cwd,'');await pause();
 let records=(await h.admin('ssh_history_list')).structuredContent.items;
 let entry=(await h.admin('ssh_history_get',{historyId:records[0].id})).structuredContent.entry;
 assert.equal(entry.requestedCommand,'df -h');assert.match(entry.command,/env -i/);assert.equal(entry.cwd,'/');
 assert.equal((await h.call('ssh_history_get',{historyId:entry.id})).isError,true);
 assert.equal((await h.admin('ssh_history_get',{historyId:999999})).isError,true);
 await h.patchPolicy({mode:'approval'});await h.grants();h.setElicitation(m=>h.answer(m.id,{action:'accept',content:{confirm:true}}));
 const raw=await h.call('ssh_exec',{hostId:'fixture',command:'echo diagnostic-sensitive-fixture',explanation:'输出测试标记，验证执行历史会隐藏敏感返回值。'});assert.ok(raw.structuredContent.task);await pause();
 records=(await h.admin('ssh_history_list')).structuredContent.items;
 entry=(await h.admin('ssh_history_get',{historyId:records[0].id})).structuredContent.entry;
 assert.equal(entry.redacted,true);assert.equal(entry.stdout,'');assert.ok(!JSON.stringify(entry).includes('test-fixture-value'));
 assert.equal((await h.call('ssh_task_read',{taskId:raw.structuredContent.task.id},'other')).isError,true);
});

test('native host confirmation cannot authorize a broader policy changed while its prompt is open',async t=>{
 const h=await setup(t);await h.patchPolicy({grantMinutes:5});let notify;const prompt=new Promise(resolve=>{notify=resolve;});h.setElicitation(notify);
 const access=h.call('ssh_request_access',{hostIds:['fixture']});const message=await prompt;assert.match(message.params.message,/5 分钟/);
 await h.patchPolicy({grantMinutes:1440});h.answer(message.id,{action:'accept',content:{confirm:true}});assert.equal((await access).isError,true);
 assert.deepEqual((await h.call('ssh_status')).structuredContent.state.grantedHostIds,[]);
});

test('file approval shows the exact content; history retains safe metadata and result, not file bodies or helper input',async t=>{
 const h=await setup(t);await h.patchPolicy({roots:[{id:'app',path:'/srv/app',read:true,write:true}]});await h.grants();
 const content='This file body must never remain in execution history.';
 h.setElicitation(m=>{assert.ok(m.params.message.includes(content));assert.ok(m.params.message.includes('/srv/app/test.txt'));h.answer(m.id,{action:'accept',content:{confirm:true}});});
 const written=await h.call('ssh_write_file',{hostId:'fixture',path:'/srv/app/test.txt',content,explanation:'更新测试文件的非敏感内容，确认原生审批后的写入流程。'});
 assert.equal(written.structuredContent.result.written,true);
 const read=await h.call('ssh_read_file',{hostId:'fixture',path:'/srv/app/public.txt'});assert.equal(read.structuredContent.content,'fixture readable file body');
 const list=(await h.admin('ssh_history_list')).structuredContent.items;assert.equal(list.length,2);
 const details=await Promise.all(list.map(async item=>(await h.admin('ssh_history_get',{historyId:item.id})).structuredContent.entry));
 const serialized=JSON.stringify(details);assert.ok(!serialized.includes(content));assert.ok(!serialized.includes('fixture readable file body'));assert.ok(!serialized.includes('base64'));
 assert.equal(details.find(entry=>entry.operationSnapshot.kind==='write').operationSnapshot.bytes,Buffer.byteLength(content));
 assert.match(details.find(entry=>entry.operationSnapshot.kind==='read').stdout,/正文未保存/);
});

test('connection checks are also persisted with result and exit code',async t=>{
 const h=await setup(t);await h.grants();
 const result=await h.call('ssh_test_connection',{hostId:'fixture'});assert.equal(result.structuredContent.connectionTest.ok,true);
 const list=(await h.admin('ssh_history_list')).structuredContent.items;
 const entry=(await h.admin('ssh_history_get',{historyId:list[0].id})).structuredContent.entry;
 assert.equal(entry.status,'completed');assert.equal(entry.exitCode,0);assert.match(entry.stdout,/SSH_CONTROL_OK/);
});

test('same-packet cancellation prevents auto-allowed execution after its gate resolves',async t=>{
 const h=await setup(t);await h.grants();
 const result=await h.call('ssh_exec',{hostId:'fixture',command:'df -h',explanation:'查看当前文件系统容量'},'owner',{cancelImmediately:true});
 assert.equal(result.isError,true);
 assert.equal(result.structuredContent.code,'APPROVAL_CANCELLED');
 assert.equal(await h.count(),0);
 const history=(await h.admin('ssh_history_list')).structuredContent.items;
 assert.equal(history.length,1);assert.equal(history[0].status,'cancelled');
 const db=new DatabaseSync(path.join(h.dir,'store.sqlite'));
 try{assert.equal(db.prepare("SELECT COUNT(*) n FROM operations WHERE status='active'").get().n,0);}finally{db.close();}
});

test('same-packet host approval accept and cancellation do not grant access',async t=>{
 const h=await setup(t);let access;
 h.setElicitation(message=>h.answerAndCancel(message.id,{action:'accept',content:{confirm:true}},access.requestId));
 access=h.call('ssh_request_access',{hostIds:['fixture']});
 const result=await access;assert.equal(result.isError,true);
 assert.equal(result.structuredContent.code,'APPROVAL_CANCELLED');
 assert.deepEqual((await h.call('ssh_status')).structuredContent.state.grantedHostIds,[]);
 assert.equal(await h.count(),0);
});

test('file completion propagates scanner sensitivity from stderr to persistent history',async t=>{
 const h=await setup(t);await h.patchPolicy({roots:[{id:'app',path:'/srv/app',read:true,write:true}]});await h.grants();
 const response=await h.call('ssh_read_file',{hostId:'fixture',path:'/srv/app/diagnostic-stderr-fixture.txt'});
 assert.equal(response.structuredContent.content,'fixture readable file body');
 const list=(await h.admin('ssh_history_list')).structuredContent.items;
 const entry=(await h.admin('ssh_history_get',{historyId:list[0].id})).structuredContent.entry;
 assert.equal(entry.redacted,true);assert.equal(entry.stdout,'');assert.equal(entry.stderr,'');assert.ok(entry.outputNotice);
 assert.ok(!JSON.stringify(entry).includes('stderr-fixture-value'));
});

test('server shutdown cancels outstanding native approvals before closing the store',async t=>{
 const h=await setup(t);await h.grants();let notify;const prompt=new Promise(resolve=>{notify=resolve;});h.setElicitation(notify);
 const executing=h.call('ssh_run_action',args);executing.catch(()=>{});
 await prompt;await h.stop();
 assert.equal(await h.count(),0);
 const db=new DatabaseSync(path.join(h.dir,'store.sqlite'));
 try{
  assert.equal(db.prepare("SELECT COUNT(*) n FROM approvals WHERE source='native' AND status IN ('pending','approved')").get().n,0);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM execution_history').get().n,0);
 }finally{db.close();}
});

test('same-packet revocation, regrant and policy changes invalidate a permit before SSH starts',async t=>{
 for(const scenario of ['revoke','revoke-regrant','policy-save'])await t.test(scenario,async t=>{
  const h=await setup(t);await h.grants();
  const record=(await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy;
  const mutations=scenario==='policy-save'?[{name:'ssh_policy_save',admin:true,args:{hostId:'fixture',policy:{...record.policy,maxConcurrent:1},expectedRevision:record.revision}}]:[
   {name:'ssh_revoke',admin:true,args:{hostIds:['fixture']}},
   ...(scenario==='revoke-regrant'?[{name:'ssh_grant',admin:true,args:{hostIds:['fixture']}}]:[]),
  ];
  const results=await h.batchCalls([{name:'ssh_exec',args:{hostId:'fixture',command:'df -h',explanation:'查看当前文件系统容量'}},...mutations]);
  assert.equal(await h.count(),0,'revoked permit must not reach SSH');
  assert.equal(results[0].isError,true);assert.equal(results[0].structuredContent.code,'OPERATION_INVALIDATED');
  for(const result of results.slice(1))assert.equal(result.isError,undefined);
  const history=(await h.admin('ssh_history_list')).structuredContent.items;
  assert.equal(history.length,1);assert.equal(history[0].status,'cancelled');
  if(scenario==='revoke-regrant')assert.deepEqual((await h.call('ssh_status')).structuredContent.state.grantedHostIds,['fixture']);
 });
});
