import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import path from 'node:path';
import {setup,pause,promptText} from './helpers/rpc-harness.mjs';
import {Store} from '../src/store.mjs';

const explanation='读取指定容器的近期有限日志，以排查运行故障。';
const request=(args={name:'example'})=>({hostId:'fixture',actionId:'container.logs',args,explanation});
const expectedCommand="cd / && /usr/bin/env -i PATH=/usr/bin:/bin HOME=/proc/self/fd LANG=C LC_ALL=C SYSTEMD_PAGER=cat SYSTEMD_COLORS=0 /usr/bin/docker --config /proc/self/fd --host unix:///var/run/docker.sock logs --since '900s' --tail 300 --timestamps -- 'example'";

async function pendingApproval(h,input=request()){
 let notify;const prompt=new Promise(resolve=>{notify=resolve;});h.setElicitation(notify);
 const executing=h.call('ssh_run_action',input);
 const message=await Promise.race([prompt,executing.then(result=>({result}))]);
 assert.equal(message.method,'elicitation/create',message.result?.structuredContent?.error);
 return {executing,message};
}

test('container logs waits for confirmation and executes exactly the displayed bounded command once',async t=>{
 const h=await setup(t);await h.grants();
 const {executing,message}=await pendingApproval(h);
 assert.equal(await h.count(),0);
 assert.ok(promptText(message).includes(explanation));
 assert.ok(promptText(message).includes(expectedCommand));
 const presentation=message.params._meta['openai/confirmation'].presentation;
 assert.equal(presentation.destructive,false);
 assert.ok(presentation.fields.some(field=>field.value.includes(expectedCommand)));
 h.answer(message.id,{action:'accept',content:{confirm:true}});
 const response=await executing;
 assert.equal(response.isError,undefined);
 assert.equal(response.structuredContent.task.command,expectedCommand);
 assert.equal(await h.count(),1);
 h.answer(message.id,{action:'accept',content:{confirm:true}});await pause();
 const spawns=(await readFile(path.join(h.dir,'spawns'),'utf8')).trim().split('\n').map(JSON.parse);
 assert.equal(spawns.length,1);
 assert.equal(spawns[0].args.at(-1),expectedCommand);
 const history=(await h.admin('ssh_history_list')).structuredContent.items;
 assert.equal(history.length,1);
 const entry=(await h.admin('ssh_history_get',{historyId:history[0].id})).structuredContent.entry;
 assert.equal(entry.status,'completed');
 assert.equal(entry.command,expectedCommand);
 assert.deepEqual(entry.operationSnapshot,{kind:'action',actionId:'container.logs',args:{name:'example',tail:300,sinceMinutes:15}});
});

test('container logs catalog is read-only but its policy cannot allow automatic execution',async t=>{
 const h=await setup(t);await h.grants();
 const permissions=(await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent;
 const action=permissions.actions.find(item=>item.id==='container.logs');
 assert.ok(action);assert.equal(action.mutating,false);assert.equal(action.approvalRequired,true);assert.equal(action.defaultDecision,'ask');
 assert.equal(permissions.policy.policy.actions['container.logs'],'ask');
 const allow=await h.patchPolicy({actions:{...permissions.policy.policy.actions,'container.logs':'allow'}});
 assert.equal(allow.isError,true);
 assert.equal((await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy.revision,permissions.policy.revision);
 assert.equal((await h.patchPolicy({actions:{...permissions.policy.policy.actions,'container.logs':'deny'}})).isError,undefined);
 await h.grants();
 assert.equal((await h.call('ssh_run_action',request())).isError,true);
 assert.equal(h.prompts.length,0);assert.equal(await h.count(),0);
});

test('container logs displays and executes the same explicit bounds',async t=>{
 const h=await setup(t);await h.grants();
 const {executing,message}=await pendingApproval(h,request({name:'app-1',tail:75,sinceMinutes:2}));
 const command=expectedCommand.replace("'900s' --tail 300","'120s' --tail 75").replace("'example'","'app-1'");
 assert.equal(await h.count(),0);assert.ok(promptText(message).includes(command));
 h.answer(message.id,{action:'accept',content:{confirm:true}});
 const response=await executing;
 assert.equal(response.structuredContent.task.command,command);
 const spawns=(await readFile(path.join(h.dir,'spawns'),'utf8')).trim().split('\n').map(JSON.parse);
 assert.equal(spawns.length,1);assert.equal(spawns[0].args.at(-1),command);
});

test('declined, cancelled or unchecked container log confirmations never start SSH',async t=>{
 for(const response of [{action:'decline'},{action:'cancel'},{action:'accept',content:{confirm:false}}])await t.test(response.action+JSON.stringify(response.content??{}),async t=>{
  const h=await setup(t);await h.grants();
  const {executing,message}=await pendingApproval(h);
  h.answer(message.id,response);
  assert.equal((await executing).isError,true);assert.equal(await h.count(),0);
  assert.equal((await h.admin('ssh_history_list')).structuredContent.items.length,0);
  const db=new DatabaseSync(path.join(h.dir,'store.sqlite'));
  try{assert.equal(db.prepare("SELECT COUNT(*) n FROM approvals WHERE status IN ('pending','approved')").get().n,0);}finally{db.close();}
 });
});

test('cancelling a container logs request rejects a late confirmation without SSH',async t=>{
 const h=await setup(t);await h.grants();
 const {executing,message}=await pendingApproval(h);
 h.cancel(executing.requestId);
 assert.equal((await executing).isError,true);
 h.answer(message.id,{action:'accept',content:{confirm:true}});await pause();
 assert.equal(await h.count(),0);
 assert.equal((await h.admin('ssh_history_list')).structuredContent.items.length,0);
});

test('revoking access while container logs confirmation is open prevents SSH',async t=>{
 const h=await setup(t);await h.grants();
 const {executing,message}=await pendingApproval(h);
 assert.equal((await h.admin('ssh_revoke',{hostIds:['fixture']})).isError,undefined);
 h.answer(message.id,{action:'accept',content:{confirm:true}});
 assert.equal((await executing).isError,true);assert.equal(await h.count(),0);
 assert.deepEqual((await h.call('ssh_status')).structuredContent.state.grantedHostIds,[]);
 assert.equal((await h.admin('ssh_history_list')).structuredContent.items.length,0);
});

test('invalid container log names, bounds and unsupported flags fail before approval or SSH',async t=>{
 const h=await setup(t);await h.grants();
 for(const args of [
  {},{name:'-example'},{name:'example;id'},{name:'example\nother'},{name:'../example'},
  ...[0,1001,-1,1.5,'300',null].map(tail=>({name:'example',tail})),
  ...[0,1441,-1,1.5,'15',null].map(sinceMinutes=>({name:'example',sinceMinutes})),
  {name:'example',follow:true},{name:'example',details:true},{name:'example',since:'2026-01-01'},
 ]){
  assert.equal((await h.call('ssh_run_action',request(args))).isError,true,JSON.stringify(args));
 }
 assert.equal(h.prompts.length,0);assert.equal(await h.count(),0);
 assert.equal((await h.admin('ssh_history_list')).structuredContent.items.length,0);
});

test('sensitive container log stdout or stderr is hidden from task tools and execution history',async t=>{
 for(const [name,marker] of [['diagnostic-sensitive-fixture','test-fixture-value'],['diagnostic-stderr-fixture','stderr-fixture-value']])await t.test(name,async t=>{
  const h=await setup(t);await h.grants();
  const {executing,message}=await pendingApproval(h,request({name}));
  h.answer(message.id,{action:'accept',content:{confirm:true}});
  const response=await executing;assert.ok(response.structuredContent.task);await pause();
  const result=await h.call('ssh_task_read',{taskId:response.structuredContent.task.id});
  assert.equal(result.structuredContent.task.status,'completed');
  assert.equal(result.structuredContent.task.sensitiveOutput,true);
  assert.equal(result.structuredContent.task.redacted,true);assert.equal(result.structuredContent.task.stdout,'');
  const cancel=await h.call('ssh_task_cancel',{taskId:response.structuredContent.task.id});
  const records=await h.admin('ssh_history_list');assert.equal(records.structuredContent.items.length,1);
  const history=await h.admin('ssh_history_get',{historyId:records.structuredContent.items[0].id});
  assert.equal(history.structuredContent.entry.redacted,true);
  assert.equal(history.structuredContent.entry.stdout,'');assert.equal(history.structuredContent.entry.stderr,'');
  assert.ok(history.structuredContent.entry.outputNotice);
  for(const output of [response,result,cancel,records,history])assert.ok(!JSON.stringify(output).includes(marker));
  const db=new DatabaseSync(path.join(h.dir,'store.sqlite'));
  try{assert.ok(!JSON.stringify(db.prepare('SELECT * FROM execution_history').all()).includes(marker));}finally{db.close();}
  assert.equal(await h.count(),1);
 });
});

test('legacy policies gain an ask-only log action on read and restart without widening grants or existing rules',async t=>{
 const h=await setup(t);
 const current=(await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy;
 assert.equal((await h.patchPolicy({
  actions:{...current.policy.actions,'docker.containers':'deny'},
  commandRules:[{id:'no-stop',match:'exact',pattern:'container.stop',decision:'deny'}],
  roots:[{id:'app',path:'/srv/app',read:true,write:false}],grantMinutes:5,
 })).isError,undefined);
 await h.grants();
 const before=(await h.call('ssh_status')).structuredContent.state;
 const original=before.policies[0];
 const db=new DatabaseSync(path.join(h.dir,'store.sqlite'));
 try{
  const legacy=structuredClone(original.policy);delete legacy.actions['container.logs'];
  db.prepare('UPDATE policies SET value=? WHERE host_id=?').run(JSON.stringify(legacy),'fixture');
 }finally{db.close();}
 const read=(await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy;
 assert.deepEqual(read,original);assert.equal(read.policy.actions['container.logs'],'ask');
 const {executing,message}=await pendingApproval(h);
 assert.equal(await h.count(),0);h.answer(message.id,{action:'decline'});assert.equal((await executing).isError,true);
 await h.stop();
 const restarted=new Store(h.dir);
 try{
  assert.deepEqual(restarted.getPolicy('fixture'),original);
  const after=restarted.state('owner');
  assert.deepEqual(after.grants,before.grants);assert.deepEqual(after.grantedHostIds,before.grantedHostIds);
  assert.deepEqual(restarted.state('other').grantedHostIds,[]);
  assert.equal(restarted.beginOperation('owner','fixture',{kind:'action',actionId:'container.logs',args:{name:'example'}},{},original.revision).status,'pending');
  assert.equal(restarted.beginOperation('owner','fixture',{kind:'action',actionId:'container.stop',args:{name:'example'}},{},original.revision).code,'ACTION_DENIED');
  assert.equal(restarted.beginOperation('owner','fixture',{kind:'action',actionId:'docker.containers',args:{}},{},original.revision).code,'ACTION_DENIED');
 }finally{restarted.close();}
 assert.equal(await h.count(),0);
});
