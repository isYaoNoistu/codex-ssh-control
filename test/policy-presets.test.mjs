import test from 'node:test';
import assert from 'node:assert/strict';
import {defaultPolicy,evaluateOperation} from '../src/policy.mjs';
import {setup,promptText} from './helpers/rpc-harness.mjs';

const raw = {kind:'command',command:'cat /etc/shadow',cwd:'/'};
const restart = {kind:'action',actionId:'service.restart',args:{name:'sshd'}};
const read = {kind:'action',actionId:'disk.usage'};
const logs = {kind:'action',actionId:'container.logs',args:{name:'jenkins'}};
const purpose='检查隔离测试主机的权限及执行结果。';
const job = {kind:'job',command:'echo hello',cwd:'/',env:{},shell:'/bin/sh',timeoutSeconds:5,maxOutputBytes:8192,disconnectPolicy:'continue'};
function decide(mode,operation,changes={}) {
  return evaluateOperation({...defaultPolicy(),...changes,mode},operation);
}

test('read-only preset rejects mutations, arbitrary shell, task controls and lifecycle deletion before execution',()=>{
  for(const operation of [restart,raw,{kind:'command',command:'echo benign'},
    {kind:'write',path:'/tmp/a',content:'ok'},{kind:'delete',path:'/tmp/a'},job,
    {kind:'job_control',id:'j1',action:'cancel'},{kind:'transfer_control',id:'x1',action:'cleanup'},
    {kind:'transfer_inspect',direction:'upload',remotePath:'/srv/x',localPath:'/tmp/x'},
    {kind:'lifecycle',action:'collect',resource:'job',id:'j1'}]) {
    assert.equal(decide('readonly',operation).code,'READ_ONLY_MODE');
  }
  assert.equal(decide('readonly',read).decision,'allow');
  assert.equal(decide('readonly',{kind:'command',command:'df -h'}).decision,'allow');
  assert.equal(decide('readonly',logs).decision,'ask');
  assert.equal(decide('readonly',{kind:'read',path:'/etc/shadow'}).decision,'deny');
});

test('god authorizes SSH account commands without changing transfer isolation or bypassing disabled jobs',()=>{
  const blocked={blockedPaths:['/etc'],commandRules:[{id:'deny',match:'prefix',pattern:'cat',decision:'deny'}],
    actions:{...defaultPolicy().actions,'service.restart':'deny'},actionArguments:{'service.restart':{names:['nginx']}}};
  for(const op of [raw,restart,logs]) {
    const allowed=decide('god',op,blocked);
    assert.equal(allowed.decision,'allow');assert.ok(allowed.command);
  }
  assert.equal(decide('god',raw,blocked).command,raw.command);
  assert.equal(decide('approval',raw,blocked).decision,'deny');
  assert.equal(decide('god',job).code,'JOBS_DISABLED');
  assert.equal(decide('god',{kind:'transfer_inspect',direction:'upload',remotePath:'/srv/x',localPath:'/tmp/x'}).code,'TRANSFERS_DISABLED');
  assert.equal(decide('god',{kind:'lifecycle',action:'collect',resource:'job',id:'j1'}).decision,'ask');
});

async function godDraft(h){
  const {policy,revision}= (await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy;
  return {hostId:'fixture',expectedRevision:revision,policy:{...policy,mode:'god'},
    godAck:{hostId:'fixture',expectedRevision:revision,confirmed:true}};
}
test('god activation is UI-only, requires native confirmation, revokes existing grants and cannot cross a changed endpoint',async t=>{
  const h=await setup(t,{initialMode:null});
  const args=await godDraft(h);
  assert.equal((await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy.policy.mode,'readonly');
  await h.grants();
  assert.equal((await h.call('ssh_policy_save',args)).isError,true);
  for(const godAck of [undefined,{...args.godAck,hostId:'other'},{...args.godAck,expectedRevision:0}]) {
    const draft={...args,godAck};if(!godAck)delete draft.godAck;
    assert.equal((await h.admin('ssh_policy_save',draft)).isError,true);
  }
  assert.equal(h.prompts.length,0);
  assert.equal((await h.admin('ssh_policy_save',args)).structuredContent.code,'APPROVAL_DECLINED');
  assert.deepEqual((await h.call('ssh_status')).structuredContent.state.grantedHostIds,['fixture']);
  let resolvePrompt;const pending=new Promise(resolve=>{resolvePrompt=resolve;});h.setElicitation(resolvePrompt);
  const save=h.admin('ssh_policy_save',args), prompt=await pending;
  assert.match(promptText(prompt),/密钥/);assert.match(promptText(prompt),/never-connect/);
  await h.admin('ssh_host_save',{host:{id:'fixture',sshAlias:'changed.invalid'}});
  h.answer(prompt.id,{action:'accept',content:{confirm:true}});
  assert.equal((await save).isError,true);
  h.setElicitation(m=>h.answer(m.id,{action:'accept',content:{confirm:true}}));
  await h.grants();
  const enabled=await h.admin('ssh_policy_save',await godDraft(h));
  assert.equal(enabled.structuredContent.policy.policy.mode,'god');assert.deepEqual(enabled.structuredContent.state.grantedHostIds,[]);
  assert.equal((await h.call('ssh_exec',{hostId:'fixture',command:raw.command,explanation:purpose})).isError,true);
  const access=await h.call('ssh_request_access',{hostIds:['fixture']});
  assert.deepEqual(access.structuredContent.state.grantedHostIds,['fixture']);
  assert.match(promptText(h.prompts.at(-1)),/完全控制/);
  const prompts=h.prompts.length;
  const result=await h.call('ssh_exec',{hostId:'fixture',command:raw.command,explanation:purpose});
  assert.ok(result.structuredContent.task);assert.equal(h.prompts.length,prompts);
  await h.admin('ssh_host_save',{host:{id:'fixture',name:'同一目标的新名称'}});
  assert.equal((await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy.policy.mode,'god');
  await h.admin('ssh_host_enabled',{hostId:'fixture',enabled:false});
  assert.equal((await h.call('ssh_task_cancel',{taskId:result.structuredContent.task.id})).isError,true);
  assert.equal((await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy.policy.mode,'god');
  await h.admin('ssh_host_save',{host:{id:'fixture',sshAlias:'new-endpoint.example.invalid'}});
  const rebound=(await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy;
  assert.equal(rebound.policy.mode,'readonly');assert.equal(rebound.revision,enabled.structuredContent.policy.revision+1);
});

test('client without elicitation cannot activate god mode',async t=>{
  const h=await setup(t,{elicitation:false,initialMode:null});
  assert.equal((await h.admin('ssh_policy_save',await godDraft(h))).structuredContent.code,'APPROVAL_UNSUPPORTED');
  assert.equal((await h.call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy.policy.mode,'readonly');
});
