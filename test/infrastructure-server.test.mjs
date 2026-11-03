import test from 'node:test';
import assert from 'node:assert/strict';
import {setup} from './helpers/rpc-harness.mjs';

test('new infrastructure tools are discoverable and key management is app-only',async t=>{
  const h=await setup(t);const {tools}=await h.rpc('tools/list',{});
  for(const name of ['ssh_capabilities','ssh_job_submit','ssh_job_read','ssh_job_cancel','ssh_job_list','ssh_transfer_prepare','ssh_transfer_start','ssh_transfer_read','ssh_transfer_resume','ssh_host_key_scan','ssh_host_keys_confirm'])assert.ok(tools.some(x=>x.name===name),name);
  for(const name of ['ssh_host_key_scan','ssh_host_keys_confirm'])assert.deepEqual(tools.find(x=>x.name===name)._meta.ui.visibility,['app']);
});
test('background execution fails closed before SSH when disabled or approval rejected',async t=>{
  const h=await setup(t);await h.grants();
  const args={hostId:'fixture',command:'sleep 10',cwd:'/srv/app',explanation:'后台执行测试命令，验证明确批准后才启动。'};
  assert.equal((await h.call('ssh_job_submit',args)).isError,true);assert.equal(await h.count(),0);
  await h.patchPolicy({mode:'approval',jobs:{enabled:true}});await h.grants();
  h.setElicitation(m=>h.answer(m.id,{action:'decline'}));
  const denied=await h.call('ssh_job_submit',args);
  assert.equal(denied.structuredContent.code,'APPROVAL_DECLINED');assert.equal(await h.count(),0);
});
test('new limits and complete job execution options appear in native confirmation',async t=>{
  const h=await setup(t);await h.patchPolicy({mode:'approval',jobs:{enabled:true,allowedEnv:['APP_MODE']}});await h.grants();
  h.setElicitation(m=>h.answer(m.id,{action:'decline'}));
  await h.call('ssh_job_submit',{hostId:'fixture',command:'sleep 10',cwd:'/srv/app',env:{APP_MODE:'staging'},timeoutSeconds:700,explanation:'让测试任务在断线后继续，并限制运行时间。'});
  assert.equal(h.prompts.length,1);const message=h.prompts[0].params.message;
  for(const piece of ['sleep 10','/srv/app','APP_MODE','staging','700','continue'])assert.ok(message.includes(piece),piece);
});
test('artifact inspection cannot read local files or start SSH without both path permissions',async t=>{
  const h=await setup(t);await h.patchPolicy({transfers:{enabled:true}});await h.grants();
  const r=await h.call('ssh_transfer_prepare',{hostId:'fixture',direction:'upload',localPath:'C:/outside/app.jar',remotePath:'/srv/app.jar'});
  assert.equal(r.structuredContent.code,process.platform==='darwin'?'PLATFORM_UNSUPPORTED':'TRANSFER_PATH_NOT_ALLOWED');assert.equal(await h.count(),0);
});
test('task and transfer lists do not leak another chat records or execute SSH',async t=>{
  const h=await setup(t);
  assert.deepEqual((await h.call('ssh_job_list')).structuredContent.jobs,[]);
  assert.deepEqual((await h.call('ssh_transfer_list')).structuredContent.transfers,[]);
  assert.equal(await h.count(),0);
});
