import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {setup,pause} from './helpers/rpc-harness.mjs';

const explanation='查看命令的工作目录，验证主机默认目录和审批内容一致。';

async function configured(t,defaultCwd='/srv/fixture-app',policy={}) {
 const h=await setup(t);
 assert.equal((await h.admin('ssh_host_save',{host:{id:'fixture',defaultCwd}})).isError,undefined);
 assert.equal((await h.patchPolicy({mode:'approval',...policy})).isError,undefined);
 await h.grants();
 h.setElicitation(m=>h.answer(m.id,{action:'accept',content:{confirm:true}}));
 return h;
}

async function latest(h) {
 const history=(await h.admin('ssh_history_list')).structuredContent.items;
 return (await h.admin('ssh_history_get',{historyId:history[0].id})).structuredContent.entry;
}

async function command(h) {
 return JSON.parse((await readFile(path.join(h.dir,'spawns'),'utf8')).trim().split('\n').at(-1)).args.at(-1);
}

test('omitted raw command cwd uses the host default in approval, execution and history',async t=>{
 const h=await configured(t);
 const response=await h.call('ssh_exec',{hostId:'fixture',command:'pwd',explanation});
 assert.equal(response.isError,undefined);
 assert.equal(response.structuredContent.task.cwd,'/srv/fixture-app');
 assert.match(h.prompts[0].params.message,/工作目录：\/srv\/fixture-app/);
 assert.equal(await command(h),"cd -- '/srv/fixture-app' || exit $?;\npwd");
 const entry=await latest(h);
 assert.equal(entry.cwd,'/srv/fixture-app');
 assert.equal(entry.operationSnapshot.cwd,'/srv/fixture-app');
 assert.equal(entry.command,'pwd');
});

test('an explicit raw cwd overrides the host default in every execution view',async t=>{
 const h=await configured(t);
 const response=await h.call('ssh_exec',{hostId:'fixture',command:'pwd',cwd:'/srv/override',explanation});
 assert.equal(response.isError,undefined);
 assert.equal(response.structuredContent.task.cwd,'/srv/override');
 assert.match(h.prompts[0].params.message,/工作目录：\/srv\/override/);
 assert.equal(await command(h),"cd -- '/srv/override' || exit $?;\npwd");
 assert.equal((await latest(h)).cwd,'/srv/override');
});

test('explicit empty cwd and an unconfigured default preserve the SSH login directory',async t=>{
 for(const [name,defaultCwd,input] of [['explicit empty','/srv/fixture-app',{cwd:''}],['unconfigured','',{}]])await t.test(name,async t=>{
  const h=await configured(t,defaultCwd);
  const response=await h.call('ssh_exec',{hostId:'fixture',command:'pwd',explanation,...input});
  assert.equal(response.isError,undefined);
  assert.equal(response.structuredContent.task.cwd,'');
  assert.match(h.prompts[0].params.message,/工作目录：\(SSH默认目录\)/);
  assert.equal(await command(h),'pwd');
  assert.equal((await latest(h)).cwd,'(SSH默认目录)');
 });
});

test('protected and policy-blocked defaults are denied before approval or SSH',async t=>{
 for(const [name,defaultCwd,policy] of [['protected','/root/.ssh',{}],['blocked','/srv/private',{blockedPaths:['/srv/private']}]])await t.test(name,async t=>{
  const h=await configured(t,defaultCwd,policy);
  const response=await h.call('ssh_exec',{hostId:'fixture',command:'pwd',explanation});
  assert.equal(response.isError,true);
  assert.equal(response.structuredContent.code,'SENSITIVE_COMMAND');
  assert.equal(h.prompts.length,0);
  assert.equal(await h.count(),0);
  assert.equal((await h.admin('ssh_history_list')).structuredContent.items.length,0);
 });
});

test('fixed actions and safe aliases keep their isolated cwd even with a protected host default',async t=>{
 const h=await configured(t,'/root/.ssh');
 for(const [name,args] of [['ssh_run_action',{actionId:'disk.usage',explanation}],['ssh_exec',{command:'df -h',explanation}],['ssh_test_connection',{}]]){
  const response=await h.call(name,{hostId:'fixture',...args});
  assert.equal(response.isError,undefined,name);
  assert.equal(h.prompts.length,0);
  assert.match(await command(h),/^cd \/ && \/usr\/bin\/env -i /);
  assert.equal((await latest(h)).cwd,'/');
  await pause();
 }
 assert.equal(await h.count(),3);
});

test('policy previews resolve the same saved default and explicit override as execution',async t=>{
 const h=await configured(t,'/root/.ssh');
 let preview=(await h.admin('ssh_policy_preview',{hostId:'fixture',operation:{kind:'command',command:'pwd'}})).structuredContent.evaluation;
 assert.equal(preview.operation.cwd,'/root/.ssh');
 assert.equal(preview.code,'SENSITIVE_COMMAND');
 preview=(await h.admin('ssh_policy_preview',{hostId:'fixture',operation:{kind:'command',command:'pwd',cwd:'/srv/override'}})).structuredContent.evaluation;
 assert.equal(preview.operation.cwd,'/srv/override');
 assert.equal(preview.decision,'ask');
 preview=(await h.admin('ssh_policy_preview',{hostId:'fixture',operation:{kind:'command',command:'pwd',cwd:''}})).structuredContent.evaluation;
 assert.equal(preview.operation.cwd,'');
 assert.equal(preview.decision,'ask');
 assert.equal(await h.count(),0);
});

test('changing the default while its command approval is open invalidates the old execution',async t=>{
 const h=await configured(t);
 let notify;const prompt=new Promise(resolve=>{notify=resolve;});h.setElicitation(notify);
 const executing=h.call('ssh_exec',{hostId:'fixture',command:'pwd',explanation});
 const message=await prompt;
 assert.equal((await h.admin('ssh_host_save',{host:{id:'fixture',defaultCwd:'/srv/replacement'}})).isError,undefined);
 await h.grants();
 h.answer(message.id,{action:'accept',content:{confirm:true}});
 assert.equal((await executing).isError,true);
 assert.equal(await h.count(),0);
});
