import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

test('real stdio isolates chats, exposes native UI, validates inputs and requests explicit access',async()=>{
 const dir=await mkdtemp(path.join(tmpdir(),'ssh-control-test-'));
 const child=spawn(process.execPath,[fileURLToPath(new URL('../src/server.mjs',import.meta.url))],{env:{...process.env,SSH_CONTROL_DATA:dir,SSH_CONTROL_SKILLS:path.join(dir,'skills')},stdio:['pipe','pipe','pipe'],windowsHide:true});
 let next=0,errors='',elicitationAccept=false;const pending=new Map();
 child.stderr.on('data',b=>{errors+=b;});
 const send=m=>child.stdin.write(JSON.stringify({jsonrpc:'2.0',...m})+'\n');
 createInterface({input:child.stdout}).on('line',line=>{
  const m=JSON.parse(line);
  if(m.method==='elicitation/create')send({id:m.id,result:{action:elicitationAccept?'accept':'decline',content:{confirm:elicitationAccept}}});
  else if(pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);clearTimeout(p.timeout);m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);}
 });
 const request=(method,params)=>new Promise((resolve,reject)=>{const id=++next;const timeout=setTimeout(()=>reject(new Error('MCP request timeout '+errors)),5000);pending.set(id,{resolve,reject,timeout});send({id,method,params});});
 const call=(name,args={},threadId='a')=>request('tools/call',{name,arguments:args,_meta:threadId?{threadId,sessionId:'shared','x-codex-turn-metadata':{turn_id:'turn-'+threadId}}:{}});
 let uiToken;
 const admin=(name,args={},threadId='a')=>call(name,{...args,uiToken},threadId);
 try {
  await request('initialize',{protocolVersion:'2025-11-25',capabilities:{elicitation:{form:{}}},clientInfo:{name:'test',version:'1'}});
  const initialResources=await request('resources/list',{});
  const panel=await request('resources/read',{uri:initialResources.resources[0].uri});
  uiToken=panel.contents[0].text.match(/(?:const\s+UI_TOKEN\s*=\s*['"])([a-f0-9]{64})/)[1];
  const list=await request('tools/list',{});
  assert.ok(list.tools.find(t=>t.name==='ssh_manager')._meta['openai/ui'].entrypoints.some(e=>e.type==='thread'));
  assert.deepEqual(list.tools.find(t=>t.name==='ssh_grant')._meta.ui.visibility,['app']);
  assert.equal(list.tools.find(t=>t.name==='ssh_test_connection')?.annotations.readOnlyHint,true);
  assert.equal((await admin('ssh_host_save',{host:{id:'dev',sshAlias:'never-connect-test',enabled:true}})).isError,undefined);
  assert.equal((await admin('ssh_grant',{hostIds:['dev']})).isError,undefined);
  assert.deepEqual((await call('ssh_status',{},'b')).structuredContent.state.grantedHostIds,[]);
  assert.deepEqual((await call('ssh_status')).structuredContent.state.grantedHostIds,['dev']);
  assert.equal((await call('ssh_exec',{hostId:'dev',command:'true'},'b')).isError,true);
  assert.equal((await call('ssh_test_connection',{hostId:'dev'},'b')).isError,true);
  assert.equal((await call('ssh_test_connection',{hostId:'dev'},null)).isError,true);
  assert.equal((await call('ssh_test_connection',{hostId:'dev',command:'touch /tmp/unexpected'})).isError,true);
  assert.equal((await call('ssh_grant',{hostIds:['dev'],threadId:'a'},'b')).isError,true);
  assert.equal((await call('ssh_grant',{hostIds:['dev']},null)).isError,true);
  await call('ssh_request_access',{hostIds:['dev']},'b');
  assert.deepEqual((await call('ssh_status',{},'b')).structuredContent.state.grantedHostIds,[]);
  elicitationAccept=true;await call('ssh_request_access',{hostIds:['dev']},'b');
  assert.deepEqual((await call('ssh_status',{},'b')).structuredContent.state.grantedHostIds,['dev']);
  await admin('ssh_host_save',{host:{id:'dev',sshAlias:'changed-destination',enabled:true}});
  assert.deepEqual((await call('ssh_status')).structuredContent.state.grantedHostIds,[]);
  const resources=await request('resources/list',{});
  const resource=await request('resources/read',{uri:resources.resources[0].uri});
  assert.equal(resource.contents[0].mimeType,'text/html;profile=mcp-app');
  assert.deepEqual(resource.contents[0]._meta.ui.permissions,{clipboardWrite:{}});
  assert.ok(resource.contents[0].text.includes('ui/initialize'));
 }finally{
  child.stdin.end();await new Promise(resolve=>{child.once('close',resolve);setTimeout(()=>{child.kill();resolve();},1000).unref();});
  for(const p of pending.values())clearTimeout(p.timeout);
  await rm(dir,{recursive:true,force:true});
 }
});
