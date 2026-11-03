import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFixture } from './fixture.mjs';
import { prepareInvocation } from '../../src/transport.mjs';
import { buildRemoteCapabilityProbe, parseRemoteCapabilities, classifySshError } from '../../src/capabilities.mjs';
import { JobService } from '../../src/job-service.mjs';

test('isolated real SSH transport and task lifecycle',{timeout:900000},async t=>{
 const f=createFixture(),state=mkdtempSync(join(tmpdir(),'si-'));
 t.after(()=>{try{f.cleanup();}finally{rmSync(state,{recursive:true,force:true});}});
 const ssh=(host,command,input)=>{const p=prepareInvocation(host,command,'',{dataDir:state});const r=spawnSync(p.file,p.args,{input,encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:2000000});if(r.error)throw r.error;return {stdout:r.stdout,stderr:r.stderr,exitCode:r.status,status:r.status===0?'completed':'failed'};};
 await t.test('direct and ProxyJump authenticate ordinary user and root',()=>{for(const user of ['tester','root'])for(const viaJump of [false,true]){const r=ssh(f.host(user,{viaJump}),'id -un');assert.equal(r.exitCode,0,r.stderr);assert.equal(r.stdout.trim(),user);}});
 await t.test('each hop rejects an incorrect pinned host key',()=>{
  for(const hop of ['target','jump']){const h=f.host('tester',{viaJump:true});if(hop==='target')h.connection.hostKeys=[f.jump.hostKey];else h.connection.jumpHosts[0].hostKeys=[f.target.hostKey];const r=ssh(h,'true');assert.notEqual(r.exitCode,0);assert.ok(['changed_host_key','unknown_host_key'].includes(classifySshError({stderr:r.stderr})),r.stderr);}
 });
 await t.test('capability probe reflects real container runtime',()=>{const python=ssh(f.host(),'/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/python3 -I -S -B -c "print(1)"');assert.equal(python.exitCode,0,python.stderr);assert.equal(python.stdout.trim(),'1');const r=ssh(f.host(),buildRemoteCapabilityProbe());assert.equal(r.exitCode,0,r.stderr);const capabilities=parseRemoteCapabilities(r.stdout);assert.equal(capabilities.os,'Linux');assert.equal(capabilities.python.available,true);assert.equal(capabilities.tasksReady,true);});
 await t.test('POSIX connection pool establishes and reuses a real master',{skip:process.platform==='win32'},()=>{const h=f.host('tester',{pooling:true}),p=prepareInvocation(h,'true','',{dataDir:state});assert.equal(ssh(h,'true').exitCode,0);const check=spawnSync(p.file,['-F',p.args[1],'-O','check','target'],{encoding:'utf8'});assert.equal(check.status,0,check.stderr);assert.equal(ssh(h,'true').exitCode,0);spawnSync(p.file,['-F',p.args[1],'-O','exit','target'],{encoding:'utf8'});});
 await t.test('interrupted SSH after submit is reconciled without replay',async()=>{
  let first=true;const actions=[];const jobs=new JobService({dataDir:state,authorize:()=>true,execute:async(h,c,o)=>{const action=JSON.parse(o.input).action;actions.push(action);if(first){first=false;const p=prepareInvocation(h,`${c}; sleep 30`,'',{dataDir:state});await new Promise((resolve,reject)=>{const child=spawn(p.file,p.args,{windowsHide:true});const timer=setTimeout(()=>{child.kill();reject(Error('no submit response'));},20000);child.once('error',e=>{clearTimeout(timer);reject(e);});child.stdout.once('data',()=>{clearTimeout(timer);child.kill();resolve();});child.once('exit',()=>{clearTimeout(timer);reject(Error('ssh exited before submit response'));});child.stdin.end(o.input);});throw Error('ssh interrupted after remote response');}return ssh(h,c,o.input);}});
  try{const submitted=await jobs.submit({threadId:'integration',host:f.host(),operation:{command:'printf once >> /tmp/fixture-once',cwd:'/tmp'},idempotencyKey:'once'});assert.equal(submitted.observation,'unknown');let result;for(let i=0;i<30;i++){result=await jobs.reconcile({threadId:'integration',taskId:submitted.id});if(result.status==='completed')break;await new Promise(r=>setTimeout(r,100));}assert.equal(result.status,'completed');assert.deepEqual(actions.slice(0,2),['submit','read']);assert.equal(ssh(f.host(),'cat /tmp/fixture-once').stdout,'once');}finally{jobs.close();}
 });
});
