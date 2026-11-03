import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export async function setup(t,{elicitation=true}={}){
 const dir=await mkdtemp(path.join(tmpdir(),'ssh-native-rpc-'));
 const log=path.join(dir,'spawns');
 const child=spawn(process.execPath,['--import',new URL('../fixtures/fake-ssh.mjs',import.meta.url).href,fileURLToPath(new URL('../../src/server.mjs',import.meta.url))],{env:{...process.env,SSH_CONTROL_DATA:dir,SSH_CONTROL_SKILLS:path.join(dir,'skills'),SSH_TEST_SPAWNS:log},stdio:['pipe','pipe','pipe'],windowsHide:true});
 let next=0,errors='';const pending=new Map(),prompts=[];
 child.stderr.on('data',b=>{errors+=b;});
 const sendBatch=messages=>child.stdin.write(messages.map(m=>JSON.stringify({jsonrpc:'2.0',...m})+'\n').join(''));
 const send=m=>sendBatch([m]);
 let onElicitation=m=>send({id:m.id,result:{action:'decline'}});
 createInterface({input:child.stdout}).on('line',line=>{const m=JSON.parse(line);if(m.method==='elicitation/create'){prompts.push(m);onElicitation(m);return;}const p=pending.get(m.id);if(p){pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);}});
 const rpc=(method,params,{cancelImmediately=false}={})=>{const id=++next;const promise=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('RPC timeout '+errors)),10000);pending.set(id,{resolve,reject,timer});sendBatch([{id,method,params},...(cancelImmediately?[{method:'notifications/cancelled',params:{requestId:id}}]:[])]);});promise.requestId=id;return promise;};
 const call=(name,args={},threadId='owner',options={})=>rpc('tools/call',{name,arguments:args,_meta:{threadId,sessionId:'shared-session'}},options);
 let stopping;
 const stop=()=>stopping??=(child.exitCode!==null||child.signalCode!==null?Promise.resolve():new Promise(resolve=>{const timer=setTimeout(()=>{child.kill();resolve();},1000);timer.unref();child.once('close',()=>{clearTimeout(timer);resolve();});child.stdin.end();}));
 t.after(async()=>{await stop();for(const p of pending.values())clearTimeout(p.timer);await rm(dir,{recursive:true,force:true});});
 await rpc('initialize',{protocolVersion:'2025-11-25',capabilities:elicitation?{elicitation:{form:{}}}:{}});
 const resources=await rpc('resources/list',{});
 const resource=await rpc('resources/read',{uri:resources.resources[0].uri});
 const uiToken=resource.contents[0].text.match(/(?:const\s+UI_TOKEN\s*=\s*['"])([a-f0-9]{64})/)?.[1];
 assert.ok(uiToken,'UI resource has a fresh process capability');
 const admin=(name,args={},threadId='owner')=>call(name,{...args,uiToken},threadId);
 assert.ok(!(await admin('ssh_host_save',{host:{id:'fixture',sshAlias:'never-connect.example.invalid',enabled:true}})).isError);
 const batchCalls=calls=>{
  const requests=calls.map(({name,args={},threadId='owner',admin:app=false})=>{
   const id=++next;
   const promise=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('RPC batch timeout '+errors)),10000);pending.set(id,{resolve,reject,timer});});
   return {promise,message:{id,method:'tools/call',params:{name,arguments:app?{...args,uiToken}:args,_meta:{threadId,sessionId:'shared-session'}}}};
  });
  sendBatch(requests.map(item=>item.message));return Promise.all(requests.map(item=>item.promise));
 };
 const grants=()=>admin('ssh_grant',{hostIds:['fixture']});
 const count=async()=>{try{return (await readFile(log,'utf8')).trim().split('\n').length;}catch(e){if(e.code==='ENOENT')return 0;throw e;}};
 const patchPolicy=async patch=>{const record=(await call('ssh_permissions',{hostId:'fixture'})).structuredContent.policy;return admin('ssh_policy_save',{hostId:'fixture',policy:{...record.policy,...patch},expectedRevision:record.revision});};
 return {rpc,call,admin,batchCalls,grants,count,patchPolicy,dir,prompts,stop,answerAndCancel:(id,result,requestId)=>sendBatch([{id,result},{method:'notifications/cancelled',params:{requestId}}]),setElicitation:fn=>{onElicitation=fn;},answer:(id,result)=>send({id,result}),cancel:id=>send({method:'notifications/cancelled',params:{requestId:id}})};
}
export const pause=()=>new Promise(resolve=>setTimeout(resolve,40));
export const purpose='停止指定的测试容器，以便验证用户确认后才执行的流程。';
