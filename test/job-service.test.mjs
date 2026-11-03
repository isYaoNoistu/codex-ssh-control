import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JobService } from '../src/job-service.mjs';

function fixture(t, execute, authorize = () => true) {
 const dataDir=mkdtempSync(join(tmpdir(),'jobs-'));
 const opts={dataDir,execute,authorize};
 let service=new JobService(opts);
 t.after(()=>{service.close();rmSync(dataDir,{recursive:true,force:true});});
 return {get service(){return service;}, reopen(){service.close();service=new JobService(opts);return service;}};
}
const request={threadId:'chat-a',host:{id:'host-a',hostname:'fixture'},operation:{command:'printf hello',timeoutSeconds:10},idempotencyKey:'once'};
const reply=(status='running',extra={})=>({stdout:JSON.stringify({status,exitCode:null,log:'',...extra}),exitCode:0,status:'completed'});

test('submission identity survives restart without replay and immutable arguments reject reuse',async t=>{
 const calls=[];const f=fixture(t,async(h,c,o)=>{calls.push(JSON.parse(o.input));return reply();});
 const a=await f.service.submit(request);f.reopen();
 const b=await f.service.submit(request);assert.equal(a.id,b.id);assert.equal(calls.length,1);
 await assert.rejects(f.service.submit({...request,operation:{command:'other'}}),/immutable/);
 assert.equal(f.service.list({threadId:'chat-a'}).length,1);
 assert.equal(f.service.list({threadId:'chat-b'}).length,0);
 await assert.rejects(f.service.read({threadId:'chat-b',taskId:a.id}),/belong/);
});
test('ambiguous disconnect persists unknown observation and reconcile only reads',async t=>{
 const calls=[];const f=fixture(t,async(h,c,o)=>{const p=JSON.parse(o.input);calls.push(p.action);if(p.action==='submit')throw Error('disconnect');return reply('completed',{exitCode:0,log:Buffer.from('hello').toString('base64')});});
 const a=await f.service.submit(request);assert.equal(a.observation,'unknown');
 f.reopen();const b=await f.service.reconcile({threadId:'chat-a',taskId:a.id});
 assert.equal(b.status,'completed');assert.deepEqual(calls,['submit','read']);
});
test('authorization refusal never executes and every remote stage is authorized',async t=>{
 const stages=[];let allow=false,calls=0;
 const f=fixture(t,async()=>{calls++;return reply();},(stage,record)=>{stages.push(stage);assert.equal(record.token,undefined);return allow;});
 await assert.rejects(f.service.submit(request),/authoriz/);assert.equal(calls,0);
 allow=true;const a=await f.service.submit(request);await f.service.read({threadId:'chat-a',taskId:a.id});await f.service.cancel({threadId:'chat-a',taskId:a.id});
 allow=false;await assert.rejects(f.service.reconcile({threadId:'chat-a',taskId:a.id}),/authoriz/);
 assert.deepEqual(stages,['submit','submit','read','cancel','reconcile']);assert.equal(calls,3);
});
test('bounded incremental output is persisted and credentials suppressed before publication',async t=>{
 let log='hello world';const f=fixture(t,async()=>reply('completed',{exitCode:0,log:Buffer.from(log).toString('base64')}));
 const a=await f.service.submit(request);
 const b=await f.service.read({threadId:'chat-a',taskId:a.id,limitBytes:5});assert.equal(b.output,'hello');assert.equal(b.nextCursor,5);
 const c=await f.service.read({threadId:'chat-a',taskId:a.id,cursor:5,refresh:false});assert.equal(c.output,' world');
 log='OPENAI_API_KEY=sk-proj-supersecretcredentials';
 const d=await f.service.read({threadId:'chat-a',taskId:a.id});assert.equal(d.output,'');assert.equal(d.redacted,true);
 f.reopen();assert.equal((await f.service.read({threadId:'chat-a',taskId:a.id,refresh:false})).output,'');
 assert.equal(JSON.stringify(d).includes('supersecretcredentials'),false);
});
test('control failures preserve running state and cancellation only marks request',async t=>{
 let action=0;const f=fixture(t,async()=>++action===1?reply():{stdout:'',stderr:'unreachable',exitCode:255,status:'failed'});
 const a=await f.service.submit(request);const b=await f.service.cancel({threadId:'chat-a',taskId:a.id});
 assert.equal(b.status,'running');assert.equal(b.observation,'unknown');assert.equal(b.cancelRequested,true);
});
test('invalid shell, disconnect policy, env, timeout and output limits fail before connect',async t=>{
 const f=fixture(t,async()=>{throw Error('must not connect');});
 for(const patch of [{shell:'bash;id'},{disconnectPolicy:'cancel'},{env:{'x=y':'a'}},{env:{PATH:'/malicious'}},{env:{LD_PRELOAD:'/evil.so'}},{timeoutSeconds:0},{maxOutputBytes:99999999},{cpuSeconds:0},{maxMemoryMiB:0},{maxProcesses:9999999}]) await assert.rejects(f.service.submit({...request,operation:{...request.operation,...patch}}));
});
test('resource controls are immutable and output line fragments remain withheld',async t=>{
 let payload;const f=fixture(t,async(h,c,o)=>{payload=JSON.parse(o.input);return reply('running',{log:Buffer.from('normal\nOPENAI_API_KEY=sk-proj-frag').toString('base64')});});
 const a=await f.service.submit({...request,operation:{...request.operation,cpuSeconds:3,maxMemoryMiB:128,maxProcesses:20}});
 assert.equal(payload.spec.cpuSeconds,3);assert.equal(payload.spec.maxMemoryMiB,128);assert.equal(payload.spec.maxProcesses,20);
 const b=await f.service.read({threadId:'chat-a',taskId:a.id,refresh:false});assert.equal(b.output,'normal\n');
});
test('concurrent stale read cannot erase cancellation or regress confirmed terminal state',async t=>{
 let hold,release,reads=0;const blocked=new Promise(r=>{hold=r;});
 const f=fixture(t,async(h,c,o)=>{
  const p=JSON.parse(o.input);if(p.action==='submit')return reply();
  if(p.action==='read'&&++reads===1){hold();return new Promise(r=>{release=()=>r(reply());});}
  return reply('cancelled',{signal:15,cancelRequested:true,terminationReason:'cancel_requested'});
 });
 const a=await f.service.submit(request);
 const stale=f.service.read({threadId:'chat-a',taskId:a.id});await blocked;
 await f.service.cancel({threadId:'chat-a',taskId:a.id});release();await stale;
 const current=await f.service.read({threadId:'chat-a',taskId:a.id,refresh:false});
 assert.equal(current.status,'cancelled');assert.equal(current.cancelRequested,true);assert.equal(current.signal,15);
});
test('too-small UTF-8 page fails explicitly instead of returning a stuck cursor',async t=>{
 const f=fixture(t,async()=>reply('completed',{log:Buffer.from('中文').toString('base64')}));
 const a=await f.service.submit(request);
 await assert.rejects(f.service.read({threadId:'chat-a',taskId:a.id,refresh:false,limitBytes:1}),/UTF-8/);
});

test('oversized serialized requests fail before authorization and persistence',async t=>{
 let permits=0,connections=0;
 const f=fixture(t,async()=>{connections++;return reply();},()=>{permits++;return true;});
 const env=Object.fromEntries(Array.from({length:64},(_,i)=>['FLAG_'+i,'x'.repeat(4096)]));
 await assert.rejects(f.service.submit({...request,operation:{...request.operation,env}}),/128 KiB/);
 assert.equal(permits,0);assert.equal(connections,0);assert.equal(f.service.list({threadId:'chat-a'}).length,0);
});

test('request limit includes identity overhead and UTF-8 bytes at the exact boundary',async t=>{
 let payload,permits=0;
 const f=fixture(t,async(h,c,o)=>{payload=JSON.parse(o.input);assert.ok(Buffer.byteLength(o.input)<=131072);return reply();},()=>{permits++;return true;});
 await f.service.submit(request);
 const env=Object.fromEntries(Array.from({length:16},(_,i)=>['FLAG_'+i,'x'.repeat(8192)]));
 env.FLAG_15='';env.FLAG_0='中'.repeat(2730)+'xx';
 const candidate={...payload,spec:{...payload.spec,env}};
 // Include multibyte text and fill the remaining serialized byte budget exactly.
 const room=131072-Buffer.byteLength(JSON.stringify(candidate));
 assert.ok(room>0&&room<8192);env.FLAG_15='x'.repeat(room);
 await f.service.submit({...request,idempotencyKey:'boundary',operation:{...request.operation,env}});
 assert.equal(Buffer.byteLength(JSON.stringify(payload)),131072);
 env.FLAG_15+='x';const before=permits;
 await assert.rejects(f.service.submit({...request,idempotencyKey:'too-large',operation:{...request.operation,env}}),/128 KiB/);
 assert.equal(permits,before);assert.equal(f.service.list({threadId:'chat-a'}).length,2);
});

test('out-of-order running snapshots preserve output prefix and byte cursor',async t=>{
 let release,entered,reads=0;const held=new Promise(r=>{entered=r;});
 const f=fixture(t,async(h,c,o)=>{
  const p=JSON.parse(o.input);if(p.action==='submit')return reply('running',{log:Buffer.from('a\n').toString('base64')});
  if(++reads===1){entered();return new Promise(r=>{release=()=>r(reply('running',{log:Buffer.from('a\n').toString('base64')}));});}
  return reply('running',{log:Buffer.from('a\n中文\n').toString('base64')});
 });
 const a=await f.service.submit(request);const stale=f.service.read({threadId:'chat-a',taskId:a.id});await held;
 const newer=await f.service.read({threadId:'chat-a',taskId:a.id});release();
 assert.equal((await stale).output,newer.output);
 const cached=await f.service.read({threadId:'chat-a',taskId:a.id,refresh:false,cursor:newer.nextCursor});
 assert.equal(cached.cursor,newer.nextCursor);assert.equal(cached.nextCursor,newer.nextCursor);
});

test('late harmless snapshots cannot undo persisted redaction',async t=>{
 let release,entered,reads=0;const held=new Promise(r=>{entered=r;});
 const f=fixture(t,async(h,c,o)=>{
  if(JSON.parse(o.input).action==='submit')return reply();
  if(++reads===1){entered();return new Promise(r=>{release=()=>r(reply('running',{log:Buffer.from('safe\n').toString('base64')}));});}
  return reply('running',{log:Buffer.from('safe\nTOKEN=private-value\n').toString('base64')});
 });
 const a=await f.service.submit(request);const stale=f.service.read({threadId:'chat-a',taskId:a.id});await held;
 await f.service.read({threadId:'chat-a',taskId:a.id});release();const late=await stale;
 assert.equal(late.redacted,true);assert.equal(late.output,'');
});

test('task helper uses an absolute isolated Python invocation',async t=>{
 const f=fixture(t,async(h,c)=>{assert.ok(c.startsWith('/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/python3 -I -S -B -c '));return reply();});
 const a=await f.service.submit(request);assert.equal(a.observation,'confirmed');
});
