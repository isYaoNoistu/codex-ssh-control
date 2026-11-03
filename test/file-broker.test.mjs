import test from 'node:test';
import assert from 'node:assert/strict';
import {fileRequest,parseFileResult,FILE_COMMAND} from '../src/file-broker.mjs';
import {defaultPolicy,evaluateOperation} from '../src/policy.mjs';
import {createRunner} from '../src/ssh.mjs';
import {spawn} from 'node:child_process';

test('file broker transmits data only as stdin, with fixed isolated Python command',()=>{
 const policy={...defaultPolicy(),roots:[{id:'app',path:'/srv/app',read:true,write:true}]};
 const operation={kind:'write',path:'/srv/app/a.txt',content:'中文\n\' ; whoami; $(cat /tmp/outside)'};
 const evaluated=evaluateOperation(policy,operation);
 const request=fileRequest(evaluated,16);
 assert.equal(request.command,FILE_COMMAND);assert.ok(!request.command.includes(operation.content));
 assert.match(request.command,/env -i.*python3 -I -S -B -$/);
 const encoded=request.input.match(/base64\.b64decode\('([^']+)'\)/)[1];
 const parsed=JSON.parse(Buffer.from(encoded,'base64').toString('utf8'));
 assert.deepEqual(parsed.operation,operation);assert.equal(parsed.root,'/srv/app');assert.equal(parsed.limit,16*1024);
 assert.throws(()=>fileRequest({operation}),/验证/);
});
test('file broker refuses malformed, partial, unsupported and sensitive responses without exposing content',()=>{
 const result={status:'completed',exitCode:0,truncated:false,stdout:JSON.stringify({ok:true,result:{content:'hello'}})};
 assert.deepEqual(parseFileResult(result),{content:'hello'});
 for(const change of [{truncated:true},{status:'failed'},{stdout:'not-json'},{stdout:JSON.stringify({ok:false,error:'denied'})},{stdout:JSON.stringify({ok:true,result:{content:'password=fixture-value'}})}])assert.throws(()=>parseFileResult({...result,...change}));
});

test('file broker rejects Docker registry auth returned from a renamed file',()=>{
 const auth=Buffer.from('fixture-user:fixture-password').toString('base64');
 const content=JSON.stringify({auths:{'registry.example.invalid':{auth}}});
 const task={status:'completed',exitCode:0,truncated:false,stdout:JSON.stringify({ok:true,result:{content}})};
 assert.throws(()=>parseFileResult(task),/敏感信息/);
 const safe=JSON.stringify({auths:{},auth:true});
 assert.deepEqual(parseFileResult({...task,stdout:JSON.stringify({ok:true,result:{content:safe}})}),{content:safe});
});
test('runner enforces per-operation output caps and hides private file responses from task_read',async()=>{
 const runner=createRunner({spawnImpl:(_exe,_args,options)=>spawn(process.execPath,['-e',"process.stdout.write('x'.repeat(40000));"],options)});
 const host={id:'dev',hostname:'example.invalid',username:'test',port:22,defaultCwd:''};
 try{
  const task=runner.start('a',host,'test',{outputLimitBytes:16384,privateOutput:true});
  const internal=await runner.wait('a',task.id);
  assert.equal(internal.stdout.length,16384);assert.equal(internal.truncated,true);
  assert.equal(runner.read('a',task.id).stdout,'');
 }finally{runner.close();}
});
