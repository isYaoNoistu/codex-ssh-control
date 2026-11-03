import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { buildSshArgs, createRunner, shellQuote } from '../src/ssh.mjs';

const host={id:'dev',hostname:'example.invalid',port:2222,username:'deploy',identityFile:'C:/keys/key with spaces',defaultCwd:'/srv/a b'};
test('native SSH preserves argv and strict host verification',()=>{
 const args=buildSshArgs(host,"printf '%s' hello");
 assert.ok(args.includes('StrictHostKeyChecking=yes'));
 assert.ok(args.includes('UserKnownHostsFile=~/.ssh/known_hosts'),'strict verification must use the real per-user known_hosts instead of a discard target from SSH config');
 assert.ok(args.includes('BatchMode=yes'));
 assert.equal(args[args.indexOf('-i')+1],host.identityFile);
 assert.equal(args.at(-2),'deploy@example.invalid');
 assert.equal(args.at(-1),"cd -- '/srv/a b' || exit $?;\nprintf '%s' hello");
 assert.equal(shellQuote("a'b"),"'a'\"'\"'b'");
});
test('command tasks isolate owners and drain bounded stdout',async()=>{
 let captured;
 const runner=createRunner({outputLimit:1024,spawnImpl:(exe,args,options)=>{
   captured={exe,args,options};
   return spawn(process.execPath,['-e',"process.stdout.write('x'.repeat(3000));process.stderr.write('ERR')"],options);
 }});
 const task=runner.start('thread-a',host,'true');
 assert.throws(()=>runner.read('thread-b',task.id),/对话/);
 const result=await runner.wait('thread-a',task.id);
 assert.equal(result.exitCode,0);assert.equal(result.status,'completed');
 assert.ok(result.stdout.length+result.stderr.length<=1024);assert.equal(result.truncated,true);
 assert.equal(captured.options.shell,false);assert.equal(captured.options.windowsHide,true);
});
test('stdin file content is not embedded in SSH command argv',async()=>{
 const text='中文\n$not-a-command\n';let argsSeen;
 const runner=createRunner({spawnImpl:(exe,args,options)=>{
  argsSeen=args;return spawn(process.execPath,['-e',"process.stdin.pipe(process.stdout)"],options);
 }});
 const task=runner.start('t',host,"cat > '/tmp/file'",{input:text});
 const result=await runner.wait('t',task.id);
 assert.equal(result.stdout,text);assert.ok(!argsSeen.join(' ').includes(text));
});
test('timeout and explicit cancellation stop owned local SSH tasks',async()=>{
 const runner=createRunner({spawnImpl:(_exe,_args,options)=>spawn(process.execPath,['-e','setTimeout(()=>{},10000)'],options)});
 const a=runner.start('a',host,'sleep',{timeoutSeconds:0.08});
 assert.equal((await runner.wait('a',a.id)).status,'timed_out');
 const b=runner.start('a',host,'sleep');
 assert.throws(()=>runner.cancel('b',b.id),/对话/);
 runner.cancel('a',b.id);assert.equal((await runner.wait('a',b.id)).status,'cancelled');
});

test('bounded output never splits a UTF-8 character or exceeds its byte limit',async()=>{
 const runner=createRunner({outputLimit:2,spawnImpl:(_exe,_args,options)=>spawn(process.execPath,['-e',"process.stdout.write('中')"],options)});
 const task=runner.start('a',host,'utf8');
 const result=await runner.wait('a',task.id);
 assert.equal(result.truncated,true);
 assert.ok(Buffer.byteLength(result.stdout+result.stderr)<=2);
 assert.ok(!result.stdout.includes('\uFFFD'));
});


test('sensitive output beyond retained cap is hidden publicly but available internally with a flag', async () => {
 const runner=createRunner({outputLimit:32,spawnImpl:(_exe,_args,options)=>spawn(process.execPath,['-e',"process.stdout.write('x'.repeat(100));process.stderr.write('password=fixture')"],options)});
 const task=runner.start('a',host,'diagnostic');
 const result=await runner.wait('a',task.id);
 assert.equal(result.sensitiveOutput,true);
 assert.equal(result.truncated,true);
 assert.ok(result.stdout.length>0);
 const visible=runner.read('a',task.id);
 assert.equal(visible.stdout,'');
 assert.ok(!visible.stderr.includes('fixture'));
 assert.equal(visible.sensitiveOutput,true);
});

test('runner detects sensitive values arriving in separate decoded chunks', async () => {
 const runner=createRunner({spawnImpl:(_exe,_args,options)=>spawn(process.execPath,['-e',"process.stdout.write('pass');setTimeout(()=>{process.stdout.write('word=');setTimeout(()=>process.stdout.write('fixture'),20)},20)"],options)});
 const task=runner.start('a',host,'diagnostic');
 const result=await runner.wait('a',task.id);
 assert.equal(result.stdout,'password=fixture');
 assert.equal(result.sensitiveOutput,true);
 assert.equal(runner.read('a',task.id).stdout,'');
});

test('private file output remains hidden publicly and carries sensitivity to internal completion', async () => {
 const runner=createRunner({spawnImpl:(_exe,_args,options)=>spawn(process.execPath,['-e',"process.stdout.write('private_key=fixture')"],options)});
 const task=runner.start('a',host,'file-broker',{privateOutput:true});
 const result=await runner.wait('a',task.id);
 assert.equal(result.stdout,'private_key=fixture');
 assert.equal(result.sensitiveOutput,true);
 assert.equal(runner.read('a',task.id).stdout,'');
 assert.equal(runner.read('a',task.id).stderr,'');
});
