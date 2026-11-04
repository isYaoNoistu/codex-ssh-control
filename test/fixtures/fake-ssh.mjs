// Test-only Node preload. Production never reads this module or any mock flag.
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { appendFileSync } from 'node:fs';
const original=childProcess.spawn;
childProcess.spawn=function(executable,args,options){
 if(!/^ssh(?:\.exe)?$/.test(executable))return original(executable,args,options);
 appendFileSync(process.env.SSH_TEST_SPAWNS,JSON.stringify({args})+'\n');
 const child=new EventEmitter();
 child.stdout=new PassThrough();child.stderr=new PassThrough();child.stdin=new PassThrough();
 child.kill=()=>{child.stdout.end();child.stderr.end();child.emit('close',null);return true;};
 let input='';child.stdin.on('data',chunk=>{input+=chunk;});
 child.stdin.on('finish',()=>setTimeout(()=>{
  const command=args.at(-1);
  let stderr='';
  let output=command.includes('SSH_CONTROL_OK')?'SSH_CONTROL_OK\ndeploy\nfixture\nLinux\n':command.includes('diagnostic-sensitive-fixture')?'api_key=test-fixture-value\n':'fixture command completed\n';
  if(command.includes('diagnostic-stderr-fixture'))stderr='api_key=stderr-fixture-value';
  if(input.startsWith('{"action":"storage",')||input.startsWith('{"action":"collect",')){
   const req=JSON.parse(input),collect=req.action==='collect';
   output=JSON.stringify({bytes:240,retainedBytes:collect?40:240,reclaimedBytes:collect?200:0,collected:collect});
  } else if(command.includes('python3')){
   const match=input.match(/base64\.b64decode\('([^']+)'\)/);
   const operation=JSON.parse(Buffer.from(match[1],'base64').toString('utf8')).operation;
   const result=operation.kind==='read'?{content:'fixture readable file body'}:operation.kind==='write'?{written:true,bytes:Buffer.byteLength(operation.content,'utf8')}:operation.kind==='list'?{entries:[{name:'public.txt',type:'file',bytes:12}],truncated:false}:{deleted:true};
   output=JSON.stringify({ok:true,result});
   if(operation.path.endsWith('/diagnostic-stderr-fixture.txt'))stderr='api_key=stderr-fixture-value';
  }
  child.stdout.end(output);
  child.stderr.end(stderr);child.emit('close',0);
 },10));
 return child;
};
syncBuiltinESMExports();
