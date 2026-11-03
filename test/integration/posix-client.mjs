import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { join } from 'node:path';
import { prepareInvocation } from '../../src/transport.mjs';

const info=JSON.parse(process.env.SSH_FIXTURE_INFO),state=mkdtempSync('/tmp/si-');
const key=join(state,'client');copyFileSync('/fixture/client',key);chmodSync(key,0o600);
const host={id:'fixture',hostname:info.target,port:22,username:'tester',identityFile:key,defaultCwd:'/tmp',connection:{mode:'managed',hostKeys:[info.targetKey],pooling:{enabled:true,persistSeconds:30},jumpHosts:[{hostname:info.jump,port:22,username:'tester',identityFile:key,hostKeys:[info.jumpKey]}]}};
const execute=(h,command='true')=>{const p=prepareInvocation(h,command,'',{dataDir:state}),start=performance.now(),r=spawnSync(p.file,p.args,{encoding:'utf8',timeout:30000});assert.equal(r.status,0,r.stderr);return performance.now()-start;};
try{
 const tests=readdirSync('test').filter(name=>name.endsWith('.test.mjs')).map(name=>join('test',name));
 const unit=spawnSync(process.execPath,['--test',...tests],{encoding:'utf8',timeout:300000,maxBuffer:16*1024*1024});assert.equal(unit.status,0,`${unit.stdout}\n${unit.stderr}`);
 const invocation=prepareInvocation(host,'true','',{dataDir:state});execute(host);
 const check=spawnSync(invocation.file,['-F',invocation.args[1],'-O','check','target'],{encoding:'utf8'});assert.equal(check.status,0,check.stderr);
 const reused=Array.from({length:5},()=>execute(host));
 spawnSync(invocation.file,['-F',invocation.args[1],'-O','exit','target'],{encoding:'utf8'});
 spawnSync(invocation.file,['-F',invocation.args[1],'-O','exit','hop0'],{encoding:'utf8'});
 const freshHost=structuredClone(host);freshHost.connection.pooling.enabled=false;
 const fresh=Array.from({length:5},()=>execute(freshHost));
 const mean=a=>a.reduce((x,y)=>x+y,0)/a.length;
 console.log(JSON.stringify({platform:process.platform,node:process.version,unitTestFiles:tests.length,unitTests:'all passed',route:'proxyjump',count:5,fresh:{samplesMs:fresh,meanMs:mean(fresh)},reused:{samplesMs:reused,meanMs:mean(reused)}}));
}finally{rmSync(state,{recursive:true,force:true});}
