import { performance } from 'node:perf_hooks';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createFixture } from '../test/integration/fixture.mjs';
import { prepareInvocation } from '../src/transport.mjs';

const count=Number(process.env.SSH_BENCH_COUNT??10),bytes=Number(process.env.SSH_BENCH_TRANSFER_BYTES??0);
if(!Number.isInteger(count)||count<1||count>1000||!Number.isInteger(bytes)||bytes<0||bytes>100000000)throw Error('Invalid benchmark bounds');
const f=createFixture(),state=mkdtempSync(join(tmpdir(),'sb-'));
try{
 const execute=(host,command,input)=>{const p=prepareInvocation(host,command,'',{dataDir:state}),start=performance.now(),r=spawnSync(p.file,p.args,{input,windowsHide:true,timeout:120000,maxBuffer:1024*1024});if(r.error||r.status!==0)throw Error(r.error?.message??r.stderr.toString());return performance.now()-start;};
 const measure=pooling=>{const host=f.host('tester',{pooling});if(pooling)execute(host,'true');const ms=Array.from({length:count},()=>execute(host,'true'));if(pooling){const p=prepareInvocation(host,'true','',{dataDir:state});spawnSync(p.file,['-F',p.args[1],'-O','exit','target'],{windowsHide:true});}return {samplesMs:ms,meanMs:ms.reduce((a,b)=>a+b,0)/ms.length};};
 const result={schemaVersion:1,distro:process.env.SSH_FIXTURE_DISTRO??'debian',clientPlatform:process.platform,count,fresh:measure(false),reused:process.platform==='win32'?null:measure(true)};
 if(bytes){const ms=execute(f.host(),'cat > /tmp/benchmark-transfer',randomBytes(bytes));result.transfer={bytes,elapsedMs:ms,bytesPerSecond:bytes/(ms/1000),direction:'upload',includesConnectionSetup:true};}
 process.stdout.write(JSON.stringify(result,null,2)+'\n');
}finally{try{f.cleanup();}finally{rmSync(state,{recursive:true,force:true});}}
