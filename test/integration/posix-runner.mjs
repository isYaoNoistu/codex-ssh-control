import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { createFixture } from './fixture.mjs';

const docker=(args,input)=>{const r=spawnSync('docker',args,{input,encoding:'utf8',timeout:600000,maxBuffer:16*1024*1024});if(r.error||r.status!==0)throw Error(`docker ${args[0]}: ${r.error?.message??r.stderr}`);return r.stdout.trim();};
const f=createFixture(),image=`${f.id}-client:local`,label=`codex.ssh.fixture=${f.id}`;
let built=false;
try{
 // Reuse this run's Debian fixture image (which already has SSH and Python),
 // while taking only the Node executable from the official Node image.
 docker(['build','--label',label,'-t',image,'-f','-','.'],`FROM node:24-bookworm-slim AS node\nFROM ${f.id}:local\nCOPY --from=node /usr/local/bin/node /usr/local/bin/node\n`);built=true;
 const info={target:f.containers[0],jump:f.containers[1],targetKey:f.target.hostKey,jumpKey:f.jump.hostKey};
 const output=docker(['run','--rm','--name',`${f.id}-client`,'--label',label,'--network',f.id,'--mount',`type=bind,src=${resolve('.')},dst=/work,readonly`,'--mount',`type=bind,src=${f.dir},dst=/fixture,readonly`,'-e',`SSH_FIXTURE_INFO=${JSON.stringify(info)}`,'-w','/work',image,'node','test/integration/posix-client.mjs']);
 console.log(output);
}finally{try{if(built)docker(['image','rm',image]);}finally{f.cleanup();}}
