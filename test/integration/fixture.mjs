import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const docker = (args, input) => {
 const r=spawnSync('docker',args,{encoding:'utf8',input,windowsHide:true,timeout:600000,maxBuffer:16*1024*1024});
 if(r.error || r.status!==0) throw Error(`docker ${args[0]} failed: ${r.error?.message ?? r.stderr}`);
 return r.stdout.trim();
};
const run = (file,args) => {const r=spawnSync(file,args,{encoding:'utf8',windowsHide:true,timeout:30000});if(r.error||r.status!==0)throw Error(`${file} failed: ${r.error?.message??r.stderr}`);return r.stdout;};
const platforms={
 debian:['python:3.12-slim','apt-get -o Acquire::Retries=3 update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends openssh-server python3 ca-certificates && rm -rf /var/lib/apt/lists/*'],
 ubuntu:['ubuntu:24.04','apt-get -o Acquire::Retries=3 update && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 install -y --no-install-recommends openssh-server python3 ca-certificates && rm -rf /var/lib/apt/lists/*'],
 alpine:['alpine:3.21','apk add --no-cache openssh-server python3 shadow'],
 rocky:['rockylinux:9','dnf install -y openssh-server python3 shadow-utils && dnf clean all'],
 openeuler:['openeuler/openeuler:24.03-lts','dnf install -y openssh-server python3 shadow-utils && dnf clean all'],
};

/** Creates only uniquely named, labelled, disposable resources. Caller must await cleanup(). */
export function createFixture({distro=process.env.SSH_FIXTURE_DISTRO??'debian'}={}) {
 if(!Object.hasOwn(platforms,distro))throw Error(`Unsupported fixture distro: ${distro}`);
 const id=`ssh-it-${randomBytes(8).toString('hex')}`,label=`codex.ssh.fixture=${id}`;
 const dir=mkdtempSync(join(tmpdir(),'ssh-it-')),key=join(dir,'client');
 const network=id, image=`${id}:local`, containers=[`${id}-target`,`${id}-jump`];
 let networkCreated=false,imageCreated=false;
 const safeRemove=(kind,name)=>{try{const v=JSON.parse(docker(['inspect',name]));const labels=v[0].Config?.Labels??v[0].Labels??{};if(labels['codex.ssh.fixture']!==id)throw Error(`refusing cleanup of ${name}`);docker(kind==='network'?['network','rm',name]:['rm','-f',name]);}catch(e){if(!/No such (container|network|object)/i.test(e.message))throw e;}};
 const cleanup=()=>{let error;for(const name of containers){try{safeRemove('container',name);}catch(e){error??=e;}}if(networkCreated){try{safeRemove('network',network);}catch(e){error??=e;}}if(imageCreated){try{docker(['image','rm',image]);}catch(e){error??=e;}}rmSync(dir,{recursive:true,force:true});if(error)throw error;};
 try {
  run('ssh-keygen',['-q','-t','ed25519','-N','','-f',key]);
  const [base,install]=platforms[distro];
  docker(['build','--label',label,'-t',image,'-f','-','.'],`FROM ${base}\nRUN ${install}\n`);imageCreated=true;
  docker(['network','create','--label',label,network]);networkCreated=true;
  for(const name of containers){
   docker(['run','-d','--name',name,'--label',label,'--network',network,'-p','127.0.0.1::22',image,'sh','-c','while :; do sleep 3600; done']);
   const setup=`set -eu\nmkdir -p /run/sshd /root/.ssh\n(useradd -m -s /bin/sh tester || adduser -D -s /bin/sh tester)\necho 'tester:fixture-only-password' | chpasswd\necho 'root:fixture-only-password' | chpasswd\nmkdir -p /home/tester/.ssh\ncat > /root/.ssh/authorized_keys\ncp /root/.ssh/authorized_keys /home/tester/.ssh/authorized_keys\nchmod 700 /root/.ssh /home/tester/.ssh\nchmod 600 /root/.ssh/authorized_keys /home/tester/.ssh/authorized_keys\nchown -R tester:tester /home/tester/.ssh\nssh-keygen -q -t ed25519 -N '' -f /tmp/fixture_host_key\nprintf '%s\\n' 'Port 22' 'HostKey /tmp/fixture_host_key' 'AuthorizedKeysFile .ssh/authorized_keys' 'PermitRootLogin yes' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'UsePAM no' 'AllowTcpForwarding yes' 'PidFile /tmp/sshd.pid' > /tmp/sshd_config\n/usr/sbin/sshd -f /tmp/sshd_config\n`;
   // Script is passed as an argument; stdin carries only the generated public key.
   docker(['exec','-i',name,'sh','-c',setup],readFileSync(`${key}.pub`,'utf8'));
  }
  const endpoint=(name)=>({port:Number(docker(['port',name,'22/tcp']).match(/:(\d+)$/)?.[1]),hostKey:docker(['exec',name,'cat','/tmp/fixture_host_key.pub']).split(' ').slice(0,2).join(' ')});
  const target=endpoint(containers[0]),jump=endpoint(containers[1]);
  if(!target.port||!jump.port)throw Error('Failed to resolve fixture ports');
  const host=(username='tester',{viaJump=false,pooling=false}={})=>({id:'fixture',hostname:viaJump?containers[0]:'127.0.0.1',port:viaJump?22:target.port,username,identityFile:key,defaultCwd:'/tmp',connection:{mode:'managed',hostKeys:[target.hostKey],pooling:{enabled:pooling,persistSeconds:15},jumpHosts:viaJump?[{hostname:'127.0.0.1',port:jump.port,username,identityFile:key,hostKeys:[jump.hostKey]}]:[]}});
  return {id,dir,key,target,jump,containers,host,cleanup};
 }catch(error){try{cleanup();}catch(cleanupError){error.message+=` (cleanup: ${cleanupError.message})`;}throw error;}
}
