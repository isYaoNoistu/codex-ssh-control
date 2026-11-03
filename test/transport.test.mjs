import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, lstatSync, writeFileSync, mkdirSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { normalizeConnection, prepareInvocation } from '../src/transport.mjs';
import { buildSshArgs } from '../src/ssh.mjs';

const blob=Buffer.concat([Buffer.from([0,0,0,11]),Buffer.from('ssh-ed25519'),Buffer.from([0,0,0,32]),Buffer.alloc(32,1)]);
const key=`ssh-ed25519 ${blob.toString('base64')}`;
const host={id:'dev',hostname:'example.invalid',port:2222,username:'deploy',identityFile:'C:/keys/key with spaces',defaultCwd:'/srv/a b'};
function temporary(t){const base=realpathSync(process.platform==='darwin'?'/private/tmp':tmpdir());const dir=mkdtempSync(join(base,'ssh-transport-'));t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir;}
test('hosts without connection preserve the legacy argv contract',()=>{
 assert.equal(normalizeConnection(undefined),null);
 assert.deepEqual(prepareInvocation(host,'true',undefined,{platform:'win32'}),{file:'ssh.exe',args:buildSshArgs(host,'true')});
});
test('managed normalization rejects executable config, unsafe jumps and invalid options',()=>{
 const normalized=normalizeConnection({mode:'managed',hostKeys:[key]});
 assert.equal(normalized.connectTimeoutSeconds,10);assert.deepEqual(normalized.jumpHosts,[]);assert.deepEqual(normalized.pooling,{enabled:false,persistSeconds:60});
 for(const value of [
  {mode:'managed',proxyCommand:'touch /tmp/bad'}, {mode:'managed',connectTimeoutSeconds:0},
  {mode:'managed',keepaliveCountMax:1000},{mode:'managed',pooling:{enabled:'yes'}},
  {mode:'managed',pooling:{enabled:true,persistSeconds:86400}},
  {mode:'managed',jumpHosts:[{hostname:'-oProxyCommand=x',username:'root'}]},
  {mode:'managed',jumpHosts:[{hostname:'internal',username:'root\nProxyCommand x'}]},
  {mode:'managed',jumpHosts:[{hostname:'internal',username:'root',identityFile:'/tmp/%d'}]},
  {mode:'native',alias:'alias',trustedLocalConfig:false},
 ]) assert.throws(()=>normalizeConnection(value),JSON.stringify(value));
});
test('managed invocations isolate every hop and require pinned keys before connection',t=>{
 const dataDir=temporary(t);
 assert.throws(()=>prepareInvocation({...host,connection:{mode:'managed'}},'true','',{dataDir}),/公钥|key/iu);
 const configured={...host,connection:{mode:'managed',hostKeys:[key],jumpHosts:[{hostname:'10.0.0.3',username:'jump',port:2200,identityFile:'/keys/jump',hostKeys:[key]}]}};
 const result=prepareInvocation(configured,'printf ok',host.defaultCwd,{dataDir,platform:'win32'});
 assert.equal(result.file,'ssh.exe');assert.equal(result.args[0],'-F');
 const config=readFileSync(result.args[1],'utf8');
 assert.match(config,/StrictHostKeyChecking yes/u);assert.match(config,/BatchMode yes/u);assert.match(config,/GlobalKnownHostsFile none/u);assert.match(config,/UpdateHostKeys no/u);
 assert.match(config,/ForwardAgent no/u);assert.match(config,/ClearAllForwardings yes/u);assert.match(config,/PermitLocalCommand no/u);
 assert.match(config,/HostName "10\.0\.0\.3"/u);assert.match(config,/ProxyJump hop0/u);assert.ok(!config.includes('Include'));
 assert.ok(!config.includes('ProxyCommand'));assert.match(config,/ControlMaster no/u);
 const knownPath=config.match(/UserKnownHostsFile "([^"]+)"/u)[1];
 const known=readFileSync(knownPath,'utf8');assert.ok(known.includes(`target ${key}`));assert.ok(known.includes(`hop0 ${key}`));
 assert.equal(result.args.at(-1),"cd -- '/srv/a b' || exit $?;\nprintf ok");
 assert.deepEqual(prepareInvocation(configured,'true','',{dataDir,platform:'win32'}).args.slice(0,2),result.args.slice(0,2));
 assert.equal(readdirSync(join(dataDir,'transport')).length,1);
 if(process.platform!=='win32')assert.equal(lstatSync(result.args[1]).mode&0o777,0o600);
});
test('pooling is bounded, disabled on Windows and isolated when any connection setting changes',t=>{
 const dataDir=temporary(t),configured={...host,connection:{mode:'managed',hostKeys:[key],pooling:{enabled:true,persistSeconds:30}}};
 const posix=prepareInvocation(configured,'true','',{dataDir,platform:'linux'}),windows=prepareInvocation(configured,'true','',{dataDir,platform:'win32'});
 assert.match(readFileSync(posix.args[1],'utf8'),/ControlMaster auto\n\s+ControlPersist 30/u);
 assert.match(readFileSync(windows.args[1],'utf8'),/ControlMaster no/u);
 assert.notEqual(posix.args[1],windows.args[1]);
 const changed=prepareInvocation({...configured,port:2202},'true','',{dataDir,platform:'linux'});
 assert.notEqual(posix.args[1],changed.args[1]);
});
test('native configuration requires explicit trust and validates aliases',()=>{
 const configured={...host,sshAlias:'trusted-alias',connection:{mode:'native',trustedLocalConfig:true}};
 const result=prepareInvocation(configured,'true','',{platform:'linux'});
 assert.equal(result.file,'ssh');assert.ok(!result.args.includes('-F'));assert.equal(result.args.at(-2),'trusted-alias');
 assert.throws(()=>prepareInvocation({...configured,sshAlias:'-oProxyCommand=bad'},'true',''));
});

test('multiplexing uses a separate socket for each hop',t=>{
 const dataDir=temporary(t),configured={...host,connection:{mode:'managed',hostKeys:[key],pooling:{enabled:true},jumpHosts:[{hostname:'jump.invalid',username:'jump',hostKeys:[key]}]}};
 const result=prepareInvocation(configured,'true','',{dataDir,platform:'linux'}),config=readFileSync(result.args[1],'utf8');
 const sockets=[...config.matchAll(/ControlPath "([^"]+)"/gu)].map(x=>x[1]);
 assert.equal(sockets.length,2);assert.equal(new Set(sockets).size,2);
});

test('managed config rejects target injection and state tampering before connecting',t=>{
 const dataDir=temporary(t),configured={...host,connection:{mode:'managed',hostKeys:[key]}};
 for(const patch of [{hostname:'-oProxyCommand=x'},{username:'root\nMatch exec x'},{identityFile:'/tmp/${HOME}'},{sshAlias:'ignored'}])assert.throws(()=>prepareInvocation({...configured,...patch},'true','',{dataDir}));
 const result=prepareInvocation(configured,'true','',{dataDir});writeFileSync(result.args[1],'Host *\n  ProxyCommand exploit\n');
 assert.throws(()=>prepareInvocation(configured,'true','',{dataDir}),/变更|不安全/u);
});

test('system OpenSSH parses the isolated config without making a connection',t=>{
 const dataDir=temporary(t),configured={...host,connection:{mode:'managed',hostKeys:[key],jumpHosts:[{hostname:'jump.invalid',username:'jump',hostKeys:[key]}]}};
 const invocation=prepareInvocation(configured,'true','',{dataDir});
 const result=spawnSync(invocation.file,['-G','-F',invocation.args[1],'target'],{encoding:'utf8',windowsHide:true,timeout:5000});
 if(result.error?.code==='ENOENT'){t.skip('OpenSSH is not installed');return;}
 assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/hostname example\.invalid/u);assert.match(result.stdout,/proxyjump hop0/u);assert.match(result.stdout,/stricthostkeychecking true|stricthostkeychecking yes/u);
});

test('managed authentication uses explicitly selected keys or all available agent identities',t=>{
 const dataDir=temporary(t);
 for(const identityFile of ['',host.identityFile]){
  const p=prepareInvocation({...host,identityFile,connection:{mode:'managed',hostKeys:[key]}},'true','',{dataDir});
  const config=readFileSync(p.args[1],'utf8');
  assert.match(config,new RegExp('IdentitiesOnly '+(identityFile?'yes':'no')));
 }
});

test('POSIX pooling fails clearly when the private socket path exceeds Unix limits',{skip:process.platform==='win32'},t=>{
 const dataDir=join(temporary(t),'x'.repeat(100));mkdirSync(dataDir);
 assert.throws(()=>prepareInvocation({...host,connection:{mode:'managed',hostKeys:[key],pooling:{enabled:true}}},'true','',{dataDir}),/socket|路径/u);
});
