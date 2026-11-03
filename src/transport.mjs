import { createHash } from 'node:crypto';
import { mkdirSync, lstatSync, readFileSync, writeFileSync, constants } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { buildSshArgs, shellQuote } from './ssh.mjs';
import { parsePublicKey, validateHostname } from './host-keys.mjs';

function fields(value,allowed){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!allowed.includes(k)))throw new Error('连接配置包含无效或不支持的字段。');}
function integer(value,fallback,min,max){value??=fallback;if(!Number.isInteger(value)||value<min||value>max)throw new Error('连接数值超出允许范围。');return value;}
function identity(value=''){if(typeof value!=='string'||value.length>4096||/[\r\n\0%$]/u.test(value))throw new Error('identityFile 无效。');return value;}
function username(value){if(typeof value!=='string'||!/^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}$/u.test(value))throw new Error('SSH username 无效。');return value;}
function keys(value=[]){if(!Array.isArray(value)||value.length>32)throw new Error('公钥列表无效。');return [...new Set(value.map(k=>parsePublicKey(k).publicKey))];}
function endpoint(value){return {hostname:validateHostname(value.hostname),port:integer(value.port,22,1,65535),username:username(value.username),identityFile:identity(value.identityFile),hostKeys:keys(value.hostKeys)};}
export function normalizeConnection(value) {
 if(value==null)return null;
 if(value.mode==='native'){fields(value,['mode','trustedLocalConfig']);if(value.trustedLocalConfig!==true)throw new Error('原生配置需要明确 trustedLocalConfig 授权。');return {mode:'native',trustedLocalConfig:true};}
 fields(value,['mode','jumpHosts','hostKeys','connectTimeoutSeconds','keepaliveIntervalSeconds','keepaliveCountMax','pooling']);
 if(value.mode!=='managed')throw new Error('未知连接模式。');
 const jumps=value.jumpHosts??[];if(!Array.isArray(jumps)||jumps.length>8)throw new Error('跳板数量无效。');
 const pool=value.pooling??{};fields(pool,['enabled','persistSeconds']);if(pool.enabled!==undefined&&typeof pool.enabled!=='boolean')throw new Error('pooling.enabled 必须为布尔值。');
 return {mode:'managed',jumpHosts:jumps.map(j=>{fields(j,['hostname','port','username','identityFile','hostKeys']);return endpoint(j);}),hostKeys:keys(value.hostKeys),connectTimeoutSeconds:integer(value.connectTimeoutSeconds,10,1,120),keepaliveIntervalSeconds:integer(value.keepaliveIntervalSeconds,15,1,300),keepaliveCountMax:integer(value.keepaliveCountMax,2,1,10),pooling:{enabled:pool.enabled??false,persistSeconds:integer(pool.persistSeconds,60,1,600)}};
}
function quote(value){if(/[\r\n\0%$]/u.test(value))throw new Error('SSH config 路径或值无效。');return `"${String(value).replaceAll('\\','/').replaceAll('"','\\"')}"`;}
function privateDir(path){
 try{mkdirSync(path,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw error;}
 const stat=lstatSync(path);if(!stat.isDirectory()||stat.isSymbolicLink()||(process.platform!=='win32'&&(stat.uid!==process.getuid()||(stat.mode&0o077)!==0)))throw new Error('SSH state directory 必须是私有的真实目录。');
}
function ancestors(path){let current=resolve(path);for(;;){const stat=lstatSync(current);if(stat.isSymbolicLink()||!stat.isDirectory())throw new Error('SSH state directory 不允许符号链接。');const parent=dirname(current);if(parent===current)break;current=parent;}}
function immutable(path,content){
 try{writeFileSync(path,content,{mode:0o600,flag:constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|(constants.O_NOFOLLOW??0)});}
 catch(error){if(error.code!=='EEXIST')throw error;const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||(process.platform!=='win32'&&(stat.uid!==process.getuid()||(stat.mode&0o077)!==0))||readFileSync(path,'utf8')!==content)throw new Error('SSH state file 已变更或不安全。');}
}
export function prepareInvocation(host,command,cwd=host.defaultCwd,{dataDir,platform=process.platform}={}) {
 const file=platform==='win32'?'ssh.exe':'ssh',connection=normalizeConnection(host.connection);
 if(!connection)return {file,args:buildSshArgs(host,command,cwd)};
 if(connection.mode==='native'){if(typeof host.sshAlias!=='string'||!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/u.test(host.sshAlias))throw new Error('原生模式需要有效 sshAlias。');return {file,args:buildSshArgs(host,command,cwd)};}
 if(host.sshAlias)throw new Error('托管连接不能同时使用 sshAlias。');
 const target=endpoint({...host,hostKeys:connection.hostKeys}),route=[...connection.jumpHosts,target];
 if(route.some(h=>!h.hostKeys.length))throw new Error('连接前必须确认每一跳的 SSH 公钥。');
 if(typeof dataDir!=='string'||!dataDir)throw new Error('托管连接需要 dataDir。');
 ancestors(dataDir);const base=join(resolve(dataDir),'transport');privateDir(base);
 // Include every route, key and setting so reused masters never cross policy revisions.
 const digest=createHash('sha256').update(JSON.stringify({version:2,target,connection,platform})).digest('hex').slice(0,32);
 const state=join(base,digest),known=join(state,'known_hosts'),configFile=join(state,'config');privateDir(state);
 const aliases=route.map((_,i)=>i===route.length-1?'target':`hop${i}`);
 immutable(known,route.flatMap((h,i)=>h.hostKeys.map(key=>`${aliases[i]} ${key}`)).join('\n')+'\n');
 const pooled=connection.pooling.enabled&&['linux','darwin','freebsd','openbsd','netbsd'].includes(platform);
 // OpenSSH adds a temporary suffix while binding a master socket. Keep room for it.
 if(pooled&&process.platform!=='win32'&&Buffer.byteLength(join(state,'s0'))>87)throw new Error('连接池 socket 路径过长；请使用更短的 dataDir 或关闭连接池。');
 const common=['Host *','  BatchMode yes','  StrictHostKeyChecking yes',`  UserKnownHostsFile ${quote(known)}`,'  GlobalKnownHostsFile none','  UpdateHostKeys no','  VerifyHostKeyDNS no','  ForwardAgent no','  ForwardX11 no','  ClearAllForwardings yes','  PermitLocalCommand no','  RequestTTY no','  PasswordAuthentication no','  KbdInteractiveAuthentication no',`  ConnectTimeout ${connection.connectTimeoutSeconds}`,`  ServerAliveInterval ${connection.keepaliveIntervalSeconds}`,`  ServerAliveCountMax ${connection.keepaliveCountMax}`];
 if(pooled)common.push('  ControlMaster auto',`  ControlPersist ${connection.pooling.persistSeconds}`);else common.push('  ControlMaster no','  ControlPath none');
 route.forEach((h,i)=>{common.push('',`Host ${aliases[i]}`,`  HostName ${quote(h.hostname)}`,`  Port ${h.port}`,`  User ${quote(h.username)}`,`  HostKeyAlias ${aliases[i]}`,`  IdentitiesOnly ${h.identityFile?'yes':'no'}`);if(h.identityFile)common.push(`  IdentityFile ${quote(h.identityFile)}`);if(pooled)common.push(`  ControlPath ${quote(join(state,`s${i}`))}`);if(i>0)common.push(`  ProxyJump ${aliases[i-1]}`);});
 immutable(configFile,common.join('\n')+'\n');
 return {file,args:['-F',configFile,'-T','--','target',cwd?`cd -- ${shellQuote(cwd)} || exit $?;\n${command}`:command]};
}
