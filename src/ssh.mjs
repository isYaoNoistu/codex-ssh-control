import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { StringDecoder } from 'node:string_decoder';
import { createOutputScanner } from './operation-display.mjs';
import { prepareInvocation } from './transport.mjs';

export function shellQuote(value) { return "'"+String(value).replaceAll("'", "'\"'\"'")+"'"; }
export function buildSshArgs(host, command, cwd=host.defaultCwd) {
 const args=['-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=~/.ssh/known_hosts','-o','ConnectTimeout=10','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2'];
 if (!host.sshAlias) args.push('-p',String(host.port));
 if (host.identityFile) args.push('-i',host.identityFile);
 const destination=host.sshAlias || `${host.username}@${host.hostname}`;
 args.push('--',destination,cwd?`cd -- ${shellQuote(cwd)} || exit $?;\n${command}`:command);
 return args;
}

export function createRunner({spawnImpl=spawn,outputLimit=128*1024,dataDir}={}) {
 const tasks=new Map();
 function owned(threadId,id) {
  const t=tasks.get(id);
  if (!t || t.threadId!==threadId) throw new Error('此任务不属于当前对话，或任务记录已过期。');
  return t;
 }
 function snapshot(t,internal=false) {
  const sensitiveOutput=t.scanner.sensitive, hidden=!internal&&(t.privateOutput||sensitiveOutput);
  return {id:t.id,hostId:t.hostId,status:t.status,command:t.command,cwd:t.cwd,
   stdout:hidden?'':t.stdout,stderr:hidden?(t.privateOutput?'':'输出含有可能的凭据信息，已隐藏。'):t.stderr,exitCode:t.exitCode,truncated:t.truncated,sensitiveOutput,
   startedAt:t.startedAt,finishedAt:t.finishedAt,
   ...(t.status==='cancelled'||t.status==='timed_out'?{notice:'已结束本机 SSH 进程；远端已完成的操作不会撤销，脱离会话的后台进程可能继续运行。'}:{})};
 }
 function start(threadId,host,command,{cwd=host.defaultCwd,timeoutSeconds=60,input,outputLimitBytes=outputLimit,privateOutput=false}={}) {
  if (!threadId) throw new Error('缺少当前对话标识。');
  if (typeof command!=='string'||!command.trim()||command.length>16000||command.includes('\0')) throw new Error('命令不能为空，且不能超过 16000 字符。');
  if (typeof cwd!=='string'||/[\0\r\n]/.test(cwd)||cwd.length>4096) throw new Error('工作目录无效。');
  if (!Number.isFinite(timeoutSeconds)||timeoutSeconds<=0||timeoutSeconds>300) throw new Error('超时应大于 0 且不超过 300 秒。');
  if (!Number.isInteger(outputLimitBytes)||outputLimitBytes<1||outputLimitBytes>1024*1024) throw new Error('输出限制无效');
  for (const [id,t] of tasks) if(t.finishedAt && Date.now()-Date.parse(t.finishedAt)>30*60*1000) tasks.delete(id);
  if (tasks.size>=100) {const oldest=[...tasks.values()].find(t=>t.finishedAt);if(oldest)tasks.delete(oldest.id);else throw new Error('运行中的任务过多。');}
  const t={id:randomUUID(),threadId,hostId:host.id,command,cwd,status:'running',stdout:'',stderr:'',exitCode:null,truncated:false,startedAt:new Date().toISOString(),finishedAt:null,bytes:0,privateOutput,scanner:createOutputScanner()};
  let resolveDone; t.done=new Promise(resolve=>{resolveDone=resolve;});
  tasks.set(t.id,t);
  const finish=(code,error)=>{
   if(t.finishedAt)return;
   clearTimeout(t.timer);
   if(error)append('stderr',String(error));
   t.exitCode=code;t.finishedAt=new Date().toISOString();
   if(t.status==='running')t.status=code===0?'completed':'failed';
   resolveDone(snapshot(t,true));
  };
  function append(channel,value){
   t.scanner.push(channel,value);
   const bytes=Buffer.from(value),remaining=Math.max(0,outputLimitBytes-t.bytes);
   if(bytes.length>remaining)t.truncated=true;
   let length=Math.min(bytes.length,remaining);
   // Buffer was encoded from a complete string; back up to a UTF-8 boundary.
   while(length>0 && length<bytes.length && (bytes[length]&0xc0)===0x80) length--;
   t.bytes+=Math.min(bytes.length,remaining);
   t[channel]+=bytes.subarray(0,length).toString('utf8');
  }
  try {
   const invocation=prepareInvocation(host,command,cwd,{dataDir});
   t.child=spawnImpl(invocation.file,invocation.args,{shell:false,windowsHide:true,stdio:['pipe','pipe','pipe']});
   const stdoutDecoder=new StringDecoder('utf8'),stderrDecoder=new StringDecoder('utf8');
   t.child.stdout.on('data',b=>append('stdout',stdoutDecoder.write(b)));
   t.child.stderr.on('data',b=>append('stderr',stderrDecoder.write(b)));
   t.child.stdout.on('end',()=>append('stdout',stdoutDecoder.end()));
   t.child.stderr.on('end',()=>append('stderr',stderrDecoder.end()));
   t.child.on('error',e=>finish(null,e.message));
   t.child.on('close',code=>finish(code));
   t.child.stdin.on('error',()=>{});
   t.child.stdin.end(input??'');
   t.timer=setTimeout(()=>{if(!t.finishedAt){t.status='timed_out';t.child.kill();}},timeoutSeconds*1000);
   t.timer.unref();
  }catch(e){finish(null,e.message);}
  return snapshot(t);
 }
 return {
  start,
  read:(threadId,id)=>snapshot(owned(threadId,id)),
  wait:(threadId,id)=>owned(threadId,id).done,
  cancel:(threadId,id)=>{const t=owned(threadId,id);if(!t.finishedAt){t.status='cancelled';t.child?.kill();}return snapshot(t);},
  close:()=>{for(const t of tasks.values())if(!t.finishedAt){t.status='cancelled';t.child?.kill();}},
 };
}
