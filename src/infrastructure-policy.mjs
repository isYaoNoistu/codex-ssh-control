import { isProtectedPath, isSensitiveContent, evaluateOperation } from './policy.mjs';
import path from 'node:path';
import {INFRASTRUCTURE_DEFAULTS} from './infrastructure-defaults.mjs';
export {INFRASTRUCTURE_DEFAULTS} from './infrastructure-defaults.mjs';
const kinds = new Set(['job','job_control','transfer','transfer_inspect','transfer_control','transfer_mkdir','capabilities','lifecycle']);
const shells = new Set(['/bin/sh','/bin/bash','/bin/zsh']);
const forbiddenEnv = /^(?:PATH|HOME|SHELL|ENV|BASH_ENV|ZDOTDIR|IFS|CDPATH|GLOBIGNORE|SHELLOPTS|BASHOPTS|LD_.*|DYLD_.*|PYTHON.*|NODE.*|PERL.*|RUBY.*|SSH_.*)$/iu;
const safeName = /^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$/u;
const own = (v,k) => Object.hasOwn(v,k);
function object(v, keys, label) {
  if(!v || typeof v!=='object' || Array.isArray(v)) throw new Error(label+'必须为对象');
  for(const k of Object.keys(v)) if(!keys.includes(k)) throw new Error(label+'包含未知字段：'+k);
}
function str(v,label,max=4096) {
  if(typeof v!=='string'||!v||v.length>max||/[\u0000-\u001f\u007f]/u.test(v)) throw new Error(label+'无效');
  return v;
}
function integer(v,min,max,label) { if(!Number.isSafeInteger(v)||v<min||v>max) throw new Error(label+'超出范围'); return v; }
function strings(v,label,max=64) { if(!Array.isArray(v)||v.length>max||new Set(v).size!==v.length)throw new Error(label+'无效');return v.map(x=>str(x,label,128)); }
export function normalizeLocalPath(value) {
  let p=str(value,'本地绝对路径').replaceAll('\\','/');
  if(!p.startsWith('/')&&!/^[A-Za-z]:\//u.test(p))throw new Error('本地路径必须为绝对路径');
  if(p.startsWith('//')||p.includes('//')||p.split('/').some(x=>x==='.'||x==='..'))throw new Error('本地路径不能包含 UNC、空分量或路径遍历');
  if(/^[A-Za-z]:/u.test(p)) {
    if(p.slice(2).includes(':')||p.split('/').slice(1).some(x=>/[. ]$/u.test(x)||/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(x)))throw new Error('不支持设备路径、数据流或歧义 Windows 文件名');
    p=p[0].toUpperCase()+p.slice(1);
  } else if(p.includes('\\')) throw new Error('本地路径无效');
  return p.length>1&&!/^[A-Z]:\/$/u.test(p)?p.replace(/\/$/u,''):p;
}
function remotePath(p) { str(p,'远端路径');if(!p.startsWith('/')||p.includes('\\')||p.includes('//')||p.split('/').some(x=>x==='.'||x==='..'))throw new Error('远端路径必须为明确 POSIX 绝对路径');return p.length>1?p.replace(/\/$/u,''):p; }
function inside(p,root,match='recursive',local=false) {
  if(local&&/^[A-Z]:/u.test(root)){p=p.toLowerCase();root=root.toLowerCase();}
  return p===root||(match==='recursive'&&p.startsWith(root.replace(/\/$/u,'')+'/'));
}
function deniedDescendants(roots,selected,permission,local=false) {
  if(selected.match==='exact')return [];
  // A manifest reads every descendant before per-file approvals. Carry narrower
  // restrictions into traversal itself, so forbidden content is never hashed.
  return roots.filter(r=>!r[permission]&&r.path!==selected.path&&inside(r.path,selected.path,'recursive',local)).map(r=>r.path).sort();
}
export function localProtected(p) {
  const converted=normalizeLocalPath(p).replace(/^[A-Z]:/u,'');
  return isProtectedPath(converted)||/(?:^|\/)(?:\.codex|\.agents|\.git|windows|program files(?: \(x86\))?)(?:\/|$)/iu.test(converted);
}
export function validateInfrastructurePolicy(input,catalog) {
  const localRoots=input.localRoots??[];
  if(!Array.isArray(localRoots)||localRoots.length>64)throw new Error('本地目录最多64项');
  const roots=localRoots.map(r=>{object(r,['id','path','read','write','match'],'本地目录');if(!/^[a-z][a-z0-9-]{0,47}$/u.test(r.id)||typeof r.read!=='boolean'||typeof r.write!=='boolean')throw new Error('本地目录设置无效');const match=r.match??'recursive';if(!['exact','recursive'].includes(match))throw new Error('目录匹配方式无效');return {id:r.id,path:normalizeLocalPath(r.path),read:r.read,write:r.write,match};});
  if(new Set(roots.map(r=>r.id)).size!==roots.length||new Set(roots.map(r=>/^[A-Z]:/u.test(r.path)?r.path.toLowerCase():r.path)).size!==roots.length)throw new Error('本地目录不能重复');
  const actionArguments=input.actionArguments??{};object(actionArguments,[...catalog.keys()],'动作参数规则');
  const checkedArgs={};for(const [id,rule] of Object.entries(actionArguments)){if(!catalog.get(id).parameters.length)throw new Error('无参数动作不能配置名称白名单');object(rule,['names'],'动作参数');const names=strings(rule.names,'名称白名单');if(names.some(n=>!safeName.test(n)||(id.startsWith('container.')&&n.includes('@'))))throw new Error('名称白名单格式无效');checkedArgs[id]={names};}
  const jobs={...INFRASTRUCTURE_DEFAULTS.jobs,...input.jobs};object(jobs,Object.keys(INFRASTRUCTURE_DEFAULTS.jobs),'任务权限');
  if(typeof jobs.enabled!=='boolean')throw new Error('任务开关无效');
  integer(jobs.timeoutSeconds,1,86400,'任务时限');integer(jobs.maxOutputKiB,16,1024,'任务输出');integer(jobs.cpuSeconds,1,86400,'CPU秒数');integer(jobs.maxMemoryMiB,64,65536,'进程内存');integer(jobs.maxProcesses,1,1024,'进程数');
  jobs.allowedShells=strings(jobs.allowedShells,'Shell列表',3);if(!jobs.allowedShells.length||jobs.allowedShells.some(s=>!shells.has(s)))throw new Error('Shell不受支持');
  jobs.allowedEnv=strings(jobs.allowedEnv,'环境变量白名单');if(jobs.allowedEnv.some(k=>!/^[_A-Za-z][_A-Za-z0-9]*$/u.test(k)||forbiddenEnv.test(k)||isSensitiveContent(k+'=value')))throw new Error('不允许安全敏感环境变量');
  const transfers={...INFRASTRUCTURE_DEFAULTS.transfers,...input.transfers};object(transfers,Object.keys(INFRASTRUCTURE_DEFAULTS.transfers),'制品传输');if(typeof transfers.enabled!=='boolean')throw new Error('传输开关无效');integer(transfers.maxBytes,1,10737418240,'传输大小');integer(transfers.maxEntries,1,1000,'目录文件数');integer(transfers.timeoutSeconds,1,86400,'传输时限');
  return {localRoots:roots,actionArguments:checkedArgs,jobs,transfers};
}
function snapshot(v) {
  object(v,['dev','ino','size','mtimeNs','ctimeNs','mode','sha256'],'文件快照');
  for(const k of ['dev','ino','mtimeNs','ctimeNs'])if(typeof v[k]!=='string'||!/^\d{1,32}$/u.test(v[k]))throw new Error('文件快照标识无效');
  integer(v.size,0,10737418240,'文件大小');integer(v.mode,0,511,'文件权限');if(!/^[a-f0-9]{64}$/u.test(v.sha256))throw new Error('文件 SHA256 无效');return {...v};
}
export function normalizeInfrastructureOperation(input) {
  if(!kinds.has(input.kind))return null;
  const {kind}=input;
  if(kind==='lifecycle'){
    object(input,['kind','resource','action','id'],'私有状态操作');
    if(!['job','transfer'].includes(input.resource)||!['collect','inspect'].includes(input.action))throw new Error('无效的回收目标或操作');
    return {kind,resource:input.resource,action:input.action,id:str(input.id,'记录标识',128)};
  }
  if(kind==='capabilities'){object(input,['kind'],'能力探测');return {kind};}
  if(kind.endsWith('_control')){
    object(input,['kind','id','action','transfer'],'任务控制');str(input.id,'任务ID',128);
    if(!['read','cancel','reconcile','resume','cleanup'].includes(input.action)||kind==='job_control'&&['resume','cleanup'].includes(input.action))throw new Error('任务控制动作无效');
    const out={kind,id:input.id,action:input.action};
    if(input.action==='resume'){
      if(input.transfer?.kind!=='transfer')throw new Error('续传需要完整的新审批快照');
      out.transfer=normalizeInfrastructureOperation(input.transfer);
      if(out.transfer.planId!==input.id)throw new Error('续传计划不匹配');
    }else if(input.action==='cleanup' && input.transfer!==undefined){
      if(input.transfer?.kind!=='transfer_inspect'||input.transfer.recursive===true)throw new Error('清理需要对应传输的路径快照');
      out.transfer=normalizeInfrastructureOperation(input.transfer);
    }else if(input.transfer!==undefined)throw new Error('此控制操作不接受传输快照');
    return out;
  }
  if(kind==='transfer_mkdir'){
    object(input,['kind','side','root','path','blockedPaths','expiresAt'],'传输目录');
    if(!['local','remote'].includes(input.side))throw new Error('目录端点无效');
    const normalize=input.side==='local'?normalizeLocalPath:remotePath;
    return {kind,side:input.side,root:normalize(input.root),path:normalize(input.path),blockedPaths:(input.blockedPaths??[]).map(remotePath),expiresAt:integer(input.expiresAt,1,Number.MAX_SAFE_INTEGER,'目录许可期限')};
  }
  if(kind==='job') {
    object(input,['kind','command','cwd','env','shell','timeoutSeconds','maxOutputBytes','disconnectPolicy','idempotencyKey','cpuSeconds','maxMemoryMiB','maxProcesses'],'后台任务');
    if(typeof input.command!=='string'||!input.command.trim()||input.command.length>16000||input.command.includes('\0'))throw new Error('命令无效');
    const env=input.env??{};if(!env||typeof env!=='object'||Array.isArray(env)||Object.keys(env).length>64)throw new Error('环境变量无效');
    const normalizedEnv={};for(const k of Object.keys(env).sort()){if(!/^[_A-Za-z][_A-Za-z0-9]{0,127}$/u.test(k)||forbiddenEnv.test(k)||typeof env[k]!=='string'||env[k].length>4096||/[\0\r\n]/u.test(env[k])||isSensitiveContent(k+'='+env[k]))throw new Error('环境变量涉及敏感资源或格式无效');normalizedEnv[k]=env[k];}
    const shell=input.shell??'/bin/sh';if(!shells.has(shell))throw new Error('Shell不受支持');if((input.disconnectPolicy??'continue')!=='continue')throw new Error('仅支持已确认的断线继续模式');
    const out={kind,command:input.command,cwd:input.cwd?remotePath(input.cwd):'',env:normalizedEnv,shell,timeoutSeconds:integer(input.timeoutSeconds??3600,1,86400,'任务时限'),maxOutputBytes:integer(input.maxOutputBytes??1048576,1024,1048576,'任务输出'),disconnectPolicy:'continue'};
    if(input.idempotencyKey!==undefined)out.idempotencyKey=str(input.idempotencyKey,'幂等标识',128);
    for(const [key,min,max] of [['cpuSeconds',1,86400],['maxMemoryMiB',64,65536],['maxProcesses',1,1024]])if(input[key]!==undefined)out[key]=integer(input[key],min,max,key);
    return out;
  }
  const base=['kind','direction','localPath','remotePath'];
  object(input,kind==='transfer_inspect'?[...base,'recursive']:[...base,'planId','size','sha256','sourceSnapshot','targetSnapshot','overwrite','localRoot','remoteRoot','blockedPaths','localBlockedPaths','expiresAt','maxBytes'],'文件传输');
  if(!['upload','download'].includes(input.direction))throw new Error('传输方向无效');
  const out={kind,direction:input.direction,localPath:normalizeLocalPath(input.localPath),remotePath:remotePath(input.remotePath)};
  if(kind==='transfer_inspect'){if(input.recursive!==undefined&&typeof input.recursive!=='boolean')throw new Error('递归选项无效');return {...out,recursive:input.recursive??false};}
  if(input.overwrite!=='never'||input.targetSnapshot!==null)throw new Error('制品传输使用新文件路径，不允许覆盖现有目标');
  str(input.planId,'传输计划ID',128);integer(input.size,0,10737418240,'传输大小');if(!/^[a-f0-9]{64}$/u.test(input.sha256))throw new Error('SHA256无效');
  const source=snapshot(input.sourceSnapshot);if(source.size!==input.size||source.sha256!==input.sha256)throw new Error('源文件摘要与快照不一致');
  if(!Array.isArray(input.blockedPaths)||!Array.isArray(input.localBlockedPaths))throw new Error('传输需要完整路径约束');
  return {...out,planId:input.planId,size:input.size,sha256:input.sha256,sourceSnapshot:source,targetSnapshot:null,overwrite:'never',localRoot:normalizeLocalPath(input.localRoot),remoteRoot:remotePath(input.remoteRoot),blockedPaths:input.blockedPaths.map(remotePath),localBlockedPaths:input.localBlockedPaths.map(normalizeLocalPath),expiresAt:integer(input.expiresAt,1,Number.MAX_SAFE_INTEGER,'传输期限'),maxBytes:integer(input.maxBytes,1,10737418240,'传输上限')};
}
export function evaluateInfrastructureOperation(policy,operation) {
  if(!kinds.has(operation.kind))return null;
  if(operation.kind==='lifecycle'){
    const collect=operation.action==='collect';
    return {operation,decision:collect?'ask':'allow',code:'LIFECYCLE',summary:collect?'回收已归档记录的私有状态':'查看记录的远端私有状态占用',reason:'仅核验当前聊天拥有的记录'};
  }
  const names={job:'提交可恢复远程任务',job_control:'管理远程任务',transfer:'传输制品文件',transfer_inspect:'核对制品路径和摘要',transfer_control:'管理制品传输',transfer_mkdir:'创建传输目标目录',capabilities:'探测远端执行能力'};
  const result=(decision,code,reason,extra={})=>({decision,code,reason,operation,summary:names[operation.kind],...extra});
  if(operation.kind==='capabilities')return result(policy.actions['connection.test'],'CAPABILITY_PROBE','读取远端运行条件；不安装软件');
  if(operation.kind.endsWith('_control')){
    if(operation.action==='cleanup'){
      if(!operation.transfer)return result('deny','TRANSFER_SCOPE_REQUIRED','清理需要对应传输的路径快照');
      const scope=evaluateInfrastructureOperation(policy,operation.transfer);
      if(scope.decision==='deny')return {...scope,operation,summary:names[operation.kind]};
      return result('ask','TRANSFER_CLEANUP_CONFIRM','回收此传输的私有状态必须逐次确认');
    }
    if(operation.action==='resume'){
      const next=evaluateInfrastructureOperation(policy,operation.transfer);
      return {...next,operation,summary:names[operation.kind]};
    }
    return result(operation.action==='cancel'?'ask':'allow','TASK_CONTROL','仅管理当前聊天拥有的精确任务');
  }
  if(operation.kind==='job') {
    if(!policy.jobs.enabled)return result('deny','JOBS_DISABLED','尚未启用可恢复任务');
    if(operation.timeoutSeconds>policy.jobs.timeoutSeconds||operation.maxOutputBytes>policy.jobs.maxOutputKiB*1024||!policy.jobs.allowedShells.includes(operation.shell)||Object.keys(operation.env).some(k=>!policy.jobs.allowedEnv.includes(k)))return result('deny','JOB_LIMIT','任务执行选项超出权限限制');
    if(['cpuSeconds','maxMemoryMiB','maxProcesses'].some(k=>own(operation,k)&&operation[k]>policy.jobs[k]))return result('deny','JOB_LIMIT','任务资源限制超出策略');
    const ordinary=evaluateOperation(policy,{kind:'command',command:operation.command,cwd:operation.cwd});
    if(ordinary.decision==='deny')return result('deny',ordinary.code,ordinary.reason);
    return result('ask','JOB_REQUIRES_APPROVAL','后台任务会在聊天连接断开后继续；需核对完整命令和运行限制',{command:ordinary.command});
  }
  if(!policy.transfers.enabled)return result('deny','TRANSFERS_DISABLED','尚未启用制品传输');
  if(operation.kind==='transfer_mkdir'){
    const local=operation.side==='local',roots=local?policy.localRoots:policy.roots;
    const root=roots.filter(r=>inside(operation.path,r.path,r.match??'recursive',local)).sort((a,b)=>b.path.length-a.path.length)[0];
    if((local?localProtected(operation.path):isProtectedPath(operation.path,policy.blockedPaths)))return result('deny','PROTECTED_PATH','目录涉及受保护路径');
    if(!root?.write||root.match==='exact'||root.path!==operation.root||operation.path===root.path)return result('deny','TRANSFER_PATH_NOT_ALLOWED','创建目录需要递归写权限，且不能创建授权根本身');
    if(JSON.stringify(operation.blockedPaths)!==JSON.stringify(local?[]:policy.blockedPaths))return result('deny','TRANSFER_POLICY_CHANGED','目录路径约束已变化');
    return result('ask','TRANSFER_MKDIR','仅逐级创建缺少的目录，已有安全目录保持不变');
  }
  if(localProtected(operation.localPath)||isProtectedPath(operation.remotePath,policy.blockedPaths))return result('deny','PROTECTED_PATH','本地或远端路径涉及安全配置或凭据');
  const upload=operation.direction==='upload';
  const local=policy.localRoots.filter(r=>inside(operation.localPath,r.path,r.match,true)).sort((a,b)=>b.path.length-a.path.length)[0];
  const remote=policy.roots.filter(r=>inside(operation.remotePath,r.path,r.match??'recursive')).sort((a,b)=>b.path.length-a.path.length)[0];
  if(!local||!remote||!(upload?local.read&&remote.write:local.write&&remote.read))return result('deny','TRANSFER_PATH_NOT_ALLOWED','两端路径均需配置所需权限');
  if(operation.kind==='transfer_inspect'&&operation.recursive&&(local.match==='exact'||remote.match==='exact'))return result('deny','TRANSFER_PATH_NOT_ALLOWED','递归规划需要两端递归目录权限');
  if(operation.kind==='transfer'&&((operation.localPath===local.path&&local.match!=='exact')||(operation.remotePath===remote.path&&remote.match!=='exact')))return result('deny','ROOT_MUTATION_DENIED','不能传输到授权根目录本身');
  if(operation.kind==='transfer'&&operation.size>policy.transfers.maxBytes)return result('deny','TRANSFER_LIMIT','制品超过传输大小限制');
  const localRoot=local.match==='exact'?path.posix.dirname(local.path):local.path,remoteRoot=remote.match==='exact'?path.posix.dirname(remote.path):remote.path;
  const localBlockedPaths=deniedDescendants(policy.localRoots,local,upload?'read':'write',true);
  const blockedPaths=[...new Set([...policy.blockedPaths,...deniedDescendants(policy.roots,remote,upload?'write':'read')])];
  if(operation.kind==='transfer'&&(operation.localRoot!==localRoot||operation.remoteRoot!==remoteRoot||JSON.stringify(operation.blockedPaths)!==JSON.stringify(blockedPaths)||JSON.stringify(operation.localBlockedPaths)!==JSON.stringify(localBlockedPaths)||operation.maxBytes!==policy.transfers.maxBytes))return result('deny','TRANSFER_POLICY_CHANGED','传输快照的路径约束或大小上限已变化，请重新准备');
  return result(operation.kind==='transfer'?'ask':'allow','TRANSFER_POLICY','二进制制品需确认；摘要不能证明文件不含秘密',{transfer:{localRoot,remoteRoot,blockedPaths,localBlockedPaths,...policy.transfers}});
}
