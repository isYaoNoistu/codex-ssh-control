import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { mkdirSync, readFileSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import { isSensitiveContent } from './policy.mjs';
import {installLifecycleLocks,takeLease} from './lifecycle-lock.mjs';

const terminal=new Set(['completed','failed','cancelled','timed_out']);
const statuses=new Set(['submitted','running','missing','unknown',...terminal]);
const helper=readFileSync(new URL('../remote/task_guard.py',import.meta.url),'utf8');
const quote=s=>"'"+s.replaceAll("'","'\"'\"'")+"'";
const command=`/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/python3 -I -S -B -c ${quote(helper)}`;
export {command as jobHelperCommand};
function requestInput(record,action){
 const input=JSON.stringify({action,id:record.id,token:record.token,...(action==='submit'?{spec:record.operation}:{})});
 if(Buffer.byteLength(input)>131072)throw Error('Serialized task request exceeds 128 KiB');
 return input;
}
const hash=x=>createHash('sha256').update(stable(x)).digest('hex');
function stable(x){if(Array.isArray(x))return '['+x.map(stable).join(',')+']';if(x&&typeof x==='object')return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+stable(x[k])).join(',')+'}';return JSON.stringify(x);}
function normalizeOperation(value,host){
 if(!value||typeof value!=='object')throw Error('Invalid task operation');
 const op={command:value.command,cwd:value.cwd??host.defaultCwd??'/tmp',env:value.env??{},shell:value.shell??'/bin/sh',timeoutSeconds:value.timeoutSeconds??3600,disconnectPolicy:value.disconnectPolicy??'continue',maxOutputBytes:value.maxOutputBytes??131072};
 if(typeof op.command!=='string'||!op.command.trim()||op.command.length>16000||op.command.includes('\0'))throw Error('Invalid command');
 if(typeof op.cwd!=='string'||!op.cwd.startsWith('/')||op.cwd.length>4096||/[\0\r\n]/.test(op.cwd))throw Error('Invalid cwd');
 if(!['/bin/sh','/bin/bash','/bin/zsh'].includes(op.shell))throw Error('Invalid shell');
 if(!Number.isInteger(op.timeoutSeconds)||op.timeoutSeconds<1||op.timeoutSeconds>86400)throw Error('Invalid timeoutSeconds');
 if(!Number.isInteger(op.maxOutputBytes)||op.maxOutputBytes<1024||op.maxOutputBytes>1048576)throw Error('Invalid maxOutputBytes');
 if(op.disconnectPolicy!=='continue')throw Error('Unsupported disconnectPolicy');
 for(const [key,max]of Object.entries({cpuSeconds:86400,maxMemoryMiB:1048576,maxProcesses:65536}))if(value[key]!==undefined){if(!Number.isInteger(value[key])||value[key]<1||value[key]>max)throw Error(`Invalid ${key}`);op[key]=value[key];}
 if(!op.env||typeof op.env!=='object'||Array.isArray(op.env)||Object.keys(op.env).length>64)throw Error('Invalid env');
 for(const [key,val]of Object.entries(op.env))if(!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)||/^(PATH|HOME|SHELL|ENV|BASH_ENV|IFS|CDPATH|GLOBIGNORE|SHELLOPTS|BASHOPTS|ZDOTDIR|LD_.*|DYLD_.*|PYTHON.*|NODE.*|PERL.*|RUBY.*|SSH_.*)$/i.test(key)||typeof val!=='string'||val.length>8192||val.includes('\0'))throw Error('Invalid or unsafe env');
 return JSON.parse(JSON.stringify(op));
}
function publicRecord(r){const {token,identity,idempotencyKey,log,...safe}=r;return safe;}
function textSlice(text,cursor,limit){const b=Buffer.from(text);if(cursor>b.length)cursor=b.length;while(cursor<b.length&&(b[cursor]&192)===128)cursor++;let end=Math.min(b.length,cursor+limit);while(end>cursor&&end<b.length&&(b[end]&192)===128)end--;if(end===cursor&&cursor<b.length)throw Error('Page limit cannot fit the next UTF-8 character; use at least 4 bytes');return {output:b.subarray(cursor,end).toString('utf8'),cursor,nextCursor:end,hasMore:end<b.length};}

/** Durable task control. A failed transport is an observation failure, never a replay instruction. */
export class JobService {
 constructor({dataDir,execute,authorize,beforeDispatch=()=>{},sanitizeOutput,onUpdate}={}){
  if(!dataDir||typeof execute!=='function'||typeof authorize!=='function'||typeof beforeDispatch!=='function')throw Error('Task service requires dataDir, execute and authorize');
  const stateDir=join(dataDir,'task-state');mkdirSync(stateDir,{recursive:true,mode:0o700});const stat=lstatSync(stateDir);if(stat.isSymbolicLink()||!stat.isDirectory()||(process.platform!=='win32'&&(stat.uid!==process.getuid()||(stat.mode&0o077))))throw Error('Unsafe local task state directory');
  this.db=new DatabaseSync(join(stateDir,'jobs.sqlite'));this.execute=execute;this.authorize=authorize;this.beforeDispatch=beforeDispatch;this.sanitizeOutput=sanitizeOutput;this.onUpdate=onUpdate;
  this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, idem TEXT NOT NULL, identity TEXT NOT NULL, record TEXT NOT NULL, UNIQUE(thread_id,idem))');
  installLifecycleLocks(this.db);
 }
 close(){if(this.db){this.db.close();this.db=null;}}
 owned(threadId,taskId){const row=this.db.prepare('SELECT record FROM jobs WHERE id=? AND thread_id=?').get(taskId,threadId);if(!row)throw Error('Task does not belong to this chat');return JSON.parse(row.record);}
 save(record){
  this.db.exec('BEGIN IMMEDIATE');
  try{
   const latest=this.owned(record.threadId,record.id);
   if(latest.archivedAt)throw Error('任务已归档');
   record.cancelRequested=record.cancelRequested||latest.cancelRequested;
   record.redacted=record.redacted||latest.redacted;
   if(terminal.has(latest.status)&&!terminal.has(record.status))for(const key of ['status','exitCode','signal','terminationReason','log','truncated'])record[key]=latest[key];
   // Concurrent controllers may receive snapshots out of order. Logs only append.
   if(!record.redacted){
    if(latest.log.startsWith(record.log))record.log=latest.log;
    else if(!record.log.startsWith(latest.log)){
     record.log=latest.log;record.observation='unknown';record.transportError='Remote log prefix changed; existing output retained.';
    }
   }
   record.truncated=record.truncated||latest.truncated;
   if(record.redacted)record.log='';
   record.updatedAt=new Date().toISOString();
   if(terminal.has(record.status)&&record.observation==='confirmed')record.finishedAt=latest.finishedAt??record.updatedAt;
   this.db.prepare('UPDATE jobs SET record=? WHERE id=?').run(JSON.stringify(record),record.id);
   this.db.exec('COMMIT');
  }catch(error){this.db.exec('ROLLBACK');throw error;}
 }
 async permit(stage,record){if(await this.authorize(stage,structuredClone(publicRecord(record)))===false)throw Error('Task authorization refused');}
 async update(record){this.save(record);if(this.onUpdate)await this.onUpdate(publicRecord(record));}
 async submit({threadId,sessionId=null,host,operation,idempotencyKey=randomUUID()}){
  if(typeof threadId!=='string'||!threadId||threadId.length>256||!host||typeof host.id!=='string')throw Error('Invalid task ownership');
  if(typeof idempotencyKey!=='string'||!idempotencyKey||idempotencyKey.length>128||/[\x00-\x1f]/.test(idempotencyKey))throw Error('Invalid idempotencyKey');
  const op=normalizeOperation(operation,host),snapshot=JSON.parse(JSON.stringify(host)),identity=hash({threadId,host:snapshot,operation:op});
  const prior=this.db.prepare('SELECT record FROM jobs WHERE thread_id=? AND idem=?').get(threadId,idempotencyKey);
  if(prior){const r=JSON.parse(prior.record);if(r.identity!==identity)throw Error('Task immutable snapshot mismatch');return publicRecord(r);}
  const record={id:randomUUID().replaceAll('-',''),threadId,sessionId,hostId:host.id,host:snapshot,operation:op,idempotencyKey,identity,token:randomBytes(32).toString('hex'),status:'submitted',observation:'unknown',exitCode:null,signal:null,terminationReason:null,cancelRequested:false,log:'',redacted:false,truncated:false,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
  requestInput(record,'submit');
  await this.permit('submit',record);
  // Insert before contacting SSH. A crash from this point is reconciled by read, never resubmitted.
  try{this.db.prepare('INSERT INTO jobs VALUES(?,?,?,?,?)').run(record.id,threadId,idempotencyKey,identity,JSON.stringify(record));}
  catch(error){const raced=this.db.prepare('SELECT record FROM jobs WHERE thread_id=? AND idem=?').get(threadId,idempotencyKey);if(!raced)throw error;const r=JSON.parse(raced.record);if(r.identity!==identity)throw Error('Task immutable snapshot mismatch');return publicRecord(r);}
  try{const result=this.beforeDispatch(structuredClone(publicRecord(record)));if(result&&typeof result.then==='function')throw Error('beforeDispatch must be synchronous');}
  catch(error){record.status='failed';record.observation='confirmed';record.terminationReason='launch_failed';await this.update(record);throw error;}
  const release=takeLease(this.db,record.id);
  try { await this.remote(record,'submit');return publicRecord(record); } finally { release(); }
 }
 async remote(record,action){
  let response;
  try{
   const transport=await this.execute(record.host,command,{input:requestInput(record,action),timeoutSeconds:15,maxOutputBytes:1600000});
   if(transport.exitCode!==0)throw Error('control_transport_failed');
   if(typeof transport.stdout!=='string'||Buffer.byteLength(transport.stdout)>1600000)throw Error('control_response_invalid');
   response=JSON.parse(transport.stdout);
   if(response.error||!statuses.has(response.status))throw Error('control_response_rejected');
   const bytes=Buffer.from(response.log??'','base64');if(bytes.length>record.operation.maxOutputBytes)throw Error('control_log_exceeds_limit');
   let text=bytes.toString('utf8');
   // Withhold the incomplete final line while running: split credential assignments cannot leak prefixes.
   if(!terminal.has(response.status))text=text.slice(0,text.lastIndexOf('\n')+1);
   const envValues=Object.values(record.operation.env).filter(v=>v.length>=4);
   record.redacted=record.redacted||isSensitiveContent(text)||envValues.some(v=>text.includes(v));
   if(this.sanitizeOutput&&!record.redacted){text=await this.sanitizeOutput(text,publicRecord(record));if(typeof text!=='string')throw Error('Invalid sanitized task output');}
   record.log=record.redacted?'':text;
   record.status=response.status;record.observation='confirmed';record.exitCode=Number.isInteger(response.exitCode)?response.exitCode:null;record.signal=Number.isInteger(response.signal)?response.signal:null;
   record.terminationReason=['exit','cancel_requested','timeout','identity_lost','supervisor_lost','launch_failed'].includes(response.terminationReason)?response.terminationReason:null;
   record.truncated=Boolean(response.truncated);record.transportError=null;
   record.cancelRequested=record.cancelRequested||Boolean(response.cancelRequested);
   record.capabilities=response.capabilities??record.capabilities??null;
  }catch{record.observation='unknown';record.transportError='Remote control outcome could not be verified; reconcile reads existing state only.';}
  await this.update(record);
 }
 async read({threadId,taskId,cursor=0,limitBytes=65536,refresh=true}){
  if(!Number.isInteger(cursor)||cursor<0||!Number.isInteger(limitBytes)||limitBytes<1||limitBytes>1048576)throw Error('Invalid output cursor or limit');
  let r=this.owned(threadId,taskId);if(refresh&&!r.archivedAt){
    const release=takeLease(this.db,taskId);
    try {r=this.owned(threadId,taskId);if(!r.archivedAt){await this.permit('read',r);await this.remote(r,'read');}} finally {release();}
  }
  return {...publicRecord(r),...textSlice(r.log,cursor,limitBytes)};
 }
 async reconcile({threadId,taskId}){
  const release=takeLease(this.db,taskId);
  try {const r=this.owned(threadId,taskId);if(r.archivedAt)throw Error('任务已归档');await this.permit('reconcile',r);await this.remote(r,'read');return publicRecord(r);} finally {release();}
 }
 async cancel({threadId,taskId}){
  const release=takeLease(this.db,taskId);
  try {const r=this.owned(threadId,taskId);if(r.archivedAt)throw Error('任务已归档');await this.permit('cancel',r);r.cancelRequested=true;this.save(r);await this.remote(r,'cancel');return {...publicRecord(r),notice:'Cancellation is a request to terminate the verified process group; completed effects are not rolled back.'};} finally {release();}
 }
 list({threadId,limit=100,cursor=0}){
  if(typeof threadId!=='string'||!Number.isInteger(limit)||limit<1||limit>100||!Number.isInteger(cursor)||cursor<0)throw Error('Invalid task list pagination');
  return this.db.prepare("SELECT record FROM jobs WHERE thread_id=? AND json_extract(record,'$.archivedAt') IS NULL ORDER BY rowid DESC LIMIT ? OFFSET ?").all(threadId,limit,cursor).map(row=>publicRecord(JSON.parse(row.record)));
 }
}
