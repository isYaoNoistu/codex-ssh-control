import * as fs from 'node:fs/promises';
import { readFileSync, mkdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { inspectLocalFile, validateLocalPath, openLocalSource, hashHandle, createLocalPartial, inspectLocalPartial, commitLocalPartial, cleanupLocalPartial, localManifest, sameSnapshot, recoverLocalPublication, createLocalDirectory, localFileCapabilities } from './local-files.mjs';

const HELPER=readFileSync(new URL('../remote/transfer_guard.py',import.meta.url)).toString('base64');
const EMPTY=createHash('sha256').digest('hex');
const ID=/^[a-f0-9]{32}$/;
const MAX_BYTES=16*1024**3;
const TERMINAL=new Set(['completed','cancelled']);
const clone=x=>structuredClone(x);
const publicRecord=r=>{const {remoteToken,partial,host,leaseToken,...safe}=r;return clone(safe);};
function alive(pid){if(!Number.isInteger(pid)||pid<1)return false;try{process.kill(pid,0);return true;}catch(e){return e.code!=='ESRCH';}}
export function buildTransferCommand(request){
 const data=Buffer.from(JSON.stringify(request)).toString('base64');
 // Source is trusted installed code; request is data only, never interpolated Python.
 return `/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/python3 -I -S -B -c 'import base64,json,sys;exec(base64.b64decode("${HELPER}"));sys.exit(main(json.loads(base64.b64decode("${data}"))))'`;
}
function requireLocalTransferSupport(){if(!localFileCapabilities.supported)throw new Error('local binary transfer unsupported on this platform');}
function validateRequest(r,now){
 requireLocalTransferSupport();
 if(typeof r.threadId!=='string'||!r.threadId||!r.host||!['upload','download'].includes(r.direction))throw new Error('invalid transfer request');
 if(r.overwrite!=='never')throw new Error('conditional overwrite unsupported; use a new artifact path');
 if(!Number.isFinite(r.expiresAt)||r.expiresAt<=now)throw new Error('transfer expired');
 if(r.maxBytes!==undefined&&(!Number.isSafeInteger(r.maxBytes)||r.maxBytes<0||r.maxBytes>MAX_BYTES))throw new Error('invalid transfer size limit');
 for(const value of [r.remotePath,r.remoteRoot])if(typeof value!=='string'||!value.startsWith('/')||value.includes('\\')||value.includes('//')||/[\x00-\x1f\x7f]/.test(value)||value.split('/').some(x=>x==='.'||x==='..'))throw new Error('invalid remote path');
 if(r.remotePath!==r.remoteRoot&&!r.remotePath.startsWith(r.remoteRoot.replace(/\/$/,'')+'/'))throw new Error('remote path outside root');
}
/** SQLite stores immutable plans and fences individual active transfers across
 * MCP processes. A live owner PID is never taken over; PID reuse fails closed.
 * Binary content only crosses pipes, never JSON/MCP.
 * authorize returns false/throws to reject, and must recheck live host policy and
 * approval revision on inspect/start/resume/commit. Remote token is never passed
 * to authorize or returned to callers. Approval must bind approvalPayload.
 */
export class TransferService {
 constructor({dataDir,spawnRemote,authorize,validateLease=()=>{},clock=Date.now}){
  if(!dataDir||typeof spawnRemote!=='function'||typeof authorize!=='function'||typeof validateLease!=='function')throw new Error('transfer dependencies required');
  this.directory=path.join(dataDir,'transfers');this.spawnRemote=spawnRemote;this.authorize=authorize;this.validateLease=validateLease;this.clock=clock;this.running=new Map();this.children=new Map();this.starting=new Set();
  mkdirSync(this.directory,{recursive:true,mode:0o700});this.db=new DatabaseSync(path.join(this.directory,'transfers.sqlite'));this.db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS transfers (id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, record TEXT NOT NULL, owner_pid INTEGER, owner_token TEXT, stop_requested INTEGER NOT NULL DEFAULT 0)');
 }
 async _save(r){
  r.updatedAt=this.clock();r.cursor=(r.cursor??0)+1;this.db.exec('BEGIN IMMEDIATE');try{
   const old=this.db.prepare('SELECT * FROM transfers WHERE id=?').get(r.transferId);
   if(old?.owner_token&&!r.leaseToken)throw new Error('transfer is owned by a running process');
   if(old&&r.leaseToken&&old.owner_token!==r.leaseToken)throw new Error('transfer ownership lost');
   if(old?.stop_requested&&r.leaseToken)r.status=JSON.parse(old.record).status;
   const {leaseToken,...stored}=r;
   if(old)this.db.prepare('UPDATE transfers SET record=? WHERE id=?').run(JSON.stringify(stored),r.transferId);
   else this.db.prepare('INSERT INTO transfers(id,thread_id,record) VALUES(?,?,?)').run(r.transferId,r.threadId,JSON.stringify(stored));
   this.db.exec('COMMIT');
  }catch(e){this.db.exec('ROLLBACK');throw e;}
 }
 async _load(threadId,id){if(!ID.test(id??''))throw new Error('invalid transfer identifier');const row=this.db.prepare('SELECT record FROM transfers WHERE id=? AND thread_id=?').get(id,threadId);if(!row)throw new Error('transfer not found');return JSON.parse(row.record);}
 async _claim(threadId,id){await this._load(threadId,id);this.db.exec('BEGIN IMMEDIATE');try{const row=this.db.prepare('SELECT * FROM transfers WHERE id=? AND thread_id=?').get(id,threadId);if(row.owner_token&&alive(row.owner_pid))throw new Error('transfer is owned by a running process');const token=randomBytes(32).toString('hex');this.db.prepare('UPDATE transfers SET owner_pid=?,owner_token=?,stop_requested=0 WHERE id=?').run(process.pid,token,id);this.db.exec('COMMIT');return {...JSON.parse(row.record),leaseToken:token};}catch(e){this.db.exec('ROLLBACK');throw e;}}
 _release(r){if(r?.leaseToken)this.db.prepare('UPDATE transfers SET owner_pid=NULL,owner_token=NULL WHERE id=? AND owner_token=?').run(r.transferId,r.leaseToken);}
 _owned(r){if(!r.leaseToken)return;const row=this.db.prepare('SELECT owner_token,stop_requested FROM transfers WHERE id=?').get(r.transferId);if(row?.owner_token!==r.leaseToken)throw new Error('transfer ownership lost');if(row.stop_requested)throw new Error('transfer cancelled');}
 async _auth(stage,r){if(await this.authorize(stage,publicRecord(r))===false)throw new Error('transfer authorization denied');}
 _fresh(r){this._owned(r);if(r.status==='cancelled')throw new Error('transfer cancelled');if(r.expiresAt<=this.clock())throw new Error('transfer expired');const result=this.validateLease(publicRecord(r));if(result===false)throw new Error('transfer authorization revoked');if(result&&typeof result.then==='function')throw new Error('validateLease must be synchronous');}
 _request(r,operation,extra={}){return {operation,root:r.remoteRoot,path:r.remotePath,blockedPaths:r.blockedPaths??[],token:r.remoteToken,expiresAt:r.expiresAt,size:r.size,sha256:r.sha256,mode:r.sourceSnapshot?.mode,mtimeNs:r.sourceSnapshot?.mtimeNs,overwrite:r.overwrite,...extra};}
 _spawn(r,request){
  this._fresh(r);const child=this.spawnRemote(r.host,buildTransferCommand(request));if(!child?.stdin||!child.stdout||!child.stderr)throw new Error('spawnRemote must return piped ChildProcess');
  this.children.set(r.transferId,child);let stderr='';child.stderr.on('data',b=>{if(stderr.length<4096)stderr+=b.toString('utf8').slice(0,4096-stderr.length);});
  const completion=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code)=>code===0?resolve():reject(new Error(`remote artifact process failed (${code??'signal'})`)));});
  // Attach immediately, including while an upload pipeline is still producing.
  completion.catch(()=>{});
  const timer=setTimeout(()=>child.kill(),Math.min(2**31-1,Math.max(1,r.expiresAt-this.clock()+1000)));timer.unref?.();
  completion.finally(()=>{clearTimeout(timer);if(this.children.get(r.transferId)===child)this.children.delete(r.transferId);}).catch(()=>{});
  return {child,completion};
 }
 async _metadata(r,operation,extra={},source){
  const {child,completion}=this._spawn(r,this._request(r,operation,extra));let data='',bytes=0;
  const output=(async()=>{for await(const chunk of child.stdout){bytes+=chunk.length;if(bytes>512*1024){child.kill();throw new Error('remote metadata limit exceeded');}data+=chunk.toString('utf8');}})();
  const input=source?pipeline(source,child.stdin):Promise.resolve(child.stdin.end());
  try{await Promise.all([output,input,completion]);const answer=JSON.parse(data);if(!answer.ok)throw new Error(answer.error||'remote artifact rejected');return answer.result;}catch(e){child.kill();throw e;}
 }
 async prepare(request){
  validateRequest(request,this.clock());
  const r={...clone(request),transferId:randomBytes(16).toString('hex'),remoteToken:randomBytes(32).toString('hex'),status:'preparing',createdAt:this.clock(),cursor:0,bytesTransferred:0,blockedPaths:clone(request.blockedPaths??[])};
  // Do not accept caller-supplied internal state, identity or frozen hashes.
  for(const k of ['partial','sourceSnapshot','targetSnapshot','sha256','size','approvalPayload','error','finishedAt'])delete r[k];
  await this._auth('inspect',r);this._fresh(r);
  if(r.direction==='upload'){
   r.sourceSnapshot=await inspectLocalFile(r.localPath,r.localRoot,{blockedPaths:r.localBlockedPaths??[]});
   r.targetSnapshot=(await this._metadata(r,'target')).snapshot;
  }else{
   await validateLocalPath(r.localPath,r.localRoot,{allowMissing:true,blockedPaths:r.localBlockedPaths??[]});
   r.sourceSnapshot=(await this._metadata(r,'inspect')).snapshot;
   try{r.targetSnapshot=await inspectLocalFile(r.localPath,r.localRoot);}catch(e){if(e.code!=='ENOENT')throw e;r.targetSnapshot=null;}
  }
  if(r.targetSnapshot!==null)throw new Error('destination exists; overwrite unsupported');
  r.size=r.sourceSnapshot.size;r.sha256=r.sourceSnapshot.sha256;if(!Number.isSafeInteger(r.size)||r.size<0||r.size>(r.maxBytes??MAX_BYTES)||!/^[a-f0-9]{64}$/.test(r.sha256))throw new Error('source exceeds approved transfer size limit or invalid digest');
  this._fresh(r);r.status='prepared';r.approvalPayload={kind:'transfer',direction:r.direction,hostId:r.host.id,localPath:r.localPath,localRoot:r.localRoot,remotePath:r.remotePath,remoteRoot:r.remoteRoot,blockedPaths:r.blockedPaths,localBlockedPaths:r.localBlockedPaths??[],sourceSnapshot:r.sourceSnapshot,targetSnapshot:r.targetSnapshot,size:r.size,sha256:r.sha256,overwrite:r.overwrite,expiresAt:r.expiresAt,maxBytes:r.maxBytes??MAX_BYTES};
  await this._save(r);return {...publicRecord(r),planId:r.transferId};
 }
 async start({threadId,planId}){
  requireLocalTransferSupport();
  if(this.starting.has(planId))throw new Error('transfer already starting');this.starting.add(planId);
  let r,launched=false;try{r=await this._claim(threadId,planId);if(r.status!=='prepared')throw new Error('transfer plan already started');this._fresh(r);await this._auth('start',r);this._fresh(r);await this._verifySource(r);this._fresh(r);r.status='queued';await this._save(r);this._launch(r);launched=true;return publicRecord(r);}finally{if(!launched)this._release(r);this.starting.delete(planId);}
 }
 async _verifySource(r){
  const current=r.direction==='upload'?await inspectLocalFile(r.localPath,r.localRoot,{blockedPaths:r.localBlockedPaths??[]}):(await this._metadata(r,'inspect')).snapshot;
  if(!sameSnapshot(current,r.sourceSnapshot))throw new Error('source changed since approval');
 }
 _launch(r){const promise=this._run(r).catch(async error=>{if(r.status!=='cancelled'){r.status=r.status==='committing'||r.status==='commit_unknown'?'commit_unknown':'interrupted';r.error=String(error.message).slice(0,1024);}await this._save(r);}).finally(()=>{this._release(r);this.running.delete(r.transferId);});this.running.set(r.transferId,{record:r,promise});promise.catch(()=>{});}
 async _run(r){
  r.status='streaming';r.error=null;await this._save(r);this._fresh(r);
  if(r.direction==='upload'){
   const state=await this._metadata(r,'stage');if(state.committed){r.status='completed';r.bytesTransferred=r.size;r.finishedAt=this.clock();await this._save(r);return;}const handle=await openLocalSource(r.localPath,r.localRoot,r.sourceSnapshot);
   try{
    if(!Number.isInteger(state.offset)||state.offset<0||state.offset>r.size||await hashHandle(handle,state.offset)!==state.prefixSha256)throw new Error('remote partial prefix mismatch');
    r.bytesTransferred=state.offset;await this._save(r);
    if(state.offset<r.size){
     const counter=this._counter(r);const stream=handle.createReadStream({start:state.offset,autoClose:false});
     const pumping=pipeline(stream,counter);pumping.catch(()=>{});
     await Promise.all([this._metadata(r,'write',{offset:state.offset,prefixSha256:state.prefixSha256},counter),pumping]);
    }
   }finally{await handle.close();}
   await this._verifySource(r);await this._beforeCommit(r);r.status='committing';await this._save(r);this._fresh(r);await this._metadata(r,'commit');
  }else{
   if(r.partial&&await recoverLocalPublication(r.partial,r.localPath,r.localRoot,r.sourceSnapshot)){r.partial=null;r.status='completed';r.bytesTransferred=r.size;r.finishedAt=this.clock();await this._save(r);return;}
   if(!r.partial){r.partial=await createLocalPartial(r.localPath,r.localRoot,r.remoteToken);await this._save(r);}
   const partial=await inspectLocalPartial(r.partial,r.localPath,r.localRoot);if(partial.size>r.size)throw new Error('local partial exceeds source size');
   r.bytesTransferred=partial.size;await this._save(r);
   if(partial.size<r.size){
    const {child,completion}=this._spawn(r,this._request(r,'read',{offset:partial.size,prefixSha256:partial.sha256,sourceSnapshot:r.sourceSnapshot}));child.stdin.end();
    const handle=await fs.open(r.partial.path,'r+');const sink=handle.createWriteStream({start:partial.size,autoClose:true});
    try{await Promise.all([pipeline(child.stdout,this._counter(r),sink),completion]);}catch(e){child.kill();throw e;}
   }else if(r.size===0&&partial.sha256!==EMPTY)throw new Error('empty source hash mismatch');
   await this._verifySource(r);await this._beforeCommit(r);
   await commitLocalPartial(r.partial,r.localPath,r.localRoot,r.sourceSnapshot,async()=>{this._fresh(r);r.status='committing';await this._save(r);this._fresh(r);});r.partial=null;
  }
  r.status='completed';r.bytesTransferred=r.size;r.finishedAt=this.clock();await this._save(r);
 }
 _counter(r){let saved=0;return new Transform({transform:(chunk,encoding,callback)=>{try{this._fresh(r);r.bytesTransferred+=chunk.length;r.cursor++;if(r.bytesTransferred>r.size)throw new Error('stream exceeds approved source size');if(this.clock()-saved>=1000){saved=this.clock();this._save(r).then(()=>callback(null,chunk),callback);}else callback(null,chunk);}catch(e){callback(e);}}});}
 async _beforeCommit(r){this._fresh(r);const current=await this._load(r.threadId,r.transferId);if(current.status==='cancelled')throw new Error('transfer cancelled');r.status='verifying';await this._save(r);await this._auth('commit',r);this._fresh(r);}
 async resume({threadId,transferId,expiresAt}){
  requireLocalTransferSupport();
  if(this.starting.has(transferId))throw new Error('transfer already starting');this.starting.add(transferId);
  let r,launched=false;try{r=await this._claim(threadId,transferId);if(this.running.has(transferId)||TERMINAL.has(r.status)||r.status==='prepared')throw new Error('transfer cannot resume in current state');
  if(expiresAt!==undefined){if(!Number.isFinite(expiresAt)||expiresAt<=this.clock())throw new Error('transfer expired');r.previousExpiresAt=r.expiresAt;r.expiresAt=expiresAt;r.approvalPayload={...r.approvalPayload,expiresAt};}
  this._fresh(r);await this._auth('resume',r);this._fresh(r);await this._verifySource(r);this._fresh(r);r.status='queued';await this._save(r);this._launch(r);launched=true;return publicRecord(r);}finally{if(!launched)this._release(r);this.starting.delete(transferId);}
 }
 async read({threadId,transferId,cursor=0}){if(!Number.isSafeInteger(cursor)||cursor<0)throw new Error('invalid progress cursor');const r=await this._load(threadId,transferId),live=this.running.get(transferId)?.record;const value=publicRecord(r);if(live){value.bytesTransferred=live.bytesTransferred;value.cursor=Math.max(value.cursor,live.cursor);}const owner=this.db.prepare('SELECT owner_pid,owner_token FROM transfers WHERE id=?').get(transferId);if(!owner.owner_token||!alive(owner.owner_pid)){if(['queued','streaming','verifying'].includes(value.status))value.status='interrupted';if(value.status==='committing')value.status='commit_unknown';}return {...value,changed:value.cursor>cursor};}
 async list({threadId,cursor=0,limit=50}){if(!Number.isSafeInteger(cursor)||cursor<0||!Number.isInteger(limit)||limit<1||limit>100)throw new Error('invalid list cursor/limit');const rows=this.db.prepare('SELECT id FROM transfers WHERE thread_id=? ORDER BY id LIMIT ? OFFSET ?').all(threadId,limit+1,cursor);const transfers=[];for(const row of rows.slice(0,limit))transfers.push(await this.read({threadId,transferId:row.id}));return {transfers,cursor:cursor+transfers.length,hasMore:rows.length>limit};}
 async cancel({threadId,transferId}){
  const persisted=await this._load(threadId,transferId);const r=this.running.get(transferId)?.record??persisted;if(TERMINAL.has(r.status))return publicRecord(r);
  // Cancel is always available to the owning chat, including after grant expiry.
  this.db.exec('BEGIN IMMEDIATE');try{const row=this.db.prepare('SELECT record FROM transfers WHERE id=? AND thread_id=?').get(transferId,threadId);const latest=JSON.parse(row.record);if(TERMINAL.has(latest.status)){this.db.exec('COMMIT');return publicRecord(latest);}latest.status=['committing','commit_unknown'].includes(latest.status)?'commit_unknown':'cancelled';latest.finishedAt=this.clock();latest.cursor++;this.db.prepare('UPDATE transfers SET record=?,stop_requested=1 WHERE id=?').run(JSON.stringify(latest),transferId);this.db.exec('COMMIT');Object.assign(r,latest);}catch(e){this.db.exec('ROLLBACK');throw e;}this.children.get(transferId)?.kill();return publicRecord(r);
 }
 async cleanup({threadId,transferId}){
  const r=await this._claim(threadId,transferId);try{if(this.running.has(transferId)||!['cancelled','completed'].includes(r.status))throw new Error('only stopped cancelled/completed transfer can clean partials');
  await this._auth('cleanup',r);
  if(r.direction==='download'&&r.partial){await cleanupLocalPartial(r.partial,r.localPath,r.localRoot);r.partial=null;}
  else if(r.direction==='upload'){const lease={...r,status:'cleanup',expiresAt:this.clock()+30000};await this._metadata(lease,'cleanup');}
  r.cleanedAt=this.clock();await this._save(r);return publicRecord(r);}finally{this._release(r);}
 }
 close(){if(this.running.size)throw new Error('cannot close transfer service with active transfers');this.db.close();}
 async createDirectory(request){
  if(!['local','remote'].includes(request.side)||typeof request.threadId!=='string'||!request.threadId||!request.host||!Number.isFinite(request.expiresAt)||request.expiresAt<=this.clock())throw new Error('invalid or expired directory request');
  const r={...clone(request),transferId:randomBytes(16).toString('hex'),status:'mkdir',remoteRoot:request.root,remotePath:request.path,blockedPaths:clone(request.blockedPaths??[])};
  r.approvalPayload={kind:'transfer_mkdir',hostId:r.host.id,side:r.side,root:r.root,path:r.path,blockedPaths:r.blockedPaths,expiresAt:r.expiresAt};await this._auth('mkdir',r);this._fresh(r);
  if(r.side==='remote')return this._metadata(r,'mkdir');
  return createLocalDirectory(r.path,r.root,{blockedPaths:r.blockedPaths,beforeCreate:()=>this._fresh(r)});
 }
 async wait({threadId,transferId}){await this._load(threadId,transferId);await this.running.get(transferId)?.promise;return this.read({threadId,transferId});}
 async planManifest(request){
  validateRequest(request,this.clock());const r={...clone(request),transferId:randomBytes(16).toString('hex'),status:'inspecting',remoteToken:randomBytes(32).toString('hex')};await this._auth('inspect',r);this._fresh(r);
  const limits={maxEntries:request.maxEntries??256,maxBytes:request.maxBytes??1024**3};
  const entries=r.direction==='upload'?await localManifest(r.localPath,r.localRoot,{...limits,blockedPaths:r.localBlockedPaths??[]}):(await this._metadata(r,'manifest',limits)).entries;
  // Manifest is a plan, never an authorization. Each file must be prepare/start
  // approved separately. New directories are explicit managed mkdir requests.
  const directories=new Set(['']);const files=entries.map(entry=>{const parts=entry.relativePath.split('/');for(let i=1;i<parts.length;i++)directories.add(parts.slice(0,i).join('/'));const {host,...safe}=clone(request);return {relativePath:entry.relativePath,sourceSnapshot:entry.snapshot,request:{...safe,hostId:host.id,localPath:path.join(r.localPath,...parts),remotePath:path.posix.join(r.remotePath,entry.relativePath)}};});
  return {files,directoryRequests:[...directories].sort((a,b)=>a.split('/').length-b.split('/').length).map(relativePath=>({kind:'mkdir',threadId:r.threadId,hostId:r.host.id,side:r.direction==='upload'?'remote':'local',root:r.direction==='upload'?r.remoteRoot:r.localRoot,path:r.direction==='upload'?path.posix.join(r.remotePath,relativePath):path.join(r.localPath,...relativePath.split('/')),relativePath,expiresAt:r.expiresAt,blockedPaths:r.direction==='upload'?r.blockedPaths:r.localBlockedPaths??[]})),totalBytes:entries.reduce((n,e)=>n+e.snapshot.size,0),requiresIndividualApproval:true};
 }
}
