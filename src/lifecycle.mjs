import {DatabaseSync} from 'node:sqlite';
import {statSync} from 'node:fs';
import {join} from 'node:path';
import {cleanupLocalPartial} from './local-files.mjs';
import {isSensitiveContent} from './policy.mjs';
import {occupants,takeLease,transaction} from './lifecycle-lock.mjs';
import {confirmedJob,confirmedTransfer} from './terminal-evidence.mjs';

const DAY=86_400_000;
const sources={job:{schema:'jobdb',table:'jobs'},transfer:{schema:'transferdb',table:'transfers'}};
const idOf=r=>r.id??r.transferId;
const hostOf=r=>r.hostId??r.host?.id??r.approvalPayload?.hostId;
const millis=value=>typeof value==='number'?value:Date.parse(value);
const endOf=(kind,r)=>millis(r.finishedAt??(kind==='job'?r.updatedAt:NaN));
function owned(kind,row,r) {
  return idOf(r)===row.id && r.threadId===row.thread_id && r.host?.id===hostOf(r)
    && typeof hostOf(r)==='string' && /^[a-f0-9]{64}$/.test(kind==='job'?r.token:r.remoteToken)
    && (kind==='job'||r.approvalPayload?.hostId===hostOf(r));
}
function confirmed(kind,r) {
  return kind==='job'?confirmedJob(r):confirmedTransfer(r);
}
function archiveRow(kind,r) {
  return {kind,id:idOf(r),hostId:hostOf(r),threadId:r.threadId,sessionId:r.sessionId??null,status:r.status,summary:r.summary,
    createdAt:millis(r.createdAt),finishedAt:endOf(kind,r),archivedAt:r.archivedAt,remoteCleaned:Boolean(r.remoteCleanedAt)};
}
function archivedRecord(kind,r,now) {
  const common={threadId:r.threadId,sessionId:r.sessionId??null,hostId:hostOf(r),host:r.host,status:r.status,createdAt:r.createdAt,
    updatedAt:r.updatedAt,finishedAt:r.finishedAt??r.updatedAt,archivedAt:now};
  if(kind==='job'){
    const command=r.operation?.command??'';
    return {...common,id:r.id,identity:r.identity,token:r.token,observation:r.observation,exitCode:r.exitCode,signal:r.signal,
      terminationReason:r.terminationReason,redacted:r.redacted,truncated:r.truncated,log:'',
      summary:r.redacted||isSensitiveContent(command)?'后台任务（内容已隐藏）':command.slice(0,256)};
  }
  // Retain the private route and frozen ownership evidence until collection is
  // confirmed. No source/destination file bodies belong in this summary.
  const keep=['transferId','direction','remotePath','remoteRoot','blockedPaths','localPath','localRoot',
    'localBlockedPaths','remoteToken','partial','size','sha256','expiresAt','bytesTransferred','cursor',
    'sourceSnapshot','overwrite','cancelConfirmed','cancelledBeforeDispatch','cleanedAt'];
  const out={...common,summary:(r.direction==='upload'?'上传':'下载')+' · '+r.remotePath,approvalPayload:{hostId:hostOf(r)}};
  for(const key of keep)if(r[key]!==undefined)out[key]=r[key];
  if(!r.partial&&(r.direction==='download'||r.cancelledBeforeDispatch||r.privateCleanupVerifiedAt)){
    out.remoteCleanedAt=r.privateCleanupVerifiedAt??now;out.retainedBytes=r.privateRetainedBytes??0;
    delete out.remoteToken;delete out.host;
  }
  return out;
}
function bytes(path) {
  try{return statSync(path).size;}catch(error){if(error.code==='ENOENT')return 0;throw error;}
}
export class LifecycleService {
  constructor({dataDir,jobs,transfers,clock=Date.now}){
    this.jobs=jobs;this.transfers=transfers;this.clock=clock;
    this.paths=[join(dataDir,'store.sqlite'),join(dataDir,'task-state','jobs.sqlite'),join(dataDir,'transfers','transfers.sqlite')];
    this.db=new DatabaseSync(this.paths[0]);
    this.db.exec('PRAGMA busy_timeout=5000');
    this.db.prepare('ATTACH DATABASE ? AS jobdb').run(this.paths[1]);
    this.db.prepare('ATTACH DATABASE ? AS transferdb').run(this.paths[2]);
    this.db.exec('CREATE TABLE IF NOT EXISTS lifecycle_settings(id INTEGER PRIMARY KEY CHECK(id=1),retention_days INTEGER NOT NULL); INSERT OR IGNORE INTO lifecycle_settings VALUES(1,30)');
    this.hasOperations=Boolean(this.db.prepare("SELECT 1 FROM main.sqlite_master WHERE type='table' AND name='operations'").get());
  }
  close(){this.db.close();}
  settings(){return {retentionDays:this.db.prepare('SELECT retention_days FROM main.lifecycle_settings WHERE id=1').get().retention_days};}
  configure({retentionDays}){
    if(!Number.isInteger(retentionDays)||retentionDays<1||retentionDays>3650)throw Error('保留时间必须是 1 到 3650 天');
    this.db.prepare('UPDATE main.lifecycle_settings SET retention_days=? WHERE id=1').run(retentionDays);
    return this.settings();
  }
  activeSlot(kind,id){
    return this.hasOperations && Boolean(this.db.prepare("SELECT 1 FROM main.operations WHERE external_kind=? AND external_id=? AND status='active'").get(kind,id));
  }
  sweep(){
    return transaction(this.db,()=>{
      const now=this.clock(), cutoff=now-this.settings().retentionDays*DAY, counts={jobs:0,transfers:0,purged:0};
      for(const [kind,{schema,table}] of Object.entries(sources)){
        const name=schema+'.'+table;
        // Stream only plausibly old rows and never read an artifact body.
        const candidates=this.db.prepare(`SELECT id,thread_id,record FROM ${name} WHERE json_extract(record,'$.archivedAt') IS NULL
          AND json_extract(record,'$.status') IN ('completed','failed','cancelled')
          AND ${kind==='transfer'?"owner_token IS NULL AND json_extract(record,'$.finishedAt')<=?":"COALESCE(json_extract(record,'$.finishedAt'),json_extract(record,'$.updatedAt'))<=?"} ORDER BY rowid`).iterate(kind==='job'?new Date(cutoff).toISOString():cutoff);
        for(const row of candidates){
          const {id,record}=row;
          const r=JSON.parse(record);
          if(!owned(kind,row,r)||!confirmed(kind,r)||!(endOf(kind,r)<=cutoff)||this.activeSlot(kind,id)||occupants(this.db,id,schema+'.lifecycle_users').length)continue;
          this.db.prepare(`UPDATE ${name} SET record=? WHERE id=?`).run(JSON.stringify(archivedRecord(kind,r,now)),id);
          counts[table]++;
          if(counts[table]>=64)break;
        }
        // Keep archive summaries for one more retention interval. Never drop
        // the last cleanup token merely because a disconnected host is old.
        const obsolete=this.db.prepare(`SELECT id,record FROM ${name} WHERE json_extract(record,'$.archivedAt')<=?
          AND json_extract(record,'$.remoteCleanedAt') IS NOT NULL AND json_extract(record,'$.purgedAt') IS NULL LIMIT 64`).all(cutoff);
        for(const {id,record} of obsolete){
          if(this.activeSlot(kind,id)||occupants(this.db,id,schema+'.lifecycle_users').length)continue;
          if(kind==='transfer')this.db.prepare(`DELETE FROM ${name} WHERE id=? AND owner_token IS NULL`).run(id);
          else {
            const r=JSON.parse(record);
            // UNIQUE(thread,idem) must stay reserved even after history expiry.
            const tombstone={id,threadId:r.threadId,hostId:r.hostId,identity:r.identity,status:r.status,archivedAt:r.archivedAt,purgedAt:now,log:''};
            this.db.prepare(`UPDATE ${name} SET record=? WHERE id=?`).run(JSON.stringify(tombstone),id);
          }
          counts.purged++;
        }
      }
      return counts;
    });
  }
  overview(){
    const local={databaseBytes:0,reusableDatabaseBytes:0,outputBytes:0,activeRecords:0,archivedRecords:0,protectedRecords:0};
    for(const path of this.paths)for(const suffix of ['','-wal','-shm'])local.databaseBytes+=bytes(path+suffix);
    for(const [kind,{schema,table}] of Object.entries(sources)){
      local.reusableDatabaseBytes+=this.db.prepare('PRAGMA '+schema+'.freelist_count').get().freelist_count*this.db.prepare('PRAGMA '+schema+'.page_size').get().page_size;
      for(const row of this.db.prepare(`SELECT json_extract(record,'$.status') AS status,json_extract(record,'$.observation') AS observation,
        json_extract(record,'$.terminationReason') AS terminationReason,json_extract(record,'$.archivedAt') AS archivedAt,
        json_extract(record,'$.cancelConfirmed') AS cancelConfirmed,json_extract(record,'$.cancelledBeforeDispatch') AS cancelledBeforeDispatch,
        json_extract(record,'$.unresolvedCommit') AS unresolvedCommit,json_extract(record,'$.finishedAt') AS finishedAt,json_extract(record,'$.updatedAt') AS updatedAt,
        length(CAST(json_extract(record,'$.log') AS BLOB)) AS logBytes FROM ${schema}.${table} WHERE json_extract(record,'$.purgedAt') IS NULL`).iterate()){
        local.outputBytes+=row.logBytes??0;
        if(row.archivedAt)local.archivedRecords++;else local.activeRecords++;
        const terminal=['completed','cancelled','failed'].includes(row.status);
        const evidence={...row,cancelConfirmed:row.cancelConfirmed===1,cancelledBeforeDispatch:row.cancelledBeforeDispatch===1};
        if(['unknown','missing','commit_unknown','interrupted','timed_out'].includes(row.status)||row.observation==='unknown'||
          terminal&&(!confirmed(kind,evidence)||!Number.isFinite(endOf(kind,row))))local.protectedRecords++;
      }
    }
    return {...this.settings(),local,remote:{measured:false}};
  }
  listArchives({hostId,threadId,cursor=0,limit=50}={}){
    if(!Number.isSafeInteger(cursor)||cursor<0||!Number.isInteger(limit)||limit<1||limit>100)throw Error('归档分页无效');
    const query=Object.entries(sources).map(([kind,{schema,table}])=>`SELECT '${kind}' AS kind,id,thread_id,json_extract(record,'$.hostId') AS host_id,json_extract(record,'$.archivedAt') AS at,record FROM ${schema}.${table} WHERE json_extract(record,'$.archivedAt') IS NOT NULL AND json_extract(record,'$.purgedAt') IS NULL`).join(' UNION ALL ');
    const filters=[],args=[];if(hostId){filters.push('host_id=?');args.push(hostId);}if(threadId){filters.push('thread_id=?');args.push(threadId);}
    const rows=this.db.prepare(`SELECT * FROM (${query}) ${filters.length?'WHERE '+filters.join(' AND '):''} ORDER BY at DESC, kind, id LIMIT ? OFFSET ?`).all(...args,limit+1,cursor);
    return {items:rows.slice(0,limit).map(row=>archiveRow(row.kind,JSON.parse(row.record))),nextCursor:rows.length>limit?cursor+limit:null};
  }
  async remote({kind,id,threadId,hostId,collect=false},callback,beforeRemove){
    if(!Object.hasOwn(sources,kind)||!/^[a-f0-9]{32}$/.test(id)||!threadId||!hostId||typeof collect!=='boolean')throw Error('无效回收目标');
    const {schema,table}=sources[kind], conn=kind==='job'?this.jobs.db:this.transfers.db;
    const release=takeLease(conn,id,true);
    try {
      const row=this.db.prepare(`SELECT * FROM ${schema}.${table} WHERE id=? AND thread_id=?`).get(id,threadId);
      if(!row||row.owner_token)throw Error('记录不存在或正在使用');
      const r=JSON.parse(row.record);
      if(hostOf(r)!==hostId||r.purgedAt)throw Error('目标主机或所有权不匹配');
      if(collect&&(!r.archivedAt||!confirmed(kind,r)||!(endOf(kind,r)<=this.clock()-this.settings().retentionDays*DAY)||this.activeSlot(kind,id)))throw Error('仅回收超过保留期、确认终态且未恢复的归档记录');
      if(r.remoteCleanedAt) return {bytes:r.retainedBytes??0,retainedBytes:r.retainedBytes??0,reclaimedBytes:0,collected:true};
      if(!owned(kind,row,r))throw Error('资源所有权不匹配');
      const result=await callback(r);
      if(collect&&result?.collected){
        if(kind==='transfer'&&r.direction==='download'&&r.partial){
          if(r.partial.token!==r.remoteToken)throw Error('临时文件与传输所有权不符');
          if(typeof beforeRemove!=='function')throw Error('本地临时文件回收需要有效授权');
          await cleanupLocalPartial(r.partial,r.localPath,r.localRoot,()=>beforeRemove(r));
          r.partial=null;
        }
        r.remoteCleanedAt=this.clock();r.retainedBytes=result.retainedBytes??0;
        delete r.token;delete r.remoteToken;delete r.host;
        this.db.prepare(`UPDATE ${schema}.${table} SET record=? WHERE id=? AND thread_id=?`).run(JSON.stringify(r),id,threadId);
      }
      return result;
    } finally {release();}
  }
}
