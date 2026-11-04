import {AsyncLocalStorage} from 'node:async_hooks';
import {spawn} from 'node:child_process';
import {prepareInvocation} from './transport.mjs';
import {buildHostKeyScanInvocation,parseHostKeyCandidates,confirmHostKeys} from './host-keys.mjs';
import {buildRemoteCapabilityProbe,parseRemoteCapabilities,getLocalCapabilities,classifySshError} from './capabilities.mjs';
import {runControlProcess} from './control-process.mjs';
import {JobService} from './job-service.mjs';
import {TransferService} from './transfer-service.mjs';
import {LifecycleService} from './lifecycle.mjs';
import {inspectJobPrivate,inspectTransferPrivate} from './remote-lifecycle.mjs';
import {normalizeOperation,evaluateOperation} from './policy.mjs';

const terminal=new Set(['completed','failed','cancelled','timed_out']);
const stable=v=>JSON.stringify(v,(_k,x)=>x&&typeof x==='object'&&!Array.isArray(x)?Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b))):x);
const hostIdentity=h=>Object.fromEntries(['id','hostname','username','port','sshAlias','identityFile','defaultCwd','connection'].filter(k=>h[k]!==undefined).map(k=>[k,h[k]]));
const publicJob=r=>{const {host,...out}=r;return out;};
const publicTransfer=r=>({...r,id:r.transferId,hostId:r.approvalPayload.hostId,totalBytes:r.size??0});

export function createInfrastructureRuntime({dataDir,store,gate,requireActive,finish,spawnImpl=spawn}) {
  const context=new AsyncLocalStorage(),children=new Set(),inflight=new Set();let closing=false;
  const watch=child=>{children.add(child);child.once('close',()=>children.delete(child));};
  function current(host) {
    const ticket=context.getStore();if(closing||!ticket)throw new Error('当前执行上下文已结束');
    store.assertOperationReady(ticket.ctx.threadId,ticket.activeOperationId??ticket.permit.operationId);
    if(host&&stable(hostIdentity(host))!==stable(hostIdentity(ticket.permit.host)))throw new Error('任务主机配置已变化，不能使用旧连接快照');
    return ticket;
  }
  const execute=async(host,command,options={})=>{
    let safeRead=command===buildRemoteCapabilityProbe();
    if(options.input){try{safeRead=JSON.parse(options.input).action==='read';}catch{}}
    for(let attempt=0;attempt<2;attempt++){
      current(host);const invocation=prepareInvocation(host,command,'',{dataDir});
      current(host);const result=await runControlProcess(invocation,{...options,spawnImpl,onChild:watch});
      const code=classifySshError({stderr:result.stderr,status:result.status});
      if(!safeRead||attempt===1||result.exitCode===0||!['connection_lost','network_timeout'].includes(code))return {...result,errorCode:result.exitCode===0?null:code};
      // Only fixed capability probes and queries of existing task identities retry.
      // Submit, cancel, file writes and artifact commits are never replayed here.
    }
  };
  const spawnRemote=(host,command)=>{
    current(host);const invocation=prepareInvocation(host,command,'',{dataDir});current(host);
    const child=spawnImpl(invocation.file,invocation.args,{shell:false,windowsHide:true,stdio:['pipe','pipe','pipe']});watch(child);return child;
  };
  function transferOperation(record,changes={}) {
    const p={...record.approvalPayload,...changes};
    const {hostId,...operation}=p;
    return normalizeOperation({...operation,kind:'transfer',planId:record.transferId});
  }
  function transferScope(record) {
    return normalizeOperation({kind:'transfer_inspect',direction:record.direction,localPath:record.localPath,remotePath:record.remotePath,recursive:false});
  }
  async function authorize(stage,record) {
    const ticket=current(record.host);if(record.threadId!==ticket.ctx.threadId)throw new Error('任务不属于当前聊天');
    const op=ticket.permit.evaluation.operation;
    if(stage==='submit') {
      if(op.kind!=='job')throw new Error('后台任务缺少精确执行批准');
      const {kind,idempotencyKey,...expected}=op;
      if(stable({...expected,command:ticket.permit.evaluation.command})!==stable(record.operation))throw new Error('后台任务执行选项与审批内容不一致');
    } else if(['start','resume','commit'].includes(stage)) {
      const approved=op.kind==='transfer_control'&&op.action==='resume'?op.transfer:op;
      if(approved.kind!=='transfer'||stable(approved)!==stable(transferOperation(record)))throw new Error('传输内容与已批准快照不一致');
      if(stage==='start'){
        if(op.kind!=='transfer')throw new Error('开始传输需要独立批准');
      } else if(stage==='resume') {
        if(op.kind!=='transfer_control'||op.action!=='resume')throw new Error('续传需要重新批准');
        const renewed=store.renewExternalOperation(record.threadId,ticket.permit.operationId,'transfer',record.transferId,{deadline:record.expiresAt});
        ticket.activeOperationId=renewed.id;
      }
    } else if(stage==='inspect') {
      if(op.kind!=='transfer_inspect')throw new Error('缺少传输路径检查许可');
      if(op.direction!==record.direction||op.localPath.replaceAll('\\','/')!==record.localPath.replaceAll('\\','/')||op.remotePath!==record.remotePath)throw new Error('路径检查请求不一致');
    } else if(stage==='cleanup') {
      if(op.kind!=='transfer_control'||op.action!=='cleanup'||op.id!==record.transferId||stable(op.transfer)!==stable(transferScope(record)))throw new Error('缺少对应传输路径的临时文件清理批准');
    } else if(stage==='mkdir') {
      const {hostId,...payload}=record.approvalPayload;
      if(op.kind!=='transfer_mkdir'||stable(op)!==stable(normalizeOperation(payload)))throw new Error('创建目录与已批准内容不一致');
    } else if(['read','cancel','reconcile'].includes(stage)) {
      if(op.kind!=='job_control'||op.id!==record.id)throw new Error('缺少任务控制许可');
      if(stage==='cancel'&&op.action!=='cancel')throw new Error('停止任务需要原生批准');
    } else throw new Error('未知授权阶段');
    current(record.host);return true;
  }
  async function onJobUpdate(record) {
    if(closing)return;
    const tracked=store.getExternalOperation(record.threadId,'job',record.id);if(!tracked)return;
    if(record.observation!=='confirmed'||['unknown','missing'].includes(record.status)){store.markOperationUnknown(tracked.id);return;}
    if(terminal.has(record.status)) {
      const cached=await jobs.read({threadId:record.threadId,taskId:record.id,refresh:false,limitBytes:65536});
      finish(tracked.id,{status:record.status,exitCode:record.exitCode,stdout:cached.output,truncated:record.truncated||cached.hasMore,sensitiveOutput:record.redacted});
    }
  }
  function beforeDispatch(kind,record) {
    const ticket=current(record.host);
    const id=kind==='job'?record.id:record.transferId;
    const deadline=kind==='job'?Date.now()+(record.operation.timeoutSeconds+30)*1000:record.expiresAt;
    store.trackExternalOperation(record.threadId,ticket.permit.operationId,kind,id,{deadline});
    ticket.externalTracked=true;
  }
  const jobs=new JobService({dataDir,execute,authorize,beforeDispatch:r=>beforeDispatch('job',r),onUpdate:onJobUpdate});
  const transfers=new TransferService({dataDir,spawnRemote,authorize,beforeDispatch:r=>beforeDispatch('transfer',r),validateLease:()=>current()});
  function checkedLifecycleRecord(record,kind,collect){
    const ticket=current(record.host);
    if(kind!=='transfer'||!collect)return record;
    const {policy}=store.getPolicy(ticket.permit.host.id);
    const rights=evaluateOperation(policy,transferScope(record));
    if(rights.decision==='deny'||!rights.transfer||rights.transfer.localRoot!==record.localRoot||rights.transfer.remoteRoot!==record.remoteRoot)
      throw new Error('当前目录授权不再覆盖此传输，无法回收临时文件。');
    return {...record,blockedPaths:[...new Set([...record.blockedPaths??[],...rights.transfer.blockedPaths])],
      localBlockedPaths:[...new Set([...record.localBlockedPaths??[],...rights.transfer.localBlockedPaths])]};
  }
  const lifecycle=new LifecycleService({dataDir,jobs,transfers});
  let sweepInFlight=null, lastSweepError='';
  function sweepLocal(){
    if(!sweepInFlight) sweepInFlight=Promise.resolve().then(()=>lifecycle.sweep()).then(result=>{
      lastSweepError='';
      return result;
    },error=>{
      lastSweepError=error.message;
      throw error;
    }).finally(()=>{sweepInFlight=null;});
    return sweepInFlight;
  }
  function scheduledSweep(){
    if(!closing) sweepLocal().catch(()=>process.stderr.write('Local lifecycle sweep incomplete.\n'));
  }
  const maintenanceTimer=setInterval(scheduledSweep,60*60*1000);
  maintenanceTimer.unref();
  scheduledSweep();
  function onTransferUpdate(record) {
    if(closing)return;
    const tracked=store.getExternalOperation(record.threadId,'transfer',record.transferId);if(!tracked)return;
    if(['completed','cancelled'].includes(record.status))finish(tracked.id,{status:record.status,exitCode:record.status==='completed'?0:null,stdout:JSON.stringify({direction:record.direction,path:record.remotePath,bytes:record.bytesTransferred,sha256:record.sha256,status:record.status})});
    else if(['commit_unknown','interrupted'].includes(record.status))store.markOperationUnknown(tracked.id,'传输中断或提交结果未知，需要核实；未自动重新提交。');
  }
  const followTransfer=record=>{transfers.wait({threadId:record.threadId,transferId:record.transferId}).then(onTransferUpdate).catch(()=>{});};
  async function permitted(ctx,args,op,signal,action,{durable=false}={}) {
    const permit=await gate(ctx,args,op,signal);
    const ticket={ctx,permit,externalTracked:false};
    return context.run(ticket,async()=>{
      try {
        requireActive(signal,permit.operationId,ctx.threadId);
        const result=await action(permit);
        if(!durable)finish(permit.operationId,{status:'completed',exitCode:0,stdout:'操作已完成；详细状态请查看任务或传输记录。'});
        return result;
      } catch(error) {
        if(!closing){if(durable&&ticket.externalTracked)store.markOperationUnknown(permit.operationId,'请求未能确认完成，请查询任务记录；没有自动重放。');else finish(permit.operationId,{status:'failed',stderr:error.message});}
        throw error;
      }
    });
  }
  const findHost=id=>{const host=store.listHosts().find(h=>h.id===id);if(!host)throw new Error('主机不存在');return host;};
  async function handle(name,ctx,args,signal) {
    const threadId=ctx.threadId;
    if(['ssh_transfer_prepare','ssh_transfer_manifest','ssh_transfer_start','ssh_transfer_resume'].includes(name)&&!getLocalCapabilities().artifactTransfer.supported)throw Object.assign(new Error('当前本机平台不支持受管二进制传输；仅支持 Linux 与 Windows，未启动 SSH。'),{code:'PLATFORM_UNSUPPORTED'});
    switch(name) {
      case 'ssh_lifecycle_overview':
        return {overview:await lifecycle.overview(),archive:await lifecycle.listArchives(args),lastSweepError};
      case 'ssh_lifecycle_configure':
        return {settings:await lifecycle.configure({retentionDays:args.retentionDays})};
      case 'ssh_lifecycle_sweep':
        return {sweep:await sweepLocal()};
      case 'ssh_lifecycle_inspect':case 'ssh_lifecycle_collect': {
        const collect=name==='ssh_lifecycle_collect';
        const operation={kind:'lifecycle',resource:args.kind,id:args.id,action:collect?'collect':'inspect'};
        return permitted(ctx,args,operation,signal,async()=>({
          measurement:await lifecycle.remote({kind:args.kind,id:args.id,threadId,hostId:args.hostId,collect},async record=>{
            const checked=checkedLifecycleRecord(record,args.kind,collect);
            return args.kind==='job'?inspectJobPrivate(jobs,checked,collect):inspectTransferPrivate(transfers,checked,collect);
          },record=>checkedLifecycleRecord(record,args.kind,collect)),
        }));
      }
      case 'ssh_host_key_scan': {
        const host=findHost(args.hostId),index=args.hopIndex??-1,target=index<0?host:host.connection?.jumpHosts?.[index];
        if(!target?.hostname)throw new Error('请先保存明确的主机地址；SSH别名请在可信本地配置中核验指纹');
        const result=await runControlProcess(buildHostKeyScanInvocation(target),{spawnImpl,onChild:watch,timeoutSeconds:8,maxOutputBytes:65536});
        const candidates=parseHostKeyCandidates(result.stdout,{source:'scan'});if(!candidates.length)throw new Error('未取得公钥；内网目标请从可信控制台复制公钥后核验');
        return {candidates};
      }
      case 'ssh_host_keys_confirm': {
        const host=findHost(args.hostId),index=args.hopIndex??-1;
        if(!host.hostname||host.sshAlias)throw new Error('固定指纹需要受管地址连接');
        const connection=structuredClone(host.connection??{mode:'managed',hostKeys:[],jumpHosts:[]});if(connection.mode!=='managed')throw new Error('可信SSH别名的信任记录请在OpenSSH中管理');
        const target=index<0?connection:connection.jumpHosts?.[index];if(!target)throw new Error('跳板不存在');
        target.hostKeys=confirmHostKeys(target.hostKeys??[],args.candidates,{confirmed:args.confirmed,fingerprints:args.fingerprints,expectedCurrentFingerprints:args.expectedCurrentFingerprints});
        store.saveHost({id:host.id,connection});return {hostKeys:target.hostKeys};
      }
      case 'ssh_capabilities':return permitted(ctx,args,{kind:'capabilities'},signal,async p=>{
        const result=await execute(p.host,buildRemoteCapabilityProbe(),{timeoutSeconds:20,maxOutputBytes:65536});
        if(result.exitCode!==0||result.truncated)throw new Error('能力探测未能完成，请查看连接诊断');
        return {capabilities:{local:getLocalCapabilities(),remote:parseRemoteCapabilities(result.stdout)}};
      });
      case 'ssh_job_submit': {
        const host=findHost(args.hostId),policy=store.getPolicy(host.id).policy;
        const op={kind:'job',command:args.command,cwd:args.cwd??host.defaultCwd??'/',env:args.env??{},shell:args.shell??'/bin/sh',timeoutSeconds:args.timeoutSeconds??policy.jobs.timeoutSeconds,maxOutputBytes:policy.jobs.maxOutputKiB*1024,disconnectPolicy:'continue',cpuSeconds:policy.jobs.cpuSeconds,maxMemoryMiB:policy.jobs.maxMemoryMiB,maxProcesses:policy.jobs.maxProcesses,...(args.idempotencyKey?{idempotencyKey:args.idempotencyKey}:{})};
        if(!op.cwd)op.cwd='/';
        return permitted(ctx,args,op,signal,async p=>{
          const {kind,idempotencyKey,...operation}=p.evaluation.operation;
          const job=await jobs.submit({threadId,sessionId:ctx.sessionId,host:p.host,operation:{...operation,command:p.evaluation.command},idempotencyKey});
          const tracked=store.getExternalOperation(threadId,'job',job.id);
          if(!tracked||tracked.id!==p.operationId)finish(p.operationId,{status:'completed',exitCode:0,stdout:'相同提交已存在，返回原任务；未重复执行。'});
          return {job:publicJob(job)};
        },{durable:true});
      }
      case 'ssh_job_list': {
        const cursor=args.cursor??0,limit=args.limit??50,list=jobs.list({threadId,cursor,limit});
        const more=list.length===limit&&jobs.list({threadId,cursor:cursor+limit,limit:1}).length>0;
        return {jobs:list.map(publicJob),nextCursor:more?cursor+limit:null};
      }
      case 'ssh_job_read':case 'ssh_job_reconcile':case 'ssh_job_cancel': {
        const local=await jobs.read({threadId,taskId:args.taskId,refresh:false,cursor:args.cursor??0,limitBytes:args.limitBytes??65536});
        if(name==='ssh_job_read'&&args.refresh===false)return {job:publicJob(local)};
        const action=name==='ssh_job_cancel'?'cancel':name==='ssh_job_reconcile'?'reconcile':'read';
        return permitted(ctx,{...args,hostId:local.hostId},{kind:'job_control',id:args.taskId,action},signal,async()=>{
          const job=action==='cancel'?await jobs.cancel({threadId,taskId:args.taskId}):action==='reconcile'?await jobs.reconcile({threadId,taskId:args.taskId}):await jobs.read({threadId,taskId:args.taskId,cursor:args.cursor??0,limitBytes:args.limitBytes??65536});
          return {job:publicJob(job)};
        });
      }
      case 'ssh_transfer_prepare':case 'ssh_transfer_manifest': {
        const op={kind:'transfer_inspect',direction:args.direction,localPath:args.localPath,remotePath:args.remotePath,recursive:name==='ssh_transfer_manifest'};
        return permitted(ctx,args,op,signal,async p=>{
          const grant=store.state(threadId).grants.find(x=>x.hostId===p.host.id),rules=p.evaluation.transfer;
          const request={threadId,host:p.host,direction:op.direction,localPath:p.evaluation.operation.localPath,remotePath:op.remotePath,localRoot:rules.localRoot,remoteRoot:rules.remoteRoot,blockedPaths:rules.blockedPaths,localBlockedPaths:rules.localBlockedPaths??[],overwrite:'never',maxBytes:rules.maxBytes,maxEntries:rules.maxEntries,expiresAt:Math.min(grant.expiresAt,Date.now()+rules.timeoutSeconds*1000)};
          if(name==='ssh_transfer_manifest')return {manifest:await transfers.planManifest(request)};
          const plan=await transfers.prepare(request);return {plan:publicTransfer(plan),planId:plan.planId};
        });
      }
      case 'ssh_transfer_start': {
        const id=args.planId??args.transferId,record=await transfers.read({threadId,transferId:id}),op=transferOperation(record);
        return permitted(ctx,{...args,hostId:record.hostId??record.approvalPayload.hostId},op,signal,async()=>{
          const transfer=await transfers.start({threadId,sessionId:ctx.sessionId,planId:id});followTransfer(transfer);
          return {transfer:publicTransfer(transfer)};
        },{durable:true});
      }
      case 'ssh_transfer_resume': {
        const id=args.transferId,record=await transfers.read({threadId,transferId:id}),hostId=record.approvalPayload.hostId;
        const policy=store.getPolicy(hostId).policy,grant=store.state(threadId).grants.find(x=>x.hostId===hostId);
        if(!grant)throw new Error('请先重新授权当前主机');
        const expiresAt=Math.min(grant.expiresAt,Date.now()+policy.transfers.timeoutSeconds*1000);
        const transfer=transferOperation(record,{expiresAt});
        return permitted(ctx,{...args,hostId},{kind:'transfer_control',id,action:'resume',transfer},signal,async()=>{
          const resumed=await transfers.resume({threadId,transferId:id,expiresAt});followTransfer(resumed);
          return {transfer:publicTransfer(resumed)};
        });
      }
      case 'ssh_transfer_mkdir': {
        const policy=store.getPolicy(args.hostId).policy,grant=store.state(threadId).grants.find(x=>x.hostId===args.hostId);
        if(!grant)throw new Error('请先授权当前主机');
        const expiresAt=Math.min(grant.expiresAt,Date.now()+policy.transfers.timeoutSeconds*1000);
        const op={kind:'transfer_mkdir',side:args.side,root:args.root,path:args.path,blockedPaths:args.side==='remote'?policy.blockedPaths:[],expiresAt};
        return permitted(ctx,args,op,signal,async p=>({directory:await transfers.createDirectory({...p.evaluation.operation,threadId,host:p.host})}));
      }
      case 'ssh_transfer_list': {
        const list=await transfers.list({threadId,cursor:args.cursor??0,limit:args.limit??50});for(const r of list.transfers)onTransferUpdate(r);
        return {transfers:list.transfers.map(publicTransfer),nextCursor:list.hasMore?list.cursor:null};
      }
      case 'ssh_transfer_read': {
        const transfer=await transfers.read({threadId,transferId:args.transferId,cursor:args.cursor??0});onTransferUpdate(transfer);return {transfer:publicTransfer(transfer)};
      }
      case 'ssh_transfer_cancel':case 'ssh_transfer_cleanup': {
        const record=await transfers.read({threadId,transferId:args.transferId});
        const cleanup=name==='ssh_transfer_cleanup';
        const operation={kind:'transfer_control',id:args.transferId,action:cleanup?'cleanup':'cancel',...(cleanup?{transfer:transferScope(record)}:{})};
        return permitted(ctx,{...args,hostId:record.hostId??record.approvalPayload.hostId},operation,signal,async()=>{
          const identity={threadId,transferId:args.transferId};
          const transfer=cleanup?await transfers.cleanup(identity,r=>checkedLifecycleRecord(r,'transfer',true)):await transfers.cancel(identity);
          onTransferUpdate(transfer);return {transfer:publicTransfer(transfer)};
        });
      }
      default:throw new Error('未知基础设施操作');
    }
  }
  return {
    call(name,ctx,args,signal){const promise=handle(name,ctx,args,signal);inflight.add(promise);promise.finally(()=>inflight.delete(promise)).catch(()=>{});return promise;},
    async close(){closing=true;clearInterval(maintenanceTimer);for(const child of children)child.kill();await Promise.allSettled([...inflight,sweepInFlight,...[...transfers.running.values()].map(x=>x.promise)]);lifecycle.close();jobs.close();transfers.close();},
  };
}
