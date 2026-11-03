import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultPolicy, validatePolicy, evaluateOperation, normalizeOperation } from '../src/policy.mjs';

const policy = patch => validatePolicy({ ...defaultPolicy(), mode:'approval', roots:[{id:'remote',path:'/srv/releases',read:true,write:true}], localRoots:[{id:'build',path:'C:/build',read:true,write:true}], jobs:{enabled:true}, transfers:{enabled:true}, ...patch });
const job = patch => ({kind:'job',command:'sleep 10',cwd:'/srv/releases',shell:'/bin/sh',env:{},timeoutSeconds:600,maxOutputBytes:65536,disconnectPolicy:'continue',...patch});

test('legacy policies gain disabled task and artifact capabilities without widening access',()=>{
  const p=validatePolicy({});
  assert.equal(p.jobs.enabled,false);
  assert.equal(p.transfers.enabled,false);
  assert.deepEqual(p.localRoots,[]);
  assert.equal(evaluateOperation(p,job()).decision,'deny');
});
test('exact remote path permission does not authorize descendants',()=>{
  const p=policy({roots:[{id:'one',path:'/srv/releases/a.txt',match:'exact',read:true,write:true}]});
  assert.equal(evaluateOperation(p,{kind:'read',path:'/srv/releases/a.txt'}).decision,'allow');
  assert.deepEqual(evaluateOperation(p,{kind:'read',path:'/srv/releases/a.txt'}).file,{root:'/srv/releases',relativePath:'a.txt',blockedPaths:[]});
  assert.equal(evaluateOperation(p,{kind:'write',path:'/srv/releases/a.txt',content:'hello'}).decision,'ask');
  assert.equal(evaluateOperation(p,{kind:'read',path:'/srv/releases/a.txt/child'}).decision,'deny');
});
test('named action allowlists distinguish target arguments and reject unlisted services',()=>{
  const p=policy({actionArguments:{'service.restart':{names:['nginx']}}});
  assert.equal(evaluateOperation(p,{kind:'action',actionId:'service.restart',args:{name:'nginx'}}).decision,'ask');
  assert.equal(evaluateOperation(p,{kind:'action',actionId:'service.restart',args:{name:'postgresql'}}).code,'ARGUMENT_NOT_ALLOWED');
  assert.throws(()=>policy({actionArguments:{'service.restart':{names:['nginx;id']}}}));
});
test('jobs bind execution fields and cannot weaken shell, env, duration or output policy',()=>{
  const p=policy({jobs:{enabled:true,allowedEnv:['APP_MODE'],timeoutSeconds:900,maxOutputKiB:64}});
  assert.equal(evaluateOperation(p,job({env:{APP_MODE:'test'}})).decision,'ask');
  for(const patch of [{timeoutSeconds:901},{maxOutputBytes:65537},{shell:'/bin/bash'},{env:{UNLISTED:'x'}}]) assert.equal(evaluateOperation(p,job(patch)).decision,'deny');
  for(const env of [{PATH:'/tmp'},{LD_PRELOAD:'/tmp/a.so'},{BASH_ENV:'/tmp/a'},{APP_TOKEN:'secret-value'}]) assert.throws(()=>normalizeOperation(job({env})));
  assert.equal(evaluateOperation(policy({mode:'restricted'}),job()).decision,'deny');
});
test('transfer inspection requires both roots and rejects local and remote protected paths',()=>{
  const p=policy();
  const inspect=patch=>({kind:'transfer_inspect',direction:'upload',localPath:'C:/build/app.jar',remotePath:'/srv/releases/app.jar',...patch});
  assert.equal(evaluateOperation(p,inspect()).decision,'allow');
  for(const patch of [{localPath:'C:/else/app.jar'},{localPath:'C:/build/.ssh/id_rsa'},{remotePath:'/etc/shadow'},{remotePath:'/srv/releases/../other'}]) {
    try { assert.equal(evaluateOperation(p,inspect(patch)).decision,'deny'); } catch(e) { if(e.code==='ERR_ASSERTION') throw e; }
  }
  assert.equal(evaluateOperation(policy({localRoots:[{id:'build',path:'C:/build',read:true,write:false}]}),inspect({direction:'download'})).decision,'deny');
  assert.equal(evaluateOperation(policy({localRoots:[{id:'one',path:'C:/build/app.jar',match:'exact',read:true,write:false}]}),inspect({recursive:true})).decision,'deny');
});

test('managed directory creation requires recursive write permission and exact blocked-path policy',()=>{
  const p=policy(),op={kind:'transfer_mkdir',side:'remote',root:'/srv/releases',path:'/srv/releases/v1',blockedPaths:[],expiresAt:Date.now()+60000};
  assert.equal(evaluateOperation(p,op).decision,'ask');
  for(const patch of [{root:'/srv'},{path:'/srv/releases'},{path:'/srv/releases/.ssh'},{blockedPaths:['/other']}])assert.equal(evaluateOperation(p,{...op,...patch}).decision,'deny');
});
test('artifact approval binds source digest, size, direction and no-overwrite destination',()=>{
  const p=policy();
  const op={kind:'transfer',planId:'fixture-plan',direction:'upload',localPath:'C:/build/app.jar',remotePath:'/srv/releases/app.jar',size:500_000_000,sha256:'a'.repeat(64),sourceSnapshot:{dev:'1',ino:'2',size:500_000_000,mtimeNs:'1',ctimeNs:'1',mode:420,sha256:'a'.repeat(64)},targetSnapshot:null,overwrite:'never'};
  Object.assign(op,{localRoot:'C:/build',remoteRoot:'/srv/releases',blockedPaths:[],localBlockedPaths:[],expiresAt:Date.now()+60000,maxBytes:1073741824});
  const normalized=normalizeOperation(op);
  assert.equal(normalized.sha256,op.sha256);
  assert.equal(evaluateOperation(p,normalized).decision,'ask');
  assert.equal(evaluateOperation(policy({transfers:{enabled:true,maxBytes:1024}}),normalized).decision,'deny');
  assert.throws(()=>normalizeOperation({...op,sha256:'broken'}));
  assert.throws(()=>normalizeOperation({...op,overwrite:'always'}));
  assert.equal(normalized.expiresAt,op.expiresAt);
  assert.equal(evaluateOperation(p,{...op,localRoot:'C:/'}).decision,'deny');
  assert.equal(evaluateOperation(p,{kind:'transfer_control',id:op.planId,action:'resume',transfer:op}).decision,'ask');
  assert.equal(evaluateOperation(policy({transfers:{enabled:false}}),{kind:'transfer_control',id:op.planId,action:'resume',transfer:op}).decision,'deny');
  assert.throws(()=>normalizeOperation({kind:'transfer_control',id:'wrong-plan',action:'resume',transfer:op}));
});
test('task control is narrowly typed and cancellation still requires confirmation',()=>{
  for(const kind of ['job_control','transfer_control']) {
    assert.equal(evaluateOperation(policy(),{kind,id:'opaque-task',action:'read'}).decision,'allow');
    assert.equal(evaluateOperation(policy(),{kind,id:'opaque-task',action:'cancel'}).decision,'ask');
    assert.throws(()=>normalizeOperation({kind,id:'opaque-task',action:'exec',command:'id'}));
  }
});

test('recursive transfer constraints include more-specific denied source and destination roots',()=>{
  const p=policy({
    roots:[{id:'all',path:'/srv/releases',read:true,write:true},{id:'private',path:'/srv/releases/private',read:false,write:true},{id:'locked',path:'/srv/releases/locked',read:true,write:false}],
    localRoots:[{id:'all',path:'C:/build',read:true,write:true},{id:'private',path:'C:/build/private',read:false,write:true},{id:'locked',path:'C:/build/locked',read:true,write:false}],
    blockedPaths:['/srv/releases/blocked'],
  });
  const op={kind:'transfer_inspect',direction:'upload',localPath:'C:/build',remotePath:'/srv/releases',recursive:true};
  const upload=evaluateOperation(p,op);
  assert.deepEqual(upload.transfer.localBlockedPaths,['C:/build/private']);
  assert.deepEqual(upload.transfer.blockedPaths,['/srv/releases/blocked','/srv/releases/locked']);
  const download=evaluateOperation(p,{...op,direction:'download'});
  assert.deepEqual(download.transfer.localBlockedPaths,['C:/build/locked']);
  assert.deepEqual(download.transfer.blockedPaths,['/srv/releases/blocked','/srv/releases/private']);
});

test('derived transfer constraints are bound into the exact approval snapshot',()=>{
  const p=policy({localRoots:[{id:'all',path:'C:/build',read:true,write:true},{id:'private',path:'C:/build/private',read:false,write:false}],roots:[{id:'all',path:'/srv/releases',read:true,write:true},{id:'locked',path:'/srv/releases/locked',read:false,write:false}]});
  const op={kind:'transfer',planId:'plan',direction:'upload',localPath:'C:/build/app.jar',remotePath:'/srv/releases/app.jar',localRoot:'C:/build',remoteRoot:'/srv/releases',blockedPaths:['/srv/releases/locked'],localBlockedPaths:['C:/build/private'],expiresAt:Date.now()+60000,maxBytes:1073741824,size:1,sha256:'a'.repeat(64),sourceSnapshot:{dev:'1',ino:'2',size:1,mtimeNs:'1',ctimeNs:'1',mode:420,sha256:'a'.repeat(64)},targetSnapshot:null,overwrite:'never'};
  assert.equal(evaluateOperation(p,op).decision,'ask');
  assert.equal(evaluateOperation(p,{...op,localBlockedPaths:[]}).decision,'deny');
  assert.equal(evaluateOperation(p,{...op,blockedPaths:[]}).decision,'deny');
});
