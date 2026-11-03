import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,realpathSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomUUID} from 'node:crypto';
import {Store} from '../src/store.mjs';
import {createInfrastructureRuntime} from '../src/infrastructure-runtime.mjs';

test('recursive planning refuses a more-specific unreadable local directory before returning hashes',{skip:process.platform==='darwin'?'local binary transfer unsupported on this platform':false},async()=>{
  const dir=mkdtempSync(join(realpathSync(tmpdir()),'recursive-permissions-')),local=join(dir,'artifacts');
  mkdirSync(local);mkdirSync(join(local,'private'));writeFileSync(join(local,'private','hidden.txt'),'synthetic restricted fixture');
  const store=new Store(dir);let runtime,spawns=0;
  try{
    store.saveHost({id:'fixture',sshAlias:'no-network.invalid',enabled:true});
    const initial=store.getPolicy('fixture');
    store.savePolicy('owner','fixture',{...initial.policy,
      roots:[{id:'remote',path:'/srv/artifacts',read:true,write:true}],
      localRoots:[{id:'all',path:local,read:true,write:true},{id:'private',path:join(local,'private'),read:false,write:false}],
      transfers:{enabled:true},
    },initial.revision);store.grant('owner',['fixture']);
    runtime=createInfrastructureRuntime({dataDir:dir,store,
      gate:async(ctx,args,op)=>{
        const permit=store.beginNativeOperation(ctx.threadId,args.hostId,op,'检查隔离的目录权限测试文件。',randomUUID(),store.getPolicy(args.hostId).revision);
        assert.equal(permit.status,'ready');return permit;
      },
      requireActive:(signal,id,threadId)=>store.assertOperationReady(threadId,id),
      finish:(id,result)=>store.finishOperation(id,result),
      spawnImpl:()=>{spawns++;throw Error('network prohibited in local planning test');},
    });
    await assert.rejects(()=>runtime.call('ssh_transfer_manifest',{threadId:'owner'},{hostId:'fixture',direction:'upload',localPath:local,remotePath:'/srv/artifacts/release'},new AbortController().signal),/protected local path/);
    assert.equal(spawns,0);
  }finally{await runtime?.close();store.close();rmSync(dir,{recursive:true,force:true});}
});
