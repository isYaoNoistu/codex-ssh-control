import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { inspectLocalFile, validateLocalPath, openLocalSource, createLocalPartial, inspectLocalPartial, commitLocalPartial, cleanupLocalPartial, localManifest, recoverLocalPublication, createLocalDirectory, localFileCapabilities } from '../src/local-files.mjs';
test('local file capability exposes the real client platform',()=>{assert.equal(localFileCapabilities.platform,process.platform);assert.equal(localFileCapabilities.supported,['linux','win32'].includes(process.platform));});
test('unsupported macOS local binary inspection fails clearly',{skip:process.platform!=='darwin'},async()=>{await assert.rejects(inspectLocalFile('/not-used','/not-used'),/local binary transfer unsupported on this platform/);});
test('unsupported platform rejects binary inspection before opening a path',()=>{
 const source=`Object.defineProperty(process,'platform',{value:'darwin'});const m=await import(${JSON.stringify(new URL('../src/local-files.mjs',import.meta.url).href)});try{await m.inspectLocalFile('/not-used','/not-used');process.exitCode=1;}catch(e){if(!/local binary transfer unsupported on this platform/.test(e.message)||m.localFileCapabilities.supported)process.exitCode=1;}`;
 const result=spawnSync(process.execPath,['--input-type=module','-e',source],{encoding:'utf8',windowsHide:true});assert.equal(result.status,0,result.stderr);
});
const fixture = async t => { const dir = await fs.mkdtemp(path.join(await fs.realpath(os.tmpdir()), 'transfer-test-')); t.after(() => fs.rm(dir, { recursive:true,force:true })); return dir; };
const binaryTest=(name,fn)=>test(name,{skip:process.platform==='darwin'?'local binary transfer unsupported on this platform':false},fn);
binaryTest('local source snapshot hashes binary, binds identity and rejects changes', async t => {
  const root=await fixture(t), file=path.join(root,'data'); await fs.writeFile(file,Buffer.from([0,255,3]));
  const snap=await inspectLocalFile(file,root); assert.equal(snap.size,3); assert.equal(snap.sha256.length,64);
  await fs.writeFile(file,'changed'); await assert.rejects(openLocalSource(file,root,snap), /changed/);
});
test('paths reject traversal, links, hardlinks and sensitive names',async t=>{
 const root=await fixture(t); await fs.writeFile(path.join(root,'data'),'x');
 await assert.rejects(validateLocalPath(path.join(root,'..','outside'),root), /root/);
 await assert.rejects(validateLocalPath(path.join(root,'.env'),root), /protected/);
 await fs.link(path.join(root,'data'),path.join(root,'hard')); if(process.platform!=='darwin')await assert.rejects(inspectLocalFile(path.join(root,'hard'),root),/hardlink/);
 if(process.platform!=='win32'){await fs.symlink(path.join(root,'data'),path.join(root,'link'));await assert.rejects(validateLocalPath(path.join(root,'link'),root),/link/);}
});
test('partial commit verifies digest and never replaces a concurrent target',async t=>{
 const root=await fixture(t),target=path.join(root,'result'),token='a'.repeat(64);
 const partial=await createLocalPartial(target,root,token); await fs.writeFile(partial.path,'abc');
 const state=await inspectLocalPartial(partial,target,root); assert.equal(state.size,3);
 await assert.rejects(commitLocalPartial(partial,target,root,{size:3,sha256:'0'.repeat(64),mode:384}),/digest/);
 await fs.writeFile(target,'keep'); await assert.rejects(commitLocalPartial(partial,target,root,{size:3,sha256:state.sha256,mode:384}),/exist/i);
 assert.equal(await fs.readFile(target,'utf8'),'keep'); await cleanupLocalPartial(partial,target,root);
});
test('cleanup refuses a partial whose identity changed',async t=>{
 const root=await fixture(t), target=path.join(root,'result'); const partial=await createLocalPartial(target,root,'b'.repeat(64));
 const wrong={...partial,ino:'0'}; await assert.rejects(cleanupLocalPartial(wrong,target,root),/identity/); assert.ok(await fs.stat(partial.path));
});
test('recovery only finishes the exact owned inode after publication interrupted before unlink',async t=>{
 const root=await fixture(t), target=path.join(root,'result');const partial=await createLocalPartial(target,root,'c'.repeat(64));await fs.writeFile(partial.path,'abc');const snap=await inspectLocalPartial(partial,target,root);await fs.link(partial.path,target);
 assert.equal(await recoverLocalPublication(partial,target,root,snap),true);assert.equal((await fs.stat(target)).nlink,1);assert.equal(await fs.readFile(target,'utf8'),'abc');
});
binaryTest('recursive manifest bounds entries and rejects links instead of silently skipping',async t=>{
 const root=await fixture(t); await fs.writeFile(path.join(root,'a'),'abc');await fs.writeFile(path.join(root,'b'),'def');
 await assert.rejects(localManifest(root,root,{maxEntries:1,maxBytes:100}),/limit/);
 const entries=await localManifest(root,root,{maxEntries:2,maxBytes:6});assert.equal(entries.length,2);
 await fs.link(path.join(root,'a'),path.join(root,'c'));await assert.rejects(localManifest(root,root,{maxEntries:10,maxBytes:100}),/hardlink/);
});
test('managed mkdir creates only scoped directories and rejects files/protected paths',async t=>{
 const root=await fixture(t);const target=path.join(root,'one','two');assert.equal((await createLocalDirectory(target,root)).created.length,2);assert.equal((await createLocalDirectory(target,root)).created.length,0);
 await fs.writeFile(path.join(root,'file'),'x');await assert.rejects(createLocalDirectory(path.join(root,'file','child'),root),/directory/);await assert.rejects(createLocalDirectory(path.join(root,'.ssh','child'),root),/protected/);
});

test('recursive local inspection shares infrastructure protected directories',async t=>{
 const root=await fixture(t);
 for(const segment of ['.codex','.agents','.git','Windows','Program Files','Program Files (x86)'])await assert.rejects(validateLocalPath(path.join(root,segment,'data'),root,{allowMissing:true}),/protected/);
 await fs.mkdir(path.join(root,'.codex'));await fs.writeFile(path.join(root,'.codex','auth.json'),'private');
 await assert.rejects(localManifest(root,root),/protected/);
});
