/** Local filesystem boundary. Defends normal accidental/linked paths, not an
 * adversary with arbitrary access to this OS account. Node cannot provide
 * descriptor-relative Windows reparse/ACL or atomic conditional replacement.
 * Consequently replacement is unsupported and new files inherit local ACLs.
 */
import * as fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isProtectedPath } from './policy.mjs';
const execute = promisify(execFile);
const TOKEN = /^[a-f0-9]{64}$/;
const localProtected = p => {const converted=p.replaceAll('\\','/').replace(/^[A-Za-z]:/u,'');return isProtectedPath(converted)||/(?:^|\/)(?:\.codex|\.agents|\.git|windows|program files(?: \(x86\))?)(?:\/|$)/iu.test(converted);};
const inside = (target, root) => { const rel=path.relative(root,target); return rel==='' || (!rel.startsWith(`..${path.sep}`)&&rel!=='..'&&!path.isAbsolute(rel)); };
function ordinary(info) { if(!info.isFile()||info.nlink!==1n)throw new Error('only regular files without hardlinks are allowed'); if((Number(info.mode)&0o6000)!==0)throw new Error('special file permissions unsupported'); }
function identity(info){return {dev:String(info.dev),ino:String(info.ino)};}
function metadata(info){return {...identity(info),size:Number(info.size),mtimeNs:String(info.mtimeNs),ctimeNs:String(info.ctimeNs),mode:process.platform==='win32'?0o600:Number(info.mode)&0o777};}
export function sameSnapshot(a,b){return !!a&&!!b&&['dev','ino','size','mtimeNs','ctimeNs','sha256'].every(k=>a[k]===b[k]);}
async function rejectReparse(candidates){
 if(process.platform!=='win32')return;
 // Get-Item handles junctions and other reparse tags Node's isSymbolicLink may miss.
 const script='$paths=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\''+Buffer.from(JSON.stringify(candidates)).toString('base64')+'\'))); foreach ($p in $paths) { $i=Get-Item -LiteralPath $p -Force -ErrorAction Stop; if (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 9 } }';
 try{await execute('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{windowsHide:true,maxBuffer:1024,timeout:15000});}catch{throw new Error('local reparse point or uninspectable path rejected');}
}
export async function validateLocalPath(target,root,{allowMissing=false,directory=false,blockedPaths=[]}={}){
 if(typeof target!=='string'||typeof root!=='string'||!path.isAbsolute(target)||!path.isAbsolute(root)||/[\x00-\x1f]/.test(target+root))throw new Error('absolute local root and path required');
 if(process.platform==='win32'&&(/^\\\\/.test(target)||/^\\\\/.test(root)||target.slice(2).includes(':')||root.slice(2).includes(':')||target.split(/[\\/]/).some(p=>/[. ]$/.test(p))))throw new Error('unsafe Windows path');
 target=path.resolve(target);root=path.resolve(root);
 if(!inside(target,root)||(!directory&&target===root))throw new Error('local path outside authorized root');
 if(localProtected(target)||blockedPaths.some(p=>inside(target,path.resolve(p))))throw new Error('protected local path');
 if(process.platform!=='win32'&&['/proc','/sys','/dev','/run','/etc','/boot'].some(p=>inside(target,p)))throw new Error('protected local path');
 const parsed=path.parse(target);let current=parsed.root;const rootDev=(await fs.lstat(root,{bigint:true})).dev;const checked=[];
 const parts=target.slice(parsed.root.length).split(path.sep).filter(Boolean);
 for(let i=0;i<parts.length;i++){
  current=path.join(current,parts[i]);let info;
  try{info=await fs.lstat(current,{bigint:true});}catch(e){if(e.code==='ENOENT'&&allowMissing&&i===parts.length-1){await rejectReparse(checked);return target;}throw e;}
  if(info.isSymbolicLink())throw new Error('local symlink/junction rejected');checked.push(current);
  if(inside(current,root)&&info.dev!==rootDev)throw new Error('local mount boundary rejected');
  if(i<parts.length-1&&!info.isDirectory())throw new Error('local parent is not a directory');
 }
 await rejectReparse(checked);return target;
}
export async function hashHandle(handle,limit=Infinity){
 const hash=createHash('sha256'),buffer=Buffer.allocUnsafe(256*1024);let offset=0;
 while(offset<limit){const {bytesRead}=await handle.read(buffer,0,Math.min(buffer.length,limit-offset),offset);if(!bytesRead)break;hash.update(buffer.subarray(0,bytesRead));offset+=bytesRead;}
 if(Number.isFinite(limit)&&offset!==limit)throw new Error('source prefix shorter than expected');
 return hash.digest('hex');
}
async function rejectExtendedAttributes(file){
 if(process.platform==='win32')return; // Windows security descriptors are not exported as POSIX metadata.
 // Python is also the remote helper prerequisite. Fail closed if unavailable.
 const program='import os,sys; f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW); a=os.listxattr(f); os.close(f); sys.exit(7 if a else 0)';
 try{await execute('python3',['-c',program,file],{maxBuffer:1024,timeout:15000});}catch{throw new Error('local ACL/xattr inspection failed or extended attributes unsupported');}
}
export async function inspectLocalFile(target,root,options={}){
 if(!localFileCapabilities.supported)throw new Error('local binary transfer unsupported on this platform');
 await validateLocalPath(target,root,options);await rejectExtendedAttributes(target);
 const h=await fs.open(target,constants.O_RDONLY|(constants.O_NOFOLLOW??0));
 try{const before=await h.stat({bigint:true});ordinary(before);if(before.size>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('file too large');
  const snapshot={...metadata(before),sha256:await hashHandle(h)};const after=await h.stat({bigint:true});
  if(JSON.stringify(metadata(before))!==JSON.stringify(metadata(after)))throw new Error('source changed during hash');return snapshot;
 }finally{await h.close();}
}
export async function openLocalSource(target,root,snapshot){
 const current=await inspectLocalFile(target,root);if(!sameSnapshot(snapshot,current))throw new Error('local source changed since approval');
 const h=await fs.open(target,constants.O_RDONLY|(constants.O_NOFOLLOW??0));const info=await h.stat({bigint:true});
 if(JSON.stringify(metadata(info))!==JSON.stringify(Object.fromEntries(Object.entries(current).filter(([k])=>k!=='sha256')))){await h.close();throw new Error('local source changed during open');}return h;
}
export async function createLocalPartial(target,root,token){
 if(!TOKEN.test(token))throw new Error('invalid partial token');await validateLocalPath(target,root,{allowMissing:true});
 try{await fs.lstat(target);throw new Error('destination exists; overwrite unsupported');}catch(e){if(e.code!=='ENOENT')throw e;}
 const directory=path.join(path.dirname(target),'.ssh-transfer-'+token);await fs.mkdir(directory,{mode:0o700});
 const file=path.join(directory,'data');const h=await fs.open(file,'wx',0o600);const info=await h.stat({bigint:true});await h.close();
 const dir=await fs.lstat(directory,{bigint:true});return {token,path:file,directory,...identity(info),directoryDev:String(dir.dev),directoryIno:String(dir.ino)};
}
async function checkPartial(partial,target,root){
 if(!TOKEN.test(partial.token)||partial.directory!==path.join(path.dirname(target),'.ssh-transfer-'+partial.token)||partial.path!==path.join(partial.directory,'data'))throw new Error('partial identity mismatch');
 await validateLocalPath(partial.path,root);const dir=await fs.lstat(partial.directory,{bigint:true}),info=await fs.lstat(partial.path,{bigint:true});ordinary(info);
 if(String(dir.dev)!==partial.directoryDev||String(dir.ino)!==partial.directoryIno||String(info.dev)!==partial.dev||String(info.ino)!==partial.ino)throw new Error('partial identity mismatch');return info;
}
export async function inspectLocalPartial(partial,target,root){await checkPartial(partial,target,root);const h=await fs.open(partial.path,constants.O_RDONLY|(constants.O_NOFOLLOW??0));try{return {...metadata(await h.stat({bigint:true})),sha256:await hashHandle(h)};}finally{await h.close();}}
export async function commitLocalPartial(partial,target,root,snapshot,beforePublish=()=>{}){
 await validateLocalPath(target,root,{allowMissing:true});const actual=await inspectLocalPartial(partial,target,root);
 if(actual.size!==snapshot.size||actual.sha256!==snapshot.sha256)throw new Error('final size or digest mismatch');
 const h=await fs.open(partial.path,constants.O_RDWR|(constants.O_NOFOLLOW??0));try{if(process.platform!=='win32')await h.chmod(snapshot.mode&0o777);if(snapshot.mtimeNs)await h.utimes(new Date(),Number(BigInt(snapshot.mtimeNs))/1e9);await h.sync();}finally{await h.close();}
 // link is an atomic no-replace publication. A crash between link and unlink can
 // leave two names; never treat that state as resumable regular source data.
 await beforePublish();await fs.link(partial.path,target);await fs.unlink(partial.path);await fs.rmdir(partial.directory);
 return {committed:true};
}
export async function cleanupLocalPartial(partial,target,root){await checkPartial(partial,target,root);await fs.unlink(partial.path);await fs.rmdir(partial.directory);}
export async function recoverLocalPublication(partial,target,root,snapshot){
 await validateLocalPath(target,root,{allowMissing:true});let info;try{info=await fs.lstat(target,{bigint:true});}catch(e){if(e.code==='ENOENT')return false;throw e;}
 if(!info.isFile()||String(info.dev)!==partial.dev||String(info.ino)!==partial.ino||![1n,2n].includes(info.nlink))throw new Error('publication target identity mismatch');
 const handle=await fs.open(target,constants.O_RDONLY|(constants.O_NOFOLLOW??0));try{if(Number(info.size)!==snapshot.size||await hashHandle(handle)!==snapshot.sha256)throw new Error('publication digest mismatch');}finally{await handle.close();}
 if(!TOKEN.test(partial.token)||partial.directory!==path.join(path.dirname(target),'.ssh-transfer-'+partial.token)||partial.path!==path.join(partial.directory,'data'))throw new Error('partial identity mismatch');
 let directory;try{directory=await fs.lstat(partial.directory,{bigint:true});}catch(e){if(e.code==='ENOENT'&&info.nlink===1n)return true;throw e;}
 if(directory.isSymbolicLink()||String(directory.dev)!==partial.directoryDev||String(directory.ino)!==partial.directoryIno)throw new Error('partial directory identity mismatch');
 await validateLocalPath(partial.directory,root,{directory:true});
 let staged;try{staged=await fs.lstat(partial.path,{bigint:true});}catch(e){if(e.code!=='ENOENT')throw e;}
 if(staged){if(!staged.isFile()||String(staged.dev)!==partial.dev||String(staged.ino)!==partial.ino||staged.nlink!==2n||info.nlink!==2n)throw new Error('partial identity mismatch');await fs.unlink(partial.path);}
 else if(info.nlink!==1n)throw new Error('unaccounted publication hardlink');
 await fs.rmdir(partial.directory);return true;
}
export async function localManifest(target,root,{maxEntries=256,maxBytes=1024**3,maxDepth=16,blockedPaths=[]}={}){
 if(!Number.isInteger(maxEntries)||maxEntries<1||maxEntries>1024||!Number.isSafeInteger(maxBytes)||maxBytes<0)throw new Error('manifest limit invalid');
 await validateLocalPath(target,root,{directory:true,blockedPaths});const result=[];let total=0,visited=0;
 async function walk(dir,depth){if(depth>maxDepth)throw new Error('manifest depth limit exceeded');for await(const entry of await fs.opendir(dir)){
  if(++visited>maxEntries*4)throw new Error('manifest directory limit exceeded');const file=path.join(dir,entry.name);await validateLocalPath(file,root,{directory:entry.isDirectory(),blockedPaths});
  if(/^\.ssh-transfer-[a-f0-9]{64}$/.test(entry.name)){const reserved=await fs.lstat(file);if(!reserved.isDirectory()||(process.platform!=='win32'&&(reserved.uid!==process.getuid()||(reserved.mode&0o777)!==0o700)))throw new Error('unsafe reserved transfer directory');continue;}
  if(entry.isDirectory()){await walk(file,depth+1);continue;}const snapshot=await inspectLocalFile(file,root,{blockedPaths});total+=snapshot.size;
  if(result.length>=maxEntries||total>maxBytes)throw new Error('manifest limit exceeded');result.push({relativePath:path.relative(target,file).split(path.sep).join('/'),snapshot});
 }}await walk(target,0);return result;
}
export async function createLocalDirectory(target,root,{blockedPaths=[],beforeCreate=()=>{}}={}){
 if(typeof target!=='string'||!path.isAbsolute(target)||typeof root!=='string'||!path.isAbsolute(root))throw new Error('absolute local root and path required');
 target=path.resolve(target);root=path.resolve(root);if(!inside(target,root))throw new Error('local directory outside authorized root');
 // Validate the complete lexical path before any mutation so a protected final
 // component cannot cause otherwise unintended ancestors to be created.
 if(localProtected(target)||blockedPaths.some(p=>inside(target,path.resolve(p))))throw new Error('protected local path');
 await validateLocalPath(root,root,{directory:true,blockedPaths});const parts=path.relative(root,target).split(path.sep).filter(Boolean);if(parts.length>64)throw new Error('directory depth limit exceeded');
 const created=[];let current=root;
 for(const part of parts){current=path.join(current,part);await validateLocalPath(current,root,{allowMissing:true,directory:true,blockedPaths});await beforeCreate();
  try{await fs.mkdir(current,{mode:0o700});created.push(current);}catch(e){if(e.code!=='EEXIST')throw e;}
  await validateLocalPath(current,root,{directory:true,blockedPaths});if(!(await fs.lstat(current)).isDirectory())throw new Error('local parent is not a directory');
 }return {created,path:target};
}
export const localFileCapabilities=Object.freeze({platform:process.platform,supported:['linux','win32'].includes(process.platform),symlinkChecks:true,windowsReparseChecks:true,atomicNoReplace:true,conditionalOverwrite:false,hostileSameUserFilesystem:false,windowsAclExport:false,ordinaryPosixMode:process.platform!=='win32'});
