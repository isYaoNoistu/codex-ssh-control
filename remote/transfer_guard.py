"""One-shot binary artifact broker; no daemon and no text-secret bypass.

Binary authorization is separate from guard.py text access. Hashes prove byte
integrity, never absence of secrets. Kernel openat2 is mandatory. Metadata with
ACL/xattrs or privileged mode cannot be represented and is rejected explicitly.
"""
import ctypes
import errno
import hashlib
import json
import os
import platform
import re
import stat
import sys
import time
try:
 import fcntl
except ImportError:
 fcntl=None  # Importable for policy tests; openat2 still rejects non-Linux.

class Denied(Exception): pass
CORE=('/proc','/sys','/dev','/run','/etc','/boot')
SEGMENTS={'.ssh','.aws','.azure','.kube','.gnupg','.docker','.bashrc','.bash_profile','.bash_login','.profile','.zshrc','.zprofile','.zshenv','.zlogin'}
MAX_BYTES=16*1024**3
CHUNK=256*1024
class OpenHow(ctypes.Structure):
 _fields_=[('flags',ctypes.c_uint64),('mode',ctypes.c_uint64),('resolve',ctypes.c_uint64)]
def openat2(directory,path,flags,mode=0,root=False):
 if platform.system()!='Linux' or platform.machine() not in ('x86_64','aarch64','riscv64'):raise Denied('Linux openat2 required')
 how=OpenHow(flags|os.O_CLOEXEC|os.O_NOFOLLOW,mode,0x02|0x04|(0 if root else 0x08|0x01))
 libc=ctypes.CDLL(None,use_errno=True);fd=libc.syscall(ctypes.c_long(437),ctypes.c_int(directory),ctypes.c_char_p(os.fsencode(path)),ctypes.byref(how),ctypes.sizeof(how))
 if fd<0:
  code=ctypes.get_errno()
  if code in (errno.ENOSYS,errno.EINVAL):raise Denied('safe path resolution unsupported')
  raise OSError(code,os.strerror(code))
 return fd
def valid_path(p):
 if not isinstance(p,str) or not p.startswith('/') or len(p)>4096 or '\\' in p or '//' in p or any(ord(c)<32 or ord(c)==127 for c in p) or any(x in ('.','..') for x in p.split('/')):raise Denied('invalid path')
 return p.rstrip('/') or '/'
def within(p,r):return p==r or p.startswith(r.rstrip('/')+'/')
def protected(p,blocked):
 parts=p.lower().split('/')
 return any(within(p.lower(),x) for x in CORE) or any(within(p,x) for x in blocked) or any(s in SEGMENTS or s.startswith(('.env','id_rsa','id_ed25519')) or s.endswith(('.pem','.key')) or 'credential' in s or 'secret' in s or (s=='.config' and i+1<len(parts) and parts[i+1]=='fish') for i,s in enumerate(parts))
def regular(fd):
 s=os.fstat(fd)
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_mode&0o6000:raise Denied('regular file without hardlinks or special permissions required')
 return s
def no_xattr(fd):
 libc=ctypes.CDLL(None,use_errno=True)
 try:f=libc.flistxattr
 except AttributeError:raise Denied('ACL/xattr inspection unsupported')
 f.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t];f.restype=ctypes.c_ssize_t
 count=f(fd,None,0)
 if count!=0:raise Denied('ACL/xattr metadata unsupported or uninspectable')
def identity(s):return {'dev':str(s.st_dev),'ino':str(s.st_ino)}
def metadata(s):return dict(identity(s),size=s.st_size,mtimeNs=str(s.st_mtime_ns),ctimeNs=str(s.st_ctime_ns),mode=stat.S_IMODE(s.st_mode)&0o777)
def digest(fd,length=None):
 h=hashlib.sha256();offset=0
 while length is None or offset<length:
  data=os.pread(fd,CHUNK if length is None else min(CHUNK,length-offset),offset)
  if not data:break
  h.update(data);offset+=len(data)
 if length is not None and offset!=length:raise Denied('prefix shorter than expected')
 return h.hexdigest()
def snapshot(fd):
 s=regular(fd);no_xattr(fd)
 if s.st_size>MAX_BYTES:raise Denied('source exceeds helper size limit')
 result=dict(metadata(s),sha256=digest(fd))
 if metadata(s)!=metadata(regular(fd)):raise Denied('source changed during hash')
 return result
def expired(req):
 if not isinstance(req.get('expiresAt'),(int,float)) or req['expiresAt']<=time.time()*1000:raise Denied('transfer expired')
def bounded(req):
 if type(req.get('size')) is not int or not 0<=req['size']<=MAX_BYTES or not re.fullmatch('[a-f0-9]{64}',req.get('sha256','')):raise Denied('invalid source size/digest')
 if type(req.get('mode')) is not int or not 0<=req['mode']<=0o777:raise Denied('unsupported mode')
 if req.get('overwrite')!='never':raise Denied('conditional overwrite unsupported')
def rename_noreplace(srcdir,src,dstdir,dst):
 libc=ctypes.CDLL(None,use_errno=True)
 try:rename=libc.renameat2
 except AttributeError:raise Denied('atomic no-replace unavailable')
 result=rename(ctypes.c_int(srcdir),ctypes.c_char_p(os.fsencode(src)),ctypes.c_int(dstdir),ctypes.c_char_p(os.fsencode(dst)),ctypes.c_uint(1))
 if result<0:
  code=ctypes.get_errno();raise OSError(code,os.strerror(code))
def write_all(fd,data):
 while data:
  count=os.write(fd,data);data=data[count:]
def committed_receipt(parent,req,cleanup=False):
 """The pre-rename durable inode record also resolves a lost commit response.

 No success inference from content alone: exact staged inode and contract must
 now be present at the target. Retain the tiny receipt until explicit cleanup.
 """
 token=req.get('token','')
 if not re.fullmatch('[a-f0-9]{64}',token):raise Denied('invalid transfer token')
 name='.ssh-transfer-'+token
 try:directory=openat2(parent,name,os.O_RDONLY|os.O_DIRECTORY)
 except FileNotFoundError:return None
 try:
  ds=os.fstat(directory)
  if ds.st_uid!=os.geteuid() or stat.S_IMODE(ds.st_mode)!=0o700:raise Denied('unsafe staging directory')
  fcntl.flock(directory,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:os.stat('data',dir_fd=directory,follow_symlinks=False);return None
  except FileNotFoundError:pass
  try:meta=openat2(directory,'identity.json',os.O_RDONLY)
  except FileNotFoundError:return None
  try:
   ms=regular(meta)
   if ms.st_uid!=os.geteuid() or stat.S_IMODE(ms.st_mode)!=0o600 or ms.st_size>8192:raise Denied('invalid staging metadata')
   record=json.loads(os.read(meta,8193))
  finally:os.close(meta)
  contract={k:req[k] for k in ('path','root','token','size','sha256','mode','mtimeNs','overwrite')}
  if record.get('contract')!=contract or record.get('directory')!=identity(ds):raise Denied('staging receipt mismatch')
  fd=openat2(parent,os.path.basename(req['path']),os.O_RDONLY|os.O_NONBLOCK)
  try:
   snap=snapshot(fd)
   if identity(regular(fd))!=record.get('file') or snap['size']!=req['size'] or snap['sha256']!=req['sha256']:raise Denied('committed target identity mismatch')
  finally:os.close(fd)
  if cleanup:os.unlink('identity.json',dir_fd=directory);os.rmdir(name,dir_fd=parent)
  return {'committed':True,'offset':req['size'],'cleaned':cleanup}
 finally:os.close(directory)
def stage_open(parent,req,create=False):
 token=req.get('token','')
 if not re.fullmatch('[a-f0-9]{64}',token):raise Denied('invalid transfer token')
 name='.ssh-transfer-'+token
 if create:
  try:os.mkdir(name,0o700,dir_fd=parent)
  except FileExistsError:pass
 directory=openat2(parent,name,os.O_RDONLY|os.O_DIRECTORY)
 try:
  ds=os.fstat(directory)
  if ds.st_uid!=os.geteuid() or stat.S_IMODE(ds.st_mode)!=0o700:raise Denied('unsafe staging directory')
  fcntl.flock(directory,fcntl.LOCK_EX|fcntl.LOCK_NB)
  contract={k:req[k] for k in ('path','root','token','size','sha256','mode','mtimeNs','overwrite')}
  # Lease is deliberately not immutable: explicit newly approved resume may renew it.
  try:meta=openat2(directory,'identity.json',os.O_RDONLY)
  except FileNotFoundError:
   if not create:raise
   fd=openat2(directory,'data',os.O_RDWR|os.O_CREAT|os.O_EXCL,mode=0o600)
   try:
    no_xattr(fd);info=regular(fd);record={'contract':contract,'directory':identity(ds),'file':identity(info)}
    meta=openat2(directory,'identity.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode=0o600)
    try:write_all(meta,json.dumps(record,separators=(',',':')).encode());os.fsync(meta)
    finally:os.close(meta)
    os.fsync(directory)
   finally:os.close(fd)
   meta=openat2(directory,'identity.json',os.O_RDONLY)
  try:
   ms=regular(meta)
   if ms.st_uid!=os.geteuid() or stat.S_IMODE(ms.st_mode)!=0o600 or ms.st_size>8192:raise Denied('invalid staging metadata')
   record=json.loads(os.read(meta,8193))
  finally:os.close(meta)
  if record.get('contract')!=contract or record.get('directory')!=identity(ds):raise Denied('staging contract/identity mismatch')
  fd=openat2(directory,'data',os.O_RDWR)
  try:
   s=regular(fd)
   if identity(s)!=record.get('file') or s.st_uid!=os.geteuid() or s.st_size>req['size']:raise Denied('staging file identity mismatch')
   no_xattr(fd)
  except BaseException:os.close(fd);raise
  return directory,fd,name
 except BaseException:os.close(directory);raise
def handle(req,input_stream=None,output_stream=None):
 input_stream=input_stream or sys.stdin.buffer;output_stream=output_stream or sys.stdout.buffer
 op=req.get('operation');root=valid_path(req['root']);target=valid_path(req['path']);blocked=[valid_path(x) for x in req.get('blockedPaths',[])]
 if not within(target,root) or protected(target,blocked) or protected(root,blocked):raise Denied('protected path or outside authorized root')
 expired(req)
 rootfd=openat2(-100,root,os.O_RDONLY|os.O_DIRECTORY,root=True)
 try:
  relative=os.path.relpath(target,root)
  if op=='mkdir':
   parts=[] if relative=='.' else relative.split('/')
   if len(parts)>64:raise Denied('directory depth limit exceeded')
   directory=os.dup(rootfd);created=[];current=root
   try:
    for part in parts:
     expired(req);current=os.path.join(current,part)
     try:os.mkdir(part,0o700,dir_fd=directory);created.append(current);os.fsync(directory)
     except FileExistsError:pass
     child=openat2(directory,part,os.O_RDONLY|os.O_DIRECTORY);os.close(directory);directory=child
    return {'created':created,'path':target}
   finally:os.close(directory)
  if op=='manifest':
   max_entries=req.get('maxEntries',256);max_bytes=req.get('maxBytes',1024**3)
   if type(max_entries) is not int or not 1<=max_entries<=1024 or type(max_bytes) is not int or not 0<=max_bytes<=MAX_BYTES:raise Denied('invalid manifest limits')
   entries=[];total=0;visited=0
   def walk(rel,depth):
    nonlocal total,visited
    if depth>16:raise Denied('manifest depth exceeded')
    d=openat2(rootfd,rel,os.O_RDONLY|os.O_DIRECTORY)
    try:
     with os.scandir(d) as iterator:
      for entry in iterator:
       visited+=1
       if visited>max_entries*4:raise Denied('manifest directory limit exceeded')
       child=os.path.join(rel,entry.name);full=os.path.join(root,child)
       if re.fullmatch(r'\.ssh-transfer-[a-f0-9]{64}',entry.name):
        # Reserved private transport state is not artifact tree content. Still
        # reject a link or unsafe directory pretending to be that namespace.
        reserved=openat2(rootfd,child,os.O_RDONLY|os.O_DIRECTORY)
        try:
         info=os.fstat(reserved)
         if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise Denied('unsafe reserved transfer directory')
        finally:os.close(reserved)
        continue
       if protected(full,blocked):raise Denied('manifest contains protected path')
       info=entry.stat(follow_symlinks=False)
       if stat.S_ISDIR(info.st_mode):walk(child,depth+1)
       else:
        fd=openat2(rootfd,child,os.O_RDONLY|os.O_NONBLOCK)
        try:snap=snapshot(fd)
        finally:os.close(fd)
        total+=snap['size']
        if len(entries)>=max_entries or total>max_bytes:raise Denied('manifest limit exceeded')
        entries.append({'relativePath':os.path.relpath(full,target),'snapshot':snap})
    finally:os.close(d)
   walk(relative,0);return {'entries':entries}
  if relative=='.':raise Denied('file target cannot be authorized root')
  if op in ('inspect','target','read'):
   try:fd=openat2(rootfd,relative,os.O_RDONLY|os.O_NONBLOCK)
   except FileNotFoundError:
    if op=='target':return {'snapshot':None}
    raise
   try:
    snap=snapshot(fd)
    if op!='read':return {'snapshot':snap}
    if snap!=req.get('sourceSnapshot'):raise Denied('source changed since approval')
    offset=req.get('offset',0)
    if type(offset) is not int or not 0<=offset<=snap['size'] or digest(fd,offset)!=req.get('prefixSha256'):raise Denied('source prefix mismatch')
    position=offset
    while position<snap['size']:
     expired(req);data=os.pread(fd,min(CHUNK,snap['size']-position),position)
     if not data:raise Denied('source truncated during read')
     output_stream.write(data);position+=len(data)
    output_stream.flush()
    if metadata(regular(fd))!={k:v for k,v in snap.items() if k!='sha256'}:raise Denied('source changed during read')
    return None
   finally:os.close(fd)
  if op not in ('stage','write','commit','cleanup'):raise Denied('unknown transfer operation')
  bounded(req);parentpath,name=os.path.split(relative);parent=openat2(rootfd,parentpath or '.',os.O_RDONLY|os.O_DIRECTORY)
  try:
   if op in ('stage','commit','cleanup'):
    receipt=committed_receipt(parent,req,cleanup=op=='cleanup')
    if receipt:return receipt
   directory,fd,stage=stage_open(parent,req,create=op=='stage')
   try:
    size=regular(fd).st_size
    if op=='stage':return {'offset':size,'prefixSha256':digest(fd),'partialIdentity':identity(regular(fd))}
    if op=='write':
     if req.get('offset')!=size or digest(fd)!=req.get('prefixSha256'):raise Denied('partial prefix mismatch')
     os.lseek(fd,size,os.SEEK_SET)
     while True:
      expired(req);data=input_stream.read(min(CHUNK,req['size']-size+1))
      if not data:break
      if size+len(data)>req['size']:raise Denied('stream exceeds approved size')
      write_all(fd,data);size+=len(data)
     os.fsync(fd);return {'offset':size,'prefixSha256':digest(fd)}
    if op=='commit':
     if size!=req['size'] or digest(fd)!=req['sha256']:raise Denied('final size/digest mismatch')
     expired(req);os.fchmod(fd,req['mode']);mtime=int(req['mtimeNs']);os.utime(fd,ns=(time.time_ns(),mtime));os.fsync(fd)
     # Open pinned parent plus RENAME_NOREPLACE never replaces a racing target.
     # Recheck staging name still identifies the locked descriptor before rename.
     if identity(os.stat('data',dir_fd=directory,follow_symlinks=False))!=identity(regular(fd)):raise Denied('staging path changed')
     rename_noreplace(directory,'data',parent,name);os.fsync(parent)
     os.fsync(directory);return {'committed':True}
    os.unlink('data',dir_fd=directory);os.unlink('identity.json',dir_fd=directory);os.rmdir(stage,dir_fd=parent);return {'cleaned':True}
   finally:os.close(fd);os.close(directory)
  finally:os.close(parent)
 finally:os.close(rootfd)
def main(req):
 try:
  result=handle(req)
  if req.get('operation')!='read':sys.stdout.write(json.dumps({'ok':True,'result':result},separators=(',',':'))+'\n');sys.stdout.flush()
 except (Denied,OSError,KeyError,ValueError,TypeError) as error:
  # Never leak source contents or paths via stderr. stdout is exclusively raw for read.
  message=str(error) if isinstance(error,Denied) else 'artifact operation rejected by filesystem safety checks'
  if req.get('operation')=='read':sys.stderr.write(message+'\n')
  else:sys.stdout.write(json.dumps({'ok':False,'error':message},separators=(',',':'))+'\n');sys.stdout.flush()
  return 1
 return 0
