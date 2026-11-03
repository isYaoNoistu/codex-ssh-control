"""Linux temporary-directory tests, never a user host."""
import importlib.util, pathlib, tempfile, unittest, os, io, hashlib, time, platform
spec=importlib.util.spec_from_file_location('transfer_guard',pathlib.Path(__file__).resolve().parents[1]/'remote'/'transfer_guard.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
@unittest.skipUnless(platform.system()=='Linux','requires Linux openat2')
class Transfers(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=self.tmp.name
  self.req=dict(root=self.root,path=self.root+'/out',blockedPaths=[],token='a'*64,expiresAt=int(time.time()*1000)+60000,size=3,sha256=hashlib.sha256(b'abc').hexdigest(),mode=0o600,mtimeNs='1000000000',overwrite='never')
 def call(self,op,**kw):return g.handle(dict(self.req,operation=op,**kw),io.BytesIO(kw.pop('data',b'')),io.BytesIO())
 def test_resume_prefix_and_atomic_commit(self):
  self.assertEqual(self.call('stage')['offset'],0)
  self.call('write',offset=0,prefixSha256=hashlib.sha256(b'').hexdigest(),data=b'ab')
  state=self.call('stage');self.assertEqual(state['offset'],2)
  with self.assertRaises(g.Denied):self.call('write',offset=2,prefixSha256='0'*64,data=b'c')
  self.call('write',offset=2,prefixSha256=state['prefixSha256'],data=b'c');self.call('commit')
  self.assertEqual(pathlib.Path(self.req['path']).read_bytes(),b'abc')
  self.assertTrue(self.call('stage')['committed'])
  self.assertEqual([e['relativePath'] for e in self.call('manifest',path=self.root)['entries']],['out'])
  self.assertTrue(self.call('cleanup')['cleaned'])
 def test_existing_target_is_never_replaced(self):
  self.call('stage');self.call('write',offset=0,prefixSha256=hashlib.sha256(b'').hexdigest(),data=b'abc')
  pathlib.Path(self.req['path']).write_text('keep')
  with self.assertRaises(OSError):self.call('commit')
  self.assertEqual(pathlib.Path(self.req['path']).read_text(),'keep')
 def test_expired_or_wrong_token_does_not_commit(self):
  self.call('stage');self.call('write',offset=0,prefixSha256=hashlib.sha256(b'').hexdigest(),data=b'abc')
  with self.assertRaises(g.Denied):self.call('commit',expiresAt=0)
  with self.assertRaises((g.Denied,OSError)):self.call('commit',token='b'*64)
  self.assertFalse(os.path.exists(self.req['path']))
 def test_rejects_symlinks_hardlinks_and_source_changes(self):
  p=pathlib.Path(self.root)/'source';p.write_bytes(b'abc');os.link(p,self.root+'/hard')
  with self.assertRaises(g.Denied):self.call('inspect',path=str(p))
  os.unlink(self.root+'/hard');os.symlink(p,self.root+'/link')
  with self.assertRaises(OSError):self.call('inspect',path=self.root+'/link')
  snap=self.call('inspect',path=str(p))['snapshot'];p.write_bytes(b'def')
  with self.assertRaises(g.Denied):self.call('read',path=str(p),sourceSnapshot=snap,offset=0,prefixSha256=hashlib.sha256(b'').hexdigest())
 def test_rejects_protected_paths_and_hash_mismatch(self):
  with self.assertRaises(g.Denied):self.call('inspect',path=self.root+'/.ssh/key')
  self.call('stage');self.call('write',offset=0,prefixSha256=hashlib.sha256(b'').hexdigest(),data=b'xyz')
  with self.assertRaises(g.Denied):self.call('commit')
 def test_cleanup_rejects_replaced_partial_and_xattrs(self):
  self.call('stage');stage=pathlib.Path(self.root)/('.ssh-transfer-'+self.req['token']);(stage/'data').rename(stage/'old');(stage/'data').write_bytes(b'abc')
  with self.assertRaises(g.Denied):self.call('cleanup')
  self.assertTrue((stage/'data').exists())
  p=pathlib.Path(self.root)/'source';p.write_bytes(b'abc');os.setxattr(p,'user.test',b'value')
  with self.assertRaises(g.Denied):self.call('inspect',path=str(p))
 def test_scoped_mkdir_rejects_links_and_protected_subtrees(self):
  self.assertEqual(len(self.call('mkdir',path=self.root+'/nested/child')['created']),2)
  self.assertEqual(self.call('mkdir',path=self.root+'/nested/child')['created'],[])
  os.symlink(self.root+'/nested',self.root+'/link')
  with self.assertRaises(OSError):self.call('mkdir',path=self.root+'/link/no')
  with self.assertRaises(g.Denied):self.call('mkdir',path=self.root+'/.ssh/no')
 def test_openat2_rejects_mount_crossing(self):
  fd=g.openat2(-100,'/',os.O_RDONLY|os.O_DIRECTORY,root=True)
  try:
   with self.assertRaises(OSError):g.openat2(fd,'proc',os.O_RDONLY|os.O_DIRECTORY)
  finally:os.close(fd)
 def test_recursive_manifest_rejects_shell_configuration_subtrees(self):
  d=pathlib.Path(self.root)/'.config'/'fish';d.mkdir(parents=True);(d/'config.fish').write_text('set ordinary_config 1')
  with self.assertRaises(g.Denied):self.call('manifest',path=self.root)
 @unittest.skipUnless(os.environ.get('SSH_TRANSFER_LARGE_TEST')=='1','opt-in 500 MiB streaming acceptance')
 def test_500mib_interrupted_resume_and_download_constant_memory(self):
  import resource, json
  size=500*1024*1024;cut=173*1024*1024
  # Constant byte stream avoids a full source buffer or a benchmark source file.
  class Source:
   def __init__(self,left):self.left=left
   def read(self,n):n=min(n,self.left);self.left-=n;return b'\xa5'*n
  class Sink:
   def __init__(self):self.hash=hashlib.sha256();self.count=0
   def write(self,b):self.hash.update(b);self.count+=len(b)
   def flush(self):pass
  h=hashlib.sha256();remaining=size
  while remaining:n=min(256*1024,remaining);h.update(b'\xa5'*n);remaining-=n
  self.req.update(size=size,sha256=h.hexdigest(),expiresAt=int(time.time()*1000)+300000)
  started=time.monotonic();self.call('stage')
  g.handle(dict(self.req,operation='write',offset=0,prefixSha256=hashlib.sha256(b'').hexdigest()),Source(cut),io.BytesIO())
  checkpoint=self.call('stage');self.assertEqual(checkpoint['offset'],cut)
  g.handle(dict(self.req,operation='write',offset=cut,prefixSha256=checkpoint['prefixSha256']),Source(size-cut),io.BytesIO())
  self.call('commit');snap=self.call('inspect')['snapshot'];sink=Sink()
  g.handle(dict(self.req,operation='read',sourceSnapshot=snap,offset=0,prefixSha256=hashlib.sha256(b'').hexdigest()),io.BytesIO(),sink)
  self.assertEqual(sink.count,size);self.assertEqual(sink.hash.hexdigest(),h.hexdigest())
  rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;self.assertLess(rss,128*1024)
  print(json.dumps({'bytes':size,'interruptedAt':cut,'elapsedSeconds':round(time.monotonic()-started,3),'maxRssKiB':rss,'transport':'local Linux helper pipes, not SSH'}))
if __name__=='__main__':unittest.main()
