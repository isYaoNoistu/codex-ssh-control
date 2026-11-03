import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import time
import unittest
import uuid

HELPER = pathlib.Path(__file__).resolve().parents[1] / 'remote' / 'task_guard.py'

@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process identity required')
class TaskGuardTest(unittest.TestCase):
    def setUp(self):
        self.id=uuid.uuid4().hex
        self.token=uuid.uuid4().hex+uuid.uuid4().hex

    def call(self, action, spec=None, token=None, python38=False):
        payload={'action':action,'id':self.id,'token':token or self.token}
        if spec is not None: payload['spec']=spec
        invocation=[sys.executable,str(HELPER)]
        if python38:
            invocation=[sys.executable,'-c',"import os,runpy; delattr(os,'waitstatus_to_exitcode') if hasattr(os,'waitstatus_to_exitcode') else None; runpy.run_path("+repr(str(HELPER))+",run_name='__main__')"]
        result=subprocess.run(invocation,input=json.dumps(payload),text=True,capture_output=True,timeout=5)
        return json.loads(result.stdout)

    def spec(self, command, **kw):
        return {'command':command,'cwd':'/tmp','env':{},'shell':'/bin/sh','timeoutSeconds':5,'disconnectPolicy':'continue','maxOutputBytes':1024,**kw}

    def finish(self):
        for _ in range(80):
            r=self.call('read')
            if r['status'] in ('completed','failed','cancelled','timed_out'): return r
            time.sleep(.05)
        self.fail('task never finished')

    def test_detached_submission_deduplicates_and_limits_log(self):
        spec=self.spec("sleep .1; python3 -c 'print(\"x\"*4000)'")
        a=self.call('submit',spec);b=self.call('submit',spec)
        self.assertNotIn('error',a);self.assertNotIn('error',b)
        done=self.finish();self.assertEqual(done['status'],'completed')
        self.assertEqual(len(base64.b64decode(done['log'])),1024);self.assertTrue(done['truncated'])
        mismatch=self.call('submit',self.spec('echo duplicate'))
        self.assertIn('error',mismatch)

    def test_token_and_invalid_identity_fail_closed(self):
        self.call('submit',self.spec('sleep .2'))
        self.assertIn('error',self.call('cancel',token='a'*64))
        self.id='../escape';self.assertIn('error',self.call('read'))

    def test_timeout_and_cancel_are_verified_terminal_results(self):
        self.call('submit',self.spec('sleep 30',timeoutSeconds=1))
        self.assertEqual(self.finish()['status'],'timed_out')
        self.id=uuid.uuid4().hex
        self.call('submit',self.spec('sleep 30'))
        self.call('cancel');self.assertEqual(self.finish()['status'],'cancelled')

    def test_read_missing_does_not_create_state(self):
        result=self.call('read');self.assertEqual(result['status'],'missing')
        root=pathlib.Path('/tmp')/('codex-ssh-tasks-'+str(os.getuid()))
        self.assertFalse((root/self.id).exists())

    def test_cancel_before_submit_is_token_bound_and_never_launches(self):
        marker=pathlib.Path('/tmp')/('cancel-marker-'+self.id)
        cancelled=self.call('cancel')
        self.assertEqual(cancelled['status'],'cancelled')
        self.assertTrue(cancelled['cancelRequested'])
        self.assertIn('error',self.call('submit',self.spec('true'),token='a'*64))
        submitted=self.call('submit',self.spec('echo unwanted > '+str(marker)))
        self.assertEqual(submitted['status'],'cancelled')
        time.sleep(.1)
        self.assertFalse(marker.exists())
        self.assertEqual(self.call('read')['terminationReason'],'cancel_requested')

    def test_cancel_tombstone_survives_incomplete_state_record(self):
        self.call('cancel')
        folder=pathlib.Path('/tmp')/('codex-ssh-tasks-'+str(os.getuid()))/self.id
        for name in ('state.json','cancel.json'):
            (folder/name).unlink(missing_ok=True)
        self.assertEqual(self.call('read')['status'],'cancelled')
        self.assertEqual(self.call('submit',self.spec('true'))['status'],'cancelled')

    def test_exit_status_works_without_python39_waitstatus_api(self):
        for command,expected_code,expected_signal in [('true',0,None),('exit 7',7,None),('kill -TERM $$',None,15)]:
            with self.subTest(command=command):
                self.id=uuid.uuid4().hex
                self.call('submit',self.spec(command),python38=True)
                done=self.finish()
                self.assertEqual(done['exitCode'],expected_code)
                self.assertEqual(done.get('signal'),expected_signal)
                self.assertEqual(done['terminationReason'],'exit')

    def test_stale_pid_identity_is_not_signalled(self):
        spec=importlib.util.spec_from_file_location('task_guard',HELPER)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertFalse(module.signal_verified({'pid':os.getpid(),'pgid':os.getpgrp(),'starttime':'0'},15))

    def test_process_resource_limits_are_applied(self):
        self.call('submit',self.spec("python3 -c 'import resource; print(resource.getrlimit(resource.RLIMIT_CPU)[0])'",cpuSeconds=3,maxMemoryMiB=128,maxProcesses=20))
        done=self.finish();self.assertEqual(done['status'],'completed')
        self.assertEqual(base64.b64decode(done['log']),b'3\n')

    def test_state_symlinks_are_not_followed(self):
        self.call('submit',self.spec('true'));self.finish()
        root=pathlib.Path('/tmp')/('codex-ssh-tasks-'+str(os.getuid()))
        self.id=uuid.uuid4().hex
        (root/self.id).symlink_to('/tmp',target_is_directory=True)
        self.assertIn('error',self.call('submit',self.spec('true')))

    def test_cancel_preserves_unrelated_process(self):
        unrelated=subprocess.Popen(['sleep','10'])
        try:
            self.call('submit',self.spec('sleep 30'))
            self.call('cancel');self.assertEqual(self.finish()['status'],'cancelled')
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate();unrelated.wait()

    def test_parallel_submission_executes_once(self):
        marker='/tmp/marker-'+self.id
        payload=json.dumps({'action':'submit','id':self.id,'token':self.token,'spec':self.spec('echo once >> '+marker)})
        processes=[subprocess.Popen([sys.executable,str(HELPER)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for _ in range(8)]
        for proc in processes:
            out,err=proc.communicate(payload,timeout=5)
            self.assertNotIn('error',json.loads(out),err)
        self.finish()
        self.assertEqual(pathlib.Path(marker).read_text(),'once\n')

    def test_state_file_symlink_and_permissive_directory_are_rejected(self):
        self.call('submit',self.spec('true'));self.finish()
        root=pathlib.Path('/tmp')/('codex-ssh-tasks-'+str(os.getuid()))
        folder=root/self.id
        (folder/'identity.json').unlink();(folder/'identity.json').symlink_to('/etc/passwd')
        self.assertIn('error',self.call('read'))
        folder.chmod(0o755)
        self.assertIn('error',self.call('cancel'))

if __name__=='__main__': unittest.main()
