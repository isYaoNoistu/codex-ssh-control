"""One-shot Linux task controller. No installer, daemon, user-selected PID or state path.

The detached, finite-lifetime supervisor owns its child until waitpid, preventing PID
reuse during process-group signalling. Processes deliberately escaping the group are
outside this contract. Root and processes with the same uid are trusted.
"""
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import resource
import selectors
import signal
import stat
import sys
import time
import uuid

TERMINAL = {'completed', 'failed', 'cancelled', 'timed_out'}
CAPABILITIES = {'platform': 'linux', 'detached': True, 'processGroup': True,
                'persistent': True, 'disconnectPolicies': ['continue'], 'pty': False}


def checked(fd, directory=False):
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Unsafe state ownership or permissions')
    if directory:
        if not stat.S_ISDIR(info.st_mode): raise ValueError('Not a state directory')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Not a private regular state file')
    return fd


def directory(parent, name, create=False):
    if create:
        try: os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError: pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try: return checked(fd, True)
    except BaseException:
        os.close(fd)
        raise


def open_file(fd, name, flags=os.O_RDONLY):
    result = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
    try: return checked(result)
    except BaseException:
        os.close(result)
        raise


def read_json(fd, name):
    try:
        with os.fdopen(open_file(fd, name), 'r') as stream:
            data=stream.read(131073)
            if len(data)>131072: raise ValueError('State exceeds limit')
            return json.loads(data)
    except FileNotFoundError: return None


def atomic(fd, name, value):
    tmp = '.tmp-' + uuid.uuid4().hex
    f = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(f, 'w') as stream:
            json.dump(value, stream, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try: os.unlink(tmp, dir_fd=fd)
        except FileNotFoundError: pass


def proc_identity(pid):
    try:
        with open('/proc/%d/stat' % pid) as stream: raw=stream.read()
        fields=raw[raw.rfind(')')+2:].split()
        return {'pid':pid, 'pgid':int(fields[2]), 'starttime':fields[19]}
    except (FileNotFoundError, ProcessLookupError): return None


def signal_verified(identity, sig):
    if not identity or identity.get('pid', 0)<=1 or identity.get('pgid')!=identity.get('pid'):
        return False
    if proc_identity(identity['pid'])!=identity: return False
    try: os.killpg(identity['pgid'], sig)
    except ProcessLookupError: return False
    return True


def spec_valid(spec):
    if not isinstance(spec, dict): raise ValueError('Invalid task spec')
    required={'command','cwd','env','shell','timeoutSeconds','disconnectPolicy','maxOutputBytes'}
    if not required.issubset(spec) or set(spec)-required-{'cpuSeconds','maxMemoryMiB','maxProcesses'}: raise ValueError('Invalid spec fields')
    if not isinstance(spec['command'],str) or not spec['command'].strip() or len(spec['command'])>16000 or '\0' in spec['command']: raise ValueError('Invalid command')
    if not isinstance(spec['cwd'],str) or not spec['cwd'].startswith('/') or len(spec['cwd'])>4096 or re.search(r'[\0\r\n]',spec['cwd']): raise ValueError('Invalid cwd')
    if spec['shell'] not in ('/bin/sh','/bin/bash','/bin/zsh') or not os.access(spec['shell'],os.X_OK): raise ValueError('Requested shell is unavailable')
    if type(spec['timeoutSeconds']) is not int or not 1<=spec['timeoutSeconds']<=86400: raise ValueError('Invalid timeout')
    if type(spec['maxOutputBytes']) is not int or not 1024<=spec['maxOutputBytes']<=1048576: raise ValueError('Invalid log limit')
    if spec['disconnectPolicy']!='continue': raise ValueError('Unsupported disconnect policy')
    for key,maximum in {'cpuSeconds':86400,'maxMemoryMiB':1048576,'maxProcesses':65536}.items():
        if key in spec and (type(spec[key]) is not int or not 1<=spec[key]<=maximum): raise ValueError('Invalid resource limit')
    if not isinstance(spec['env'],dict) or len(spec['env'])>64: raise ValueError('Invalid env')
    for key,value in spec['env'].items():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',key) or re.fullmatch(r'(PATH|HOME|SHELL|ENV|BASH_ENV|IFS|CDPATH|GLOBIGNORE|SHELLOPTS|BASHOPTS|ZDOTDIR|LD_.*|DYLD_.*|PYTHON.*|NODE.*|PERL.*|RUBY.*|SSH_.*)',key,re.I) or not isinstance(value,str) or len(value)>8192 or '\0' in value: raise ValueError('Invalid or unsafe env')
    return spec


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def detached(fd):
    os.setsid()
    # Close every inherited SSH descriptor, including stdio and lock handles.
    for entry in os.listdir('/proc/self/fd'):
        number=int(entry)
        if number != fd:
            try: os.close(number)
            except OSError: pass
    null=os.open('/dev/null',os.O_RDWR)
    for number in (0,1,2): os.dup2(null,number)
    if null>2: os.close(null)


def supervise(fd, spec):
    child=None
    try:
        detached(fd)
        atomic(fd,'supervisor.json',proc_identity(os.getpid()))
        logfd=open_file(fd,'output',os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        output_read, output_write=os.pipe()
        gate_read, gate_write=os.pipe()
        ready_read, ready_write=os.pipe()
        child=os.fork()
        if child==0:
            try:
                os.close(gate_write);os.close(ready_read);os.close(output_read);os.close(logfd)
                os.setsid()
                os.dup2(output_write,1);os.dup2(output_write,2)
                os.close(output_write)
                os.write(ready_write,b'1');os.close(ready_write)
                if os.read(gate_read,1)!=b'1': os._exit(125)
                os.close(gate_read);os.close(fd)
                os.chdir(spec['cwd'])
                for key,kind,multiplier in (('cpuSeconds',resource.RLIMIT_CPU,1),('maxMemoryMiB',resource.RLIMIT_AS,1048576),('maxProcesses',resource.RLIMIT_NPROC,1)):
                    if key in spec:
                        value=spec[key]*multiplier
                        resource.setrlimit(kind,(value,value))
                env=dict(os.environ);env.update(spec['env'])
                os.execve(spec['shell'],[spec['shell'],'-c',spec['command']],env)
            except BaseException:
                os.write(2,b'Task launch failed\n');os._exit(126)
        os.close(gate_read);os.close(ready_write);os.close(output_write)
        ready=os.read(ready_read,1);os.close(ready_read)
        if ready!=b'1': raise ValueError('Child did not initialize')
        identity=proc_identity(child)
        if not identity or identity['pgid']!=child: raise ValueError('Child identity unavailable')
        state={'status':'running','exitCode':None,'signal':None,'terminationReason':None,'truncated':False,'cancelRequested':False,'process':identity}
        atomic(fd,'state.json',state)
        os.write(gate_write,b'1');os.close(gate_write)
        os.set_blocking(output_read,False)
        selector=selectors.DefaultSelector();selector.register(output_read,selectors.EVENT_READ)
        started=time.monotonic();reason=None;sent=None;written=0;exited=False;eof=False
        while True:
            now=time.monotonic()
            cancelled=read_json(fd,'cancel.json') is not None
            if reason is None and (cancelled or now-started>=spec['timeoutSeconds']):
                reason='cancel_requested' if cancelled else 'timeout'
                state['cancelRequested']=cancelled
                if signal_verified(identity,signal.SIGTERM): sent=now
                else: reason='identity_lost'
            if sent is not None and now-sent>=.5:
                signal_verified(identity,signal.SIGKILL)
            for key,_ in selector.select(.05):
                try: data=os.read(output_read,65536)
                except BlockingIOError: continue
                if not data:
                    selector.unregister(output_read);eof=True
                else:
                    room=max(0,spec['maxOutputBytes']-written)
                    kept=data[:room]
                    if kept: os.write(logfd,kept);written+=len(kept)
                    if len(data)>room: state['truncated']=True
            if not exited:
                # WNOWAIT keeps the leader PID allocated while signals target its process group.
                exited=os.waitid(os.P_PID,child,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None
                if exited:
                    signal_verified(identity,signal.SIGKILL)
                    ended=time.monotonic()
            if exited and (eof or time.monotonic()-ended>.5): break
        _,wait_status=os.waitpid(child,0)
        child=None
        # waitstatus_to_exitcode was only introduced in Python 3.9.
        if os.WIFEXITED(wait_status): code=os.WEXITSTATUS(wait_status)
        elif os.WIFSIGNALED(wait_status): code=-os.WTERMSIG(wait_status)
        else: raise ValueError('Child did not exit')
        state.update(status=('cancelled' if reason=='cancel_requested' else 'timed_out' if reason=='timeout' else 'failed' if reason=='identity_lost' or code!=0 else 'completed'),exitCode=code if code>=0 else None,signal=-code if code<0 else None,terminationReason=reason or 'exit')
        os.fsync(logfd);os.close(logfd);os.close(output_read);selector.close()
        atomic(fd,'state.json',state)
    except BaseException:
        if child:
            identity=proc_identity(child)
            signal_verified(identity,signal.SIGKILL)
            # This is still our unreaped direct child even if setsid initialization failed.
            try: os.kill(child,signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(child,0)
            except OSError: pass
        try: atomic(fd,'state.json',{'status':'failed','exitCode':None,'terminationReason':'launch_failed','log':''})
        except BaseException: pass
    finally: os._exit(0)


def snapshot(fd):
    cancelled_before_submit=(read_json(fd,'identity.json') or {}).get('cancelledBeforeSubmit') is True
    state=read_json(fd,'state.json') or {'status':'submitted','exitCode':None}
    if cancelled_before_submit:
        state={'status':'cancelled','exitCode':None,'signal':None,'terminationReason':'cancel_requested'}
    if state['status'] not in TERMINAL:
        supervisor=read_json(fd,'supervisor.json')
        if supervisor and proc_identity(supervisor['pid'])!=supervisor:
            state.update(status='unknown',terminationReason='supervisor_lost')
    state.pop('process',None)
    state['cancelRequested']=cancelled_before_submit or read_json(fd,'cancel.json') is not None
    try:
        with os.fdopen(open_file(fd,'output'),'rb') as stream: data=stream.read(1048577)
        if len(data)>1048576: raise ValueError('Log exceeds limit')
    except FileNotFoundError: data=b''
    state['log']=base64.b64encode(data).decode()
    state['capabilities']=CAPABILITIES
    return state


def control(payload):
    if not sys.platform.startswith('linux'): raise ValueError('Linux is required')
    if set(payload)-{'action','id','token','spec'}: raise ValueError('Unsupported request fields')
    action=payload.get('action');task=payload.get('id');token=payload.get('token')
    if action not in ('submit','read','cancel') or not isinstance(task,str) or not re.fullmatch('[a-f0-9]{32}',task) or not isinstance(token,str) or not re.fullmatch('[a-f0-9]{64}',token): raise ValueError('Invalid task identity')
    spec=spec_valid(payload.get('spec')) if action=='submit' else None
    root=None;fd=None;lock=None
    try:
        # /tmp is OS-owned; uid-specific directory is never followed through a link.
        tmp=os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        create=action in ('submit','cancel')
        try: root=directory(tmp,'codex-ssh-tasks-'+str(os.getuid()),create)
        finally: os.close(tmp)
        fd=directory(root,task,create)
        lock=open_file(fd,'lock',os.O_RDWR|(os.O_CREAT if create else 0))
        fcntl.flock(lock,fcntl.LOCK_EX)
        identity=read_json(fd,'identity.json')
        token_hash=hashlib.sha256(token.encode()).hexdigest()
        if identity:
            if not hmac.compare_digest(identity['tokenHash'],token_hash): raise ValueError('Task token mismatch')
            if identity.get('cancelledBeforeSubmit') is True: return snapshot(fd)
            if spec is not None and identity['specHash']!=digest(spec): raise ValueError('Task immutable spec mismatch')
        elif action=='cancel':
            # Bind cancellation before any submit arrives. The identity itself is
            # the tombstone, so a crash before writing state cannot permit launch.
            atomic(fd,'identity.json',{'tokenHash':token_hash,'specHash':None,'cancelledBeforeSubmit':True})
            atomic(fd,'cancel.json',{'requestedAt':time.time()})
            atomic(fd,'state.json',{'status':'cancelled','exitCode':None,'signal':None,'terminationReason':'cancel_requested'})
            return snapshot(fd)
        elif action!='submit': raise ValueError('Incomplete task identity; cannot adopt or replay')
        else:
            atomic(fd,'identity.json',{'tokenHash':token_hash,'specHash':digest(spec)})
            atomic(fd,'state.json',{'status':'submitted','exitCode':None})
            child=os.fork()
            if child==0: supervise(fd,spec)
        if action=='cancel' and (read_json(fd,'state.json') or {}).get('status') not in TERMINAL:
            atomic(fd,'cancel.json',{'requestedAt':time.time()})
        return snapshot(fd)
    except FileNotFoundError:
        if action!='submit': return {'status':'missing','exitCode':None,'log':'','capabilities':CAPABILITIES}
        raise
    finally:
        for handle in (lock,fd,root):
            if handle is not None: os.close(handle)


def main():
    try:
        raw=sys.stdin.buffer.read(131073)
        if len(raw)>131072: raise ValueError('Request exceeds limit')
        response=control(json.loads(raw))
    except BaseException as error:
        response={'error':str(error)[:240]}
    print(json.dumps(response,separators=(',',':')))


if __name__=='__main__': main()
