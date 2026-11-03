export function getLocalCapabilities({platform=process.platform}={}) {
 const supported=['linux','darwin','freebsd','openbsd','netbsd'].includes(platform);
 return {platform,artifactTransfer:{supported:['linux','win32'].includes(platform),platform},pooling:{supported,reason:supported?'系统 OpenSSH 支持 ControlMaster；需可用的私有 Unix socket 路径。':platform==='win32'?'Windows 原生 OpenSSH 不支持 ControlMaster，已禁用连接池。':'此平台的 OpenSSH 连接池支持尚未验证。'},ssh:{available:null},sftp:{available:null}};
}

export function buildRemoteCapabilityProbe(){
 return `if test -x /usr/bin/python3; then /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/python3 -I -S -B - <<'SSH_CONTROL_CAPABILITY_PY'
import ctypes, errno, json, os, platform, shutil, sys
result = {"schemaVersion":1,"os":platform.system(),"python":{"available":True,"version":platform.python_version()},"openat2":{"available":False,"errno":None},"processGroups":hasattr(os,"setsid") and hasattr(os,"killpg"),"commands":{name:shutil.which(name) is not None for name in ["sh","bash","python3","tar","sha256sum","stat","timeout","setsid","systemctl","docker"]},"sftp":{"available":None,"reason":"SSH subsystem requires a separate protocol check"}}
if result["os"] == "Linux" and platform.machine().lower() in ["x86_64","amd64","aarch64","arm64","riscv64","i386","i686","armv7l","ppc64le","s390x"]:
    class How(ctypes.Structure):
        _fields_ = [("flags",ctypes.c_uint64),("mode",ctypes.c_uint64),("resolve",ctypes.c_uint64)]
    try:
        libc=ctypes.CDLL(None,use_errno=True)
        how=How(getattr(os,"O_PATH",os.O_RDONLY)|os.O_CLOEXEC,0,8)
        fd=libc.syscall(ctypes.c_long(437),ctypes.c_int(-100),ctypes.c_char_p(b"."),ctypes.byref(how),ctypes.c_size_t(ctypes.sizeof(how)))
        if fd >= 0:
            os.close(fd)
            result["openat2"]["available"]=True
        else:
            result["openat2"]["errno"]=ctypes.get_errno()
    except (OSError,AttributeError):
        result["openat2"]["available"]=False
print("SSH_CONTROL_CAPABILITIES_V1="+json.dumps(result,separators=(",",":")))
SSH_CONTROL_CAPABILITY_PY
else printf '%s\\n' 'SSH_CONTROL_CAPABILITIES_V1={"schemaVersion":1,"os":null,"python":{"available":false,"version":null},"openat2":{"available":false,"errno":null},"processGroups":false,"commands":{},"sftp":{"available":null}}'; fi`;
}
export function parseRemoteCapabilities(stdout){
 if(typeof stdout!=='string'||stdout.length>64*1024)throw new Error('能力探测输出无效。');
 const lines=stdout.split(/\r?\n/u).filter(x=>x.startsWith('SSH_CONTROL_CAPABILITIES_V1='));
 if(lines.length!==1)throw new Error('能力探测需要唯一响应。');
 let value;try{value=JSON.parse(lines[0].slice('SSH_CONTROL_CAPABILITIES_V1='.length));}catch{throw new Error('能力探测 JSON 无效。');}
 if(!value||value.schemaVersion!==1||!(typeof value.os==='string'||value.os===null)||typeof value.python?.available!=='boolean'||!(typeof value.python?.version==='string'||value.python?.version===null)||typeof value.openat2?.available!=='boolean'||!(value.openat2.errno==null||Number.isInteger(value.openat2.errno))||typeof value.processGroups!=='boolean')throw new Error('能力探测字段无效。');
 const commands=value.commands??{};if(!commands||typeof commands!=='object'||Array.isArray(commands)||Object.entries(commands).some(([key,val])=>!/^[a-z0-9_-]{1,64}$/u.test(key)||typeof val!=='boolean'))throw new Error('命令能力字段无效。');
 const sftp=value.sftp??{available:null};if(!sftp||![true,false,null].includes(sftp.available))throw new Error('SFTP 能力字段无效。');
 const version=value.python.version?.match(/^(\d+)\.(\d+)(?:\.|$)/u),pythonSupported=value.python.available&&!!version&&(Number(version[1])>3||(Number(version[1])===3&&Number(version[2])>=8));
 const tasksReady=value.os==='Linux'&&pythonSupported&&value.processGroups;
 return {...value,commands,sftp,tasksReady,transfersReady:value.os==='Linux'&&pythonSupported&&value.openat2.available};
}
export function classifySshError({stderr='',code,status}={}) {
 const text=String(stderr);
 if(code==='ENOENT')return 'ssh_unavailable';
 if(/REMOTE HOST IDENTIFICATION HAS CHANGED|Offending .* key|host key .* changed/iu.test(text))return 'changed_host_key';
 if(/No .*host key is known|Host key verification failed/iu.test(text))return 'unknown_host_key';
 if(/Load key .*:|Identity file .* not accessible|UNPROTECTED PRIVATE KEY FILE|bad permissions/iu.test(text))return 'key_unavailable';
 if(status==='timed_out'||/Connection timed out|Operation timed out/iu.test(text))return 'network_timeout';
 if(/Permission denied|Authentication failed|Too many authentication failures/iu.test(text))return 'authentication_failed';
 if(/Could not resolve hostname|Name or service not known|nodename nor servname/iu.test(text))return 'name_resolution_failed';
 if(/Connection refused/iu.test(text))return 'connection_refused';
 if(/Connection reset|Broken pipe|Connection closed|Connection to .* closed|No route to host|Network is unreachable/iu.test(text))return 'connection_lost';
 return 'unknown';
}
