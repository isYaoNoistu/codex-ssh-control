import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getLocalCapabilities, buildRemoteCapabilityProbe, parseRemoteCapabilities, classifySshError } from '../src/capabilities.mjs';

test('local binary transfer is advertised only on supported client platforms',()=>{
 for(const platform of ['linux','win32'])assert.deepEqual(getLocalCapabilities({platform}).artifactTransfer,{supported:true,platform});
 for(const platform of ['darwin','freebsd','unknown'])assert.deepEqual(getLocalCapabilities({platform}).artifactTransfer,{supported:false,platform});
});

test('local capabilities do not enable unsupported native Windows multiplexing',()=>{
 assert.equal(getLocalCapabilities({platform:'win32'}).pooling.supported,false);
 assert.match(getLocalCapabilities({platform:'win32'}).pooling.reason,/Windows/u);
 assert.equal(getLocalCapabilities({platform:'linux'}).pooling.supported,true);
 assert.equal(getLocalCapabilities({platform:'unknown'}).pooling.supported,false);
});
test('remote capability probe is read-only and parser distinguishes task and transfer prerequisites',()=>{
 const command=buildRemoteCapabilityProbe();assert.match(command,/python3/u);assert.match(command,/openat2|437/u);assert.ok(!/apt-get|pip install|sudo/u.test(command));
 const value={schemaVersion:1,os:'Linux',python:{available:true,version:'3.11.9'},openat2:{available:true,errno:null},processGroups:true};
 const parse=v=>parseRemoteCapabilities(`SSH_CONTROL_CAPABILITIES_V1=${JSON.stringify(v)}\n`);
 assert.equal(parse(value).tasksReady,true);assert.equal(parse(value).transfersReady,true);
 assert.equal(parse({...value,openat2:{available:false,errno:38}}).transfersReady,false);
 assert.equal(parse({...value,os:'Darwin'}).tasksReady,false);
 assert.equal(parse({...value,python:{available:false,version:null},openat2:{available:false,errno:null},processGroups:false}).tasksReady,false);
 assert.throws(()=>parseRemoteCapabilities('not-json'));
 assert.throws(()=>parse({...value,openat2:{available:'yes'}}));
 assert.throws(()=>parseRemoteCapabilities(`SSH_CONTROL_CAPABILITIES_V1=${JSON.stringify(value)}\nSSH_CONTROL_CAPABILITIES_V1=${JSON.stringify(value)}`));
});
test('SSH diagnostics classify key, authentication, transport and missing-client errors',()=>{
 assert.equal(classifySshError({stderr:'REMOTE HOST IDENTIFICATION HAS CHANGED!'}),'changed_host_key');
 assert.equal(classifySshError({stderr:'No ED25519 host key is known for host and you have requested strict checking.'}),'unknown_host_key');
 assert.equal(classifySshError({stderr:'Load key key: invalid format\nPermission denied'}),'key_unavailable');
 assert.equal(classifySshError({stderr:'Connection reset by peer'}),'connection_lost');
 assert.equal(classifySshError({stderr:'Permission denied (publickey)'}),'authentication_failed');
 assert.equal(classifySshError({code:'ENOENT'}),'ssh_unavailable');
 assert.equal(classifySshError({status:'timed_out'}),'network_timeout');
});

test('unknown subsystem and command availability stays unknown, old Python is not ready',()=>{
 const value={schemaVersion:1,os:'Linux',python:{available:true,version:'3.7.0'},openat2:{available:true,errno:null},processGroups:true};
 const parse=v=>parseRemoteCapabilities(`SSH_CONTROL_CAPABILITIES_V1=${JSON.stringify(v)}`);
 assert.equal(parse(value).tasksReady,false);assert.equal(parse(value).transfersReady,false);
 assert.equal(parse(value).sftp.available,null);assert.equal(parse(value).commands.docker,undefined);
 assert.throws(()=>parse({...value,commands:{docker:'yes'}}));assert.throws(()=>parse({...value,sftp:{available:'unknown'}}));
});
