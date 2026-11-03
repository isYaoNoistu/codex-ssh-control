import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parsePublicKey, fingerprintPublicKey, parseHostKeyCandidates, confirmHostKeys, buildHostKeyScanInvocation } from '../src/host-keys.mjs';

function key(seed=1) {
 const type=Buffer.from('ssh-ed25519'),blob=Buffer.alloc(4+type.length+4+32);
 blob.writeUInt32BE(type.length);type.copy(blob,4);blob.writeUInt32BE(32,4+type.length);blob.fill(seed,8+type.length);
 return `ssh-ed25519 ${blob.toString('base64')}`;
}
test('public keys are parsed structurally and fingerprinted from the wire blob',()=>{
 const value=key(),parsed=parsePublicKey(`${value} admin@console`);
 assert.equal(parsed.publicKey,value);assert.equal(parsed.type,'ssh-ed25519');
 assert.equal(fingerprintPublicKey(value),`SHA256:${createHash('sha256').update(Buffer.from(value.split(' ')[1],'base64')).digest('base64').replace(/=+$/u,'')}`);
 for(const invalid of ['ssh-ed25519 !!!','ssh-rsa '+value.split(' ')[1],value+'\nHost *',value.replace('AAAAC3','AAAAC4'),'@cert-authority '+value]) assert.throws(()=>parsePublicKey(invalid));
});
test('manual and scanned public keys remain untrusted candidates',()=>{
 const manual=parseHostKeyCandidates(key(),{source:'manual'}),scan=parseHostKeyCandidates(`# banner\n[internal]:2222 ${key()}\ninternal ${key()}`,{source:'scan'});
 assert.equal(manual[0].trusted,false);assert.equal(manual[0].source,'manual');
 assert.equal(scan.length,1);assert.equal(scan[0].publicKey,key());assert.equal(scan[0].trusted,false);
 assert.throws(()=>parseHostKeyCandidates(`internal ${key()}\nProxyCommand exec`,{source:'scan'}));
});
test('confirmation requires exact fingerprints and rejects stale or unacknowledged replacement',()=>{
 const candidates=parseHostKeyCandidates(key(2)),fingerprints=candidates.map(x=>x.fingerprint);
 assert.throws(()=>confirmHostKeys([],candidates,{fingerprints}),/确认|confirm/iu);
 assert.throws(()=>confirmHostKeys([],candidates,{confirmed:true,fingerprints:['SHA256:wrong']}));
 assert.deepEqual(confirmHostKeys([],candidates,{confirmed:true,fingerprints}),[key(2)]);
 assert.throws(()=>confirmHostKeys([key()],candidates,{confirmed:true,fingerprints}),/变更|current|旧/iu);
 assert.throws(()=>confirmHostKeys([key()],candidates,{confirmed:true,fingerprints,expectedCurrentFingerprints:[fingerprintPublicKey(key(3))]}));
 assert.deepEqual(confirmHostKeys([key()],candidates,{confirmed:true,fingerprints,expectedCurrentFingerprints:[fingerprintPublicKey(key())]}),[key(2)]);
});
test('candidate scans build only bounded explicit argv and never persist trust',()=>{
 assert.deepEqual(buildHostKeyScanInvocation({hostname:'10.0.0.2',port:2222},{platform:'win32'}),{file:'ssh-keyscan.exe',args:['-T','5','-p','2222','-t','ed25519,ecdsa,rsa','10.0.0.2']});
 for(const hostname of ['-f','a,b','a/24','$(exec)','a\nHost *','a b']) assert.throws(()=>buildHostKeyScanInvocation({hostname,port:22}));
 assert.throws(()=>buildHostKeyScanInvocation({hostname:'internal',port:0}));
});
