import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

export function parsePublicKey(value) {
 if(typeof value!=='string'||value.length>16384||/[\r\n\0]/u.test(value))throw new Error('公钥格式无效。');
 const match=value.trim().match(/^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) ([A-Za-z0-9+/]+={0,2})(?:[ \t]+[^\r\n]*)?$/u);
 if(!match)throw new Error('不支持或无效的 SSH 公钥。');
 const [,type,encoded]=match,blob=Buffer.from(encoded,'base64');
 if(blob.toString('base64').replace(/=+$/u,'')!==encoded.replace(/=+$/u,''))throw new Error('公钥编码无效。');
 let offset=0;
 function field(){if(offset+4>blob.length)throw new Error('公钥数据不完整。');const n=blob.readUInt32BE(offset);offset+=4;if(n>blob.length-offset)throw new Error('公钥数据不完整。');const result=blob.subarray(offset,offset+n);offset+=n;return result;}
 if(field().toString()!==type)throw new Error('公钥类型与数据不一致。');
 if(type==='ssh-ed25519'){if(field().length!==32)throw new Error('Ed25519 公钥长度无效。');}
 else if(type==='ssh-rsa'){const e=field(),n=field();if(!e.length||!n.length||e[0]&128||n[0]&128||!e.some(Boolean)||!n.some(Boolean))throw new Error('RSA 公钥无效。');}
 else {const curve=type.slice('ecdsa-sha2-'.length),sizes={nistp256:65,nistp384:97,nistp521:133};if(field().toString()!==curve)throw new Error('ECDSA 曲线不一致。');const point=field();if(point.length!==sizes[curve]||point[0]!==4)throw new Error('ECDSA 公钥无效。');}
 if(offset!==blob.length)throw new Error('公钥含多余数据。');
 return {type,publicKey:`${type} ${blob.toString('base64')}`,fingerprint:`SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/u,'')}`};
}
export function fingerprintPublicKey(value){return parsePublicKey(value).fingerprint;}
export function parseHostKeyCandidates(text,{source='manual'}={}) {
 if(typeof text!=='string'||text.length>256*1024||!['manual','scan'].includes(source))throw new Error('公钥候选输入无效。');
 const result=new Map();
 for(const raw of text.split(/\r?\n/u)){const line=raw.trim();if(!line||line.startsWith('#'))continue;const publicKey=source==='scan'?line.replace(/^\S+\s+/u,''):line;const key=parsePublicKey(publicKey);result.set(key.fingerprint,{...key,source,trusted:false});}
 if(!result.size||result.size>32)throw new Error('需要 1 至 32 个公钥候选。');
 return [...result.values()];
}
function same(a,b){return Array.isArray(a)&&Array.isArray(b)&&a.length===b.length&&new Set(a).size===a.length&&[...a].sort().every((v,i)=>v===[...b].sort()[i]);}
export function confirmHostKeys(currentKeys,candidates,confirmation={}) {
 if(confirmation.confirmed!==true)throw new Error('必须明确确认公钥。');
 if(!Array.isArray(currentKeys)||!Array.isArray(candidates)||!candidates.length||candidates.length>32)throw new Error('公钥候选无效。');
 const parsed=candidates.map(candidate=>parsePublicKey(typeof candidate==='string'?candidate:candidate.publicKey));
 if(!same(confirmation.fingerprints,parsed.map(k=>k.fingerprint)))throw new Error('确认指纹必须与全部候选完全一致。');
 const old=currentKeys.map(fingerprintPublicKey),next=parsed.map(k=>k.fingerprint);
 if(old.length&&!same(old,next)&&!same(confirmation.expectedCurrentFingerprints,old))throw new Error('旧公钥已变更或缺少 current 指纹确认。');
 return parsed.map(k=>k.publicKey);
}
export function validateHostname(value){
 if(typeof value!=='string'||value.length>253||(!isIP(value)&&!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.?$/u.test(value)))throw new Error('SSH hostname 无效。');
 return value;
}
export function buildHostKeyScanInvocation({hostname,port=22},{platform=process.platform,timeoutSeconds=5}={}) {
 validateHostname(hostname);if(!Number.isInteger(port)||port<1||port>65535||!Number.isInteger(timeoutSeconds)||timeoutSeconds<1||timeoutSeconds>30)throw new Error('扫描端口或超时无效。');
 return {file:platform==='win32'?'ssh-keyscan.exe':'ssh-keyscan',args:['-T',String(timeoutSeconds),'-p',String(port),'-t','ed25519,ecdsa,rsa',hostname]};
}
