import { readFile } from 'node:fs/promises';
import { isSensitiveContent } from './policy.mjs';

const source = await readFile(new URL('../remote/guard.py', import.meta.url), 'utf8');
export const FILE_COMMAND = '/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/python3 -I -S -B -';

export function fileRequest(evaluation, maxOutputKiB=128) {
 if (!evaluation.file || !['list','read','write','delete'].includes(evaluation.operation.kind)) throw new Error('缺少已验证的文件操作');
 const request = {...evaluation.file,operation:evaluation.operation,limit:maxOutputKiB*1024};
 const payload=Buffer.from(JSON.stringify(request),'utf8').toString('base64');
 return {command:FILE_COMMAND,input:source+"\nmain(json.loads(base64.b64decode('"+payload+"')))\n"};
}

export function parseFileResult(task) {
 if(task.status!=='completed' || task.exitCode!==0) throw new Error('安全文件工具执行失败：请确认远端有 /usr/bin/python3 和支持 openat2 的 Linux 内核。');
 if(task.truncated) throw new Error('文件工具响应超过大小限制，未返回截断内容。');
 let data;
 try { data=JSON.parse(task.stdout); } catch { throw new Error('安全文件工具返回无效响应，未返回文件内容。'); }
 if(data?.ok!==true) throw new Error(typeof data?.error==='string'?data.error:'文件访问被拒绝。');
 if(!data.result || typeof data.result!=='object') throw new Error('文件工具响应无效');
 if(typeof data.result.content==='string' && isSensitiveContent(data.result.content)) throw new Error('文件包含敏感信息，未返回内容。');
 return data.result;
}
