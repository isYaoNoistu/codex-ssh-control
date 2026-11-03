import test from 'node:test';
import assert from 'node:assert/strict';
import { operationApprovalRequest, accessApprovalRequest } from '../src/approval-presentation.mjs';

const host={id:'example',name:'测试主机',username:'deploy',hostname:'example.invalid',port:22};
const makeApproval=patch=>({host,presentation:{summary:'停止容器：jenkins',explanation:'停止 Jenkins，关闭服务和任务调度。',cwd:'/',requestedCommand:'',command:"/usr/bin/docker stop -- 'jenkins'",operation:{kind:'action',actionId:'container.stop',args:{name:'jenkins'}},mutating:true,...patch}});
const native=request=>request._meta?.['openai/confirmation'];

function assertNative(request){
 assert.equal(request.mode,'form');
 assert.deepEqual(Object.keys(request.requestedSchema.properties),['confirm']);
 assert.deepEqual(request.requestedSchema.required,['confirm']);
 assert.equal(request.requestedSchema.properties.confirm.type,'boolean');
 assert.equal(request.requestedSchema.properties.confirm.default,false);
 const meta=native(request);assert.equal(meta.version,1);assert.equal(meta.field,'confirm');
 const p=meta.presentation;
 for(const [key,limit] of [['title',120],['triggerLabel',80],['confirmLabel',80]])assert.ok(p[key].trim().length>0&&p[key].length<=limit,key);
 if(p.fields){
  assert.ok(p.fields.length>0&&p.fields.length<=20);
  for(const field of p.fields){assert.ok(field.label.trim().length>0&&field.label.length<=120);assert.ok(field.value.trim().length>0&&field.value.length<=10000);}
 }
 if(p.sections){
  const indices=p.sections.flatMap(s=>[s.bodyField,s.captionField]);
  assert.deepEqual([...indices].sort((a,b)=>a-b),p.fields.map((_,i)=>i),'sections show every field once');
 }
 return p;
}

test('native cards separate purpose and target from full execution and keep the ordinary fallback complete',()=>{
 const request=operationApprovalRequest(makeApproval());const p=assertNative(request);
 assert.equal(p.title,'确认停止容器：jenkins');
 assert.equal(p.fields.length,4);assert.equal(p.sections.length,2);
 assert.equal(p.fields[0].label,'执行目的');assert.equal(p.fields[0].value,'停止 Jenkins，关闭服务和任务调度。');
 assert.ok(p.fields[1].value.includes('deploy@example.invalid:22'));assert.ok(p.fields[1].value.includes('工作目录：/'));
 assert.ok(p.fields[2].value.includes("/usr/bin/docker stop -- 'jenkins'"));
 assert.ok(p.fields[3].value.includes('取消'));assert.ok(p.fields[3].value.includes('收起'));
 assert.equal(p.destructive,true);
 for(const field of p.fields)assert.ok(request.message.includes(field.value),'fallback includes '+field.label);
 assert.equal(request.requestedSchema.properties.confirm.description,undefined,'no duplicated pale text in fallback');
});

test('requested and effective commands are kept verbatim in both native cards and fallback',()=>{
 const original='df -h';const effective='cd / && /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/df -h';
 const request=operationApprovalRequest(makeApproval({requestedCommand:original,command:effective}));
 const p=assertNative(request);const value=p.fields[2].value;
 assert.ok(value.includes('请求命令\n'+original+'\n\n'));assert.ok(value.includes('实际执行命令（受管模板）\n'+effective));
 const raw="printf '%s\\n' '```bash'\nprintf '%s\\n' '<script>not HTML</script>'";
 const single=operationApprovalRequest(makeApproval({requestedCommand:raw,command:raw}));
 assert.equal(assertNative(single).fields[2].value.split(raw).length,2);
 assert.equal(single.message.split(raw).length,2,'never escape or duplicate executable content');
});

test('128 KiB file data remains complete across readonly fields without splitting Unicode',()=>{
 const content='x'.repeat(9985)+'😀'+'line\n'.repeat(22000)+'\nEND_OF_EXACT_CONTENT';
 const request=operationApprovalRequest(makeApproval({command:'',cwd:'',operation:{kind:'write',path:'/srv/app/test.txt',content}}));
 const p=assertNative(request);const chunks=p.fields.filter(f=>f.label.startsWith('完整写入内容'));
 assert.ok(chunks.length>1);assert.equal(chunks.map(f=>f.value).join(''),content);
 assert.ok(request.message.includes(content));assert.ok(p.fields[1].value.includes('目标路径：/srv/app/test.txt'));
 for(const {value} of chunks){assert.doesNotMatch(value,/^[\udc00-\udfff]|[\ud800-\udbff]$/u);}
});

test('empty and whitespace-only files are explicit and complete; oversized cards use a full scrollable message',()=>{
 for(const content of ['',' \t\n'.repeat(40000)]){
  const request=operationApprovalRequest(makeApproval({command:'',cwd:'',operation:{kind:'write',path:'/srv/app/empty.txt',content}}));
  const p=assertNative(request);
  assert.ok(request.message.includes('完整写入内容（JSON 转义）\n'+JSON.stringify(content)));
  if(content.length>100000){assert.equal(p.fields,undefined);assert.equal(p.sections,undefined);}
 }
});

test('job options and host access durations remain visible without making the form editable',()=>{
 const operation={kind:'job',command:'sleep 10',cwd:'/srv/app',env:{APP_MODE:'staging'},timeoutSeconds:700,disconnectPolicy:'continue'};
 const job=operationApprovalRequest(makeApproval({command:'',requestedCommand:operation.command,cwd:operation.cwd,operation}));
 assert.ok(assertNative(job).fields[2].value.includes(JSON.stringify(operation,null,2)));
 const access=accessApprovalRequest([{host,grantMinutes:5},{host:{...host,id:'jump',name:'跳板机',sshAlias:'jump-alias'},grantMinutes:60}]);
 const p=assertNative(access);assert.equal(p.fields.length,4);assert.equal(p.sections.length,2);assert.equal(p.destructive,false);
 for(const part of ['测试主机 (example) · deploy@example.invalid:22','跳板机 (jump) · jump-alias','5 分钟','60 分钟']){assert.ok(access.message.includes(part));assert.ok(p.fields[1].value.includes(part));}
 assert.ok(p.fields[2].value.includes('修改操作仍需逐次审批'));
});

test('blank continuation chunks never cause the client to silently lose all fields',()=>{
 const content='start\n'+' '.repeat(20000)+'\nend';
 const request=operationApprovalRequest(makeApproval({command:'',operation:{kind:'write',path:'/srv/app/a',content}}));
 const p=assertNative(request);
 assert.equal(p.fields,undefined);assert.equal(p.sections,undefined);
 assert.ok(request.message.includes(content),'complete text stays in the scrollable modal fallback');
});

test('chunk boundaries preserve a surrogate pair or CRLF exactly at the field limit',()=>{
 for(const boundary of ['😀','\r\n']){
  const content='x'.repeat(9999)+boundary+'y'.repeat(25);
  const request=operationApprovalRequest(makeApproval({command:'',operation:{kind:'write',path:'/srv/app/a',content}}));
  const chunks=assertNative(request).fields.filter(f=>f.label.startsWith('完整写入内容'));
  assert.equal(chunks[0].value.length,9999);
  assert.ok(chunks[1].value.startsWith(boundary));
  assert.equal(chunks.map(f=>f.value).join(''),content);
 }
});
