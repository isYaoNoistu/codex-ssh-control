import test from 'node:test';
import assert from 'node:assert/strict';
import { operationApprovalRequest, accessApprovalRequest } from '../src/approval-presentation.mjs';

const host={id:'example',name:'测试主机',username:'deploy',hostname:'example.invalid',port:22};
const makeApproval=patch=>({host,presentation:{summary:'启动容器：jenkins',explanation:'启动 Jenkins，恢复现有服务。',cwd:'/',requestedCommand:'',command:"/usr/bin/docker start -- 'jenkins'",operation:{kind:'action',actionId:'container.start',args:{name:'jenkins'}},...patch}});

test('purpose is the native heading, immutable details use the normal-weight description',()=>{
 const request=operationApprovalRequest(makeApproval());
 assert.equal(request.mode,'form');
 assert.equal(request.message,'执行目的\n启动 Jenkins，恢复现有服务。');
 const {confirm}=request.requestedSchema.properties;
 assert.equal(confirm.type,'boolean');assert.equal(confirm.default,false);
 assert.deepEqual(request.requestedSchema.required,['confirm']);
 assert.deepEqual(Object.keys(request.requestedSchema.properties),['confirm']);
 assert.ok(confirm.description.includes('deploy@example.invalid:22'));
 assert.ok(confirm.description.includes('工作目录：/'));
 assert.ok(confirm.description.includes("/usr/bin/docker start -- 'jenkins'"));
 assert.ok(confirm.description.indexOf('目标主机')<confirm.description.indexOf('/usr/bin/docker'));
 assert.equal(request._meta,undefined,'keep immediate confirmation, do not add a chip/modal step');
 assert.doesNotMatch(confirm.description,/```bash/,'plain-text host must not receive Markdown decoration');
});

test('requested and effective commands are preserved exactly in separate sections',()=>{
 const original='df -h';const effective='cd / && /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/df -h';
 const request=operationApprovalRequest(makeApproval({requestedCommand:original,command:effective}));
 const body=request.requestedSchema.properties.confirm.description;
 assert.ok(body.includes('请求命令\n'+original+'\n\n'));
 assert.ok(body.includes('实际执行命令（受管模板）\n'+effective+'\n\n'));
 const raw="printf '%s\\n' '```bash'\nprintf '%s\\n' '<script>not HTML</script>'";
 const single=operationApprovalRequest(makeApproval({requestedCommand:raw,command:raw}));
 assert.equal(single.requestedSchema.properties.confirm.description.split(raw).length,2,'same command is displayed only once without escaping or reformatting');
});

test('large write content and complete execution options are not truncated or made editable',()=>{
 const content='line\n'.repeat(22000)+'\nEND_OF_EXACT_CONTENT';
 const write=operationApprovalRequest(makeApproval({command:'',cwd:'',operation:{kind:'write',path:'/srv/app/test.txt',content}}));
 assert.ok(write.requestedSchema.properties.confirm.description.includes(content));
 assert.ok(write.requestedSchema.properties.confirm.description.includes('目标路径：/srv/app/test.txt'));
 assert.ok(!write.requestedSchema.properties.confirm.description.includes('工作目录：\n'));
 const operation={kind:'job',command:'sleep 10',cwd:'/srv/app',env:{APP_MODE:'staging'},timeoutSeconds:700,disconnectPolicy:'continue'};
 const job=operationApprovalRequest(makeApproval({command:'',requestedCommand:operation.command,cwd:operation.cwd,operation}));
 assert.ok(job.requestedSchema.properties.confirm.description.includes(JSON.stringify(operation,null,2)));
 assert.deepEqual(Object.keys(write.requestedSchema.properties),['confirm']);
});

test('host access has a short heading and retains each exact target and grant duration',()=>{
 const request=accessApprovalRequest([{host,grantMinutes:5},{host:{...host,id:'jump',name:'跳板机',sshAlias:'jump-alias'},grantMinutes:60}]);
 assert.equal(request.message,'授权当前聊天访问 SSH 主机');
 const confirm=request.requestedSchema.properties.confirm;
 assert.equal(confirm.default,false);
 assert.ok(confirm.description.includes('测试主机 (example) · deploy@example.invalid:22'));
 assert.ok(confirm.description.includes('跳板机 (jump) · jump-alias'));
 assert.ok(confirm.description.includes('5 分钟'));assert.ok(confirm.description.includes('60 分钟'));
 assert.ok(confirm.description.includes('修改操作仍需逐次审批'));
});
