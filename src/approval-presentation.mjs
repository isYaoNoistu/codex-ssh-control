// Codex Desktop renders message as a heading and the single boolean field's
// description as normal-weight, pre-wrapped text. Neither parses Markdown.
// Keep all executable details immutable and out of editable form fields.
function form(message, description, title) {
 return {
  mode:'form',message,
  requestedSchema:{type:'object',properties:{confirm:{type:'boolean',title,description,default:false}},required:['confirm']},
 };
}

function target(host) {
 return `${host.name} (${host.id}) · ${host.sshAlias || host.username+'@'+host.hostname+':'+host.port}`;
}

export function operationApprovalRequest(approval) {
 const view=approval.presentation;
 const lines=['目标主机：'+(approval.host?target(approval.host):approval.hostId),'实际操作：'+view.summary];
 if(view.cwd)lines.push('工作目录：'+view.cwd);
 if(view.operation.path)lines.push('目标路径：'+view.operation.path);
 if(view.requestedCommand)lines.push('',view.command&&view.command!==view.requestedCommand?'请求命令':'执行命令（完整内容）',view.requestedCommand);
 if(view.command&&view.command!==view.requestedCommand)lines.push('',view.requestedCommand?'实际执行命令（受管模板）':'执行命令（完整内容）',view.command);
 if(view.operation.kind==='write')lines.push('','完整写入内容',view.operation.content);
 if(['job','job_control','transfer','transfer_inspect','transfer_control','transfer_mkdir'].includes(view.operation.kind))lines.push('','完整执行选项',JSON.stringify(view.operation,null,2));
 lines.push('','本次确认','仅执行这一次操作；取消不执行。权限或授权变化后，本次确认失效。');
 return form('执行目的\n'+view.explanation,lines.join('\n'),'已核对以上内容，执行这一次操作');
}

export function accessApprovalRequest(preview) {
 const lines=['授权范围','仅当前聊天可按各主机权限策略访问；修改操作仍需逐次审批。'];
 for(const {host,grantMinutes} of preview)lines.push('','目标主机：'+target(host),'授权时长：最长 '+grantMinutes+' 分钟');
 lines.push('','确认后授予限时访问权限，不执行远程命令；取消不授权。');
 return form('授权当前聊天访问 SSH 主机',lines.join('\n'),'授权当前聊天访问以上主机');
}
