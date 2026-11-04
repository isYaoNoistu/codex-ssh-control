// Native readonly cards are a display enhancement; the required boolean and
// complete standard message remain the response contract and compatibility path.
const FIELD_LIMIT=10000;
const FIELD_COUNT=20;
const notice='仅执行这一次操作；授权或权限变化后，本次确认失效。关闭详情仅收起，不会执行；放弃操作请点“取消”。';

function splitField({label,value}) {
 const chunks=[];
 for(let start=0;start<value.length;){
  let end=Math.min(start+FIELD_LIMIT,value.length);
  if(end<value.length){
   const before=value.charCodeAt(end-1),after=value.charCodeAt(end);
   if((before>=0xd800&&before<=0xdbff&&after>=0xdc00&&after<=0xdfff)||(before===13&&after===10))end--;
  }
  chunks.push(value.slice(start,end));start=end;
 }
 return chunks.map((value,i)=>({label:chunks.length===1?label:`${label}（${i+1}/${chunks.length}，按顺序连续阅读）`,value}));
}

function form(entries,{title,triggerLabel,confirmLabel,destructive,sectionTitles}) {
 const message=entries.map(({label,value})=>label+'\n'+value).join('\n\n');
 const fields=entries.flatMap(splitField);
 const presentation={title,triggerLabel,confirmLabel,destructive};
 // The host silently drops invalid fields. Fall back explicitly to the FULL
 // message inside its scrollable dialog rather than a partial card preview.
 if(fields.length>0&&fields.length<=FIELD_COUNT&&fields.every(f=>f.value.trim())){
  presentation.fields=fields;
  if(fields.length===4)presentation.sections=[
   {title:sectionTitles[0],bodyField:0,captionField:1},
   {title:sectionTitles[1],bodyField:2,captionField:3},
  ];
 }
 return {
  mode:'form',message,
  requestedSchema:{type:'object',properties:{confirm:{type:'boolean',title:'已核对以上内容，'+confirmLabel,default:false}},required:['confirm']},
  _meta:{'openai/confirmation':{version:1,field:'confirm',presentation}},
 };
}

function target(host) {
 return `${host.name} (${host.id}) · ${host.sshAlias || host.username+'@'+host.hostname+':'+host.port}`;
}

export function operationApprovalRequest(approval) {
 const view=approval.presentation;
 const targets=['目标主机：'+(approval.host?target(approval.host):approval.hostId),'实际操作：'+view.summary];
 if(view.cwd)targets.push('工作目录：'+view.cwd);
 if(view.operation.path)targets.push('目标路径：'+view.operation.path);
 const blocks=[];
 if(view.requestedCommand)blocks.push({label:view.command&&view.command!==view.requestedCommand?'请求命令':'完整执行命令',value:view.requestedCommand});
 if(view.command&&view.command!==view.requestedCommand)blocks.push({label:view.requestedCommand?'实际执行命令（受管模板）':'完整执行命令',value:view.command});
 if(view.operation.kind==='write'){
  const content=view.operation.content;
  blocks.push(content.trim()?{label:'完整写入内容',value:content}:{label:'完整写入内容（JSON 转义）',value:JSON.stringify(content)});
 }
 if(['job','job_control','transfer','transfer_inspect','transfer_control','transfer_mkdir'].includes(view.operation.kind))blocks.push({label:'完整执行选项',value:JSON.stringify(view.operation,null,2)});
 if(!blocks.length)blocks.push({label:'完整操作',value:JSON.stringify(view.operation,null,2)});
 return form([
  {label:'执行目的',value:view.explanation},
  {label:'执行目标',value:targets.join('\n')},
  blocks.length===1?blocks[0]:{label:'完整操作内容',value:blocks.map(({label,value})=>label+'\n'+value).join('\n\n')},
  {label:'本次确认',value:notice},
 ],{title:view.summary.length<100?'确认'+view.summary:'确认远程操作',triggerLabel:'查看并确认操作',confirmLabel:'执行一次',destructive:Boolean(view.mutating),sectionTitles:['操作说明','执行内容']});
}

export function accessApprovalRequest(preview) {
 const elevated=preview.filter(item=>item.mode==='god');
 return form([
  {label:'授权目的',value:'允许当前聊天限时访问下列 SSH 主机。'},
  {label:'目标主机',value:preview.map(({host,grantMinutes})=>target(host)+'\n授权时长：最长 '+grantMinutes+' 分钟').join('\n\n')},
  {label:'操作权限',value:elevated.length?'以下主机已启用完全控制模式：'+elevated.map(({host})=>host.id).join('、')+'。授权后可以使用 SSH 账号权限读取敏感资源、修改或删除文件并执行任意 Shell，无需逐次确认。其他主机依各自策略执行。':'只读主机禁止修改；其他主机按各自策略执行，修改操作仍需逐次审批。此次授权不执行远程命令。'},
  {label:'本次确认',value:'仅授权当前聊天；授权到期需要重新确认。关闭详情仅收起；点“取消”不授权。'},
 ],{title:'确认主机授权',triggerLabel:'查看并授权主机',confirmLabel:'授权此聊天',destructive:elevated.length>0,sectionTitles:['授权范围','授权规则']});
}

export function godActivationRequest({host,policyRevision}) {
 return form([
  {label:'权限变更',value:'为此主机开启上帝模式（完全控制）。'},
  {label:'目标主机',value:target(host)+'\n当前策略版本：'+policyRevision},
  {label:'授权影响',value:'获得本主机授权的聊天可以直接运行任意 Shell，包括读取密钥和凭据、停止服务、删除文件。远端权限上限是配置的 SSH 账号。命令不再逐次询问，远端路径限制、命令禁令和固定操作名称限制不约束原始 Shell。'},
  {label:'生效范围',value:'保存时撤销旧授权并使未完成确认失效。之后每个聊天仍需获得限时授权；SSH 身份验证、审计和本地制品目录限制继续生效。'},
 ],{title:'确认开启上帝模式',triggerLabel:'查看完整授权并确认',confirmLabel:'开启上帝模式',destructive:true,sectionTitles:['主机与范围','完全控制权限']});
}
