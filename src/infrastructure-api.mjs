export function infrastructureDefinitions(tool) {
  const str={type:'string'},number={type:'integer',minimum:0},explanation={type:'string'},hostId=str;
  const list={cursor:number,limit:{type:'integer',minimum:1,maximum:100}};
  const task={taskId:str},transfer={transferId:str};
  return [
    tool('ssh_host_key_scan','获取主机公钥候选','用户侧栏：仅扫描直接可达地址的公钥候选，不建立信任。内网主机可从控制台粘贴公钥。',{hostId,hopIndex:{type:'integer',minimum:-1,maximum:7}},['hostId'],{app:true,read:true}),
    tool('ssh_host_keys_confirm','确认主机指纹','用户核对外部渠道的SHA256指纹后固定公钥；变化会撤销旧授权。',{hostId,hopIndex:{type:'integer',minimum:-1,maximum:7},candidates:{type:'array',items:str,maxItems:16},fingerprints:{type:'array',items:str,maxItems:16},expectedCurrentFingerprints:{type:'array',items:str,maxItems:16},confirmed:{type:'boolean'}},['hostId','candidates','fingerprints','expectedCurrentFingerprints','confirmed'],{app:true}),
    tool('ssh_capabilities','检查主机能力','读取Linux、Python、路径保护和执行条件；不安装软件。',{hostId},['hostId'],{read:true}),
    tool('ssh_job_submit','提交可恢复任务','解释目的和影响；批准后后台执行，连接断开可继续。必须启用后台任务；读取和核实使用返回taskId，禁止超时重放命令。',{hostId,command:str,cwd:str,env:{type:'object',additionalProperties:{type:'string'}},shell:{type:'string',enum:['/bin/sh','/bin/bash','/bin/zsh']},timeoutSeconds:{type:'integer',minimum:1,maximum:86400},idempotencyKey:str,explanation},['hostId','command','explanation']),
    tool('ssh_job_list','查看持久任务','仅列出当前聊天的持久任务；不连接远端。',list,[],{read:true}),
    tool('ssh_job_read','读取任务增量输出','按字节游标读取当前聊天任务；refresh默认核实远端，授权失效时可用refresh:false读取已有记录。',{...task,cursor:number,limitBytes:{type:'integer',minimum:4,maximum:65536},refresh:{type:'boolean'}},['taskId'],{read:true}),
    tool('ssh_job_reconcile','核实断线任务','只查询已有任务，不重新提交命令。',task,['taskId'],{read:true}),
    tool('ssh_job_cancel','申请停止后台任务','说明目的，原生确认后请求停止验证过身份的远端进程组；已发生的效果不会回滚。',{...task,explanation},['taskId','explanation']),
    tool('ssh_transfer_prepare','核对文件传输','核对已授权的本地/远端路径并计算源摘要，返回planId供精确审批；不传输文件正文到聊天。',{hostId,direction:{type:'string',enum:['upload','download']},localPath:str,remotePath:str},['hostId','direction','localPath','remotePath'],{read:true}),
    tool('ssh_transfer_start','申请开始文件传输','展示完整源目标、大小、SHA256和期限，批准后流式传输到新文件。',{planId:str,explanation},['planId','explanation']),
    tool('ssh_transfer_manifest','规划递归目录传输','冻结目录文件清单，返回逐项准备和目录创建请求；清单本身不是写入批准。',{hostId,direction:{type:'string',enum:['upload','download']},localPath:str,remotePath:str},['hostId','direction','localPath','remotePath'],{read:true}),
    tool('ssh_transfer_mkdir','申请创建传输目录','展示完整路径并确认后，在递归写权限目录内逐级创建缺少的目录，不跟随符号链接。',{hostId,side:{type:'string',enum:['local','remote']},root:str,path:str,explanation},['hostId','side','root','path','explanation']),
    tool('ssh_transfer_list','查看文件传输', '仅列出当前聊天的传输记录和进度。',list,[],{read:true}),
    tool('ssh_transfer_read','读取传输进度','查询当前聊天传输的进度和结果；不返回二进制文件正文。',{...transfer,cursor:number},['transferId'],{read:true}),
    tool('ssh_transfer_resume','申请恢复文件传输','重新确认相同源摘要和目标，核验已传前缀后继续；源改变时拒绝。',{...transfer,explanation},['transferId','explanation']),
    tool('ssh_transfer_cancel','停止文件传输','请求停止当前聊天传输；若提交结果未知必须先核实，不声称回滚。',{...transfer,explanation},['transferId','explanation']),
    tool('ssh_transfer_cleanup','清理自有传输临时文件','确认后仅清理已结束传输的身份匹配临时文件，不删除最终制品。',{...transfer,explanation},['transferId','explanation']),
  ];
}
