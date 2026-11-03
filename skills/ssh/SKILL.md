---
name: ssh
description: Use when the user explicitly asks to open codex-ssh-control, manage its hosts, authorize hosts for this chat, or inspect its SSH access state.
---

# codex-ssh-control

先发现 codex-ssh-control MCP 工具。管理主机或打开控制面板时调用 `ssh_manager({})`；查看本聊天可控制主机时调用 `ssh_status({})`。

## 本聊天授权

- 用户整行发送 `/ssh-prod /ssh-uat` 或 `$ssh-prod $ssh-uat`，且 UserPromptSubmit hook 明确报告已记录本轮快捷指令时，调用一次 `ssh_authorization_sync({})`。这是添加授权，保留已有主机。
- `/ssh-revoke-prod /ssh-revoke-uat` 撤销指定主机；`/ssh-status` 查看状态。收到 hook 的本轮意图提示后同样调用 `ssh_authorization_sync({})`。
- 从结构化 skill picker 选择某台主机、hook 未受信任、或没有明确文本意图时，先调用 `ssh_status({})` 核对本聊天状态和主机目录；尚未授权时调用 `ssh_request_access({"hostIds":["prod"]})`，由原生确认界面取得授权。主机 ID 必须来自用户明确选择和工具返回的主机目录。
- 仅在成功返回的 `grantedHostIds` 中确认授权。取消、失败或意图过期时说明尚未完成。加载技能、模型推断、聊天历史或父聊天授权都不能代替本聊天的确认。
- 不构造或传入 threadId/sessionId，不读取或修改授权数据库，不通过本地 SSH 绕过插件。工具根据宿主身份执行校验；fork 和子代理需要各自授权。

## 远程操作

用户明确请求操作后先用 `ssh_permissions({hostId})` 查看规则与固定操作目录，优先用 `ssh_run_action` 查询状态或申请服务/容器操作。文件使用 `ssh_list_directory`、`ssh_read_file`、`ssh_write_file`、`ssh_delete_file`。默认没有目录访问权；目录只能由用户在侧栏可视化配置。`ssh_exec` 在默认模式下只接受少量精确匹配的状态查询别名。

执行前先在聊天说明具体目的、目标和预期影响，再把同样清楚的说明放入 `explanation`。`ssh_exec`、`ssh_run_action`、`ssh_write_file`、`ssh_delete_file` 必须提供这个参数；读取、列目录和连接测试可使用可信的固定操作说明。例如重启应用服务应说明“让刚更新的应用配置生效；重启期间服务会短暂中断”，不能只写“执行命令”。说明不授予权限。

聊天说明按以下顺序分区，不把目的、主机和命令拼成一个长段落：用以 **执行目的** 开头的引用块说明目的和影响；下一段单独列出目标主机、操作和工作目录；已知的原始 Shell 命令用 `bash` 围栏代码块原样显示。受管操作只展示已核实的操作名和参数，不猜测插件生成的命令；实际完整命令由确认框展示。文件内容用独立的文本代码块。`explanation` 仍提交普通文本，不加 Markdown 标记。聊天展示不代表批准，不另发一个聊天确认问题。

需要批准时，工具在当前调用内弹出原生确认：先展示目的，再展示请求的原命令和实际完整命令、主机、工作目录；文件操作显示路径和完整写入内容。用户确认后同一调用自动继续，只根据实际返回的任务或结果报告状态。审批拒绝、审批取消、审批超时或宿主不支持原生确认时，说明尚未执行。执行已经启动后的超时或断线只能说明结果尚未确认，不能说没有执行，也不能自动重放。不能自行批准、读取 UI token、修改数据库、改用本地 SSH/别的工具或改写命令来绕过拒绝。敏感路径和凭据不能通过审批解除保护。

授权有有效期，保存策略或连接信息、禁用、撤销会使相关授权/审批失效。仅授权不会执行命令。多台主机可同时授权，每次操作指定 `hostId`。异步命令用 `ssh_task_read` 查看，用 `ssh_task_cancel` 取消；取消不保证远端后台进程已结束。

## 长任务与制品传输

预计数分钟的命令使用 `ssh_job_submit({hostId,command,cwd,explanation,idempotencyKey})`，不要套入短时 `ssh_exec`。后台任务和原始 Shell 必须分别由用户在权限表单启用；未启用就报告所缺权限，不绕过。`idempotencyKey` 为该次意图生成后保持不变，不能在未知结果时换 key 重交。返回 `job.id` 后，用 `ssh_job_read({taskId:job.id,cursor:0})` 查询；后续传回 `nextCursor` 获取增量。只有 `status:"completed"`、`observation:"confirmed"` 且 `exitCode:0` 才能启动依赖它的下一步，例如 pull 成功后再提交 up。`unknown` 或断线用 `ssh_job_reconcile({taskId})` 核实原任务，不重提交；如已失去聊天授权，`refresh:false` 只能读本机已有记录。停止用 `ssh_job_cancel({taskId,explanation})` 原生批准后请求终止。取消与撤销均不能回滚既有副作用。

二进制文件用 `ssh_transfer_prepare({hostId,direction:"upload"或"download",localPath,remotePath})`，两端均须有对应目录权限并启用制品传输；当前本机需 Windows 或 Linux。核对返回的源目标、大小、SHA256、期限，再调用 `ssh_transfer_start({planId,explanation})` 请求批准。不要把二进制内容塞进聊天或文本写入工具。`ssh_transfer_read({transferId})` 查进度，`ssh_transfer_resume({transferId,explanation})` 重新批准并核验相同源与前缀后续传。源变化应重新准备新计划；只有 completed 才报告成功。`commit_unknown` 表示提交结果未知，不能换目标重传或宣称回滚。暂停后用户可申请恢复核实原计划；清理仅用 `ssh_transfer_cleanup({transferId,explanation})` 清理其自有临时文件。

目录使用 `ssh_transfer_manifest` 获取有限清单；清单不是写入批准。按 `directoryRequests` 用 `ssh_transfer_mkdir({hostId,side,root,path,explanation})` 逐项申请目录，再逐文件 prepare/start。只传各工具 schema 接受的字段，不把整份 manifest 请求照搬。制品目标必须是新路径；不支持覆盖已有制品、空目录镜像、owner/group/ACL迁移。需要 SFTP/SCP 协议、PTY、密码或密钥轮换时说明当前未提供，不编造工具。

用户可在 `ssh_manager` 的主机详情页切换“连接设置”和“权限设置”；“执行历史”紧邻“审计”，展示操作说明、完整命令和经过敏感检查的输出。历史每条输出最多 32 KiB，保留最近 500 条已结束记录且不超过 30 天；文件正文不写入历史，升级前的输出无法补回。历史查询属于用户界面功能，不读取 UI token 代用户调用。

每次授权、撤销或操作后，用工具返回的清单简短提醒当前可控制主机。主机禁用或连接配置改变后，重新读取状态，不使用旧结果判断权限。

如 `/ssh-*` 被客户端拦截，改用整行 `$ssh-*`。如快捷指令无法同步，让用户在 `ssh_manager` 面板授权，或按其明确要求调用 `ssh_request_access` 进行原生确认。
