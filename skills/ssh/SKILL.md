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

需要批准时，工具在当前调用内弹出原生确认：先展示目的，再展示请求的原命令和实际完整命令、主机、工作目录；文件操作显示路径和完整写入内容。用户确认后同一调用自动继续，只根据实际返回的任务或结果报告状态。拒绝、取消、超时或宿主不支持原生确认时，明确说明操作未执行。不能自行批准、读取 UI token、修改数据库、改用本地 SSH/别的工具或改写命令来绕过拒绝。敏感路径和凭据不能通过审批解除保护。

授权有有效期，保存策略或连接信息、禁用、撤销会使相关授权/审批失效。仅授权不会执行命令。多台主机可同时授权，每次操作指定 `hostId`。异步命令用 `ssh_task_read` 查看，用 `ssh_task_cancel` 取消；取消不保证远端后台进程已结束。

用户可在 `ssh_manager` 的主机详情页切换“连接设置”和“权限设置”；“执行历史”紧邻“审计”，展示操作说明、完整命令和经过敏感检查的输出。历史每条输出最多 32 KiB，保留最近 500 条已结束记录且不超过 30 天；文件正文不写入历史，升级前的输出无法补回。历史查询属于用户界面功能，不读取 UI token 代用户调用。

每次授权、撤销或操作后，用工具返回的清单简短提醒当前可控制主机。主机禁用或连接配置改变后，重新读取状态，不使用旧结果判断权限。

如 `/ssh-*` 被客户端拦截，改用整行 `$ssh-*`。如快捷指令无法同步，让用户在 `ssh_manager` 面板授权，或按其明确要求调用 `ssh_request_access` 进行原生确认。
