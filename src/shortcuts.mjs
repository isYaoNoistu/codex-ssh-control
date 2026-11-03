const HOST_ID = /^[a-z][a-z0-9-]{0,47}$/;

function validHostId(id) {
  return typeof id === 'string' && HOST_ID.test(id) && id !== 'status' && !id.startsWith('revoke-');
}

export function parseShortcut(prompt) {
  if (typeof prompt !== 'string' || prompt.length > 8192) return null;
  const line = prompt.trim();
  if (!line) return null;
  const tokens = line.split(/[ \t]+/);
  if (tokens.length === 1 && /^[/$]ssh-status$/.test(tokens[0])) {
    return { operation: 'status', hostIds: [] };
  }
  let operation;
  const hostIds = [];
  for (const token of tokens) {
    const match = /^[/$]ssh-([a-z][a-z0-9-]*)$/.exec(token);
    if (!match) return null;
    const isRevoke = match[1].startsWith('revoke-');
    const currentOperation = isRevoke ? 'revoke' : 'grant';
    const id = isRevoke ? match[1].slice(7) : match[1];
    if (!validHostId(id) || (operation && operation !== currentOperation)) return null;
    operation = currentOperation;
    hostIds.push(id);
  }
  return { operation, hostIds: [...new Set(hostIds)] };
}

export const EXPLICIT_SKILL_POLICY = 'policy:\n  allow_implicit_invocation: false\n';

export function renderHostSkill(host) {
  const id = host?.id;
  if (!validHostId(id)) throw new Error('主机 ID 无效，无法生成快捷技能。');
  return `---
name: ssh-${id}
description: Use when the user explicitly selects the SSH host ${id} for this chat or invokes its SSH shortcut.
---

# SSH 主机 ${id}

此技能只处理本聊天的主机选择和授权。先发现 codex-ssh-control MCP 工具。

- 用户整行输入 \`/ssh-${id}\` 或 \`$ssh-${id}\`，且 UserPromptSubmit hook 明确报告已记录本轮快捷指令时，调用 \`ssh_authorization_sync({})\`。一次输入多台时也只同步一次，保留已有授权。
- 从结构化 skill picker 选择本技能，或没有 hook 的文本意图记录时，先调用 \`ssh_status({})\`。若返回清单尚未授权此主机，调用 \`ssh_request_access({"hostIds":["${id}"]})\`，由原生确认界面取得授权。取消或失败就停止授权流程。
- 只根据工具成功返回的 \`grantedHostIds\` 告知当前可控制主机；加载技能、旧聊天内容、父聊天的授权都不代表本聊天已经授权。
- 不构造或传入 threadId/sessionId，不自行假定授权，不读取数据库或用本地 ssh 绕过插件校验。授权身份由宿主元数据确定。
- 授权后不要自动执行远程命令。用户随后明确请求操作时使用 codex-ssh-control 工具，并指定 \`hostId: "${id}"\`。
- 操作前查看 \`ssh_permissions\`，优先用 \`ssh_run_action\` 和受管文件工具。先在聊天说明具体目的、目标和影响，并在命令、固定操作、写入或删除工具的 \`explanation\` 参数中提交这段说明。非敏感状态查询按策略自动通过；需要批准时工具弹出原生确认，先显示说明再显示原命令及实际完整命令；用户确认后同一调用自动继续。拒绝、取消、超时或不支持原生确认时不执行，不能自行批准或绕过。授权限时有效，规则变化后须重新授权。
- 用户在主机详情页切换连接与权限设置；执行历史位于审计旁，显示说明、完整命令及经过敏感检查的结果。历史不保存文件正文，旧版未保存的输出无法补回；查询历史属于用户界面功能，不读取 UI token 代用户调用。
- 查看状态用 \`ssh_status({})\`；撤销可让用户整行发送 \`/ssh-revoke-${id}\`，或在 \`ssh_manager({})\` 面板中撤销。

如果同步失败、意图过期或缺少身份，说明授权尚未完成。用户仍明确要求授权时可调用 \`ssh_request_access\` 完成原生确认；不得把失败当作批准。
`;
}
