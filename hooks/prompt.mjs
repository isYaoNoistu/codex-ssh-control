import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseShortcut } from '../src/shortcuts.mjs';

const INTENT_TTL_MS = 120_000;
const MAX_INPUT_BYTES = 1024 * 1024;
const IDENTITY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

function warning(message) {
  return {
    systemMessage: message,
    hookSpecificOutput: {
      hookEventName: 'UserPromptSubmit',
      additionalContext: 'SSH 快捷指令没有建立授权意图。不得声称已经授权或撤销，也不得绕过 codex-ssh-control 的身份校验。需要授权时使用 ssh_request_access 的原生确认。',
    },
  };
}

function isSubagent(input) {
  for (const key of ['agent_id', 'agentId', 'agent_type', 'agentType', 'subagent', 'subagent_id', 'subagentId', 'parent_thread_id', 'parentThreadId']) {
    if (input[key] !== undefined && input[key] !== null && input[key] !== '' && input[key] !== false) return true;
  }
  const source = input.session_source ?? input.sessionSource;
  return (typeof source === 'string' && /subagent/i.test(source))
    || (source && typeof source === 'object' && Object.keys(source).some((key) => /subagent/i.test(key)));
}

async function defaultOpenStore() {
  const { Store, resolveDataDir } = await import('../src/store.mjs');
  return new Store(resolveDataDir());
}

export async function handlePrompt(input, { now = Date.now, openStore = defaultOpenStore } = {}) {
  if (!input || typeof input !== 'object' || input.hook_event_name !== 'UserPromptSubmit') return {};
  const shortcut = parseShortcut(input.prompt);
  if (!shortcut) return {};
  if (isSubagent(input)) return warning('SSH 快捷指令未处理：子代理不能通过提示文本建立聊天授权。');
  if (typeof input.session_id !== 'string' || typeof input.turn_id !== 'string'
    || !IDENTITY.test(input.session_id) || !IDENTITY.test(input.turn_id)) {
    return warning('SSH 快捷指令未处理：缺少有效的宿主会话或轮次身份。');
  }
  let store;
  try {
    const timestamp = now();
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error('Invalid clock');
    store = await openStore();
    store.recordIntent({
      sessionId: input.session_id,
      turnId: input.turn_id,
      operation: shortcut.operation,
      hostIds: shortcut.hostIds,
      expiresAt: timestamp + INTENT_TTL_MS,
    });
    return {
      hookSpecificOutput: {
        hookEventName: 'UserPromptSubmit',
        additionalContext: 'codex-ssh-control 已记录本轮明确快捷指令，有效期 120 秒，尚未改变授权。现在调用 ssh_authorization_sync({})，由工具使用宿主身份同步本聊天。只根据成功返回的授权清单显示当前可控制主机；添加授权保留已有主机。失败不得声称成功，不要自动执行远程命令，不要传入 threadId 或 hostIds。',
      },
    };
  } catch {
    return warning('SSH 快捷指令未处理：无法记录授权意图，请在 SSH 管理面板检查主机状态后重试。');
  } finally {
    try { store?.close(); } catch { /* No authorization can be inferred from a cleanup failure. */ }
  }
}

export async function main() {
  let output;
  try {
    const chunks = [];
    let bytes = 0;
    for await (const chunk of process.stdin) {
      bytes += chunk.length;
      if (bytes > MAX_INPUT_BYTES) throw new Error('Input too large');
      chunks.push(chunk);
    }
    const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    output = await handlePrompt(input);
  } catch {
    output = warning('SSH 快捷指令未处理：hook 输入无效或过大。');
  }
  if (Object.keys(output).length) process.stdout.write(`${JSON.stringify(output)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
