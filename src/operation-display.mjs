import { createHash } from 'node:crypto';
import { ACTION_CATALOG, normalizeOperation, resolveSafeCommand, isSensitiveContent } from './policy.mjs';

const catalog = new Map(ACTION_CATALOG.map(action => [action.id, action]));
const unsafeDisplay = /[\u0000-\u0008\u000b-\u001f\u007f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
const OUTPUT_LIMIT = 32 * 1024;
const REDACTED_TEXT = '[已隐藏可能的敏感信息]';
const REDACTED_NOTICE = '输出含有可能的凭据信息，已隐藏。';

export function normalizeExplanation(value, { required = false, fallback = '' } = {}) {
  if (value === undefined || value === null) value = fallback;
  if (typeof value !== 'string' || value.length > 1200 || unsafeDisplay.test(value)) throw new Error('操作说明须为最多 1200 字符的普通文本，不能包含控制字符或双向文本控制符');
  const normalized = value.trim();
  if (required && normalized.length < 4) throw new Error('此操作必须提供至少 4 个字符的用途说明');
  if (isSensitiveContent(normalized)) throw new Error('操作说明不能包含可识别的凭据或私钥');
  return normalized;
}

export function operationPresentation(evaluation, explanation) {
  if (!evaluation || typeof evaluation !== 'object') throw new Error('缺少已验证的操作');
  const operation = normalizeOperation(evaluation.operation);
  if(['job','job_control','transfer','transfer_inspect','transfer_control','transfer_mkdir','capabilities'].includes(operation.kind)) {
    const mutating=['job','transfer','transfer_mkdir'].includes(operation.kind)||['cancel','resume','cleanup'].includes(operation.action);
    const fallback=operation.kind==='capabilities'?'读取远端系统与文件访问能力':operation.kind==='transfer_inspect'?'核对传输两端路径和源文件摘要':'读取当前聊天任务的已有状态';
    const explanationText=normalizeExplanation(explanation,{required:mutating,fallback:mutating?'':fallback});
    if(unsafeDisplay.test(JSON.stringify(operation).replaceAll('\\n','').replaceAll('\\r','').replaceAll('\\t','')))throw new Error('操作包含无法安全展示的控制字符');
    return {summary:evaluation.summary,explanation:explanationText,requestedCommand:operation.command??'',command:evaluation.command??'',cwd:operation.cwd??'',operation,mutating};
  }
  for (const value of [operation.command, operation.cwd, operation.path, evaluation.command]) {
    if (typeof value === 'string' && unsafeDisplay.test(value)) throw new Error('命令或目标路径包含无法安全展示的控制字符或双向文本控制符');
  }
  const alias = operation.kind === 'command' ? resolveSafeCommand(operation.command) : null;
  const actionId = operation.kind === 'action' ? operation.actionId : operation.kind === 'test' ? 'connection.test' : alias?.actionId;
  const action = actionId ? catalog.get(actionId) : null;
  const raw = operation.kind === 'command' && !alias;
  const mutating = Boolean(action?.mutating || ['write', 'delete'].includes(operation.kind) || raw);
  const fileLabels = { list: '列出目录', read: '读取文件', write: '写入文件', delete: '删除文件' };
  const summary = action ? action.label + (operation.args?.name ? '：' + operation.args.name : '') : raw ? '执行完整 Shell 命令（影响由原始命令决定）' : fileLabels[operation.kind] + '：' + operation.path;
  const fallback = action?.description ?? ({ list: '列出允许目录内的非敏感文件', read: '读取允许目录内的非敏感文本文件' }[operation.kind] ?? '');
  return {
    summary,
    explanation: normalizeExplanation(explanation, { required: mutating || raw, fallback: mutating || raw ? '' : fallback }),
    requestedCommand: operation.kind === 'command' ? operation.command : '',
    command: typeof evaluation.command === 'string' ? evaluation.command : '',
    cwd: action ? '/' : raw ? operation.cwd || '(SSH默认目录)' : '',
    operation,
    mutating,
  };
}

function redactMetadata(value) {
  if (typeof value === 'string') return isSensitiveContent(value) ? REDACTED_TEXT : value;
  if (Array.isArray(value)) return value.map(redactMetadata);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redactMetadata(item)]));
  return value;
}

export function historySnapshot(evaluation, explanation, host) {
  const presentation = operationPresentation(evaluation, explanation);
  if (!host || typeof host !== 'object') throw new Error('缺少主机快照');
  const operation = presentation.operation;
  const operationSnapshot = operation.kind === 'write' ? {
    kind: 'write', path: operation.path, bytes: Buffer.byteLength(operation.content, 'utf8'), sha256: createHash('sha256').update(operation.content, 'utf8').digest('hex'),
  } : operation;
  return redactMetadata({
    summary: presentation.summary, explanation: presentation.explanation,
    requestedCommand: presentation.requestedCommand, command: presentation.command, cwd: presentation.cwd,
    operationSnapshot,
    hostSnapshot: { id: host.id, name: host.name, hostname: host.hostname, sshAlias: host.sshAlias, username: host.username, port: host.port },
  });
}

function truncateUtf8(text, maxBytes) {
  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length <= maxBytes) return text;
  let length = Math.max(0, maxBytes);
  while (length > 0 && (bytes[length] & 0xc0) === 0x80) length--;
  return bytes.subarray(0, length).toString('utf8');
}

export function sanitizeHistoryOutput({ stdout = '', stderr = '', truncated = false, sensitiveOutput = false } = {}) {
  if (typeof stdout !== 'string' || typeof stderr !== 'string' || typeof truncated !== 'boolean' || typeof sensitiveOutput !== 'boolean') throw new Error('历史输出及状态格式无效');
  const wasTruncated = truncated || Buffer.byteLength(stdout, 'utf8') + Buffer.byteLength(stderr, 'utf8') > OUTPUT_LIMIT;
  // Examine both complete supplied streams before truncation, including discarded suffixes.
  if (sensitiveOutput || isSensitiveContent(stdout) || isSensitiveContent(stderr)) return { stdout: '', stderr: '', truncated: wasTruncated, redacted: true, outputNotice: REDACTED_NOTICE };
  const keptStdout = truncateUtf8(stdout, OUTPUT_LIMIT);
  const keptStderr = truncateUtf8(stderr, OUTPUT_LIMIT - Buffer.byteLength(keptStdout, 'utf8'));
  return { stdout: keptStdout, stderr: keptStderr, truncated: wasTruncated, redacted: false, outputNotice: wasTruncated ? '输出已截断；历史最多保留合计 32 KiB。' : '' };
}

export function createOutputScanner() {
  const tails = { stdout: '', stderr: '' };
  let sensitive = false;
  return {
    push(channel, text) {
      if (!Object.hasOwn(tails, channel) || typeof text !== 'string') throw new Error('输出扫描参数无效');
      if (sensitive || !text) return;
      // Fixed-size scan windows bound memory independently of total SSH output.
      for (let offset = 0; offset < text.length; offset += 4096) {
        const combined = tails[channel] + text.slice(offset, offset + 4096);
        if (isSensitiveContent(combined)) { sensitive = true; tails.stdout = ''; tails.stderr = ''; return; }
        // Keep an unfinished credential assignment through arbitrarily long whitespace.
        // This changes only the detector tail, never the captured or executed text.
        tails[channel] = combined.replace(/\s{16,}/gu, ' ').slice(-8192);
      }
    },
    get sensitive() { return sensitive; },
  };
}
