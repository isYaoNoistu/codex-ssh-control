import { validateInfrastructurePolicy, normalizeInfrastructureOperation, evaluateInfrastructureOperation } from './infrastructure-policy.mjs';
import { INFRASTRUCTURE_DEFAULTS } from './infrastructure-defaults.mjs';
import { posix } from 'node:path';
const decisions = new Set(['allow', 'ask', 'deny']);
const nameParameter = Object.freeze({ name: 'name', label: '服务或容器名称', type: 'string', required: true });
const actionDefinitions = [
  ['connection.test', '测试连接', '验证账号、主机与系统', '诊断', false],
  ['system.summary', '系统概况', '查看主机名、系统版本与运行时间', '系统', false],
  ['disk.usage', '磁盘容量', '查看文件系统容量使用情况', '系统', false],
  ['disk.inodes', '磁盘 inode', '查看文件系统 inode 使用情况', '系统', false],
  ['memory.usage', '内存使用', '查看内存与交换空间使用情况', '系统', false],
  ['network.listeners', '监听端口', '查看监听端口，不返回进程命令行', '网络', false],
  ['docker.containers', '容器列表', '查看容器名称、镜像、状态与端口', '容器', false],
  ['docker.stats', '容器资源', '查看容器 CPU、内存与网络统计', '容器', false],
  ['docker.disk', '容器磁盘', '查看 Docker 磁盘用量', '容器', false],
  ['system.services', '系统服务', '查看服务运行状态', '服务', false],
  ['system.failed', '异常服务', '查看失败的系统服务', '服务', false],
  ['service.status', '服务状态', '查看指定服务状态，不读取环境配置或日志', '服务', false, true],
  ['service.start', '启动服务', '申请启动指定服务', '服务', true, true],
  ['service.stop', '停止服务', '申请停止指定服务', '服务', true, true],
  ['service.restart', '重启服务', '申请重启指定服务', '服务', true, true],
  ['container.start', '启动容器', '申请启动指定容器', '容器', true, true],
  ['container.stop', '停止容器', '申请停止指定容器', '容器', true, true],
  ['container.restart', '重启容器', '申请重启指定容器', '容器', true, true],
];
export const ACTION_CATALOG = Object.freeze(actionDefinitions.map(([id, label, description, category, mutating, named]) => Object.freeze({
  id, label, description, category, mutating, defaultDecision: mutating ? 'ask' : 'allow', parameters: Object.freeze(named ? [nameParameter] : []),
})));
const catalog = new Map(ACTION_CATALOG.map(action => [action.id, action]));
function freeze(value) { for (const item of Object.values(value)) if (item && typeof item === 'object') freeze(item); return Object.freeze(value); }
export const DEFAULT_POLICY = freeze({ mode: 'restricted', roots: [], blockedPaths: [], commandRules: [], actions: Object.fromEntries(ACTION_CATALOG.map(a => [a.id, a.defaultDecision])), grantMinutes: 60, timeoutSeconds: 60, maxConcurrent: 2, maxOutputKiB: 128, ...INFRASTRUCTURE_DEFAULTS });
export function defaultPolicy() { return structuredClone(DEFAULT_POLICY); }
export const CORE_PROTECTED_PATHS = Object.freeze(['/proc', '/sys', '/dev', '/run', '/etc/ssh', '/etc/ssl/private', '/etc/shadow', '/etc/gshadow', '/etc/passwd', '/etc/group', '/etc/sudoers', '/etc/sudoers.d', '/etc/pam.d', '/etc/security', '/etc/systemd', '/etc/docker', '/etc/ufw', '/etc/nftables.conf', '/etc/iptables', '/etc/firewalld', '/etc/fail2ban', '/etc/audit', '/etc/selinux', '/etc/apparmor', '/etc/apparmor.d', '/etc/environment', '/etc/profile', '/etc/profile.d', '/etc/bash.bashrc', '/etc/ld.so.preload', '/etc/ld.so.conf', '/etc/ld.so.conf.d', '/etc/fish']);
const protectedSegments = new Set(['.ssh', '.aws', '.azure', '.kube', '.gnupg', '.docker', '.bashrc', '.bash_profile', '.bash_login', '.profile', '.zshrc', '.zprofile', '.zshenv', '.zlogin']);
const securityServices = new Set(['ssh', 'sshd', 'firewall', 'ufw', 'firewalld', 'nftables', 'iptables', 'ip6tables', 'fail2ban', 'auditd', 'polkit', 'apparmor', 'selinux', 'sssd', 'systemd-logind', 'systemd-resolved', 'systemd-networkd', 'networkmanager', 'dbus', 'cron', 'crond']);
const fields = Object.keys(DEFAULT_POLICY);
function object(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(label + '必须是对象');
  for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new Error(label + '包含未知字段：' + key);
}
function string(value, label, max = 4096, allowEmpty = false) {
  if (typeof value !== 'string' || value.length > max || (!allowEmpty && !value.trim()) || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error(label + '文本无效');
  return value;
}
function slug(value) {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{0,47}$/u.test(value)) throw new Error('规则或目录 ID 必须为最多 48 字符的小写标识');
  return value;
}
function absolutePath(value) {
  string(value, '路径');
  if (!value.startsWith('/') || value.includes('\\') || value.includes('//')) throw new Error('路径必须为明确的 POSIX 绝对路径');
  const parts = value.split('/');
  if (parts.some(p => p === '..' || p === '.')) throw new Error('路径不能包含 . 或 .. 分量');
  return value.length > 1 ? value.replace(/\/$/u, '') : value;
}
function inside(path, root) { return root === '/' || path === root || path.startsWith(root + '/'); }
function unique(items, key, label) { if (new Set(items.map(key)).size !== items.length) throw new Error(label + '不能重复'); }
function list(value, label) { if (!Array.isArray(value) || value.length > 64) throw new Error(label + '最多 64 项'); return value; }
export function validatePolicy(input) {
  object(input, fields, '权限策略');
  const policy = { ...defaultPolicy(), ...input };
  if (!['restricted', 'approval'].includes(policy.mode)) throw new Error('执行模式无效');
  for (const [key, min, max] of [['grantMinutes', 5, 1440], ['timeoutSeconds', 1, 300], ['maxConcurrent', 1, 8], ['maxOutputKiB', 16, 128]]) {
    if (!Number.isInteger(policy[key]) || policy[key] < min || policy[key] > max) throw new Error(key + '超出允许范围');
  }
  policy.roots = list(policy.roots, '目录').map(root => {
    object(root, ['id', 'path', 'read', 'write', 'match'], '目录');
    if (typeof root.read !== 'boolean' || typeof root.write !== 'boolean') throw new Error('目录读写权限必须是布尔值');
    if(root.match!==undefined&&!['exact','recursive'].includes(root.match))throw new Error('目录匹配方式无效');
    return { id: slug(root.id), path: absolutePath(root.path), read: root.read, write: root.write, ...(root.match===undefined?{}:{match:root.match}) };
  });
  unique(policy.roots, r => r.id, '目录 ID'); unique(policy.roots, r => r.path, '目录路径');
  policy.blockedPaths = list(policy.blockedPaths, '禁止目录').map(absolutePath);
  unique(policy.blockedPaths, p => p, '禁止目录');
  policy.commandRules = list(policy.commandRules, '命令规则').map(rule => {
    object(rule, ['id', 'match', 'pattern', 'decision'], '命令规则');
    if (!['exact', 'prefix', 'contains'].includes(rule.match) || !['ask', 'deny'].includes(rule.decision)) throw new Error('命令规则只能申请或禁止，不支持正则');
    return { id: slug(rule.id), match: rule.match, pattern: string(rule.pattern, '匹配文本', 256), decision: rule.decision };
  });
  unique(policy.commandRules, r => r.id, '命令规则 ID');
  object(policy.actions, [...catalog.keys()], '动作权限');
  policy.actions = { ...DEFAULT_POLICY.actions, ...policy.actions };
  for (const action of ACTION_CATALOG) {
    const decision = policy.actions[action.id];
    if (!decisions.has(decision) || (action.mutating && decision === 'allow')) throw new Error(action.label + '不允许自动执行修改操作');
  }
  return {...policy,...validateInfrastructurePolicy(policy,catalog)};
}
function actionArgs(actionId, args = {}) {
  const action = catalog.get(actionId);
  if (!action) throw new Error('未知操作模板：' + actionId);
  object(args, action.parameters.map(p => p.name), '模板参数');
  if (!action.parameters.length) return {};
  if (typeof args.name !== 'string' || args.name.length > 128 || !/^[A-Za-z0-9][A-Za-z0-9_.@-]*$/u.test(args.name)) throw new Error('名称只能包含字母、数字、点、下划线、@ 和短横线，且不能以选项符开头');
  if (actionId.startsWith('container.') && !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/u.test(args.name)) throw new Error('容器名称无效');
  return { name: args.name };
}
export function normalizeOperation(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('操作必须是对象');
  const { kind } = input;
  const extended=normalizeInfrastructureOperation(input);if(extended)return extended;
  if (kind === 'test') { object(input, ['kind'], '操作'); return { kind }; }
  if (kind === 'action') { object(input, ['kind', 'actionId', 'args'], '操作'); return { kind, actionId: input.actionId, args: actionArgs(input.actionId, input.args) }; }
  if (kind === 'command') {
    object(input, ['kind', 'command', 'cwd'], '操作');
    if (typeof input.command !== 'string' || !input.command.trim() || input.command.length > 16000 || input.command.includes('\0')) throw new Error('命令不能为空、包含空字符或超过 16000 字符');
    return { kind, command: input.command, cwd: input.cwd === undefined || input.cwd === '' ? '' : absolutePath(input.cwd) };
  }
  if (['list', 'read', 'write', 'delete'].includes(kind)) {
    object(input, kind === 'write' ? ['kind', 'path', 'content'] : ['kind', 'path'], '操作');
    const operation = { kind, path: absolutePath(input.path) };
    if (kind === 'write') {
      if (typeof input.content !== 'string' || Buffer.byteLength(input.content, 'utf8') > 128 * 1024) throw new Error('写入内容必须是最多 128 KiB 的 UTF-8 文本');
      operation.content = input.content;
    }
    return operation;
  }
  throw new Error('未知操作类型');
}
export function isProtectedPath(value, blockedPaths = []) {
  let path;
  try { path = absolutePath(value); } catch { return true; }
  const lower = path.toLowerCase();
  if (CORE_PROTECTED_PATHS.some(root => inside(lower, root)) || blockedPaths.some(root => inside(path, root))) return true;
  const parts = lower.split('/').filter(Boolean);
  if (parts[0] === 'etc' && parts[1]?.startsWith('cron')) return true;
  return parts.some((part, i) => protectedSegments.has(part) || part.startsWith('.env') || /^id_(rsa|ed25519)/u.test(part) || /\.(pem|key)$/u.test(part) || /credential|secret/u.test(part) || (part === '.config' && parts[i + 1] === 'fish'));
}
export function isSensitiveContent(text) {
  if (typeof text !== 'string') return false;
  if (/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/u.test(text) || /\bAuthorization\s*:\s*(?:Bearer|Basic)\s+\S+/iu.test(text) || /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:]+:[^\s/@]+@/iu.test(text)) return true;
  // Docker permits a custom config directory; its auth field is an encoded credential.
  // Parse complete configs as well so JSON-escaped property names cannot evade this check.
  try {
    const auths = JSON.parse(text)?.auths;
    if (auths && typeof auths === 'object' && !Array.isArray(auths)
        && Object.values(auths).some(entry => typeof entry?.auth === 'string' && entry.auth.trim())) return true;
  } catch { /* Non-JSON output is checked by the assignment scanner below. */ }
  // Catch auth fragments in streamed output without treating auth:true/required as secrets.
  const encodedAuth = /(?:^|[\s{,;])["']?auth["']?\s*[:=]\s*["']?([A-Za-z0-9+/]+={0,2})(?=["'\s,;}]|$)/giu;
  for (const [, value] of text.matchAll(encodedAuth)) {
    const decoded = Buffer.from(value, 'base64');
    if (decoded.includes(58) && decoded.toString('base64').replace(/=+$/u, '') === value.replace(/=+$/u, '')) return true;
  }
  const assignments = /(?:^|[\s{,;])(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*([^\r\n,;}]+)/gu;
  for (const match of text.matchAll(assignments)) {
    if (!/(?:password|passwd|(?:^|[_.-])pwd(?:$|[_.-])|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization)/iu.test(match[1])) continue;
    const value = match[2].trim().replace(/^["']|["']$/gu, '').trim();
    if (value && !/^(?:null|none|false)$/iu.test(value)) return true;
  }
  return false;
}
const quote = value => "'" + value.replaceAll("'", "'\"'\"'") + "'";
const environment = 'cd / && /usr/bin/env -i PATH=/usr/bin:/bin HOME=/proc/self/fd LANG=C LC_ALL=C SYSTEMD_PAGER=cat SYSTEMD_COLORS=0';
// /proc/self/fd is a kernel-owned directory with no config.json; no user Docker contexts/config are loaded.
const docker = '/usr/bin/docker --config /proc/self/fd --host unix:///var/run/docker.sock';
const fixedCommands = {
  'connection.test': '/bin/sh -c ' + quote("/usr/bin/printf '%s\\n' 'SSH_CONTROL_OK' && /usr/bin/id -un && /usr/bin/hostname && /usr/bin/uname -s"),
  'system.summary': '/bin/sh -c ' + quote('/usr/bin/hostname && /usr/bin/uname -srmo && /usr/bin/uptime -p'),
  'disk.usage': '/usr/bin/df -h', 'disk.inodes': '/usr/bin/df -i', 'memory.usage': '/usr/bin/free -m',
  'network.listeners': '/usr/bin/ss -lntu',
  'docker.containers': docker + " ps -a --format 'table {{.ID}}\\t{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}'",
  'docker.stats': docker + " stats --no-stream --format 'table {{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.NetIO}}\\t{{.BlockIO}}'",
  'docker.disk': docker + ' system df',
  'system.services': '/usr/bin/systemctl --no-pager --no-legend --plain list-units --type=service --all',
  'system.failed': '/usr/bin/systemctl --no-pager --no-legend --plain list-units --type=service --failed',
};
export function buildActionCommand(actionId, input = {}) {
  const args = actionArgs(actionId, input);
  let command = fixedCommands[actionId];
  if (actionId === 'service.status') command = '/usr/bin/systemctl --no-pager show --property=Id,LoadState,ActiveState,SubState,UnitFileState -- ' + quote(args.name);
  else if (actionId.startsWith('service.')) command = '/usr/bin/systemctl --no-pager ' + actionId.slice(8) + ' -- ' + quote(args.name);
  else if (actionId.startsWith('container.')) command = docker + ' ' + actionId.slice(10) + ' -- ' + quote(args.name);
  return environment + ' ' + command;
}
const aliases = new Map(Object.entries({
  'df -h': 'disk.usage', 'df -i': 'disk.inodes', 'free -m': 'memory.usage', 'free -h': 'memory.usage',
  'ss -lntu': 'network.listeners', 'docker ps': 'docker.containers', 'docker ps -a': 'docker.containers',
  'docker stats --no-stream': 'docker.stats', 'docker system df': 'docker.disk',
  'systemctl --failed': 'system.failed', 'systemctl list-units --failed': 'system.failed', 'systemctl list-units --type=service': 'system.services',
}));
export function resolveSafeCommand(command) {
  const actionId = aliases.get(command);
  return actionId ? { kind: 'action', actionId, args: {} } : null;
}
function securityService(name) { return securityServices.has(name.toLowerCase().split('@')[0].replace(/\.(?:service|socket|target)$/u, '')); }
function ruleDecision(policy, command) {
  let decision = null;
  for (const rule of policy.commandRules) {
    const matches = rule.match === 'exact' ? command === rule.pattern : rule.match === 'prefix' ? command.startsWith(rule.pattern) : command.includes(rule.pattern);
    if (matches && rule.decision === 'deny') return 'deny';
    if (matches) decision = 'ask';
  }
  return decision;
}
function sensitiveCommand(command, cwd, blockedPaths) {
  if (cwd && isProtectedPath(cwd, blockedPaths)) return true;
  if (isSensitiveContent(command) || /(?:^|[\s;&|])(?:\S*\/)?(?:env|printenv|set|export|declare|typeset|ssh-keygen|ssh-add|ssh-agent|passwd|chpasswd|visudo)(?:\s|$)/iu.test(command) || /\bsudo\s/iu.test(command)) return true;
  if (/\bdocker\b[^\r\n;|&]*\b(?:inspect|secret)\b|\bkubectl\b[^\r\n;|&]*\bsecrets?\b|\baws\s+(?:configure|secretsmanager|ssm)\b|\b(?:az|gcloud)\b[^\r\n;|&]*\b(?:credential|secret|login|auth|token)\b/iu.test(command)) return true;
  // This is a conservative visible-token check, not a shell parser or a sandbox.
  // Advanced shell still requires confirmation, including when paths are computed.
  const visible = command.replace(/["'\\]/gu, '');
  for (const token of visible.split(/[\s`;|&<>()]+/u).filter(Boolean)) {
    if (token.startsWith('-') || token.includes('=')) continue;
    const path = token.startsWith('~') ? '/home/user' + token.slice(1) : token.startsWith('/') ? token : (cwd || '') + '/' + token;
    if (isProtectedPath(path, blockedPaths)) return true;
  }
  return false;
}
export function evaluateOperation(inputPolicy, inputOperation) {
  const policy = validatePolicy(inputPolicy), operation = normalizeOperation(inputOperation);
  const extended=evaluateInfrastructureOperation(policy,operation);if(extended)return extended;
  const summary = operation.kind === 'action' ? catalog.get(operation.actionId).label + (operation.args.name ? '：' + operation.args.name : '') : operation.kind === 'command' ? '执行自定义命令' : operation.kind === 'test' ? '测试连接' : ({ list: '列出目录', read: '读取文件', write: '写入文件', delete: '删除文件' }[operation.kind] + '：' + operation.path);
  const result = (decision, code, reason, extra = {}) => ({ decision, code, reason, operation, summary, ...extra });
  if (['list', 'read', 'write', 'delete'].includes(operation.kind)) {
    if (isProtectedPath(operation.path, policy.blockedPaths)) return result('deny', 'PROTECTED_PATH', '安全配置、凭据或明确禁止的路径不可访问');
    if (operation.kind === 'write' && isSensitiveContent(operation.content)) return result('deny', 'SENSITIVE_CONTENT', '检测到私钥或凭据内容，禁止写入');
    const root = policy.roots.filter(r => r.match==='exact'?operation.path===r.path:inside(operation.path, r.path)).sort((a, b) => b.path.length - a.path.length)[0];
    const mutating = ['write', 'delete'].includes(operation.kind);
    if (!root || !(mutating ? root.write : root.read)) return result('deny', 'PATH_NOT_ALLOWED', '目标不在具有所需权限的目录内');
    if (mutating && operation.path === root.path && root.match!=='exact') return result('deny', 'ROOT_MUTATION_DENIED', '不能覆盖或删除授权根目录');
    const exactFile=root.match==='exact'&&operation.kind!=='list';
    const fileRoot=exactFile?posix.dirname(root.path):root.path;
    const relativePath = exactFile?posix.basename(root.path):operation.path === root.path ? '.' : operation.path.slice(root.path === '/' ? 1 : root.path.length + 1);
    const file = { root: fileRoot, relativePath, blockedPaths: [...policy.blockedPaths] };
    return result(mutating ? 'ask' : 'allow', mutating ? 'MUTATION_REQUIRES_APPROVAL' : 'READ_ALLOWED', mutating ? '文件修改必须由用户确认' : '允许目录内的非敏感读取', { file });
  }
  let action, supplement = null;
  if (operation.kind === 'command') {
    if (sensitiveCommand(operation.command, operation.cwd, policy.blockedPaths)) return result('deny', 'SENSITIVE_COMMAND', '命令涉及可识别的安全资源或凭据操作');
    supplement = ruleDecision(policy, operation.command);
    if (supplement === 'deny') return result('deny', 'COMMAND_RULE_DENY', '命中禁止命令规则');
    action = resolveSafeCommand(operation.command);
    if (!action) return policy.mode === 'restricted' ? result('deny', 'RAW_SHELL_DISABLED', '受限模式只接受内置操作或完全匹配的只读命令') : result('ask', 'RAW_SHELL_REQUIRES_APPROVAL', '完整 Shell 必须确认；目录规则不能限制其内部操作', { command: operation.command });
  } else action = operation.kind === 'test' ? { kind: 'action', actionId: 'connection.test', args: {} } : operation;
  const info = catalog.get(action.actionId);
  const argumentRule=policy.actionArguments[action.actionId];
  if(argumentRule&&!argumentRule.names.includes(action.args.name))return result('deny','ARGUMENT_NOT_ALLOWED','目标服务或容器不在名称白名单中');
  if (info.mutating && action.actionId.startsWith('service.') && securityService(action.args.name)) return result('deny', 'SECURITY_SERVICE_DENIED', '禁止修改 SSH、认证、防火墙或其他安全服务');
  const command = buildActionCommand(action.actionId, action.args);
  const equivalents = [command, action.actionId, ...[...aliases].filter(([, id]) => id === action.actionId).map(([alias]) => alias)];
  if (action.actionId.startsWith('service.')) equivalents.push('systemctl ' + action.actionId.slice(8) + ' ' + action.args.name);
  if (action.actionId.startsWith('container.')) equivalents.push('docker ' + action.actionId.slice(10) + ' ' + action.args.name);
  const matchingRules = equivalents.map(value => ruleDecision(policy, value));
  const actionRule = matchingRules.includes('deny') ? 'deny' : matchingRules.includes('ask') ? 'ask' : null;
  if (policy.actions[action.actionId] === 'deny' || actionRule === 'deny') return result('deny', 'ACTION_DENIED', '当前策略禁止此操作');
  const decision = info.mutating || policy.actions[action.actionId] === 'ask' || supplement === 'ask' || actionRule === 'ask' ? 'ask' : 'allow';
  return result(decision, decision === 'ask' ? 'ACTION_REQUIRES_APPROVAL' : 'ACTION_ALLOWED', decision === 'ask' ? '此操作必须由用户确认' : '允许内置非敏感诊断操作', { command });
}
