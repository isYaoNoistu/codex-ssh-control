import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { isIP } from 'node:net';
import { randomUUID, createHash } from 'node:crypto';
import { DEFAULT_POLICY, validatePolicy, normalizeOperation, evaluateOperation } from './policy.mjs';
import { operationPresentation, historySnapshot, sanitizeHistoryOutput } from './operation-display.mjs';
import { normalizeHostOperation } from './host-operation.mjs';

const fields = ['id', 'name', 'hostname', 'port', 'username', 'identityFile', 'sshAlias', 'defaultCwd', 'enabled'];
const connectionFields = ['hostname', 'port', 'username', 'identityFile', 'sshAlias', 'defaultCwd'];

function text(value, label, max = 4096) {
  if (typeof value !== 'string' || value.length > max || /[\0\r\n]/u.test(value)) {
    throw new Error(`${label}必须是有效文本，且不能包含换行或空字符`);
  }
  return value;
}

function identity(value, label) {
  text(value, label, 1024);
  if (!value.trim()) throw new Error(`缺少可信${label}，请在当前聊天中重新操作`);
  return value;
}

function hostId(value) {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{0,47}$/u.test(value)
      || value === 'status' || value.startsWith('revoke-')) {
    throw new Error('主机 ID 须以小写字母开头，仅包含小写字母、数字或短横线，且不能使用保留名称');
  }
  return value;
}

function ids(values) {
  if (!Array.isArray(values) || values.length > 256) throw new Error('主机 ID 列表无效或过长');
  return [...new Set(values.map(hostId))].sort();
}

function connectionText(value, label, max) {
  text(value, label, max);
  if (value.startsWith('-') || /[;&|<>$`"'(){}!?*\[\]#\u0001-\u001f\u007f]/u.test(value)) {
    throw new Error(`${label}不能包含选项前缀、控制字符或 Shell 标点`);
  }
  return value;
}

function validateHost(input, previous) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new Error('主机配置必须是对象');
  for (const key of Object.keys(input)) if (!fields.includes(key)) throw new Error(`未知主机字段：${key}；请勿保存密码或密钥内容`);
  const id = hostId(input.id);
  const host = {
    id, name: id, hostname: '', port: 22, username: '', identityFile: '', sshAlias: '', defaultCwd: '', enabled: false,
    ...previous, ...input,
  };
  host.name = text(host.name, '显示名称', 80) || id;
  connectionText(host.hostname, '主机地址', 253);
  connectionText(host.username, '用户名', 64);
  connectionText(host.sshAlias, 'SSH 别名', 253);
  connectionText(host.identityFile, '密钥路径', 4096);
  connectionText(host.defaultCwd, '默认目录', 4096);
  if (!Number.isInteger(host.port) || host.port < 1 || host.port > 65535) throw new Error('SSH 端口必须为 1 到 65535 的整数');
  if (typeof host.enabled !== 'boolean') throw new Error('主机启用状态必须是布尔值');
  if (Boolean(host.hostname) === Boolean(host.sshAlias)) throw new Error('主机地址与 SSH 别名必须且只能填写一项');
  if (host.hostname) {
    const domain = host.hostname.endsWith('.') ? host.hostname.slice(0, -1) : host.hostname;
    if (isIP(host.hostname) === 0 && !domain.split('.').every(label => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/u.test(label))) {
      throw new Error('主机地址必须是有效的 IP 地址或域名');
    }
    if (!host.username) throw new Error('填写主机地址时必须提供 SSH 用户名');
  }
  if (host.username && !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$/u.test(host.username)) throw new Error('SSH 用户名格式无效');
  if (host.sshAlias && !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,252}$/u.test(host.sshAlias)) throw new Error('SSH 别名格式无效');
  return host;
}

export function resolveDataDir(env = process.env) {
  if (env.SSH_CONTROL_DATA !== undefined) {
    const directory = text(env.SSH_CONTROL_DATA, '数据目录');
    if (!directory.trim()) throw new Error('数据目录不能为空');
    return directory;
  }
  // Keep the established data location so a plugin rename cannot lose hosts or permissions.
  return join(homedir(), '.codex', 'ssh-control');
}

// Audit summaries are deliberately independent of user content and shell text.
function operationSummary(operation) {
  if (operation?.kind === 'action') return `执行预设动作：${operation.actionId}`;
  return ({ test: '连接测试', command: '自定义命令（正文已隐藏）', list: '列出目录', read: '读取文件', write: '写入文件（内容已隐藏）', delete: '删除文件' })[operation?.kind] || '操作请求';
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}

function pageLimit(value, fallback = 50) {
  const limit = value ?? fallback;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new Error('每页条数必须为 1 到 100');
  return limit;
}

export class Store {
  #db;
  #closed = false;

  constructor(dataDir) {
    text(dataDir, '数据目录');
    if (!dataDir.trim()) throw new Error('数据目录不能为空');
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.#db = new DatabaseSync(join(dataDir, 'store.sqlite'));
    try {
      this.#db.exec('PRAGMA busy_timeout = 10000; PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;');
      this.#transaction(() => this.#migrate());
    } catch (error) {
      this.#db.close(); this.#closed = true; throw error;
    }
  }

  #migrate() {
    const version = this.#db.prepare('PRAGMA user_version').get().user_version;
    if (version > 4) throw new Error('数据版本高于当前插件支持范围，请使用更新版本');
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS hosts (id TEXT PRIMARY KEY, value TEXT NOT NULL, revision TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS grants (
        thread_id TEXT NOT NULL, host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
        PRIMARY KEY (thread_id, host_id)
      );
      CREATE TABLE IF NOT EXISTS intents (
        session_id TEXT NOT NULL, turn_id TEXT NOT NULL,
        operation TEXT NOT NULL CHECK (operation IN ('grant', 'revoke', 'status')),
        host_ids TEXT NOT NULL, revisions TEXT NOT NULL, expires_at INTEGER NOT NULL,
        consumed_at INTEGER, consumed_thread_id TEXT, PRIMARY KEY (session_id, turn_id)
      );
      CREATE TABLE IF NOT EXISTS intent_revocations (
        revision INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id TEXT NOT NULL, host_id TEXT NOT NULL, UNIQUE(thread_id,host_id)
      );
      CREATE TABLE IF NOT EXISTS policies (
        host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
        revision INTEGER NOT NULL, value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, host_id TEXT NOT NULL,
        host_revision TEXT NOT NULL, policy_revision INTEGER NOT NULL, grant_id TEXT NOT NULL,
        operation TEXT NOT NULL, request_hash TEXT NOT NULL, summary TEXT NOT NULL, reason TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','expired','invalidated','consumed')),
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS approvals_request ON approvals(thread_id,host_id,request_hash,status);
      CREATE INDEX IF NOT EXISTS approvals_expiry ON approvals(status,expires_at);
      CREATE TABLE IF NOT EXISTS operations (
        id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, host_id TEXT NOT NULL,
        policy_revision INTEGER NOT NULL, request_hash TEXT NOT NULL, summary TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active','completed','failed','timed_out','cancelled')),
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, authorization_invalidated INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS operations_active ON operations(host_id,status,expires_at);
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL,
        thread_id TEXT, host_id TEXT, event TEXT NOT NULL, operation_id TEXT,
        summary TEXT NOT NULL, result TEXT NOT NULL, reason TEXT NOT NULL, policy_revision INTEGER
      );
      CREATE INDEX IF NOT EXISTS audit_host ON audit(host_id,id);
      CREATE INDEX IF NOT EXISTS audit_thread ON audit(thread_id,id);
      CREATE TABLE IF NOT EXISTS execution_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL UNIQUE,
        thread_id TEXT NOT NULL, host_id TEXT NOT NULL, policy_revision INTEGER NOT NULL,
        snapshot TEXT NOT NULL, summary TEXT NOT NULL, explanation TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('running','completed','failed','timed_out','cancelled','unknown')),
        started_at INTEGER NOT NULL, finished_at INTEGER, exit_code INTEGER,
        completion_known INTEGER NOT NULL DEFAULT 0,
        stdout TEXT NOT NULL DEFAULT '', stderr TEXT NOT NULL DEFAULT '',
        truncated INTEGER NOT NULL DEFAULT 0, redacted INTEGER NOT NULL DEFAULT 0,
        output_notice TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS history_host ON execution_history(host_id,id);
      CREATE INDEX IF NOT EXISTS history_thread ON execution_history(thread_id,id);
    `);
    const columns = new Set(this.#db.prepare('PRAGMA table_info(grants)').all().map(row => row.name));
    for (const [name, type] of Object.entries({ host_revision: 'TEXT', policy_revision: 'INTEGER', expires_at: 'INTEGER', grant_id: 'TEXT', source: 'TEXT' })) {
      if (!columns.has(name)) this.#db.exec(`ALTER TABLE grants ADD COLUMN ${name} ${type}`);
    }
    const intentColumns = new Set(this.#db.prepare('PRAGMA table_info(intents)').all().map(row => row.name));
    // NULL marks pre-upgrade intents: their ordering against revocations is unknowable.
    if (!intentColumns.has('revocation_revision')) this.#db.exec('ALTER TABLE intents ADD COLUMN revocation_revision INTEGER');
    const approvalColumns = new Set(this.#db.prepare('PRAGMA table_info(approvals)').all().map(row => row.name));
    for (const [name, type] of Object.entries({ source: "TEXT NOT NULL DEFAULT 'legacy'", prompt_token_hash: 'TEXT', explanation: 'TEXT', presentation: 'TEXT', host_snapshot: 'TEXT', policy_snapshot: 'TEXT' })) {
      if (!approvalColumns.has(name)) this.#db.exec(`ALTER TABLE approvals ADD COLUMN ${name} ${type}`);
    }
    this.#db.exec('CREATE UNIQUE INDEX IF NOT EXISTS native_prompt_nonce ON approvals(prompt_token_hash) WHERE prompt_token_hash IS NOT NULL');
    const initialPolicy = JSON.stringify(validatePolicy(DEFAULT_POLICY));
    this.#db.prepare('INSERT OR IGNORE INTO policies(host_id,revision,value) SELECT id,1,? FROM hosts').run(initialPolicy);
    const legacy = this.#db.prepare(`SELECT g.thread_id,g.host_id,h.revision,p.revision AS policy_revision
      FROM grants g JOIN hosts h ON h.id=g.host_id JOIN policies p ON p.host_id=g.host_id
      WHERE g.host_revision IS NULL OR g.policy_revision IS NULL OR g.expires_at IS NULL OR g.grant_id IS NULL`).all();
    const now = Date.now();
    const migrateGrant = this.#db.prepare('UPDATE grants SET host_revision=?,policy_revision=?,expires_at=?,grant_id=?,source=? WHERE thread_id=? AND host_id=?');
    for (const row of legacy) migrateGrant.run(row.revision, row.policy_revision, now + 3_600_000, randomUUID(), 'migration', row.thread_id, row.host_id);
    if (version < 2) this.#audit({ event: 'schema_migrated', summary: '权限治理数据迁移', result: 'completed', reason: '保留主机；已有授权设置 60 分钟有效期' });
    if (version < 3) {
      this.#db.exec("UPDATE approvals SET status='invalidated' WHERE source='legacy' AND status IN ('pending','approved')");
      this.#audit({ event: 'history_migrated', summary: '原生确认与执行历史数据迁移', result: 'completed', reason: '旧待审批请求已失效；旧输出未保存，不补造历史' });
    }
    this.#scrubNative();
    if (version < 4) this.#audit({ event: 'intent_revocations_migrated', summary: '快捷授权撤销隔离迁移', result: 'completed', reason: '升级前未消费的快捷授权请求已失效；保留现有主机、策略和有效授权' });
    this.#db.exec('PRAGMA user_version = 4');
  }

  close() {
    if (!this.#closed) { this.#db.close(); this.#closed = true; }
  }

  #transaction(action, write = true) {
    if (this.#closed) throw new Error('主机状态存储已关闭');
    this.#db.exec(write ? 'BEGIN IMMEDIATE' : 'BEGIN');
    try {
      const result = action();
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      this.#db.exec('ROLLBACK');
      throw error;
    }
  }

  #row(id) { return this.#db.prepare('SELECT value,revision FROM hosts WHERE id=?').get(id); }
  #host(id) { const row = this.#row(id); return row ? JSON.parse(row.value) : undefined; }
  #hosts() { return this.#db.prepare('SELECT value FROM hosts ORDER BY id').all().map(row => JSON.parse(row.value)); }

  #policy(id) {
    const row = this.#db.prepare('SELECT revision,value FROM policies WHERE host_id=?').get(id);
    if (!row) throw new Error(`主机不存在：${id}`);
    return { hostId: id, revision: row.revision, policy: JSON.parse(row.value) };
  }

  #audit({ threadId = null, hostId: id = null, event, operationId = null, summary, result, reason = '', policyRevision = null }) {
    this.#db.prepare(`INSERT INTO audit(created_at,thread_id,host_id,event,operation_id,summary,result,reason,policy_revision)
      VALUES(?,?,?,?,?,?,?,?,?)`).run(Date.now(), threadId, id, event, operationId, summary, result, reason, policyRevision);
    this.#db.exec('DELETE FROM audit WHERE id <= (SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET 5000)');
  }

  #invalidate(id, threadId = null) {
    const suffix = threadId === null ? 'host_id=?' : 'host_id=? AND thread_id=?';
    const args = threadId === null ? [id] : [id, threadId];
    this.#db.prepare(`DELETE FROM grants WHERE ${suffix}`).run(...args);
    this.#db.prepare(`UPDATE approvals SET status='invalidated' WHERE ${suffix} AND status IN ('pending','approved')`).run(...args);
    this.#scrubNative();
    // Do not free a running operation's concurrency slot: revocation cannot undo remote work.
    this.#db.prepare(`UPDATE operations SET authorization_invalidated=1 WHERE ${suffix} AND status='active'`).run(...args);
  }

  #scrubNative(approvalId = null) {
    // Pending prompts need their exact input; terminal tickets only retain replay-denial metadata.
    const suffix = approvalId === null ? '' : ' AND id=?';
    this.#db.prepare(`UPDATE approvals SET operation='{}',presentation='{}',explanation=''
      WHERE source='native' AND status!='pending' AND (operation!='{}' OR presentation!='{}' OR explanation!='')${suffix}`)
      .run(...(approvalId === null ? [] : [approvalId]));
  }

  #expire(now) {
    const approvals = this.#db.prepare("SELECT * FROM approvals WHERE status IN ('pending','approved') AND expires_at<=?").all(now);
    for (const row of approvals) {
      this.#db.prepare("UPDATE approvals SET status='expired' WHERE id=?").run(row.id);
      this.#scrubNative(row.id);
      this.#audit({ threadId: row.thread_id, hostId: row.host_id, event: 'approval_expired', summary: row.summary, result: 'expired', reason: '操作审批已过期', policyRevision: row.policy_revision });
    }
    const operations = this.#db.prepare("SELECT * FROM operations WHERE status='active' AND expires_at<=?").all(now);
    for (const row of operations) {
      this.#db.prepare("UPDATE operations SET status='timed_out' WHERE id=?").run(row.id);
      this.#db.prepare("UPDATE execution_history SET status='unknown',finished_at=?,output_notice=? WHERE operation_id=? AND status='running'")
        .run(now, '执行租约已过期，尚未收到完成结果；远端实际状态未知。', row.id);
      this.#audit({ threadId: row.thread_id, hostId: row.host_id, operationId: row.id, event: 'operation_finished', summary: row.summary, result: 'timed_out', reason: '执行租约已过期；远程任务状态需重新核实', policyRevision: row.policy_revision });
    }
  }

  #pruneHistory(now = Date.now()) {
    this.#db.prepare("DELETE FROM execution_history WHERE status!='running' AND finished_at<=?").run(now - 30 * 24 * 60 * 60_000);
    this.#db.exec("DELETE FROM execution_history WHERE status!='running' AND id IN (SELECT id FROM execution_history WHERE status!='running' ORDER BY id DESC LIMIT -1 OFFSET 500)");
  }

  listHosts() { return this.#transaction(() => this.#hosts(), false); }

  saveHost(input) {
    return this.#transaction(() => {
      const previous = this.#host(hostId(input?.id));
      const host = validateHost(input, previous);
      const changed = !previous || connectionFields.some(key => previous[key] !== host[key]) || previous.enabled !== host.enabled;
      const revision = changed ? randomUUID() : this.#row(host.id).revision;
      this.#db.prepare('INSERT INTO hosts(id,value,revision) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value,revision=excluded.revision')
        .run(host.id, JSON.stringify(host), revision);
      this.#db.prepare('INSERT OR IGNORE INTO policies(host_id,revision,value) VALUES(?,1,?)').run(host.id, JSON.stringify(validatePolicy(DEFAULT_POLICY)));
      if (previous && changed) this.#invalidate(host.id);
      this.#audit({ hostId: host.id, event: 'host_saved', summary: '保存主机配置', result: 'completed', reason: previous && changed ? '连接或启用状态变更；已撤销授权和未完成审批' : '配置已保存' });
      return host;
    });
  }

  removeHost(id) {
    hostId(id);
    this.#transaction(() => {
      this.#invalidate(id);
      this.#db.prepare('DELETE FROM hosts WHERE id=?').run(id);
      this.#audit({ hostId: id, event: 'host_removed', summary: '删除主机配置', result: 'completed', reason: '已撤销相关授权与审批' });
    });
  }

  setEnabled(id, enabled) {
    hostId(id);
    if (typeof enabled !== 'boolean') throw new Error('主机启用状态必须是布尔值');
    return this.#transaction(() => {
      const host = this.#host(id);
      if (!host) throw new Error(`主机不存在：${id}`);
      if (host.enabled !== enabled) {
        host.enabled = enabled;
        this.#db.prepare('UPDATE hosts SET value=?,revision=? WHERE id=?').run(JSON.stringify(host), randomUUID(), id);
        this.#invalidate(id);
      }
      this.#audit({ hostId: id, event: 'host_enabled_changed', summary: enabled ? '启用主机' : '禁用主机', result: 'completed', reason: '重新启用不会恢复旧授权' });
      return host;
    });
  }

  getPolicy(id) {
    hostId(id);
    return this.#transaction(() => this.#policy(id), false);
  }

  savePolicy(actorThreadId, id, value, expectedRevision) {
    identity(actorThreadId, '聊天标识'); hostId(id);
    return this.#transaction(() => {
      const current = this.#policy(id);
      if (!Number.isSafeInteger(expectedRevision) || expectedRevision !== current.revision) throw new Error('权限策略版本冲突，请刷新后重新保存');
      const policy = validatePolicy(value);
      const revision = current.revision + 1;
      this.#db.prepare('UPDATE policies SET revision=?,value=? WHERE host_id=?').run(revision, JSON.stringify(policy), id);
      this.#invalidate(id);
      this.#audit({ threadId: actorThreadId, hostId: id, event: 'policy_saved', summary: '保存权限策略', result: 'completed', reason: '旧授权及未完成审批已失效', policyRevision: revision });
      return { hostId: id, revision, policy };
    });
  }

  #activeGrant(threadId, id, now) {
    const row = this.#row(id);
    if (!row || !JSON.parse(row.value).enabled) return null;
    const record = this.#policy(id);
    const grant = this.#db.prepare('SELECT * FROM grants WHERE thread_id=? AND host_id=?').get(threadId, id);
    return grant && grant.expires_at > now && grant.host_revision === row.revision && grant.policy_revision === record.revision ? grant : null;
  }

  #state(threadId) {
    const hosts = this.#hosts();
    const now = Date.now();
    const grants = threadId === null ? [] : hosts.flatMap(host => {
      const grant = this.#activeGrant(threadId, host.id, now);
      return grant ? [{ hostId: host.id, expiresAt: grant.expires_at, policyRevision: grant.policy_revision }] : [];
    });
    const examples = hosts.map(host => `/ssh-${host.id}`).join(' ');
    const pendingApprovalCount = threadId === null ? 0 : this.#db.prepare(`SELECT COUNT(*) AS n FROM approvals a
      JOIN grants g ON g.thread_id=a.thread_id AND g.host_id=a.host_id AND g.grant_id=a.grant_id
      JOIN hosts h ON h.id=a.host_id AND h.revision=a.host_revision
      JOIN policies p ON p.host_id=a.host_id AND p.revision=a.policy_revision
      WHERE a.thread_id=? AND a.status='pending' AND a.expires_at>? AND g.expires_at>?`).get(threadId, now, now).n;
    return {
      threadId, hosts, grantedHostIds: grants.map(grant => grant.hostId), grants,
      policies: hosts.map(host => this.#policy(host.id)), pendingApprovalCount,
      shortcutHelp: `授权：${examples || '/ssh-主机ID'}；撤销：/ssh-revoke-主机ID；查看：/ssh-status。快捷命令须单独发送，仅对当前聊天生效；授权到期需重新确认。`,
    };
  }

  state(threadId) {
    if (threadId !== null) identity(threadId, '聊天标识');
    return this.#transaction(() => this.#state(threadId), false);
  }

  #grant(threadId, hostIds, options = {}) {
    if (!options || typeof options !== 'object' || Array.isArray(options) || Object.keys(options).some(key => !['minutes', 'source'].includes(key))) throw new Error('授权参数无效');
    const { minutes, source = 'ui' } = options;
    if (minutes !== undefined && (!Number.isSafeInteger(minutes) || minutes < 1 || minutes > 1440)) throw new Error('授权分钟数必须为 1 到 1440 的整数');
    text(source, '授权来源', 64);
    const targets = hostIds.map(id => {
      const row = this.#row(id);
      if (!row) throw new Error(`主机不存在：${id}`);
      if (!JSON.parse(row.value).enabled) throw new Error(`主机已禁用，请先启用：${id}`);
      const record = this.#policy(id);
      if (minutes !== undefined && minutes > record.policy.grantMinutes) throw new Error(`授权分钟数超过主机策略上限：${id}`);
      return { id, row, record, minutes: minutes ?? record.policy.grantMinutes };
    });
    const insert = this.#db.prepare(`INSERT INTO grants(thread_id,host_id,host_revision,policy_revision,expires_at,grant_id,source)
      VALUES(?,?,?,?,?,?,?) ON CONFLICT(thread_id,host_id) DO UPDATE SET host_revision=excluded.host_revision,
      policy_revision=excluded.policy_revision,expires_at=excluded.expires_at,grant_id=excluded.grant_id,source=excluded.source`);
    const now = Date.now();
    for (const target of targets) {
      this.#invalidate(target.id, threadId);
      insert.run(threadId, target.id, target.row.revision, target.record.revision, now + target.minutes * 60_000, randomUUID(), source);
      this.#audit({ threadId, hostId: target.id, event: 'grant_issued', summary: '授权当前聊天访问主机', result: 'completed', reason: `授权有效期 ${target.minutes} 分钟`, policyRevision: target.record.revision });
    }
  }

  grant(threadId, values, options = {}) {
    identity(threadId, '聊天标识'); const hostIds = ids(values);
    return this.#transaction(() => { this.#grant(threadId, hostIds, options); return this.#state(threadId); });
  }

  authorizationPreview(values) {
    const hostIds = ids(values);
    return this.#transaction(() => hostIds.map(id => {
      const row = this.#row(id);
      if (!row) throw new Error(`主机不存在：${id}`);
      const host = JSON.parse(row.value);
      if (!host.enabled) throw new Error(`主机已禁用，请先启用：${id}`);
      const record = this.#policy(id);
      return { host, hostRevision: row.revision, policyRevision: record.revision, grantMinutes: record.policy.grantMinutes };
    }), false);
  }

  grantConfirmed(threadId, expectedHosts, options = {}) {
    identity(threadId, '聊天标识');
    if (!Array.isArray(expectedHosts) || expectedHosts.length > 256) throw new Error('待确认的主机列表无效');
    if (!options || typeof options !== 'object' || Array.isArray(options)) throw new Error('授权参数无效');
    const { expectedSnapshots, ...grantOptions } = options;
    const hostIds = ids(expectedHosts.map(host => host?.id));
    return this.#transaction(() => {
      for (const expected of expectedHosts) {
        const current = this.#host(expected.id);
        if (!current || JSON.stringify(current) !== JSON.stringify(expected)) throw new Error('确认期间主机配置已变更，请重新确认');
      }
      if (expectedSnapshots !== undefined) {
        if (!Array.isArray(expectedSnapshots) || expectedSnapshots.length !== hostIds.length) throw new Error('授权确认快照必须覆盖全部主机');
        const seen = new Set();
        for (const snapshot of expectedSnapshots) {
          const id = snapshot?.host?.id;
          if (!hostIds.includes(id) || seen.has(id)) throw new Error('授权确认快照包含重复或未显示的主机');
          seen.add(id);
          const row = this.#row(id), record = this.#policy(id);
          if (row.revision !== snapshot.hostRevision || record.revision !== snapshot.policyRevision
              || record.policy.grantMinutes !== snapshot.grantMinutes
              || row.value !== JSON.stringify(snapshot.host)) throw new Error('确认期间主机配置、权限策略或授权期限已变更，请重新确认');
        }
      }
      this.#grant(threadId, hostIds, grantOptions);
      return this.#state(threadId);
    });
  }

  #revoke(threadId, hostIds) {
    for (const id of hostIds) {
      // Keep the latest ordered tombstone for this chat/host, even without a grant.
      // AUTOINCREMENT avoids wall-clock races and reuse when replacing older rows.
      this.#db.prepare('INSERT OR REPLACE INTO intent_revocations(thread_id,host_id) VALUES(?,?)').run(threadId, id);
      this.#invalidate(id, threadId);
      this.#audit({ threadId, hostId: id, event: 'grant_revoked', summary: '撤销聊天主机授权', result: 'completed', reason: '旧审批不可复用；已开始的远程操作不会自动撤销' });
    }
  }

  revoke(threadId, values) {
    identity(threadId, '聊天标识'); const hostIds = ids(values);
    return this.#transaction(() => { this.#revoke(threadId, hostIds); return this.#state(threadId); });
  }

  requireHost(threadId, id) {
    identity(threadId, '聊天标识');
    if (id !== undefined) hostId(id);
    return this.#transaction(() => {
      const state = this.#state(threadId);
      if (id !== undefined) {
        const host = state.hosts.find(host => host.id === id);
        if (!host) throw new Error(`主机不存在：${id}`);
        if (!host.enabled) throw new Error(`主机已禁用：${id}`);
        if (!state.grantedHostIds.includes(id)) throw new Error(`当前聊天尚未授权主机，或授权已过期：${id}`);
        return host;
      }
      const active = state.hosts.filter(host => state.grantedHostIds.includes(host.id));
      if (!active.length) throw new Error('当前聊天没有已授权且启用的主机');
      if (active.length > 1) throw new Error('当前聊天已授权多个主机，请明确指定 hostId');
      return active[0];
    }, false);
  }

  #approval(row) {
    return {
      id: row.id, threadId: row.thread_id, hostId: row.host_id, policyRevision: row.policy_revision,
      operation: JSON.parse(row.operation), requestHash: row.request_hash, summary: row.summary,
      reason: row.reason, status: row.status, createdAt: row.created_at, expiresAt: row.expires_at,
      ...(row.source === 'native' ? {
        explanation: row.explanation, presentation: JSON.parse(row.presentation),
        host: JSON.parse(row.host_snapshot), policy: JSON.parse(row.policy_snapshot),
      } : {}),
    };
  }

  #nativeDenied(threadId, id, operation, record, code, reason) {
    this.#audit({ threadId, hostId: id, event: 'operation_denied', summary: operationSummary(operation), result: 'denied', reason: code, policyRevision: record?.revision });
    return { status: 'denied', code, reason };
  }

  #nativePermit(threadId, id, hostRow, record, evaluation, presentation, digest, approvalId, now) {
    const active = this.#db.prepare("SELECT COUNT(*) AS n FROM operations WHERE host_id=? AND status='active' AND expires_at>?").get(id, now).n;
    if (active >= record.policy.maxConcurrent) {
      if (approvalId) {
        this.#db.prepare("UPDATE approvals SET status='invalidated' WHERE id=? AND status='pending'").run(approvalId);
        this.#scrubNative(approvalId);
      }
      return this.#nativeDenied(threadId, id, evaluation.operation, record, 'CONCURRENCY_LIMIT', '主机操作已达到并发上限；本次确认不再生效，请稍后重新申请。');
    }
    const host = JSON.parse(hostRow.value);
    const snapshot = historySnapshot(evaluation, presentation.explanation, host);
    const operationId = randomUUID(), summary = operationSummary(evaluation.operation);
    if (approvalId) {
      const updated = this.#db.prepare("UPDATE approvals SET status='consumed' WHERE id=? AND status='pending' AND source='native'").run(approvalId);
      if (updated.changes !== 1) throw new Error('原生确认已被消费，不能再次执行');
      this.#scrubNative(approvalId);
      this.#audit({ threadId, hostId: id, event: 'native_approval_resolved', summary, result: 'consumed', reason: '用户已在原生确认中批准本次精确操作', policyRevision: record.revision });
    }
    this.#db.prepare(`INSERT INTO operations(id,thread_id,host_id,policy_revision,request_hash,summary,status,created_at,expires_at)
      VALUES(?,?,?,?,?,?,'active',?,?)`).run(operationId, threadId, id, record.revision, digest, summary, now, now + (record.policy.timeoutSeconds + 30) * 1000);
    this.#db.prepare(`INSERT INTO execution_history(operation_id,thread_id,host_id,policy_revision,snapshot,summary,explanation,status,started_at)
      VALUES(?,?,?,?,?,?,?,'running',?)`).run(operationId, threadId, id, record.revision, JSON.stringify(snapshot), snapshot.summary, snapshot.explanation, now);
    this.#audit({ threadId, hostId: id, operationId, event: 'operation_started', summary, result: 'ready', reason: approvalId ? '已原子消费本次原生确认' : '策略允许自动执行', policyRevision: record.revision });
    this.#pruneHistory(now);
    return { status: 'ready', operationId, host, policy: record.policy, evaluation, presentation };
  }

  assertOperationReady(threadId, operationId) {
    const invalid = () => Object.assign(new Error('执行许可已过期或因主机、授权、权限策略变更而失效；本次操作未执行。'), { code: 'OPERATION_INVALIDATED' });
    try { identity(threadId, '聊天标识'); identity(operationId, '操作标识'); }
    catch { throw invalid(); }
    return this.#transaction(() => {
      const now = Date.now();
      const operation = this.#db.prepare('SELECT * FROM operations WHERE id=?').get(operationId);
      if (!operation || operation.thread_id !== threadId || operation.status !== 'active'
          || operation.expires_at <= now || operation.authorization_invalidated !== 0) throw invalid();
      const grant = this.#activeGrant(threadId, operation.host_id, now);
      if (!grant || grant.policy_revision !== operation.policy_revision) throw invalid();
      // Read-only final check. The caller records cancellation on failure, then
      // starts the runner synchronously without another await after success.
    }, false);
  }
  beginNativeOperation(threadId, id, input, explanation, promptToken, expectedPolicyRevision) {
    identity(threadId, '聊天标识'); hostId(id); identity(promptToken, '原生确认标识');
    return this.#transaction(() => {
      const now = Date.now();
      this.#expire(now);
      let operation, record;
      const deny = (code, reason) => this.#nativeDenied(threadId, id, operation, record, code, reason);
      const hostRow = this.#row(id);
      // Resolve defaults from the same transaction snapshot as the grant, policy and approval.
      try { operation = normalizeHostOperation(input, hostRow ? JSON.parse(hostRow.value) : undefined); }
      catch { return deny('INVALID_OPERATION', '操作参数无效，请检查请求'); }
      if (!hostRow) return deny('HOST_NOT_FOUND', '主机不存在');
      record = this.#policy(id);
      if (!JSON.parse(hostRow.value).enabled) return deny('HOST_DISABLED', '主机已禁用');
      if (!Number.isSafeInteger(expectedPolicyRevision) || record.revision !== expectedPolicyRevision) return deny('POLICY_CHANGED', '权限策略已变更，请重新发起操作');
      const grant = this.#activeGrant(threadId, id, now);
      if (!grant) return deny('GRANT_REQUIRED', '当前聊天未授权，或主机授权已过期/失效');
      const evaluation = evaluateOperation(record.policy, operation);
      if (!['allow', 'ask', 'deny'].includes(evaluation.decision)) return deny('INVALID_POLICY_DECISION', '策略未给出有效许可');
      if (evaluation.decision === 'deny') return deny(evaluation.code || 'POLICY_DENIED', evaluation.reason || '权限策略拒绝此操作');
      let presentation;
      try { presentation = operationPresentation(evaluation, explanation); }
      catch { return deny('INVALID_EXPLANATION', '操作说明无效：请提供清晰目的，不得包含凭据或控制字符。'); }
      const normalizedExplanation = presentation.explanation;
      const digest = createHash('sha256').update(JSON.stringify(canonical({ operation, explanation: normalizedExplanation }))).digest('hex');
      if (evaluation.decision === 'allow') return this.#nativePermit(threadId, id, hostRow, record, evaluation, presentation, digest, null, now);
      const promptHash = createHash('sha256').update(promptToken).digest('hex');
      if (this.#db.prepare('SELECT id FROM approvals WHERE prompt_token_hash=?').get(promptHash)) return deny('PROMPT_TOKEN_REUSED', '原生确认标识不能重复使用');
      const pending = this.#db.prepare("SELECT COUNT(*) AS n FROM approvals WHERE thread_id=? AND host_id=? AND source='native' AND status='pending' AND expires_at>?").get(threadId, id, now).n;
      if (pending >= 16) return deny('PENDING_APPROVAL_LIMIT', '当前聊天在该主机上等待确认的请求过多，请先处理已有原生确认。');
      const row = {
        id: randomUUID(), thread_id: threadId, host_id: id, host_revision: hostRow.revision, policy_revision: record.revision,
        grant_id: grant.grant_id, operation: JSON.stringify(canonical(operation)), request_hash: digest,
        summary: presentation.summary, reason: evaluation.reason || '此操作需要原生确认',
        status: 'pending', created_at: now, expires_at: Math.min(now + 120_000, grant.expires_at), source: 'native',
        prompt_token_hash: promptHash, explanation: normalizedExplanation, presentation: JSON.stringify(presentation),
        host_snapshot: hostRow.value, policy_snapshot: JSON.stringify(record.policy),
      };
      this.#db.prepare(`INSERT INTO approvals(id,thread_id,host_id,host_revision,policy_revision,grant_id,operation,request_hash,summary,reason,status,created_at,expires_at,source,prompt_token_hash,explanation,presentation,host_snapshot,policy_snapshot)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(row.id, threadId, id, hostRow.revision, record.revision, grant.grant_id, row.operation, digest, row.summary, row.reason, 'pending', now, row.expires_at, 'native', promptHash, normalizedExplanation, row.presentation, row.host_snapshot, row.policy_snapshot);
      this.#audit({ threadId, hostId: id, event: 'native_approval_requested', summary: operationSummary(operation), result: 'pending', reason: '等待当前工具调用的原生确认', policyRevision: record.revision });
      return { status: 'pending', approval: this.#approval(row) };
    });
  }

  completeNativeApproval(threadId, approvalId, promptToken, decision) {
    identity(threadId, '聊天标识'); identity(approvalId, '审批标识'); identity(promptToken, '原生确认标识');
    if (!['approve', 'deny', 'cancel'].includes(decision)) throw new Error('原生确认决定无效');
    return this.#transaction(() => {
      const now = Date.now();
      this.#expire(now);
      const row = this.#db.prepare("SELECT * FROM approvals WHERE id=? AND source='native'").get(approvalId);
      const promptHash = createHash('sha256').update(promptToken).digest('hex');
      if (!row || row.thread_id !== threadId || row.prompt_token_hash !== promptHash) {
        return this.#nativeDenied(threadId, null, null, null, 'APPROVAL_NOT_OWNED', '原生确认不存在或不属于本次调用。');
      }
      const operation = JSON.parse(row.operation);
      const deny = (code, reason) => this.#nativeDenied(threadId, row.host_id, operation, { revision: row.policy_revision }, code, reason);
      if (row.status !== 'pending') return deny(row.status === 'expired' ? 'APPROVAL_EXPIRED' : 'APPROVAL_NOT_PENDING', '原生确认已过期、取消、失效或已经消费，请重新发起操作。');
      if (decision !== 'approve') {
        this.#db.prepare("UPDATE approvals SET status='denied' WHERE id=? AND status='pending'").run(approvalId);
        this.#scrubNative(approvalId);
        return deny(decision === 'cancel' ? 'APPROVAL_CANCELLED' : 'APPROVAL_DENIED', decision === 'cancel' ? '本次原生确认已取消，未执行操作。' : '用户拒绝了本次操作，未执行。');
      }
      const hostRow = this.#row(row.host_id), grant = this.#activeGrant(threadId, row.host_id, now);
      if (!hostRow || !grant || hostRow.revision !== row.host_revision || grant.grant_id !== row.grant_id || grant.policy_revision !== row.policy_revision) {
        this.#db.prepare("UPDATE approvals SET status='invalidated' WHERE id=? AND status='pending'").run(approvalId);
        this.#scrubNative(approvalId);
        return deny('APPROVAL_STALE', '确认期间主机、授权或权限策略已变更，未执行操作。');
      }
      const record = this.#policy(row.host_id), evaluation = evaluateOperation(record.policy, operation);
      const digest = createHash('sha256').update(JSON.stringify(canonical({ operation, explanation: row.explanation }))).digest('hex');
      if (!['allow', 'ask'].includes(evaluation.decision) || digest !== row.request_hash) {
        this.#db.prepare("UPDATE approvals SET status='invalidated' WHERE id=? AND status='pending'").run(approvalId);
        this.#scrubNative(approvalId);
        return deny('APPROVAL_POLICY_DENIED', '操作不再符合已确认的权限策略，未执行。');
      }
      const presentation = operationPresentation(evaluation, row.explanation);
      return this.#nativePermit(threadId, row.host_id, hostRow, record, evaluation, presentation, digest, approvalId, now);
    });
  }

  beginOperation(threadId, id, input, _decision, expectedPolicyRevision) {
    identity(threadId, '聊天标识'); hostId(id);
    return this.#transaction(() => {
      const now = Date.now();
      this.#expire(now);
      let operation, record;
      const denied = (code, reason) => {
        this.#audit({ threadId, hostId: id, event: 'operation_denied', summary: operationSummary(operation), result: 'denied', reason: code, policyRevision: record?.revision });
        return { status: 'denied', code, reason };
      };
      try { operation = normalizeOperation(input); } catch { return denied('INVALID_OPERATION', '操作参数无效，请检查请求'); }
      const host = this.#row(id);
      if (!host) return denied('HOST_NOT_FOUND', '主机不存在');
      record = this.#policy(id);
      if (!JSON.parse(host.value).enabled) return denied('HOST_DISABLED', '主机已禁用');
      if (!Number.isSafeInteger(expectedPolicyRevision) || record.revision !== expectedPolicyRevision) return denied('POLICY_CHANGED', '权限策略已变更，请刷新后重试');
      const grant = this.#activeGrant(threadId, id, now);
      if (!grant) return denied('GRANT_REQUIRED', '当前聊天尚未授权该主机，或授权已过期/失效');
      const evaluation = evaluateOperation(record.policy, operation);
      if (!['allow', 'ask', 'deny'].includes(evaluation.decision)) return denied('INVALID_POLICY_DECISION', '策略未给出有效许可');
      if (evaluation.decision === 'deny') return denied(evaluation.code || 'POLICY_DENIED', evaluation.reason || '权限策略拒绝此操作');
      const encoded = JSON.stringify(canonical(operation));
      const digest = createHash('sha256').update(encoded).digest('hex');
      const summary = operationSummary(operation);
      let approved;
      if (evaluation.decision === 'ask') {
        const candidates = this.#db.prepare(`SELECT * FROM approvals WHERE thread_id=? AND host_id=? AND request_hash=?
          AND grant_id=? AND host_revision=? AND policy_revision=? AND expires_at>?
          AND source='legacy' AND status IN ('pending','approved') ORDER BY CASE status WHEN 'approved' THEN 0 ELSE 1 END,created_at DESC`).all(threadId, id, digest, grant.grant_id, host.revision, record.revision, now);
        approved = candidates.find(row => row.status === 'approved');
        if (!approved) {
          const pending = candidates.find(row => row.status === 'pending');
          if (pending) {
            this.#audit({ threadId, hostId: id, event: 'approval_requested', summary, result: 'pending', reason: '相同操作仍待用户批准', policyRevision: record.revision });
            return { status: 'pending', approval: this.#approval(pending) };
          }
          const row = {
            id: randomUUID(), thread_id: threadId, host_id: id, host_revision: host.revision, policy_revision: record.revision,
            grant_id: grant.grant_id, operation: encoded, request_hash: digest, summary,
            reason: evaluation.reason || '此操作需要用户批准', status: 'pending', created_at: now, expires_at: Math.min(now + 300_000, grant.expires_at),
          };
          this.#db.prepare(`INSERT INTO approvals(id,thread_id,host_id,host_revision,policy_revision,grant_id,operation,request_hash,summary,reason,status,created_at,expires_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(row.id, threadId, id, host.revision, record.revision, grant.grant_id, encoded, digest, summary, row.reason, 'pending', now, row.expires_at);
          this.#audit({ threadId, hostId: id, event: 'approval_requested', summary, result: 'pending', reason: '等待用户批准精确操作', policyRevision: record.revision });
          return { status: 'pending', approval: this.#approval(row) };
        }
      }
      const active = this.#db.prepare("SELECT COUNT(*) AS n FROM operations WHERE host_id=? AND status='active' AND expires_at>?").get(id, now).n;
      if (active >= record.policy.maxConcurrent) return denied('CONCURRENCY_LIMIT', '主机正在执行的操作达到并发上限，请稍后重试');
      const operationId = randomUUID();
      if (approved) this.#db.prepare("UPDATE approvals SET status='consumed' WHERE id=? AND status='approved'").run(approved.id);
      this.#db.prepare(`INSERT INTO operations(id,thread_id,host_id,policy_revision,request_hash,summary,status,created_at,expires_at)
        VALUES(?,?,?,?,?,?,'active',?,?)`).run(operationId, threadId, id, record.revision, digest, summary, now, now + (record.policy.timeoutSeconds + 30) * 1000);
      this.#audit({ threadId, hostId: id, operationId, event: 'operation_started', summary, result: 'ready', reason: approved ? '已消费一次性审批' : '策略允许自动执行', policyRevision: record.revision });
      // Execution must use these transaction snapshots, never a pre-gate host lookup.
      return { status: 'ready', operationId, host: JSON.parse(host.value), policy: record.policy, evaluation };
    });
  }

  resolveApproval(actorThreadId, id, decision) {
    identity(actorThreadId, '聊天标识'); identity(id, '审批标识');
    if (!['approve', 'deny'].includes(decision)) throw new Error('审批决定无效');
    return this.#transaction(() => {
      const now = Date.now();
      this.#expire(now);
      const row = this.#db.prepare('SELECT * FROM approvals WHERE id=?').get(id);
      if (!row || row.source === 'native') throw new Error('操作审批不存在或必须由原生确认流程处理');
      if (row.status !== 'pending') return this.#approval(row);
      const grant = this.#activeGrant(row.thread_id, row.host_id, now);
      const host = this.#row(row.host_id);
      const valid = grant && host && grant.grant_id === row.grant_id && host.revision === row.host_revision && grant.policy_revision === row.policy_revision;
      row.status = !valid ? 'invalidated' : decision === 'approve' ? 'approved' : 'denied';
      this.#db.prepare('UPDATE approvals SET status=? WHERE id=?').run(row.status, id);
      this.#audit({ threadId: actorThreadId, hostId: row.host_id, event: 'approval_resolved', summary: row.summary, result: row.status, reason: !valid ? '主机、授权或策略已变更' : decision === 'approve' ? '已批准一次；原请求聊天需重试，尚未执行' : '用户拒绝执行', policyRevision: row.policy_revision });
      return this.#approval(row);
    });
  }

  getApproval(threadId, id) {
    identity(threadId, '聊天标识'); identity(id, '审批标识');
    return this.#transaction(() => {
      this.#expire(Date.now());
      const row = this.#db.prepare('SELECT * FROM approvals WHERE id=? AND thread_id=?').get(id, threadId);
      return row ? this.#approval(row) : null;
    });
  }

  listApprovals({ hostId: id, threadId, status = 'pending', limit } = {}) {
    if (id !== undefined) hostId(id);
    if (threadId !== undefined) identity(threadId, '聊天标识');
    if (!['pending', 'all'].includes(status)) throw new Error('审批筛选状态无效');
    const count = pageLimit(limit);
    return this.#transaction(() => {
      this.#expire(Date.now());
      const clauses = [], args = [];
      if (id !== undefined) { clauses.push('host_id=?'); args.push(id); }
      if (threadId !== undefined) { clauses.push('thread_id=?'); args.push(threadId); }
      if (status === 'pending') clauses.push("status='pending'");
      const rows = this.#db.prepare(`SELECT * FROM approvals ${clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''} ORDER BY created_at DESC,rowid DESC LIMIT ?`).all(...args, count);
      return { items: rows.map(row => this.#approval(row)) };
    });
  }

  listAudit({ hostId: id, threadId, result, beforeId, limit } = {}) {
    if (id !== undefined) hostId(id);
    if (threadId !== undefined) identity(threadId, '聊天标识');
    if (result !== undefined) text(result, '审计结果', 64);
    if (beforeId !== undefined && (!Number.isSafeInteger(beforeId) || beforeId < 1)) throw new Error('审计分页位置无效');
    const count = pageLimit(limit);
    return this.#transaction(() => {
      const clauses = [], args = [];
      for (const [column, value] of [['host_id', id], ['thread_id', threadId], ['result', result]]) {
        if (value !== undefined) { clauses.push(`${column}=?`); args.push(value); }
      }
      if (beforeId !== undefined) { clauses.push('id<?'); args.push(beforeId); }
      const rows = this.#db.prepare(`SELECT * FROM audit ${clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`).all(...args, count + 1);
      const items = rows.slice(0, count).map(row => ({
        id: row.id, createdAt: row.created_at, threadId: row.thread_id, hostId: row.host_id, event: row.event,
        ...(row.operation_id ? { operationId: row.operation_id } : {}), summary: row.summary, result: row.result, reason: row.reason,
        ...(row.policy_revision !== null ? { policyRevision: row.policy_revision } : {}),
      }));
      return { items, nextCursor: rows.length > count ? items.at(-1).id : null };
    }, false);
  }

  #history(row, detail = false) {
    const item = {
      id: row.id, operationId: row.operation_id, threadId: row.thread_id, hostId: row.host_id,
      summary: row.summary, explanation: row.explanation, status: row.status,
      startedAt: row.started_at, finishedAt: row.finished_at, exitCode: row.exit_code,
      completionKnown: Boolean(row.completion_known), truncated: Boolean(row.truncated),
      redacted: Boolean(row.redacted), outputNotice: row.output_notice,
    };
    if (!detail) return item;
    const snapshot = JSON.parse(row.snapshot);
    return { ...item, hostSnapshot: snapshot.hostSnapshot, operationSnapshot: snapshot.operationSnapshot,
      requestedCommand: snapshot.requestedCommand, command: snapshot.command, cwd: snapshot.cwd,
      stdout: row.stdout, stderr: row.stderr, policyRevision: row.policy_revision };
  }

  listHistory({ hostId: id, threadId, status, beforeId, limit } = {}) {
    if (id !== undefined) hostId(id);
    if (threadId !== undefined) identity(threadId, '聊天标识');
    if (status !== undefined && !['running', 'completed', 'failed', 'timed_out', 'cancelled', 'unknown'].includes(status)) throw new Error('执行历史筛选状态无效');
    if (beforeId !== undefined && (!Number.isSafeInteger(beforeId) || beforeId < 1)) throw new Error('执行历史分页位置无效');
    const count = pageLimit(limit);
    return this.#transaction(() => {
      const now = Date.now(); this.#expire(now); this.#pruneHistory(now);
      const clauses = [], args = [];
      for (const [column, value] of [['host_id', id], ['thread_id', threadId], ['status', status]]) {
        if (value !== undefined) { clauses.push(`${column}=?`); args.push(value); }
      }
      if (beforeId !== undefined) { clauses.push('id<?'); args.push(beforeId); }
      const rows = this.#db.prepare(`SELECT * FROM execution_history ${clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`).all(...args, count + 1);
      const items = rows.slice(0, count).map(row => this.#history(row));
      return { items, nextCursor: rows.length > count ? items.at(-1).id : null };
    });
  }

  getHistory(id) {
    if (!Number.isSafeInteger(id) || id < 1) throw new Error('执行历史标识无效');
    return this.#transaction(() => {
      const now = Date.now(); this.#expire(now); this.#pruneHistory(now);
      const row = this.#db.prepare('SELECT * FROM execution_history WHERE id=?').get(id);
      return row ? this.#history(row, true) : null;
    });
  }

  finishOperation(operationId, { status, exitCode, stdout = '', stderr = '', truncated = false, sensitiveOutput = false, reason: _reason, taskId: _taskId } = {}) {
    identity(operationId, '操作标识');
    if (!['completed', 'failed', 'timed_out', 'cancelled'].includes(status)) throw new Error('操作结束状态无效');
    if (exitCode !== undefined && exitCode !== null && !Number.isSafeInteger(exitCode)) throw new Error('退出码无效');
    const output = sanitizeHistoryOutput({ stdout, stderr, truncated, sensitiveOutput });
    this.#transaction(() => {
      const row = this.#db.prepare('SELECT * FROM operations WHERE id=?').get(operationId);
      const history = this.#db.prepare('SELECT status,completion_known FROM execution_history WHERE operation_id=?').get(operationId);
      if (!row || history?.completion_known || (row.status !== 'active' && !(history?.status === 'unknown' && !history.completion_known))) return;
      this.#db.prepare('UPDATE operations SET status=? WHERE id=?').run(status, operationId);
      if (history) {
        this.#db.prepare(`UPDATE execution_history SET status=?,finished_at=?,exit_code=?,completion_known=1,
          stdout=?,stderr=?,truncated=?,redacted=?,output_notice=? WHERE operation_id=?`)
          .run(status, Date.now(), exitCode ?? null, output.stdout, output.stderr, Number(output.truncated), Number(output.redacted), output.outputNotice, operationId);
      }
      const reason = ({ completed: '操作已完成', failed: '操作执行失败', timed_out: '操作超时', cancelled: '操作已取消' })[status] + (Number.isSafeInteger(exitCode) ? `；退出码 ${exitCode}` : '');
      this.#audit({ threadId: row.thread_id, hostId: row.host_id, event: 'operation_finished', operationId, summary: row.summary, result: status, reason, policyRevision: row.policy_revision });
      this.#pruneHistory();
    });
  }

  recordIntent({ sessionId, turnId, operation, hostIds, expiresAt }) {
    identity(sessionId, '会话标识'); identity(turnId, '轮次标识');
    if (!['grant', 'revoke', 'status'].includes(operation)) throw new Error('快捷授权操作无效');
    const values = ids(hostIds);
    if (operation === 'status' && values.length) throw new Error('状态查询不能指定授权主机');
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new Error('授权请求过期时间无效');
    const encoded = JSON.stringify(values);
    this.#transaction(() => {
      const existing = this.#db.prepare('SELECT operation,host_ids,expires_at FROM intents WHERE session_id=? AND turn_id=?').get(sessionId, turnId);
      if (existing) {
        if (existing.operation !== operation || existing.host_ids !== encoded || existing.expires_at !== expiresAt) throw new Error('同一轮次已记录授权请求，不允许替换或重新激活');
        return;
      }
      const revisions = {};
      for (const id of values) {
        const row = this.#row(id);
        if (operation === 'grant') {
          if (!row) throw new Error(`主机不存在：${id}`);
          if (!JSON.parse(row.value).enabled) throw new Error(`主机已禁用，请先启用：${id}`);
        }
        revisions[id] = row ? { host: row.revision, policy: this.#policy(id).revision } : null;
      }
      const revocationRevision = this.#db.prepare('SELECT COALESCE(MAX(revision),0) AS revision FROM intent_revocations').get().revision;
      this.#db.prepare('INSERT INTO intents(session_id,turn_id,operation,host_ids,revisions,expires_at,revocation_revision) VALUES(?,?,?,?,?,?,?)')
        .run(sessionId, turnId, operation, encoded, JSON.stringify(revisions), expiresAt, revocationRevision);
    });
  }

  consumeIntent({ threadId, sessionId, turnId, now = Date.now() }) {
    identity(threadId, '聊天标识'); identity(sessionId, '会话标识'); identity(turnId, '轮次标识');
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('当前时间无效');
    const result = this.#transaction(() => {
      const intent = this.#db.prepare('SELECT * FROM intents WHERE session_id=? AND turn_id=?').get(sessionId, turnId);
      if (!intent || intent.consumed_at !== null) return { state: this.#state(threadId) };
      this.#db.prepare('UPDATE intents SET consumed_at=?,consumed_thread_id=? WHERE session_id=? AND turn_id=?').run(now, threadId, sessionId, turnId);
      const invalid = reason => {
        this.#audit({ threadId, event: 'intent_denied', summary: '快捷授权请求', result: 'denied', reason });
        return { error: reason };
      };
      if (intent.expires_at <= now) return invalid('授权请求已过期，请重新发送快捷命令');
      const values = JSON.parse(intent.host_ids);
      if (intent.operation === 'grant') {
        if (!Number.isSafeInteger(intent.revocation_revision)) return invalid('旧版本授权请求已失效，请重新发送快捷命令');
        const revisions = JSON.parse(intent.revisions);
        for (const id of values) {
          const revocation = this.#db.prepare('SELECT revision FROM intent_revocations WHERE thread_id=? AND host_id=?').get(threadId, id);
          if (revocation && revocation.revision > intent.revocation_revision) return invalid('当前聊天已撤销此主机，旧授权请求已失效，请重新发送快捷命令');
          const row = this.#row(id);
          const expected = revisions[id];
          const hostRevision = typeof expected === 'string' ? expected : expected?.host;
          const policyRevision = typeof expected === 'string' ? 1 : expected?.policy;
          if (!row || row.revision !== hostRevision || !JSON.parse(row.value).enabled || this.#policy(id).revision !== policyRevision) return invalid('主机配置或权限策略已变更，授权请求已失效，请重新确认');
        }
        this.#grant(threadId, values, { source: 'shortcut' });
      } else if (intent.operation === 'revoke') this.#revoke(threadId, values);
      return { state: this.#state(threadId) };
    });
    if (result.error) throw new Error(result.error);
    return result.state;
  }
}
