import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { spawn } from 'node:child_process';
import { Store } from '../src/store.mjs';

const source = new URL('../src/store.mjs', import.meta.url);
const sample = { id: 'prod', hostname: 'prod.example.test', username: 'deploy', enabled: true };
const restart = { kind: 'action', actionId: 'service.restart', args: { name: 'nginx' } };
const read = { kind: 'action', actionId: 'disk.usage', args: {} };

function fixture(t, createHost = true) {
  const directory = mkdtempSync(join(tmpdir(), 'ssh-governance-test-'));
  const stores = [];
  const open = () => { const store = new Store(directory); stores.push(store); return store; };
  t.after(() => { for (const s of stores) s.close(); rmSync(directory, { recursive: true, force: true }); });
  const store = open();
  if (createHost) { store.saveHost(sample); policy(store, { mode: 'restricted' }); }
  return { directory, store, open };
}

function policy(store, changes) {
  const current = store.getPolicy('prod');
  return store.savePolicy('user', 'prod', { ...current.policy, ...changes }, current.revision);
}

function begin(store, operation = restart, thread = 'chat', revision = store.getPolicy('prod').revision) {
  return store.beginOperation(thread, 'prod', operation, { decision: 'allow', summary: 'untrusted' }, revision);
}

test('legacy migration preserves hosts and grants but adds bounded revision-bound expiry only once', t => {
  const directory = mkdtempSync(join(tmpdir(), 'ssh-governance-legacy-'));
  const db = new DatabaseSync(join(directory, 'store.sqlite'));
  db.exec('CREATE TABLE hosts(id TEXT PRIMARY KEY,value TEXT NOT NULL,revision TEXT NOT NULL); CREATE TABLE grants(thread_id TEXT NOT NULL,host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,PRIMARY KEY(thread_id,host_id));');
  db.prepare('INSERT INTO hosts VALUES(?,?,?)').run('prod', JSON.stringify(sample), 'old-host-revision');
  db.prepare('INSERT INTO grants VALUES(?,?)').run('chat', 'prod');
  db.close();
  const before = Date.now();
  const store = new Store(directory);
  t.after(() => { store.close(); rmSync(directory, { recursive: true, force: true }); });
  assert.equal(typeof store.getPolicy, 'function', 'governance migration API exists');
  assert.equal(store.getPolicy('prod').policy.mode, 'restricted');
  assert.deepEqual(store.getPolicy('prod').policy.roots, []);
  const [grant] = store.state('chat').grants;
  assert.ok(grant.expiresAt >= before + 3_600_000 && grant.expiresAt < before + 3_610_000);
  assert.equal(grant.policyRevision, 1);
  const other = new Store(directory);
  try { assert.equal(other.state('chat').grants[0].expiresAt, grant.expiresAt); } finally { other.close(); }
});

test('grants have policy-capped lifetimes, expire, and never revive after disable', t => {
  const { store } = fixture(t);
  policy(store, { grantMinutes: 5 });
  assert.throws(() => store.grant('chat', ['prod'], { minutes: 6 }), /授权|期限|分钟/);
  const state = store.grant('chat', ['prod']);
  assert.ok(state.grants[0].expiresAt <= Date.now() + 300_000);
  const now = state.grants[0].expiresAt;
  t.mock.method(Date, 'now', () => now);
  assert.deepEqual(store.state('chat').grantedHostIds, []);
  assert.throws(() => store.requireHost('chat', 'prod'), /授权|过期/);
  store.grant('chat', ['prod']);
  store.setEnabled('prod', false); store.setEnabled('prod', true);
  assert.deepEqual(store.state('chat').grantedHostIds, []);
});

test('policy save validates atomically and rejects optimistic concurrency conflicts', t => {
  const { store, open } = fixture(t);
  const initial = store.getPolicy('prod');
  store.grant('chat', ['prod']);
  assert.throws(() => store.savePolicy('user', 'prod', { ...initial.policy, surprise: true }, initial.revision));
  assert.deepEqual(store.state('chat').grantedHostIds, ['prod']);
  const approval = begin(store).approval;
  const saved = policy(open(), { timeoutSeconds: 30 });
  assert.equal(saved.revision, initial.revision + 1);
  assert.deepEqual(store.state('chat').grantedHostIds, []);
  assert.equal(store.listApprovals({ status: 'all' }).items.find(a => a.id === approval.id).status, 'invalidated');
  assert.throws(() => store.savePolicy('user', 'prod', initial.policy, initial.revision), /版本|变更|冲突/);
  assert.equal(store.getPolicy('prod').policy.timeoutSeconds, 30);
});

test('operation gate reevaluates trusted policy and audits rejected ungranted or stale calls', t => {
  const { store } = fixture(t);
  assert.equal(begin(store, read).status, 'denied');
  store.grant('chat', ['prod']);
  assert.equal(begin(store, read, 'chat', 0).status, 'denied');
  assert.equal(begin(store).status, 'pending', 'caller allow decision must not bypass write approval');
  assert.equal(begin(store, { kind: 'read', path: '/etc/shadow' }).status, 'denied');
  assert.equal(begin(store, { kind: 'action', actionId: 'missing', args: {} }).status, 'denied');
  assert.ok(store.listAudit({ result: 'denied' }).items.length >= 4);
});

test('approval is deduplicated while pending and consumed exactly once for canonical full payload', t => {
  const { store } = fixture(t);
  policy(store, { roots: [{ id: 'app', path: '/srv/app', read: true, write: true }] });
  store.grant('chat', ['prod']);
  const operation = { kind: 'write', path: '/srv/app/demo.txt', content: 'first content' };
  const first = begin(store, operation);
  assert.equal(first.status, 'pending');
  assert.equal(begin(store, { content: 'first content', path: operation.path, kind: 'write' }).approval.id, first.approval.id);
  assert.notEqual(begin(store, { ...operation, content: 'second content' }).approval.id, first.approval.id);
  assert.equal(store.state('chat').pendingApprovalCount, 2);
  assert.equal(store.resolveApproval('user', first.approval.id, 'approve').status, 'approved');
  const ready = begin(store, operation);
  assert.equal(ready.status, 'ready');
  assert.equal(store.listApprovals({ status: 'all' }).items.find(a => a.id === first.approval.id).status, 'consumed');
  store.finishOperation(ready.operationId, { status: 'completed', exitCode: 0 });
  assert.equal(begin(store, operation).status, 'pending');
});

test('approval is bound to requester, grant generation, host revision and five-minute deadline', t => {
  const { store } = fixture(t);
  store.grant('chat', ['prod']); store.grant('other', ['prod']);
  const first = begin(store).approval;
  store.resolveApproval('user', first.id, 'approve');
  assert.equal(begin(store, restart, 'other').status, 'pending');
  store.grant('chat', ['prod']);
  assert.equal(store.listApprovals({ status: 'all' }).items.find(a => a.id === first.id).status, 'invalidated');
  const second = begin(store).approval;
  t.mock.method(Date, 'now', () => second.expiresAt);
  assert.equal(store.resolveApproval('user', second.id, 'approve').status, 'expired');
  assert.equal(begin(store).status, 'pending');
  store.saveHost({ id: 'prod', hostname: 'changed.example.test' });
  assert.equal(begin(store).status, 'denied');
});

test('denial cannot be flipped into approval and reauthorization invalidates revoked approvals', t => {
  const { store } = fixture(t);
  store.grant('chat', ['prod']);
  const approval = begin(store).approval;
  store.resolveApproval('user', approval.id, 'deny');
  assert.equal(store.resolveApproval('user', approval.id, 'approve').status, 'denied');
  const next = begin(store).approval;
  store.revoke('chat', ['prod']); store.grant('chat', ['prod']);
  assert.equal(store.resolveApproval('user', next.id, 'approve').status, 'invalidated');
  assert.equal(begin(store).status, 'pending');
});

test('execution concurrency is enforced across connections and reclaimed after completion or lease expiry', t => {
  const { store, open } = fixture(t);
  policy(store, { maxConcurrent: 1, timeoutSeconds: 1 });
  store.grant('chat', ['prod']);
  const other = open();
  const first = begin(store, read);
  assert.equal(first.status, 'ready');
  assert.equal(begin(other, read).status, 'denied');
  store.finishOperation(first.operationId, { status: 'completed' });
  const second = begin(other, read);
  assert.equal(second.status, 'ready');
  const now = Date.now() + 32_000;
  t.mock.method(Date, 'now', () => now);
  assert.equal(begin(store, read).status, 'ready');
  assert.ok(store.listAudit().items.some(a => a.operationId === second.operationId && a.result === 'timed_out'));
});

test('audit failure rolls back approval consumption and execution lease creation', t => {
  const { store, directory } = fixture(t);
  store.grant('chat', ['prod']);
  const approval = begin(store).approval;
  store.resolveApproval('user', approval.id, 'approve');
  const db = new DatabaseSync(join(directory, 'store.sqlite'));
  db.exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;");
  assert.throws(() => begin(store), /audit unavailable/);
  assert.equal(store.listApprovals({ status: 'all' }).items.find(a => a.id === approval.id).status, 'approved');
  db.exec('DROP TRIGGER fail_audit'); db.close();
  assert.equal(begin(store).status, 'ready');
});

test('audit omits command text, write content, and arbitrary remote completion errors; filters paginate', t => {
  const { store } = fixture(t);
  policy(store, { mode: 'approval', roots: [{ id: 'app', path: '/srv/app', read: true, write: true }] });
  store.grant('chat', ['prod']);
  const operation = { kind: 'command', command: 'echo private-payload-462715', cwd: '/srv/app' };
  const a = begin(store, operation).approval;
  store.resolveApproval('user', a.id, 'approve');
  const ready = begin(store, operation);
  store.finishOperation(ready.operationId, { status: 'failed', reason: 'private-payload-462715', exitCode: 1 });
  begin(store, { kind: 'write', path: '/srv/app/x', content: 'private-content-873164' });
  const audit = store.listAudit({ hostId: 'prod', limit: 2 });
  assert.equal(audit.items.length, 2);
  assert.ok(audit.nextCursor);
  const next = store.listAudit({ beforeId: audit.nextCursor, limit: 2 });
  assert.ok(next.items.every(a => a.id < audit.nextCursor));
  assert.doesNotMatch(JSON.stringify(store.listAudit({ limit: 100 })), /private-payload-462715|private-content-873164/);
  assert.equal(store.listAudit({ result: 'failed' }).items.length, 1);
  assert.throws(() => store.listAudit({ limit: 101 }));
});

test('shortcut intents become invalid after policy revision, even when host fields did not change', t => {
  const { store } = fixture(t);
  store.recordIntent({ sessionId: 's', turnId: 't', operation: 'grant', hostIds: ['prod'], expiresAt: Date.now() + 10000 });
  policy(store, { grantMinutes: 5 });
  assert.throws(() => store.consumeIntent({ threadId: 'chat', sessionId: 's', turnId: 't' }), /变更|失效/);
  assert.deepEqual(store.state('chat').grantedHostIds, []);
});

test('competing processes consume one approved request only once', async t => {
  const { store, directory } = fixture(t);
  store.grant('chat', ['prod']);
  const approval = begin(store).approval;
  store.resolveApproval('user', approval.id, 'approve');
  const code = `import { Store } from ${JSON.stringify(source.href)}; const s = new Store(process.argv[1]); const r = s.beginOperation('chat','prod',${JSON.stringify(restart)}, {decision:'allow'},s.getPolicy('prod').revision); process.stdout.write(JSON.stringify(r)); s.close();`;
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', code, directory], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = ''; child.stdout.on('data', d => { out += d; }); child.stderr.on('data', d => { err += d; });
    child.on('error', reject); child.on('close', c => c === 0 ? resolve(JSON.parse(out)) : reject(new Error(err)));
  });
  const results = await Promise.all([run(), run()]);
  assert.equal(results.filter(r => r.status === 'ready').length, 1);
  assert.equal(results.filter(r => r.status === 'pending').length, 1);
});

test('getApproval isolates exact requester by approval identity', t => {
  const { store } = fixture(t);
  store.grant('chat', ['prod']);
  const approval = begin(store).approval;
  assert.equal(typeof store.getApproval, 'function');
  assert.equal(store.getApproval('chat', approval.id).id, approval.id);
  assert.equal(store.getApproval('fork', approval.id), null);
  assert.equal(store.getApproval('chat', 'unknown'), null);
  assert.throws(() => store.getApproval('', approval.id));
});

test('execution permit returns the exact host configuration checked in its transaction', t => {
  const { store, open } = fixture(t);
  store.grant('chat', ['prod']);
  const previous = store.requireHost('chat', 'prod');
  const other = open();
  other.saveHost({ id: 'prod', hostname: 'new-target.example.test' });
  other.grant('chat', ['prod']);
  const permit = begin(store, read);
  assert.equal(permit.status, 'ready');
  assert.equal(permit.host?.hostname, 'new-target.example.test');
  assert.notEqual(permit.host?.hostname, previous.hostname);
  assert.equal(permit.policy.timeoutSeconds, store.getPolicy('prod').policy.timeoutSeconds);
  assert.equal(permit.evaluation.decision, 'allow');
  assert.equal(permit.evaluation.operation.actionId, 'disk.usage');
});

test('migration rolls back schema changes and legacy grants if audit cannot be written', t => {
  const directory = mkdtempSync(join(tmpdir(), 'ssh-governance-rollback-'));
  const db = new DatabaseSync(join(directory, 'store.sqlite'));
  t.after(() => { db.close(); rmSync(directory, { recursive: true, force: true }); });
  db.exec(`CREATE TABLE hosts(id TEXT PRIMARY KEY,value TEXT NOT NULL,revision TEXT NOT NULL);
    CREATE TABLE grants(thread_id TEXT NOT NULL,host_id TEXT NOT NULL REFERENCES hosts(id),PRIMARY KEY(thread_id,host_id));
    CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at INTEGER NOT NULL,thread_id TEXT,host_id TEXT,event TEXT NOT NULL,operation_id TEXT,summary TEXT NOT NULL,result TEXT NOT NULL,reason TEXT NOT NULL,policy_revision INTEGER);
    CREATE TRIGGER fail_migration BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'audit unavailable'); END;`);
  db.prepare('INSERT INTO hosts VALUES(?,?,?)').run('prod', JSON.stringify(sample), 'legacy');
  db.prepare('INSERT INTO grants VALUES(?,?)').run('chat', 'prod');
  assert.throws(() => new Store(directory), /audit unavailable/);
  assert.equal(db.prepare('PRAGMA user_version').get().user_version, 0);
  assert.deepEqual(db.prepare('PRAGMA table_info(grants)').all().map(r => r.name), ['thread_id', 'host_id']);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM grants').get().n, 1);
  assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='policies'").get(), undefined);
});

test('approval lifetime is capped by grant expiry and raw command working directory is hashed', t => {
  const { store } = fixture(t);
  policy(store, { mode: 'approval' });
  const expiresAt = store.grant('chat', ['prod'], { minutes: 1 }).grants[0].expiresAt;
  const op = { kind: 'command', command: 'echo hello', cwd: '/srv/app' };
  const a = begin(store, op).approval;
  assert.equal(a.expiresAt, expiresAt);
  assert.notEqual(begin(store, { ...op, cwd: '/srv/other' }).approval.requestHash, a.requestHash);
});

test('busy concurrency rejection preserves approved request until its operation can acquire a lease', t => {
  const { store } = fixture(t);
  policy(store, { maxConcurrent: 1 });
  store.grant('chat', ['prod']);
  const active = begin(store, read);
  const approval = begin(store).approval;
  store.resolveApproval('user', approval.id, 'approve');
  assert.equal(begin(store).code, 'CONCURRENCY_LIMIT');
  assert.equal(store.getApproval('chat', approval.id).status, 'approved');
  store.finishOperation(active.operationId, { status: 'completed' });
  assert.equal(begin(store).status, 'ready');
});

test('audit retention keeps the newest 5000 entries and completion remains idempotent', t => {
  const { store, directory } = fixture(t);
  store.grant('chat', ['prod']);
  const db = new DatabaseSync(join(directory, 'store.sqlite'));
  db.exec(`WITH RECURSIVE sequence(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM sequence WHERE n<5100)
    INSERT INTO audit(created_at,event,summary,result,reason) SELECT n,'seed','fixture','completed','' FROM sequence;`);
  const ready = begin(store, read);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 5000);
  store.finishOperation(ready.operationId, { status: 'cancelled' });
  store.finishOperation(ready.operationId, { status: 'completed' });
  assert.equal(store.listAudit({ result: 'cancelled' }).items.length, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM audit').get().n, 5000);
  db.close();
});

test('native grant confirmation rejects policy changes while the displayed authorization is pending', t => {
  const { store, open } = fixture(t);
  policy(store, { grantMinutes: 5 });
  assert.equal(typeof store.authorizationPreview, 'function');
  const preview = store.authorizationPreview(['prod']);
  assert.equal(preview[0].host.id, 'prod');
  assert.equal(preview[0].grantMinutes, 5);
  assert.ok(preview[0].hostRevision);
  policy(open(), { grantMinutes: 1440 });
  assert.throws(() => store.grantConfirmed('chat', preview.map(p => p.host), { expectedSnapshots: preview }), /变更|确认|策略|期限/);
  assert.deepEqual(store.state('chat').grantedHostIds, []);
  const current = store.authorizationPreview(['prod']);
  const state = store.grantConfirmed('chat', current.map(p => p.host), { expectedSnapshots: current, source: 'native' });
  assert.ok(state.grants[0].expiresAt <= Date.now() + 1440 * 60_000);
});

test('native grant preview prevents host and policy ABA even if displayed values return to their originals', t => {
  const { store } = fixture(t);
  let preview = store.authorizationPreview(['prod']);
  store.setEnabled('prod', false); store.setEnabled('prod', true);
  assert.throws(() => store.grantConfirmed('chat', preview.map(p => p.host), { expectedSnapshots: preview }), /变更|确认/);
  preview = store.authorizationPreview(['prod']);
  policy(store, { grantMinutes: 5 }); policy(store, { grantMinutes: 60 });
  assert.throws(() => store.grantConfirmed('chat', preview.map(p => p.host), { expectedSnapshots: preview }), /变更|确认/);
  assert.deepEqual(store.state('chat').grantedHostIds, []);
});

test('native grant snapshots must cover exactly the shown host set and preserve multi-host atomicity', t => {
  const { store } = fixture(t);
  store.saveHost({ ...sample, id: 'uat', hostname: 'uat.example.test' });
  const preview = store.authorizationPreview(['prod', 'uat']);
  assert.throws(() => store.grantConfirmed('chat', preview.map(p => p.host), { expectedSnapshots: preview.slice(0, 1) }), /快照|确认|主机/);
  assert.throws(() => store.grantConfirmed('chat', preview.map(p => p.host), { expectedSnapshots: [preview[0], preview[0]] }), /快照|确认|主机/);
  const record = store.getPolicy('uat');
  store.savePolicy('user', 'uat', { ...record.policy, grantMinutes: 5 }, record.revision);
  assert.throws(() => store.grantConfirmed('chat', preview.map(p => p.host), { expectedSnapshots: preview }), /变更|确认/);
  assert.deepEqual(store.state('chat').grantedHostIds, []);
  store.setEnabled('uat', false);
  assert.throws(() => store.authorizationPreview(['prod', 'uat']), /禁用|启用/);
});
