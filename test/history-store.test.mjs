import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { spawn } from 'node:child_process';
import { Store } from '../src/store.mjs';

const source = new URL('../src/store.mjs', import.meta.url);
const read = { kind: 'action', actionId: 'disk.usage', args: {} };
const mutation = { kind: 'action', actionId: 'container.restart', args: { name: 'app' } };
const explanation = '重启应用以加载已审核的配置';

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'ssh-native-store-'));
  const stores = [];
  const open = () => { const store = new Store(directory); stores.push(store); return store; };
  const store = open();
  store.saveHost({ id: 'prod', name: '测试主机', hostname: 'prod.example.test', username: 'deploy', identityFile: '/not-a-real-key', enabled: true });
  store.grant('chat', ['prod']);
  t.after(() => { for (const s of stores) s.close(); rmSync(directory, { recursive: true, force: true }); });
  return { store, directory, open };
}

function begin(store, operation = mutation, purpose = explanation, token = randomUUID(), thread = 'chat') {
  return { token, result: store.beginNativeOperation(thread, 'prod', operation, purpose, token, store.getPolicy('prod').revision) };
}

function grantPolicy(store, changes) {
  const record = store.getPolicy('prod');
  store.savePolicy('user', 'prod', { ...record.policy, ...changes }, record.revision);
  store.grant('chat', ['prod']);
}

test('native calls need exact independent confirmation tickets and never return the private nonce', t => {
  const { store } = fixture(t);
  assert.equal(typeof store.beginNativeOperation, 'function');
  const a = begin(store), b = begin(store);
  assert.equal(a.result.status, 'pending');
  assert.notEqual(a.result.approval.id, b.result.approval.id);
  assert.equal(a.result.approval.requestHash, b.result.approval.requestHash);
  assert.equal(a.result.approval.presentation.explanation, explanation);
  assert.equal(a.result.approval.host.id, 'prod');
  assert.ok(a.result.approval.policy);
  assert.ok(!JSON.stringify(a.result).includes(a.token));
  assert.equal(store.completeNativeApproval('chat', a.result.approval.id, b.token, 'approve').status, 'denied');
  assert.equal(store.completeNativeApproval('other', a.result.approval.id, a.token, 'approve').status, 'denied');
  const ready = store.completeNativeApproval('chat', a.result.approval.id, a.token, 'approve');
  assert.equal(ready.status, 'ready');
  assert.equal(store.completeNativeApproval('chat', a.result.approval.id, a.token, 'approve').status, 'denied');
  assert.equal(store.completeNativeApproval('chat', b.result.approval.id, b.token, 'deny').status, 'denied');
  assert.equal(store.completeNativeApproval('chat', b.result.approval.id, b.token, 'approve').status, 'denied');
  assert.equal(store.listHistory().items.length, 1);
});

test('legacy approval methods cannot resolve or consume native tickets with the same digest', t => {
  const { store } = fixture(t);
  const a = begin(store);
  assert.throws(() => store.resolveApproval('chat', a.result.approval.id, 'approve'), /原生|不可|不存在/);
  const old = store.beginOperation('chat', 'prod', mutation, null, store.getPolicy('prod').revision);
  assert.equal(old.status, 'pending');
  assert.notEqual(old.approval.id, a.result.approval.id);
  assert.equal(store.listHistory().items.length, 0);
  assert.equal(store.completeNativeApproval('chat', a.result.approval.id, a.token, 'approve').status, 'ready');
});

test('explanations are normalized and bound to the exact immutable approval request', t => {
  const { store } = fixture(t);
  const a = begin(store, mutation, '  ' + explanation + '  '), b = begin(store, mutation, '应用更新后需要重新启动容器');
  assert.equal(a.result.approval.explanation, explanation);
  assert.notEqual(a.result.approval.requestHash, b.result.approval.requestHash);
  const invalid = begin(store, mutation, 'x');
  assert.equal(invalid.result.status, 'denied');
  const safe = begin(store, read, undefined);
  assert.equal(safe.result.status, 'ready');
  assert.ok(safe.result.presentation.explanation);
});

test('decline, cancel, expiration, revoked grants and changed policy never create execution history', t => {
  const { store } = fixture(t);
  for (const decision of ['deny', 'cancel']) {
    const a = begin(store);
    assert.equal(store.completeNativeApproval('chat', a.result.approval.id, a.token, decision).status, 'denied');
  }
  const expired = begin(store);
  assert.ok(expired.result.approval.expiresAt <= Date.now() + 120_000);
  const now = expired.result.approval.expiresAt;
  t.mock.method(Date, 'now', () => now);
  assert.equal(store.completeNativeApproval('chat', expired.result.approval.id, expired.token, 'approve').status, 'denied');
  const revoked = begin(store);
  store.revoke('chat', ['prod']); store.grant('chat', ['prod']);
  assert.equal(store.completeNativeApproval('chat', revoked.result.approval.id, revoked.token, 'approve').status, 'denied');
  const changed = begin(store);
  grantPolicy(store, { timeoutSeconds: 10 });
  assert.equal(store.completeNativeApproval('chat', changed.result.approval.id, changed.token, 'approve').status, 'denied');
  assert.equal(store.listHistory().items.length, 0);
});

test('native pending limit is per host/thread and cancelled tickets free capacity without leasing', t => {
  const { store } = fixture(t);
  const tickets = Array.from({ length: 16 }, () => begin(store));
  assert.ok(tickets.every(t => t.result.status === 'pending'));
  assert.equal(begin(store).result.status, 'denied');
  store.grant('other', ['prod']);
  assert.equal(begin(store, mutation, explanation, randomUUID(), 'other').result.status, 'pending');
  store.completeNativeApproval('chat', tickets[0].result.approval.id, tickets[0].token, 'cancel');
  assert.equal(begin(store).result.status, 'pending');
  assert.equal(store.listHistory().items.length, 0);
});

test('native approval rechecks concurrency and terminally invalidates a busy acceptance', t => {
  const { store } = fixture(t);
  grantPolicy(store, { maxConcurrent: 1 });
  const pending = begin(store);
  const running = begin(store, read, '').result;
  assert.equal(running.status, 'ready');
  assert.equal(store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve').code, 'CONCURRENCY_LIMIT');
  store.finishOperation(running.operationId, { status: 'completed' });
  assert.equal(store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve').status, 'denied');
});

test('history survives reopening and lists omit full commands and output bodies', t => {
  const { store, open } = fixture(t);
  const ready = begin(store, read, '').result;
  assert.equal(ready.status, 'ready');
  let entry = store.listHistory().items[0];
  assert.equal(entry.status, 'running'); assert.equal(entry.completionKnown, false);
  store.finishOperation(ready.operationId, { status: 'completed', exitCode: 0, stdout: 'fixture-output-body', stderr: 'fixture-warning' });
  entry = open().getHistory(entry.id);
  assert.equal(entry.status, 'completed'); assert.equal(entry.completionKnown, true);
  assert.equal(entry.stdout, 'fixture-output-body'); assert.equal(entry.stderr, 'fixture-warning');
  assert.match(entry.command, /\/usr\/bin\/df/);
  assert.equal(entry.hostSnapshot.id, 'prod'); assert.ok(!JSON.stringify(entry.hostSnapshot).includes('/not-a-real-key'));
  assert.equal(store.getHistory(987654321), null);
  const list = store.listHistory().items[0];
  for (const field of ['stdout', 'stderr', 'command', 'requestedCommand', 'operationSnapshot', 'hostSnapshot']) assert.equal(field in list, false, field);
  assert.ok(!JSON.stringify(store.listAudit()).includes('fixture-output-body'));
});

test('history removes write body and never persists recognized sensitive output', t => {
  const { store } = fixture(t);
  grantPolicy(store, { roots: [{ id: 'app', path: '/srv/app', read: true, write: true }] });
  const op = { kind: 'write', path: '/srv/app/config.txt', content: 'nonsecret body never duplicated in history' };
  const pending = begin(store, op, '更新应用的普通配置文本');
  const ready = store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve');
  store.finishOperation(ready.operationId, { status: 'completed', exitCode: 0, stdout: 'api_key=fixture-secret-value', stderr: 'normal' });
  const entry = store.getHistory(store.listHistory().items[0].id);
  assert.equal(entry.redacted, true); assert.equal(entry.stdout, ''); assert.equal(entry.stderr, '');
  assert.ok(entry.outputNotice);
  assert.ok(!JSON.stringify(entry).includes(op.content));
  assert.ok(!JSON.stringify(entry).includes('fixture-secret-value'));
  assert.equal(entry.operationSnapshot.bytes, Buffer.byteLength(op.content));
  assert.match(entry.operationSnapshot.sha256, /^[a-f0-9]{64}$/);
});

test('history scans before truncation, honors scanner flags, and truncates on UTF-8 boundaries', t => {
  const { store } = fixture(t);
  for (const output of [{ stdout: 'x'.repeat(40000) + '\npassword=late-fixture' }, { stdout: 'already truncated innocuous text', sensitiveOutput: true }]) {
    const ready = begin(store, read, '').result;
    store.finishOperation(ready.operationId, { status: 'completed', ...output });
    const entry = store.getHistory(store.listHistory().items[0].id);
    assert.equal(entry.redacted, true); assert.equal(entry.stdout, '');
  }
  const ready = begin(store, read, '').result;
  store.finishOperation(ready.operationId, { status: 'completed', stdout: '界'.repeat(20000), stderr: 'x'.repeat(20000) });
  const entry = store.getHistory(store.listHistory().items[0].id);
  assert.ok(Buffer.byteLength(entry.stdout + entry.stderr) <= 32768);
  assert.equal(entry.truncated, true); assert.ok(!entry.stdout.includes('\uFFFD'));
});

test('history and audit failure roll back permit creation and native approval consumption', t => {
  const { store, directory } = fixture(t);
  const pending = begin(store);
  const db = new DatabaseSync(join(directory, 'store.sqlite'));
  try {
    for (const table of ['execution_history', 'audit']) {
      db.exec(`CREATE TRIGGER fail_insert BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT,'fixture storage unavailable'); END`);
      assert.throws(() => store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve'), /storage unavailable/);
      db.exec('DROP TRIGGER fail_insert');
      assert.equal(store.listHistory().items.length, 0);
    }
    const ready = store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve');
    assert.equal(ready.status, 'ready');
    db.exec("CREATE TRIGGER fail_finish BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture finish unavailable'); END");
    assert.throws(() => store.finishOperation(ready.operationId, { status: 'completed', stdout: 'must rollback' }), /finish unavailable/);
    db.exec('DROP TRIGGER fail_finish');
    assert.equal(store.getHistory(store.listHistory().items[0].id).status, 'running');
    store.finishOperation(ready.operationId, { status: 'completed', stdout: 'final' });
    assert.equal(store.getHistory(store.listHistory().items[0].id).stdout, 'final');
  } finally { db.close(); }
});

test('expired execution lease becomes unknown and one actual late completion may fill history', t => {
  const { store } = fixture(t);
  grantPolicy(store, { timeoutSeconds: 1 });
  const ready = begin(store, read, '').result;
  const now = Date.now() + 32_000;
  t.mock.method(Date, 'now', () => now);
  const listed = store.listHistory().items[0];
  assert.equal(listed.status, 'unknown'); assert.equal(listed.completionKnown, false);
  store.finishOperation(ready.operationId, { status: 'completed', stdout: 'late result', exitCode: 0 });
  store.finishOperation(ready.operationId, { status: 'failed', stdout: 'duplicate may not replace', exitCode: 1 });
  const entry = store.getHistory(listed.id);
  assert.equal(entry.status, 'completed'); assert.equal(entry.completionKnown, true); assert.equal(entry.stdout, 'late result');
});

test('history filters and numeric cursor paginate without exposing other result bodies', t => {
  const { store } = fixture(t);
  for (let i = 0; i < 3; i++) { const r = begin(store, read, '').result; store.finishOperation(r.operationId, { status: i === 0 ? 'failed' : 'completed' }); }
  const first = store.listHistory({ limit: 2 });
  assert.equal(first.items.length, 2); assert.ok(first.nextCursor);
  assert.equal(store.listHistory({ beforeId: first.nextCursor }).items.length, 1);
  assert.equal(store.listHistory({ status: 'failed' }).items.length, 1);
  assert.equal(store.listHistory({ threadId: 'other' }).items.length, 0);
  assert.throws(() => store.listHistory({ status: 'bogus' }));
  assert.throws(() => store.listHistory({ limit: 101 }));
});

test('native approvals are consumed once even by competing processes', async t => {
  const { store, directory } = fixture(t);
  const pending = begin(store);
  const code = `import { Store } from ${JSON.stringify(source.href)};const s=new Store(process.argv[1]);const r=s.completeNativeApproval('chat',process.argv[2],process.argv[3],'approve');process.stdout.write(JSON.stringify(r));s.close();`;
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', code, directory, pending.result.approval.id, pending.token], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', error = ''; child.stdout.on('data', x => { output += x; }); child.stderr.on('data', x => { error += x; });
    child.on('error', reject); child.on('close', c => c === 0 ? resolve(JSON.parse(output)) : reject(new Error(error)));
  });
  const results = await Promise.all([run(), run()]);
  assert.equal(results.filter(x => x.status === 'ready').length, 1);
  assert.equal(results.filter(x => x.status === 'denied').length, 1);
  assert.equal(store.listHistory().items.length, 1);
});

test('shutdown cancellation is final and closed stores cannot later accept native confirmation', t => {
  const { store, open } = fixture(t);
  const pending = begin(store);
  store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'cancel');
  store.close();
  assert.throws(() => store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve'), /关闭/);
  assert.equal(open().completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve').status, 'denied');
});

test('history retains only 500 finished entries and 30 days without deleting live execution records', t => {
  const { store, directory } = fixture(t);
  const finished = begin(store, read, '').result;
  store.finishOperation(finished.operationId, { status: 'completed', stdout: 'seed snapshot' });
  const running = begin(store, read, '').result;
  const db = new DatabaseSync(join(directory, 'store.sqlite'));
  try {
    const seedId = store.listHistory({ status: 'completed' }).items[0].id;
    db.prepare(`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<505)
      INSERT INTO execution_history(operation_id,thread_id,host_id,policy_revision,snapshot,summary,explanation,status,started_at,finished_at,completion_known)
      SELECT 'fixture-seed-'||seq.n,thread_id,host_id,policy_revision,snapshot,summary,explanation,'completed',started_at,finished_at,1
      FROM execution_history CROSS JOIN seq WHERE id=?`).run(seedId);
    store.listHistory();
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM execution_history WHERE status!='running'").get().n, 500);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM execution_history WHERE status='running'").get().n, 1);
    const old = Date.now() - 31 * 24 * 60 * 60_000;
    db.prepare("UPDATE execution_history SET finished_at=? WHERE operation_id='fixture-seed-505'").run(old);
    db.prepare('UPDATE execution_history SET started_at=? WHERE operation_id=?').run(old, running.operationId);
    store.listHistory();
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM execution_history WHERE operation_id='fixture-seed-505'").get().n, 0);
    assert.equal(db.prepare('SELECT status FROM execution_history WHERE operation_id=?').get(running.operationId).status, 'running');
  } finally { db.close(); }
});

test('schema 3 migration invalidates legacy approvals without inventing unavailable execution output', t => {
  const { store, directory, open } = fixture(t);
  const a = store.beginOperation('chat', 'prod', mutation, null, store.getPolicy('prod').revision);
  const b = store.beginOperation('chat', 'prod', { ...mutation, args: { name: 'other' } }, null, store.getPolicy('prod').revision);
  store.resolveApproval('chat', a.approval.id, 'approve');
  const db = new DatabaseSync(join(directory, 'store.sqlite'));
  db.exec('PRAGMA user_version=2'); db.close();
  const reopened = open();
  assert.equal(reopened.getApproval('chat', a.approval.id).status, 'invalidated');
  assert.equal(reopened.getApproval('chat', b.approval.id).status, 'invalidated');
  assert.deepEqual(reopened.state('chat').grantedHostIds, ['prod']);
  assert.equal(reopened.listHistory().items.length, 0);
  const versionDb = new DatabaseSync(join(directory, 'store.sqlite'));
  try { assert.equal(versionDb.prepare('PRAGMA user_version').get().user_version, 4); } finally { versionDb.close(); }
});

test('native nonces cannot be reused and new authorization cannot revive cancelled exact tickets', t => {
  const { store } = fixture(t);
  const a = begin(store);
  assert.equal(begin(store, mutation, explanation, a.token).result.code, 'PROMPT_TOKEN_REUSED');
  store.completeNativeApproval('chat', a.result.approval.id, a.token, 'cancel');
  store.grant('chat', ['prod']);
  assert.equal(begin(store, mutation, explanation, a.token).result.code, 'PROMPT_TOKEN_REUSED');
  assert.equal(store.completeNativeApproval('chat', a.result.approval.id, a.token, 'approve').status, 'denied');
});

test('every native terminal path erases approval write bodies while retaining replay-denial metadata', t => {
  for (const scenario of ['consume', 'deny', 'cancel', 'expire', 'revoke', 'regrant', 'policy', 'disable', 'host-change', 'remove', 'busy']) {
    const { store, directory } = fixture(t);
    grantPolicy(store, { roots: [{ id: 'app', path: '/srv/app', read: true, write: true }], maxConcurrent: 1 });
    const body = `approval-payload-${scenario}-not-for-retention`;
    const pending = begin(store, { kind: 'write', path: '/srv/app/file.txt', content: body }, '更新已授权目录中的普通文本文件');
    assert.equal(pending.result.status, 'pending', scenario);
    const db = new DatabaseSync(join(directory, 'store.sqlite'));
    try {
      assert.ok(JSON.stringify(db.prepare('SELECT * FROM approvals WHERE id=?').get(pending.result.approval.id)).includes(body));
      if (scenario === 'consume') assert.equal(store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve').status, 'ready');
      else if (['deny', 'cancel'].includes(scenario)) store.completeNativeApproval('chat', pending.result.approval.id, pending.token, scenario);
      else if (scenario === 'expire') { db.prepare('UPDATE approvals SET expires_at=? WHERE id=?').run(Date.now() - 1, pending.result.approval.id); store.listHistory(); }
      else if (scenario === 'revoke') store.revoke('chat', ['prod']);
      else if (scenario === 'regrant') store.grant('chat', ['prod']);
      else if (scenario === 'policy') grantPolicy(store, { timeoutSeconds: 10 });
      else if (scenario === 'disable') store.setEnabled('prod', false);
      else if (scenario === 'host-change') store.saveHost({ id: 'prod', hostname: 'changed.example.test' });
      else if (scenario === 'remove') store.removeHost('prod');
      else if (scenario === 'busy') { begin(store, read, ''); store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve'); }
      const row = db.prepare('SELECT * FROM approvals WHERE id=?').get(pending.result.approval.id);
      assert.ok(!JSON.stringify(row).includes(body), scenario);
      assert.ok(row.prompt_token_hash); assert.ok(row.request_hash); assert.notEqual(row.status, 'pending');
      assert.equal(store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve').status, 'denied', scenario);
    } finally { db.close(); }
  }
});

test('terminal native approvals erase raw commands but successful history retains the executed command', t => {
  const { store, directory } = fixture(t);
  grantPolicy(store, { mode: 'approval' });
  const command = 'echo command-payload-fixture-78215';
  const pending = begin(store, { kind: 'command', command, cwd: '' }, '打印本次诊断使用的标记文本');
  const ready = store.completeNativeApproval('chat', pending.result.approval.id, pending.token, 'approve');
  const db = new DatabaseSync(join(directory, 'store.sqlite'));
  try { assert.ok(!JSON.stringify(db.prepare('SELECT * FROM approvals WHERE id=?').get(pending.result.approval.id)).includes(command)); }
  finally { db.close(); }
  assert.equal(store.getHistory(store.listHistory().items[0].id).command, command);
  assert.equal(ready.evaluation.command, command);
});

test('execution readiness only accepts the owned active unexpired permit',t=>{
 const {store,directory}=fixture(t);
 const ready=begin(store,read,'查看磁盘容量').result;
 assert.equal(ready.status,'ready');
 assert.doesNotThrow(()=>store.assertOperationReady('chat',ready.operationId));
 const invalid=error=>error.code==='OPERATION_INVALIDATED';
 assert.throws(()=>store.assertOperationReady('other',ready.operationId),invalid);
 assert.throws(()=>store.assertOperationReady('chat','missing-operation'),invalid);
 const db=new DatabaseSync(join(directory,'store.sqlite'));
 try{db.prepare('UPDATE operations SET expires_at=? WHERE id=?').run(Date.now()-1,ready.operationId);}finally{db.close();}
 assert.throws(()=>store.assertOperationReady('chat',ready.operationId),invalid);
});

test('execution readiness cannot be restored by regrant after revoke or policy changes',async t=>{
 for(const scenario of ['revoke','revoke-regrant','regrant','policy-save','host-change','disabled','finished','expired-grant','policy-revision'])await t.test(scenario,t=>{
  const {store,directory}=fixture(t);
  const ready=begin(store,read,'查看磁盘容量').result;
  if(scenario==='revoke'||scenario==='revoke-regrant')store.revoke('chat',['prod']);
  if(scenario==='revoke-regrant'||scenario==='regrant')store.grant('chat',['prod']);
  if(scenario==='policy-save')grantPolicy(store,{maxConcurrent:1});
  if(scenario==='host-change'){store.saveHost({id:'prod',hostname:'changed.example.test'});store.grant('chat',['prod']);}
  if(scenario==='disabled')store.setEnabled('prod',false);
  if(scenario==='finished')store.finishOperation(ready.operationId,{status:'completed',exitCode:0});
  if(scenario==='expired-grant'||scenario==='policy-revision'){
   const db=new DatabaseSync(join(directory,'store.sqlite'));
   try{
    if(scenario==='expired-grant')db.prepare('UPDATE grants SET expires_at=? WHERE thread_id=? AND host_id=?').run(Date.now()-1,'chat','prod');
    else db.prepare('UPDATE operations SET policy_revision=policy_revision+1 WHERE id=?').run(ready.operationId);
   }finally{db.close();}
  }
  assert.throws(()=>store.assertOperationReady('chat',ready.operationId),error=>error.code==='OPERATION_INVALIDATED');
 });
});
