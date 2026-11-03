import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.mjs';

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'ssh-default-cwd-store-'));
  const store = new Store(dir), other = new Store(dir);
  t.after(() => { store.close(); other.close(); rmSync(dir, { recursive: true, force: true }); });
  store.saveHost({ id: 'fixture', sshAlias: 'never-connect.example.invalid', enabled: true, defaultCwd: '/srv/old' });
  const record = store.getPolicy('fixture');
  const saved = store.savePolicy('owner', 'fixture', { ...record.policy, mode: 'approval' }, record.revision);
  store.grant('owner', ['fixture']);
  return { store, other, revision: saved.revision };
}

test('native gate resolves an omitted cwd from the transaction host, after another connection changes and regrants it', t => {
  const { store, other, revision } = fixture(t);
  assert.equal(store.listHosts()[0].defaultCwd, '/srv/old');
  other.saveHost({ id: 'fixture', defaultCwd: '/srv/current' });
  other.grant('owner', ['fixture']);
  const pending = store.beginNativeOperation('owner', 'fixture', { kind: 'command', command: 'pwd' }, '查看本次事务确认的工作目录', 'cwd-token', revision);
  assert.equal(pending.status, 'pending');
  assert.equal(pending.approval.presentation.cwd, '/srv/current');
  const ready = store.completeNativeApproval('owner', pending.approval.id, 'cwd-token', 'approve');
  assert.equal(ready.status, 'ready');
  assert.equal(ready.host.defaultCwd, '/srv/current');
  assert.equal(ready.evaluation.operation.cwd, '/srv/current');
  const history = store.getHistory(store.listHistory().items[0].id);
  assert.equal(history.cwd, '/srv/current');
});

test('a newly protected default is denied inside the native gate even with an unchanged policy revision', t => {
  const { store, other, revision } = fixture(t);
  other.saveHost({ id: 'fixture', defaultCwd: '/root/.ssh' });
  other.grant('owner', ['fixture']);
  const denied = store.beginNativeOperation('owner', 'fixture', { kind: 'command', command: 'pwd' }, '查看当前目录用于验证安全检查', 'cwd-token', revision);
  assert.equal(denied.status, 'denied');
  assert.equal(denied.code, 'SENSITIVE_COMMAND');
  assert.equal(store.listApprovals().items.length, 0);
  assert.equal(store.listHistory().items.length, 0);
});
