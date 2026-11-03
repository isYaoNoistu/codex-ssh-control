import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../src/store.mjs';
import { setup, pause } from './helpers/rpc-harness.mjs';

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'ssh-intent-revocation-'));
  const stores = [];
  const open = () => { const store = new Store(dir); stores.push(store); return store; };
  t.after(() => { for (const store of stores) store.close(); rmSync(dir, { recursive: true, force: true }); });
  const store = open();
  for (const id of ['prod', 'uat']) store.saveHost({ id, sshAlias: `${id}.example.invalid`, enabled: true });
  return { store, open, dir };
}
const record = (store, turnId, hostIds = ['prod'], operation = 'grant') => store.recordIntent({
  sessionId: 'shared-session', turnId, operation, hostIds, expiresAt: Date.now() + 120000,
});
const consume = (store, turnId, threadId = 'owner') => store.consumeIntent({ threadId, sessionId: 'shared-session', turnId });

test('revocation blocks an older pending shortcut across processes and fresh intent works in the same millisecond', t => {
  const { store, open } = fixture(t);
  const now = Date.now(); t.mock.method(Date, 'now', () => now);
  store.grant('owner', ['prod']);
  record(store, 'old');
  open().revoke('owner', ['prod']);
  assert.throws(() => consume(store, 'old'), /撤销|失效/);
  assert.deepEqual(store.state('owner').grantedHostIds, []);
  record(store, 'old');
  assert.deepEqual(consume(store, 'old').grantedHostIds, [], 'same intent cannot be reactivated');
  record(store, 'fresh');
  assert.deepEqual(consume(open(), 'fresh').grantedHostIds, ['prod']);
});

test('revoking with no active grant still prevents an already queued grant', t => {
  const { store } = fixture(t);
  record(store, 'old');
  store.revoke('owner', ['prod']);
  assert.throws(() => consume(store, 'old'), /撤销|失效/);
  assert.deepEqual(store.state('owner').grantedHostIds, []);
});

test('revocation is scoped to the target chat and host even with a shared session', t => {
  const { store } = fixture(t);
  record(store, 'other-chat');
  record(store, 'other-host', ['uat']);
  store.grant('other', ['uat']);
  store.revoke('owner', ['prod']);
  assert.deepEqual(consume(store, 'other-chat', 'other').grantedHostIds, ['prod', 'uat']);
  assert.deepEqual(consume(store, 'other-host').grantedHostIds, ['uat']);
});

test('multi-host shortcut cannot partially grant after one host is revoked', t => {
  const { store } = fixture(t);
  record(store, 'multi', ['prod', 'uat']);
  store.revoke('owner', ['uat']);
  assert.throws(() => consume(store, 'multi'), /撤销|失效/);
  assert.deepEqual(store.state('owner').grantedHostIds, []);
  assert.deepEqual(consume(store, 'multi', 'other').grantedHostIds, [], 'denied intent remains consumed');
  record(store, 'fresh', ['prod', 'uat']);
  assert.deepEqual(consume(store, 'fresh').grantedHostIds, ['prod', 'uat']);
});

test('shortcut revocation also invalidates an older unconsumed grant', t => {
  const { store } = fixture(t);
  store.grant('owner', ['prod']);
  record(store, 'old');
  record(store, 'revoke', ['prod'], 'revoke');
  assert.deepEqual(consume(store, 'revoke').grantedHostIds, []);
  assert.throws(() => consume(store, 'old'), /撤销|失效/);
});

test('regrant and restart cannot make an older revoked shortcut current again', t => {
  const { store, open } = fixture(t);
  record(store, 'old');
  store.revoke('owner', ['prod']);
  store.grant('owner', ['prod'], { minutes: 1 });
  const expiry = store.state('owner').grants[0].expiresAt;
  store.close();
  const restarted = open();
  assert.throws(() => consume(restarted, 'old'), /撤销|失效/);
  assert.equal(restarted.state('owner').grants[0].expiresAt, expiry, 'stale shortcut cannot renew the fresh grant');
});

test('upgrade rejects pending legacy shortcuts without changing hosts, policies or valid grants', t => {
  const { store, open, dir } = fixture(t);
  store.grant('owner', ['uat']);
  const before = store.state('owner');
  record(store, 'legacy');
  store.close();
  const db = new DatabaseSync(join(dir, 'store.sqlite'));
  const columns = db.prepare('PRAGMA table_info(intents)').all();
  if (columns.some(column => column.name === 'revocation_revision')) db.exec('ALTER TABLE intents DROP COLUMN revocation_revision');
  db.exec('DROP TABLE IF EXISTS intent_revocations; PRAGMA user_version=3');
  db.close();
  const upgraded = open();
  assert.throws(() => consume(upgraded, 'legacy'), /失效|重新/);
  assert.deepEqual(upgraded.state('owner'), before);
  record(upgraded, 'fresh');
  assert.deepEqual(consume(upgraded, 'fresh').grantedHostIds, ['prod', 'uat']);
});

test('MCP gate cannot resurrect a revoked host from stale turn metadata or spawn SSH', async t => {
  const h = await setup(t);
  const store = new Store(h.dir);
  try { record(store, 'older-grant-turn', ['fixture']); } finally { store.close(); }
  await h.grants();
  assert.ok(!(await h.admin('ssh_revoke', { hostIds: ['fixture'] })).isError);
  const call = () => h.rpc('tools/call', {
    name: 'ssh_run_action',
    arguments: { hostId: 'fixture', actionId: 'disk.usage', explanation: '读取测试夹具磁盘使用率，验证撤销后不执行。' },
    _meta: { threadId: 'owner', sessionId: 'shared-session', 'x-codex-turn-metadata': { turn_id: 'older-grant-turn' } },
  });
  assert.equal((await call()).isError, true);
  assert.equal((await call()).isError, true, 'replay cannot revive the consumed stale shortcut');
  await pause();
  assert.deepEqual((await h.call('ssh_status')).structuredContent.state.grantedHostIds, []);
  assert.equal(await h.count(), 0);
});
