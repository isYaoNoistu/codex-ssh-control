import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Store, resolveDataDir } from '../src/store.mjs';

const source = new URL('../src/store.mjs', import.meta.url);
const sample = (id = 'prod', extra = {}) => ({ id, hostname: `${id}.example.test`, username: 'deploy', ...extra });

function fixture(t) {
  assert.equal(typeof Store, 'function', 'Store export must exist');
  const directory = mkdtempSync(join(tmpdir(), 'ssh-control-store-test-'));
  const stores = [];
  const open = () => { const store = new Store(directory); stores.push(store); return store; };
  t.after(() => { for (const store of stores) store.close(); rmSync(directory, { recursive: true, force: true }); });
  return { directory, open, store: open() };
}

test('data directory uses an explicit override or the Codex user state directory', () => {
  assert.equal(typeof resolveDataDir, 'function', 'resolveDataDir export must exist');
  assert.equal(resolveDataDir({ SSH_CONTROL_DATA: '/chosen/ssh-state' }), '/chosen/ssh-state');
  assert.equal(resolveDataDir({}), join(homedir(), '.codex', 'ssh-control'));
  assert.throws(() => resolveDataDir({ SSH_CONTROL_DATA: '' }));
});

test('new hosts are disabled, defaults round-trip and no-thread state grants nothing', t => {
  const { store } = fixture(t);
  const host = store.saveHost(sample());
  assert.deepEqual(host, { id: 'prod', name: 'prod', hostname: 'prod.example.test', port: 22, username: 'deploy', identityFile: '', sshAlias: '', defaultCwd: '', enabled: false });
  assert.deepEqual(store.listHosts(), [host]);
  assert.deepEqual(store.state(null).grantedHostIds, []);
  assert.equal(store.state(null).threadId, null);
  assert.match(store.state('thread-a').shortcutHelp, /ssh-prod/);
  assert.throws(() => store.grant('', ['prod']));
  assert.throws(() => store.requireHost(null, 'prod'));
});

test('host validation rejects option injection, shell punctuation and reserved IDs', t => {
  const { store } = fixture(t);
  for (const bad of [
    { id: 'status' }, { id: 'revoke-prod' }, { id: '../prod' }, { id: 'Prod' },
    { hostname: '-oProxyCommand=bad' }, { hostname: 'safe;bad' }, { hostname: 'a b' },
    { hostname: 'a.example\nProxyCommand bad' }, { username: '-root' }, { username: 'root;bad' },
    { port: 0 }, { port: 65536 }, { port: '22' }, { port: 22.5 },
    { enabled: 'true' }, { name: 'x'.repeat(81) }, { name: 'x\rbad' },
    { identityFile: '-Fbad' }, { identityFile: '/tmp/key;bad' }, { defaultCwd: '/tmp/$(bad)' },
    { identityFile: '/tmp/key*' }, { identityFile: '/tmp/key[1]' }, { defaultCwd: '/tmp/#comment' },
    { sshAlias: 'alias', hostname: 'host' }, { hostname: '', username: '' },
  ]) assert.throws(() => store.saveHost(sample('prod', bad)), JSON.stringify(bad));
  assert.equal(store.listHosts().length, 0);
  assert.equal(store.saveHost(sample('ipv6', { hostname: '2001:db8::1' })).hostname, '2001:db8::1');
  const alias = store.saveHost({ id: 'alias', sshAlias: 'team-prod_1', identityFile: 'C:\\keys\\my key', defaultCwd: '/srv/my app' });
  assert.equal(alias.hostname, '');
  assert.equal(alias.username, '');
  assert.equal(alias.enabled, false);
});

test('grants are per exact thread, union is atomic and missing members never partially grant', t => {
  const { store } = fixture(t);
  store.saveHost(sample('prod', { enabled: true }));
  store.saveHost(sample('uat', { enabled: true }));
  assert.deepEqual(store.grant('thread-a', ['prod', 'prod']).grantedHostIds, ['prod']);
  assert.deepEqual(store.state('thread-b').grantedHostIds, []);
  assert.deepEqual(store.state('thread-a-fork').grantedHostIds, []);
  assert.throws(() => store.grant('thread-b', ['prod', 'missing']));
  assert.deepEqual(store.state('thread-b').grantedHostIds, []);
  assert.deepEqual(store.grant('thread-a', ['uat']).grantedHostIds, ['prod', 'uat']);
  assert.throws(() => store.requireHost('thread-a'), /主机|选择|指定/);
  assert.equal(store.requireHost('thread-a', 'uat').id, 'uat');
  assert.deepEqual(store.revoke('thread-a', ['prod', 'missing']).grantedHostIds, ['uat']);
  assert.equal(store.requireHost('thread-a').id, 'uat');
  assert.deepEqual(store.revoke('thread-a', ['prod']).grantedHostIds, ['uat']);
  assert.throws(() => store.requireHost('thread-b', 'prod'), /授权/);
});

test('global disable revokes grants and reenabling requires fresh authorization', t => {
  const { store } = fixture(t);
  store.saveHost(sample('prod', { enabled: true }));
  store.grant('thread-a', ['prod']);
  assert.equal(store.setEnabled('prod', false).enabled, false);
  assert.throws(() => store.requireHost('thread-a', 'prod'), /禁用|启用/);
  assert.throws(() => store.grant('thread-b', ['prod']), /禁用|启用/);
  assert.deepEqual(store.state('thread-a').grantedHostIds, []);
  store.setEnabled('prod', true);
  assert.throws(() => store.requireHost('thread-a'), /授权/);
  store.grant('thread-a', ['prod']);
  assert.equal(store.requireHost('thread-a').id, 'prod');
  assert.throws(() => store.setEnabled('prod', 'false'));
});

test('connection changes revoke all threads, name edits preserve grants and deletion cascades', t => {
  const { store } = fixture(t);
  store.saveHost(sample('prod', { enabled: true }));
  store.grant('thread-a', ['prod']); store.grant('thread-b', ['prod']);
  store.saveHost({ id: 'prod', name: 'Production' });
  assert.equal(store.requireHost('thread-a').name, 'Production');
  store.saveHost({ id: 'prod', port: 2222 });
  assert.deepEqual(store.state('thread-a').grantedHostIds, []);
  assert.deepEqual(store.state('thread-b').grantedHostIds, []);
  store.grant('thread-a', ['prod']);
  store.saveHost({ id: 'prod', defaultCwd: '/srv/app' });
  assert.deepEqual(store.state('thread-a').grantedHostIds, []);
  store.grant('thread-a', ['prod']);
  store.removeHost('prod');
  assert.deepEqual(store.state('thread-a').grantedHostIds, []);
  assert.deepEqual(store.listHosts(), []);
  store.removeHost('prod');
});

test('intent exact session and turn binding isolates shared sessions and consumes only once', t => {
  const { store } = fixture(t);
  store.saveHost(sample('prod', { enabled: true }));
  const intent = { sessionId: 'shared-session', turnId: 'turn-a', operation: 'grant', hostIds: ['prod'], expiresAt: Date.now() + 10000 };
  store.recordIntent(intent);
  assert.deepEqual(store.consumeIntent({ threadId: 'fork', sessionId: 'shared-session', turnId: 'turn-b' }).grantedHostIds, []);
  assert.deepEqual(store.consumeIntent({ threadId: 'other', sessionId: 'other-session', turnId: 'turn-a' }).grantedHostIds, []);
  assert.deepEqual(store.consumeIntent({ threadId: 'thread-a', sessionId: 'shared-session', turnId: 'turn-a' }).grantedHostIds, ['prod']);
  assert.deepEqual(store.consumeIntent({ threadId: 'fork', sessionId: 'shared-session', turnId: 'turn-a' }).grantedHostIds, []);
  store.recordIntent(intent);
  assert.deepEqual(store.consumeIntent({ threadId: 'fork', sessionId: 'shared-session', turnId: 'turn-a' }).grantedHostIds, []);
  assert.throws(() => store.recordIntent({ ...intent, operation: 'revoke' }));
});

test('expired intents and revised or temporarily disabled hosts cannot grant', t => {
  const { store } = fixture(t);
  store.saveHost(sample('prod', { enabled: true }));
  const record = (turnId, extra = {}) => store.recordIntent({ sessionId: 'session', turnId, operation: 'grant', hostIds: ['prod'], expiresAt: Date.now() + 10000, ...extra });
  const consume = (turnId, extra = {}) => store.consumeIntent({ threadId: 'thread-a', sessionId: 'session', turnId, ...extra });
  record('expired', { expiresAt: Date.now() + 100 });
  assert.throws(() => consume('expired', { now: Date.now() + 10000 }), /过期/);
  assert.deepEqual(store.state('thread-a').grantedHostIds, []);
  record('edited'); store.saveHost({ id: 'prod', hostname: 'other.example.test' });
  assert.throws(() => consume('edited'), /更改|变更|失效/);
  record('disabled'); store.setEnabled('prod', false); store.setEnabled('prod', true);
  assert.throws(() => consume('disabled'), /更改|变更|失效/);
  record('removed'); store.removeHost('prod'); store.saveHost(sample('prod', { enabled: true }));
  assert.throws(() => consume('removed'), /更改|变更|失效/);
  assert.deepEqual(store.state('thread-a').grantedHostIds, []);
});

test('revoke and status intents have no grant effect and survive another store instance', t => {
  const { store, open } = fixture(t);
  store.saveHost(sample('prod', { enabled: true }));
  store.grant('thread-a', ['prod']);
  const other = open();
  other.recordIntent({ sessionId: 's', turnId: 'revoke', operation: 'revoke', hostIds: ['prod'], expiresAt: Date.now() + 10000 });
  assert.deepEqual(store.consumeIntent({ threadId: 'thread-a', sessionId: 's', turnId: 'revoke' }).grantedHostIds, []);
  other.recordIntent({ sessionId: 's', turnId: 'status', operation: 'status', hostIds: [], expiresAt: Date.now() + 10000 });
  assert.deepEqual(store.consumeIntent({ threadId: 'thread-a', sessionId: 's', turnId: 'status' }).grantedHostIds, []);
  assert.throws(() => other.recordIntent({ sessionId: 's', turnId: 'bad', operation: 'other', hostIds: [], expiresAt: Date.now() + 10000 }));
  assert.throws(() => other.recordIntent({ sessionId: '', turnId: 'bad', operation: 'status', hostIds: [], expiresAt: Date.now() + 10000 }));
  assert.throws(() => store.consumeIntent({ threadId: '', sessionId: 's', turnId: 'status' }));
});

test('multi-host intent rejects atomically and an invalidated request cannot later be revived', t => {
  const { store } = fixture(t);
  store.saveHost(sample('prod', { enabled: true }));
  store.saveHost(sample('uat', { enabled: true }));
  const intent = { sessionId: 's', turnId: 'multi', operation: 'grant', hostIds: ['prod', 'uat'], expiresAt: Date.now() + 10000 };
  store.recordIntent(intent);
  store.saveHost({ id: 'uat', identityFile: '/changed/key' });
  assert.throws(() => store.consumeIntent({ threadId: 'root', sessionId: 's', turnId: 'multi' }), /失效/);
  assert.deepEqual(store.state('root').grantedHostIds, []);
  store.saveHost({ id: 'uat', identityFile: '' });
  store.recordIntent(intent);
  assert.deepEqual(store.consumeIntent({ threadId: 'fork', sessionId: 's', turnId: 'multi' }).grantedHostIds, []);
  assert.deepEqual(store.consumeIntent({ threadId: 'root', sessionId: 's', turnId: 'multi' }).grantedHostIds, []);
});

test('failed writes leave the stored host and existing grants intact', t => {
  const { store, open } = fixture(t);
  const host = store.saveHost(sample('prod', { enabled: true }));
  store.grant('root', ['prod']);
  assert.throws(() => store.saveHost({ id: 'prod', port: 2222, password: 'must-not-persist' }), /密码|字段/);
  assert.throws(() => store.saveHost({ id: 'prod', enabled: false, hostname: '-bad' }));
  const other = open();
  assert.deepEqual(other.requireHost('root', 'prod'), host);
  assert.deepEqual(other.listHosts(), [host]);
  store.close(); store.close();
  assert.throws(() => store.listHosts(), /关闭/);
});

test('concurrent stdio-like processes preserve grant unions and only one consumes an intent', async t => {
  const { store, directory } = fixture(t);
  for (let i = 0; i < 6; i++) store.saveHost(sample(`host-${i}`, { enabled: true }));
  const run = (code, args) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', '--input-type=module', '-e', `import { Store } from ${JSON.stringify(source.href)}; const s=new Store(process.argv[1]); ${code}; s.close();`, directory, ...args], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = ''; child.stderr.on('data', data => { stderr += data; });
    child.on('error', reject); child.on('close', code => code === 0 ? resolve() : reject(new Error(stderr)));
  });
  await Promise.all(Array.from({ length: 6 }, (_, i) => run("s.grant('thread-a',[process.argv[2]])", [`host-${i}`])));
  assert.deepEqual(store.state('thread-a').grantedHostIds, Array.from({ length: 6 }, (_, i) => `host-${i}`));
  store.recordIntent({ sessionId: 's', turnId: 'race', operation: 'grant', hostIds: ['host-0'], expiresAt: Date.now() + 10000 });
  await Promise.all(['root', 'fork'].map(thread => run("s.consumeIntent({threadId:process.argv[2],sessionId:'s',turnId:'race'})", [thread])));
  assert.equal(store.state('root').grantedHostIds.length + store.state('fork').grantedHostIds.length, 1);
});

test('confirmed grants compare all previewed hosts atomically before unioning access', t => {
  const { store, open } = fixture(t);
  store.saveHost(sample('prod', { enabled: true }));
  store.saveHost(sample('uat', { enabled: true }));
  store.saveHost(sample('dev', { enabled: true }));
  store.grant('root', ['dev']);
  const preview = store.listHosts().filter(host => host.id !== 'dev');
  assert.equal(typeof store.grantConfirmed, 'function', 'grantConfirmed must exist');
  const other = open();
  other.saveHost({ id: 'uat', hostname: 'changed.example.test' });
  assert.throws(() => store.grantConfirmed('root', preview), /变更|确认/);
  assert.deepEqual(store.state('root').grantedHostIds, ['dev']);
  const current = other.listHosts().filter(host => host.id !== 'dev');
  assert.deepEqual(store.grantConfirmed('root', current).grantedHostIds, ['dev', 'prod', 'uat']);
  assert.deepEqual(store.state('fork').grantedHostIds, []);
  other.setEnabled('prod', false);
  assert.throws(() => store.grantConfirmed('fork', current), /变更|确认/);
  assert.deepEqual(store.state('fork').grantedHostIds, []);
});
