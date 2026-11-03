import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.attributes = {};
    this.value = ''; this.checked = false; this.disabled = false; this.hidden = false; this._text = '';
    this.classList = { add() {}, remove() {}, toggle() {} };
    this.style = { setProperty() {} };
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent ?? child).join(''); }
  set innerHTML(_) { throw new Error('Host data must never be rendered through innerHTML.'); }
  append(...items) { this.children.push(...items); }
  appendChild(item) { this.append(item); return item; }
  replaceChildren(...items) { this._text = ''; this.children = items; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  getAttribute(key) { return this.attributes[key] ?? null; }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(type, handler) { this['on' + type] = handler; }
  focus() {} scrollIntoView() {} reportValidity() { return true; }
  async click() { if (!this.disabled) return this.onclick?.({ preventDefault() {}, target: this }); }
}
const host = (id, overrides = {}) => ({ id, name: id, hostname: id + '.example.invalid', port: 22, username: 'deploy', identityFile: '', sshAlias: '', defaultCwd: '', enabled: true, ...overrides });
const initial = (overrides = {}) => ({ threadId: 'trusted-thread-123456789', hosts: [host('prod'), host('uat')], grantedHostIds: [], shortcutHelp: '/ssh-prod /ssh-uat', ...overrides });
const settle = async () => { for (let i = 0; i < 12; i++) await new Promise(resolve => setImmediate(resolve)); };

async function harness(startState = initial(), override) {
  let html = '';
  try { html = await readFile(new URL('../ui/panel.html', import.meta.url), 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  assert.ok(html, 'The SSH host panel must exist.');
  const source = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(source, 'Panel must contain its self-contained UI controller.');
  const ids = new Map([...html.matchAll(/<([a-z][a-z0-9]*)\b[^>]*\bid="([^"]+)"[^>]*>/gi)].map(match => { const element = new Element(match[1]); element.textContent = html.slice(match.index + match[0].length).split('<')[0]; return [match[2], element]; }));
  const listeners = new Map(), documentListeners = new Map(), calls = [], messages = [], intervals = [], timeouts = new Map(), timeoutDelays = [];
  let nextTimer = 0, state = structuredClone(startState);
  const document = {
    hidden: false, documentElement: new Element('html'), body: new Element('body'),
    getElementById: id => { assert.ok(ids.has(id), 'Unknown element ' + id); return ids.get(id); },
    createElement: tag => new Element(tag),
    addEventListener: (event, handler) => documentListeners.set(event, handler),
  };
  const parent = { postMessage(message) {
    messages.push(structuredClone(message));
    if (!Object.hasOwn(message, 'id')) return;
    queueMicrotask(async () => {
      let result;
      if (message.method === 'ui/initialize') result = { protocolVersion: '2026-01-26', hostInfo: { name: 'test-host', version: '1' }, hostCapabilities: {}, hostContext: { threadId: 'ui-context-only', theme: 'light' } };
      else if (message.method === 'tools/call') {
        const call = structuredClone(message.params); calls.push(call);
        result = await override?.(call, state);
        if (!result) {
          if (call.name === 'ssh_grant') state.grantedHostIds = [...new Set([...state.grantedHostIds, ...call.arguments.hostIds])];
          if (call.name === 'ssh_revoke') state.grantedHostIds = state.grantedHostIds.filter(id => !call.arguments.hostIds.includes(id));
          if (call.name === 'ssh_host_save') { const h = structuredClone(call.arguments.host); state.hosts = [...state.hosts.filter(item => item.id !== h.id), h]; }
          if (call.name === 'ssh_host_enabled') state.hosts = state.hosts.map(h => h.id === call.arguments.hostId ? { ...h, enabled: call.arguments.enabled } : h);
          if (call.name === 'ssh_host_remove') { state.hosts = state.hosts.filter(h => h.id !== call.arguments.hostId); state.grantedHostIds = state.grantedHostIds.filter(id => id !== call.arguments.hostId); }
          result = { structuredContent: { state: structuredClone(state) }, content: [] };
        }
      } else result = {};
      listeners.get('message')?.({ source: parent, data: { jsonrpc: '2.0', id: message.id, result } });
    });
  } };
  const window = { parent, addEventListener: (event, handler) => listeners.set(event, handler) };
  const context = vm.createContext({ document, window, console, Map, Set, Object, Array, String, Number, Boolean, Date, Error,
    setTimeout: (handler, delay) => { const id = ++nextTimer; timeouts.set(id, handler); timeoutDelays.push(delay); return id; }, clearTimeout: id => timeouts.delete(id),
    setInterval: handler => { intervals.push(handler); return intervals.length; }, clearInterval() {},
  });
  new vm.Script(source, { filename: 'ssh-control-panel.js' }).runInContext(context);
  await settle();
  function findAction(action, id) {
    const walk = element => {
      if (element.dataset?.action === action && element.dataset?.hostId === id) return element;
      for (const child of element.children ?? []) { const found = walk(child); if (found) return found; }
    };
    for (const element of ids.values()) { const found = walk(element); if (found) return found; }
    assert.fail('Missing action ' + action + ' for ' + id);
  }
  return { ids, calls, messages, intervals, timeouts, timeoutDelays, document, documentListeners, findAction, settle, state: () => state };
}

test('initializes bridge then automatically reads authoritative chat state', async () => {
  const h = await harness();
  assert.equal(h.messages[0].method, 'ui/initialize');
  assert.ok(h.messages.find(message => message.method === 'ui/notifications/initialized'));
  assert.deepEqual(h.calls[0], { name: 'ssh_status', arguments: {} });
  assert.match(h.ids.get('thread-label').textContent, /trusted/);
  assert.ok(!h.ids.get('thread-label').textContent.includes('ui-context-only'));
  assert.equal(h.ids.get('host-list').children.length, 2);
  assert.equal(h.calls.some(call => call.name === 'ssh_exec'), false);
});

test('grants multiple hosts and revokes one without passing a model supplied identity', async () => {
  const h = await harness();
  await h.findAction('grant', 'prod').click(); await h.settle();
  await h.findAction('grant', 'uat').click(); await h.settle();
  assert.deepEqual(h.state().grantedHostIds, ['prod', 'uat']);
  assert.match(h.ids.get('grant-count').textContent, /2/);
  await h.findAction('revoke', 'prod').click(); await h.settle();
  assert.deepEqual(h.state().grantedHostIds, ['uat']);
  for (const call of h.calls.filter(call => ['ssh_grant', 'ssh_revoke'].includes(call.name))) assert.equal(call.arguments.uiToken, '__SSH_UI_TOKEN__');
});

test('saves a new SSH alias host with disabled default and mutually exclusive connection fields', async () => {
  const h = await harness(initial({ hosts: [] }));
  await h.ids.get('add-host').click();
  const values = { 'host-id': 'build', 'host-name': '构建机', 'host-mode': 'alias', 'host-alias': 'build-box', 'host-hostname': 'stale.invalid', 'host-username': 'stale', 'host-port': '2222', 'host-key': '', 'host-cwd': '/srv/build' };
  for (const [id, value] of Object.entries(values)) h.ids.get(id).value = value;
  h.ids.get('host-mode').onchange?.();
  await h.ids.get('host-form').onsubmit({ preventDefault() {} }); await h.settle();
  const call = h.calls.find(call => call.name === 'ssh_host_save');
  assert.ok(call);
  assert.equal(call.arguments.host.sshAlias, 'build-box');
  assert.equal(call.arguments.host.hostname, '');
  assert.equal(call.arguments.host.username, '');
  assert.equal(call.arguments.host.enabled, false);
  assert.equal(h.ids.get('editor').hidden, false);
});

test('does not offer mutation when the authoritative chat identity is absent', async () => {
  const h = await harness(initial({ threadId: null }));
  assert.equal(h.ids.get('add-host').disabled, true);
  assert.equal(h.findAction('grant', 'prod').disabled, true);
  assert.match(h.ids.get('identity-notice').textContent, /聊天/);
  await h.findAction('grant', 'prod').click();
  assert.equal(h.calls.some(call => call.name === 'ssh_grant'), false);
});

test('shows tool failure without inventing a successful grant', async () => {
  const h = await harness(initial(), call => call.name === 'ssh_grant' ? { isError: true, content: [{ type: 'text', text: '此主机已停用' }] } : undefined);
  await h.findAction('grant', 'prod').click(); await h.settle();
  assert.equal(h.ids.get('error-banner').hidden, false);
  assert.match(h.ids.get('error-message').textContent, /此主机已停用/);
  assert.equal(h.state().grantedHostIds.length, 0);
});

test('requires an explicit delete confirmation and uses only the selected host ID', async () => {
  const h = await harness();
  await h.findAction('delete', 'prod').click();
  assert.equal(h.calls.some(call => call.name === 'ssh_host_remove'), false);
  assert.equal(h.ids.get('delete-confirmation').hidden, false);
  await h.ids.get('confirm-delete').click(); await h.settle();
  assert.deepEqual(h.calls.find(call => call.name === 'ssh_host_remove').arguments, { hostId: 'prod', uiToken: '__SSH_UI_TOKEN__' });
  assert.deepEqual(h.state().hosts.map(item => item.id), ['uat']);
});

test('refreshes only while visible and renders untrusted host names as text', async () => {
  const h = await harness(initial({ hosts: [host('prod', { name: '<img src=x onerror=alert(1)>' })] }));
  assert.match(h.ids.get('host-list').textContent, /<img src=x/);
  const before = h.calls.length;
  h.document.hidden = true;
  for (const tick of h.intervals) tick();
  await h.settle(); assert.equal(h.calls.length, before);
  h.document.hidden = false;
  for (const tick of h.intervals) tick();
  await h.settle(); assert.equal(h.calls.length, before + 1);
});

test('a disabled host must be enabled before its grant action becomes available', async () => {
  const h = await harness(initial({ hosts: [host('prod', { enabled: false })] }));
  assert.equal(h.findAction('grant', 'prod').disabled, true);
  await h.findAction('enabled', 'prod').click(); await h.settle();
  assert.deepEqual(h.calls.find(call => call.name === 'ssh_host_enabled').arguments, { hostId: 'prod', enabled: true, uiToken: '__SSH_UI_TOKEN__' });
  assert.equal(h.findAction('grant', 'prod').disabled, false);
});

test('editing a hostname preserves its stable ID and sends the selected connection fields', async () => {
  const h = await harness();
  await h.findAction('edit', 'prod').click();
  assert.equal(h.ids.get('host-id').disabled, true);
  h.ids.get('host-id').value = 'attempted-renaming';
  h.ids.get('host-hostname').value = 'new.example.invalid';
  h.ids.get('host-username').value = 'operator';
  h.ids.get('host-port').value = '2202';
  h.ids.get('host-alias').value = 'stale-alias';
  await h.ids.get('host-form').onsubmit({ preventDefault() {} }); await h.settle();
  const saved = h.calls.find(call => call.name === 'ssh_host_save').arguments.host;
  assert.equal(saved.id, 'prod');
  assert.equal(saved.hostname, 'new.example.invalid');
  assert.equal(saved.username, 'operator');
  assert.equal(saved.port, 2202);
  assert.equal(saved.sshAlias, '');
  assert.equal(saved.enabled, true);
});

test('a status reply started before a grant cannot overwrite the newer authorization view', async () => {
  let statusCalls = 0, releaseOldRead;
  const h = await harness(initial(), (call, state) => {
    if (call.name !== 'ssh_status' || ++statusCalls !== 2) return;
    const oldState = structuredClone(state);
    return new Promise(resolve => { releaseOldRead = () => resolve({ content: [], structuredContent: { state: oldState } }); });
  });
  h.intervals[0](); await h.settle();
  assert.ok(releaseOldRead);
  await h.findAction('grant', 'prod').click(); await h.settle();
  assert.equal(h.ids.get('grant-count').textContent, '1');
  releaseOldRead(); await h.settle();
  assert.equal(h.ids.get('grant-count').textContent, '1');
});

test('saved host state survives shortcut warnings and keeps the unified detail open while showing the warning as text', async () => {
  const warning = '快捷技能未生成：已有同名技能 <ssh-prod>。';
  const h = await harness(initial(), (call, state) => {
    if (call.name !== 'ssh_host_save') return;
    state.hosts = state.hosts.map(item => item.id === call.arguments.host.id ? structuredClone(call.arguments.host) : item);
    return { content: [], structuredContent: { state: structuredClone(state), shortcuts: { warnings: [warning] } } };
  });
  await h.findAction('edit', 'prod').click();
  h.ids.get('host-name').value = '已保存的生产主机';
  await h.ids.get('host-form').onsubmit({ preventDefault() {} }); await h.settle();
  assert.equal(h.ids.get('editor').hidden, false);
  assert.match(h.ids.get('host-list').textContent, /已保存的生产主机/);
  assert.equal(h.ids.get('error-banner').hidden, false);
  assert.match(h.ids.get('error-message').textContent, /主机已保存/);
  assert.ok(h.ids.get('error-message').textContent.includes(warning));
  assert.equal(h.ids.get('save-host').disabled, false);
  h.intervals[0](); await h.settle();
  assert.equal(h.ids.get('error-banner').hidden, false, 'Background status refresh must not erase an unread warning.');
});

test('removed host state is applied even when generated shortcut cleanup reports warnings', async () => {
  const h = await harness(initial({ grantedHostIds: ['prod'] }), (call, state) => {
    if (call.name !== 'ssh_host_remove') return;
    state.hosts = state.hosts.filter(item => item.id !== call.arguments.hostId);
    state.grantedHostIds = state.grantedHostIds.filter(id => id !== call.arguments.hostId);
    return { content: [], structuredContent: { state: structuredClone(state), shortcuts: { warnings: ['快捷技能已被修改，未删除。'] } } };
  });
  await h.findAction('delete', 'prod').click();
  await h.ids.get('confirm-delete').click(); await h.settle();
  assert.equal(h.ids.get('delete-confirmation').hidden, true);
  assert.equal(h.ids.get('host-list').children.length, 1);
  assert.equal(h.ids.get('grant-count').textContent, '0');
  assert.equal(h.ids.get('error-banner').hidden, false);
  assert.match(h.ids.get('error-message').textContent, /主机已删除/);
  assert.match(h.ids.get('error-message').textContent, /快捷技能已被修改，未删除/);
});

const connectionResult = (overrides = {}) => ({ hostId: 'prod', ok: true, code: 'ok', message: 'SSH 连接成功。', detail: '', output: 'test response', checkedAt: '2026-11-02T08:00:00.000Z', durationMs: 420, ...overrides });
const connectionReply = (state, overrides) => ({ content: [], structuredContent: { state: structuredClone(state), connectionTest: connectionResult(overrides) } });
function findConnectionResult(h, hostId) {
  const visit = el => {
    if (el.dataset?.connectionTestHost === hostId) return el;
    for (const child of el.children ?? []) { const found = visit(child); if (found) return found; }
  };
  return visit(h.ids.get('host-list'));
}

test('connection test requires an enabled host granted to the real chat and never runs automatically', async () => {
  const h = await harness();
  assert.equal(h.findAction('test', 'prod').disabled, true);
  assert.match(h.findAction('test', 'prod').title, /先.*授权/);
  await h.findAction('test', 'prod').click();
  assert.equal(h.calls.some(call => call.name === 'ssh_test_connection'), false);
  await h.findAction('grant', 'prod').click(); await h.settle();
  assert.equal(h.findAction('test', 'prod').disabled, false);
  assert.equal(h.calls.some(call => call.name === 'ssh_test_connection'), false);
  const disabled = await harness(initial({ hosts: [host('prod', { enabled: false })], grantedHostIds: ['prod'] }));
  assert.equal(disabled.findAction('test', 'prod').disabled, true);
  const noThread = await harness(initial({ threadId: null, grantedHostIds: ['prod'] }));
  assert.equal(noThread.findAction('test', 'prod').disabled, true);
});

test('connection test displays pending state, prevents concurrent changes, and allows 180 seconds for native approval and connection testing', async () => {
  let finish;
  const h = await harness(initial({ grantedHostIds: ['prod', 'uat'] }), (call, state) => {
    if (call.name === 'ssh_test_connection') return new Promise(resolve => { finish = () => resolve(connectionReply(state)); });
  });
  assert.ok(h.timeoutDelays.every(delay => delay === 30000));
  const pending = h.findAction('test', 'prod').click(); await h.settle();
  assert.match(findConnectionResult(h, 'prod').textContent, /测试中/);
  assert.equal(h.ids.get('add-host').disabled, true);
  assert.equal(h.findAction('test', 'uat').disabled, true);
  assert.equal(h.findAction('enabled', 'prod').disabled, true);
  assert.equal(h.findAction('revoke', 'prod').disabled, true);
  assert.equal(h.timeoutDelays.at(-1), 180000);
  assert.deepEqual(h.calls.find(call => call.name === 'ssh_test_connection'), { name: 'ssh_test_connection', arguments: { hostId: 'prod' } });
  finish(); await pending; await h.settle();
  assert.match(findConnectionResult(h, 'prod').textContent, /连接成功/);
  assert.equal(h.ids.get('add-host').disabled, false);
  assert.equal(h.findAction('test', 'uat').disabled, false);
});

test('connection test failure displays the server message, stderr and output as text in the correct host row', async () => {
  const detail = 'No ED25519 host key is known. <img src=x onerror=alert(1)>';
  const output = '<script>untrusted response</script>';
  const h = await harness(initial({ grantedHostIds: ['prod'] }), (call, state) => call.name === 'ssh_test_connection'
    ? connectionReply(state, { ok: false, code: 'host_key_unknown', message: '尚未信任服务器主机公钥，请先核验。', detail, output }) : undefined);
  await h.findAction('test', 'prod').click(); await h.settle();
  const result = findConnectionResult(h, 'prod');
  assert.match(result.textContent, /连接失败/);
  assert.match(result.textContent, /尚未信任服务器主机公钥/);
  assert.ok(result.textContent.includes(detail));
  assert.ok(result.textContent.includes(output));
  assert.equal(findConnectionResult(h, 'uat'), undefined);
  assert.doesNotMatch(result.textContent, /连接成功/);
});

test('an MCP tool error is visible and cannot be displayed as a successful connection', async () => {
  const h = await harness(initial({ grantedHostIds: ['prod'] }), call => call.name === 'ssh_test_connection'
    ? { isError: true, content: [{ type: 'text', text: '当前聊天授权已撤销。' }] } : undefined);
  await h.findAction('test', 'prod').click(); await h.settle();
  assert.equal(h.ids.get('error-banner').hidden, false);
  assert.match(h.ids.get('error-message').textContent, /授权已撤销/);
  assert.match(findConnectionResult(h, 'prod').textContent, /授权已撤销/);
  assert.doesNotMatch(findConnectionResult(h, 'prod').textContent, /连接成功/);
  assert.equal(h.findAction('test', 'prod').disabled, false);
});

test('a mismatched connection result cannot mark the requested host successful', async () => {
  const h = await harness(initial({ grantedHostIds: ['prod'] }), (call, state) => call.name === 'ssh_test_connection'
    ? connectionReply(state, { hostId: 'uat' }) : undefined);
  await h.findAction('test', 'prod').click(); await h.settle();
  assert.equal(h.ids.get('error-banner').hidden, false);
  assert.doesNotMatch(findConnectionResult(h, 'prod').textContent, /连接成功/);
});

test('unchanged refreshes and display-name edits preserve a connection result', async () => {
  const h = await harness(initial({ grantedHostIds: ['prod'] }), (call, state) => call.name === 'ssh_test_connection' ? connectionReply(state) : undefined);
  await h.findAction('test', 'prod').click(); await h.settle();
  await h.ids.get('refresh').click(); await h.settle();
  assert.match(findConnectionResult(h, 'prod').textContent, /连接成功/);
  h.state().hosts[0].name = '新的显示名称';
  await h.ids.get('refresh').click(); await h.settle();
  assert.match(findConnectionResult(h, 'prod').textContent, /连接成功/);
});

test('connection, enablement, grant and chat changes invalidate old connection results', async () => {
  const changes = [
    state => { state.hosts[0].hostname = 'changed.invalid'; },
    state => { state.hosts[0].username = 'another'; },
    state => { state.hosts[0].port = 2202; },
    state => { state.hosts[0].identityFile = '/keys/changed'; },
    state => { state.hosts[0].sshAlias = 'changed-alias'; },
    state => { state.hosts[0].defaultCwd = '/changed'; },
    state => { state.hosts[0].enabled = false; },
    state => { state.grantedHostIds = []; },
    state => { state.threadId = 'another-trusted-chat'; },
  ];
  for (const change of changes) {
    const h = await harness(initial({ grantedHostIds: ['prod'] }), (call, state) => call.name === 'ssh_test_connection' ? connectionReply(state) : undefined);
    await h.findAction('test', 'prod').click(); await h.settle();
    assert.ok(findConnectionResult(h, 'prod'));
    change(h.state());
    await h.ids.get('refresh').click(); await h.settle();
    assert.equal(findConnectionResult(h, 'prod'), undefined, change.toString());
  }
});

test('a connection reply for changed host configuration is discarded while updated state is still applied', async () => {
  const h = await harness(initial({ grantedHostIds: ['prod'] }), (call, state) => {
    if (call.name !== 'ssh_test_connection') return;
    state.hosts[0].hostname = 'changed-during-test.invalid';
    return connectionReply(state);
  });
  await h.findAction('test', 'prod').click(); await h.settle();
  assert.match(h.ids.get('host-list').textContent, /changed-during-test.invalid/);
  assert.equal(findConnectionResult(h, 'prod'), undefined);
});

test('a bridge timeout ends pending status and allows a connection retry without inventing success', async () => {
  const h = await harness(initial({ grantedHostIds: ['prod'] }), call => call.name === 'ssh_test_connection' ? new Promise(() => {}) : undefined);
  const pending = h.findAction('test', 'prod').click(); await h.settle();
  const timeout = [...h.timeouts.values()].at(-1);
  assert.equal(typeof timeout, 'function'); timeout();
  await pending; await h.settle();
  assert.match(findConnectionResult(h, 'prod').textContent, /超时/);
  assert.doesNotMatch(findConnectionResult(h, 'prod').textContent, /连接成功|测试中/);
  assert.equal(h.findAction('test', 'prod').disabled, false);
});


const policy = () => ({ mode: 'restricted', roots: [], blockedPaths: [], commandRules: [], actions: { 'system.summary': 'allow', 'service.restart': 'ask' }, grantMinutes: 60, timeoutSeconds: 60, maxConcurrent: 2, maxOutputKiB: 128 });
const catalog = [
  { id: 'system.summary', label: '系统摘要', description: '读取系统信息', category: '系统', mutating: false, defaultDecision: 'allow', parameters: [] },
  { id: 'service.restart', label: '重启服务', description: '重启指定服务', category: '服务', mutating: true, defaultDecision: 'ask', parameters: [{ name: 'name', label: '服务名称', type: 'string', required: true }] },
];
function governanceReply(call, state) {
  if (call.name === 'ssh_permissions') return { content: [], structuredContent: { state: structuredClone(state), policy: { hostId: call.arguments.hostId, revision: 3, policy: policy() }, actions: catalog } };
}
function findData(root, key, value) {
  if (root.dataset?.[key] === value) return root;
  for (const child of root.children ?? []) { const found = findData(child, key, value); if (found) return found; }
}

test('injects UI capability only into UI tools and never sends chat identity in arguments', async () => {
  const h = await harness(initial(), governanceReply);
  await h.findAction('grant', 'prod').click(); await h.settle();
  await h.findAction('policy', 'prod').click(); await h.settle();
  const grant = h.calls.find(call => call.name === 'ssh_grant');
  assert.equal(grant.arguments.uiToken, '__SSH_UI_TOKEN__');
  assert.equal(grant.arguments.minutes, 60);
  assert.equal('threadId' in grant.arguments, false);
  assert.deepEqual(h.calls.find(call => call.name === 'ssh_permissions').arguments, { hostId: 'prod' });
  assert.deepEqual(h.calls.find(call => call.name === 'ssh_status').arguments, {});
});

test('policy form saves editable directory and command rows with revision and no JSON input', async () => {
  const h = await harness(initial(), (call, state) => {
    if (call.name === 'ssh_policy_save') return { content: [], structuredContent: { state: { ...state, grantedHostIds: [] }, policy: { hostId: 'prod', revision: 4, policy: call.arguments.policy } } };
    return governanceReply(call, state);
  });
  await h.findAction('policy', 'prod').click(); await h.settle();
  assert.equal(h.ids.get('policy-editor').hidden, false);
  await h.ids.get('add-root').click();
  findData(h.ids.get('policy-roots'), 'field', 'path').value = '/srv/app';
  findData(h.ids.get('policy-roots'), 'field', 'read').checked = true;
  findData(h.ids.get('policy-roots'), 'field', 'write').checked = true;
  await h.ids.get('add-command-rule').click();
  findData(h.ids.get('policy-rules'), 'field', 'pattern').value = 'rm ';
  findData(h.ids.get('policy-rules'), 'field', 'match').value = 'prefix';
  findData(h.ids.get('policy-rules'), 'field', 'decision').value = 'deny';
  await h.ids.get('policy-form').onsubmit({ preventDefault() {} }); await h.settle();
  const call = h.calls.find(call => call.name === 'ssh_policy_save');
  assert.equal(call.arguments.expectedRevision, 3);
  assert.equal(call.arguments.policy.roots[0].path, '/srv/app');
  assert.equal(call.arguments.policy.roots[0].write, true);
  assert.equal(call.arguments.policy.commandRules[0].decision, 'deny');
  assert.equal(call.arguments.uiToken, '__SSH_UI_TOKEN__');
  assert.match(h.ids.get('policy-save-notice').textContent, /撤销.*授权/);
  assert.equal(h.ids.get('policy-editor').hidden, false);
});

test('policy conflict preserves form values and automatic refresh does not replace the draft', async () => {
  const h = await harness(initial(), (call, state) => call.name === 'ssh_policy_save'
    ? { isError: true, content: [{ type: 'text', text: '策略版本已变化，请重新载入。' }] } : governanceReply(call, state));
  await h.findAction('policy', 'prod').click(); await h.settle();
  h.ids.get('policy-timeout').value = '99';
  h.intervals[0](); await h.settle();
  assert.equal(h.ids.get('policy-timeout').value, '99');
  await h.ids.get('policy-form').onsubmit({ preventDefault() {} }); await h.settle();
  assert.equal(h.ids.get('policy-editor').hidden, false);
  assert.equal(h.ids.get('policy-timeout').value, '99');
  assert.match(h.ids.get('error-message').textContent, /版本/);
});

test('mutating action form cannot select automatic allow and advanced mode keeps its confinement warning', async () => {
  const h = await harness(initial(), governanceReply);
  await h.findAction('policy', 'prod').click(); await h.settle();
  const action = findData(h.ids.get('policy-actions'), 'actionId', 'service.restart');
  assert.equal(action.children.some(child => child.value === 'allow'), false);
  h.ids.get('policy-mode').value = 'approval'; h.ids.get('policy-mode').onchange();
  assert.equal(h.ids.get('shell-warning').hidden, false);
  assert.match(h.ids.get('shell-warning').textContent, /目录.*不能|不能.*目录/);
  assert.match(h.ids.get('protected-resources').textContent, /不可关闭/);
});

test('rule preview uses draft values and named action parameters without executing SSH', async () => {
  const h = await harness(initial(), (call, state) => call.name === 'ssh_policy_preview'
    ? { content: [], structuredContent: { state, evaluation: { decision: 'ask', reason: '变更操作需要批准', summary: '重启服务 nginx' }, granted: false } } : governanceReply(call, state));
  await h.findAction('policy', 'prod').click(); await h.settle();
  h.ids.get('preview-kind').value = 'action'; h.ids.get('preview-kind').onchange();
  h.ids.get('preview-action').value = 'service.restart'; h.ids.get('preview-action').onchange();
  findData(h.ids.get('preview-parameters'), 'parameter', 'name').value = 'nginx';
  h.ids.get('policy-timeout').value = '90';
  await h.ids.get('preview-run').click(); await h.settle();
  const call = h.calls.find(call => call.name === 'ssh_policy_preview');
  assert.deepEqual(call.arguments.operation, { kind: 'action', actionId: 'service.restart', args: { name: 'nginx' } });
  assert.equal(call.arguments.draftPolicy.timeoutSeconds, 90);
  assert.match(h.ids.get('preview-result').textContent, /需确认/);
  assert.match(h.ids.get('preview-result').textContent, /未授权|未生效/);
  assert.equal(h.calls.some(call => ['ssh_exec', 'ssh_run_action', 'ssh_test_connection'].includes(call.name)), false);
});

test('raw command preview omits blank cwd to use the saved host default and preserves an override', async () => {
  const h = await harness(initial({ hosts: [host('prod', { defaultCwd: '/srv/app' })] }), (call, state) => call.name === 'ssh_policy_preview'
    ? { content: [], structuredContent: { state, evaluation: { decision: 'ask', reason: '完整命令需确认' }, granted: false } } : governanceReply(call, state));
  await h.findAction('policy', 'prod').click(); await h.settle();
  h.ids.get('preview-kind').value = 'command'; h.ids.get('preview-kind').onchange();
  h.ids.get('preview-command').value = 'pwd';
  await h.ids.get('preview-run').click(); await h.settle();
  assert.deepEqual(h.calls.filter(call => call.name === 'ssh_policy_preview').at(-1).arguments.operation, { kind: 'command', command: 'pwd' });
  h.ids.get('preview-cwd').value = ' /srv/override ';
  await h.ids.get('preview-run').click(); await h.settle();
  assert.deepEqual(h.calls.filter(call => call.name === 'ssh_policy_preview').at(-1).arguments.operation, { kind: 'command', command: 'pwd', cwd: '/srv/override' });
});



test('audit filters and next-page cursor use actual API results and render hostile summary as text', async () => {
  const h = await harness(initial(), (call, state) => call.name === 'ssh_audit_list' ? { content: [], structuredContent: { state, items: [{ id: call.arguments.beforeId ? 1 : 2, createdAt: Date.now(), hostId: 'prod', threadId: 'chat', event: 'operation', summary: '<img onerror=alert(1)>', result: 'denied', reason: '受保护路径' }], nextCursor: call.arguments.beforeId ? null : 2 } } : undefined);
  await h.ids.get('tab-audit').click(); await h.settle();
  assert.ok(h.ids.get('audit-list').textContent.includes('<img onerror=alert(1)>'));
  await h.ids.get('audit-more').click(); await h.settle();
  assert.equal(h.calls.filter(call => call.name === 'ssh_audit_list').at(-1).arguments.beforeId, 2);
  assert.equal(h.ids.get('audit-list').children.length, 2);
  h.ids.get('audit-result').value = 'denied'; h.ids.get('audit-result').onchange(); await h.settle();
  assert.equal(h.calls.filter(call => call.name === 'ssh_audit_list').at(-1).arguments.result, 'denied');
});

test('expired grant is shown as expired and cannot enable a connection test', async () => {
  const h = await harness(initial({ grantedHostIds: ['prod'], grants: [{ hostId: 'prod', expiresAt: Date.now() - 1, policyRevision: 1 }] }));
  assert.equal(h.ids.get('grant-count').textContent, '0');
  assert.equal(h.findAction('test', 'prod').disabled, true);
  assert.match(h.ids.get('host-list').textContent, /已到期/);
});


test('grant duration is capped by the selected host policy and renewal carries the duration', async () => {
  const h = await harness(initial({ policies: [{ hostId: 'prod', revision: 1, policy: { ...policy(), grantMinutes: 10 } }] }));
  h.ids.get('grant-minutes').value = '240';
  await h.findAction('grant', 'prod').click(); await h.settle();
  assert.equal(h.calls.find(call => call.name === 'ssh_grant').arguments.minutes, 10);
  await h.findAction('renew', 'prod').click(); await h.settle();
  assert.equal(h.calls.filter(call => call.name === 'ssh_grant').length, 2);
});

test('policy revision changes invalidate previously successful connection results', async () => {
  const h = await harness(initial({ grantedHostIds: ['prod'], policies: [{ hostId: 'prod', revision: 1, policy: policy() }] }), (call, state) => call.name === 'ssh_test_connection' ? connectionReply(state) : undefined);
  await h.findAction('test', 'prod').click(); await h.settle();
  assert.match(findConnectionResult(h, 'prod').textContent, /连接成功/);
  h.state().policies[0].revision = 2;
  await h.ids.get('refresh').click(); await h.settle();
  assert.equal(findConnectionResult(h, 'prod'), undefined);
});


test('pressing Enter in a preview field previews instead of saving and revoking grants', async () => {
  const h = await harness(initial(), (call, state) => call.name === 'ssh_policy_preview'
    ? { content: [], structuredContent: { state, evaluation: { decision: 'deny', reason: '未配置目录', summary: '读取文件' }, granted: false } } : governanceReply(call, state));
  await h.findAction('policy', 'prod').click(); await h.settle();
  h.ids.get('preview-kind').value = 'read'; h.ids.get('preview-kind').onchange(); h.ids.get('preview-path').value = '/srv/app/a';
  let prevented = false;
  assert.equal(typeof h.ids.get('preview-section')?.onkeydown, 'function');
  h.ids.get('preview-section').onkeydown({ key: 'Enter', target: h.ids.get('preview-path'), preventDefault() { prevented = true; } }); await h.settle();
  assert.equal(prevented, true);
  assert.ok(h.calls.some(call => call.name === 'ssh_policy_preview'));
  assert.equal(h.calls.some(call => call.name === 'ssh_policy_save'), false);
});

test('policy fields cannot change while a save is in progress and are restored on failure', async () => {
  let fail;
  const h = await harness(initial(), (call, state) => call.name === 'ssh_policy_save'
    ? new Promise(resolve => { fail = () => resolve({ isError: true, content: [{ type: 'text', text: '保存失败' }] }); }) : governanceReply(call, state));
  await h.findAction('policy', 'prod').click(); await h.settle();
  await h.ids.get('add-root').click(); const path = findData(h.ids.get('policy-roots'), 'field', 'path'); path.value = '/srv/app';
  const saving = h.ids.get('policy-form').onsubmit({ preventDefault() {} }); await h.settle();
  assert.equal(h.ids.get('policy-timeout').disabled, true);
  assert.equal(path.disabled, true);
  fail(); await saving; await h.settle();
  assert.equal(path.value, '/srv/app'); assert.equal(path.disabled, false);
  assert.equal(h.ids.get('policy-timeout').disabled, false);
});




test('edit and permissions share a full host detail view that replaces the host list', async () => {
  const h = await harness(initial(), governanceReply);
  await h.findAction('edit', 'prod').click(); await h.settle();
  assert.equal(h.ids.get('host-list-view').hidden, true);
  assert.equal(h.ids.get('host-detail-view').hidden, false);
  assert.match(h.ids.get('detail-title').textContent, /prod/);
  assert.equal(h.ids.get('editor').hidden, false);
  assert.equal(h.ids.get('policy-editor').hidden, true);
  await h.ids.get('detail-tab-policy').click(); await h.settle();
  assert.equal(h.ids.get('editor').hidden, true);
  assert.equal(h.ids.get('policy-editor').hidden, false);
  assert.equal(h.ids.get('host-list-view').hidden, true);
  await h.ids.get('detail-back').click(); await h.settle();
  assert.equal(h.ids.get('host-list-view').hidden, false);
  await h.findAction('policy', 'prod').click(); await h.settle();
  assert.equal(h.ids.get('policy-editor').hidden, false);
  assert.equal(h.ids.get('detail-tab-policy').getAttribute('aria-selected'), 'true');
});

test('host detail preserves both drafts across subtabs and dirty back requires explicit discard', async () => {
  const h = await harness(initial(), governanceReply);
  await h.findAction('edit', 'prod').click();
  h.ids.get('host-name').value = '连接草稿';
  await h.ids.get('detail-tab-policy').click(); await h.settle();
  h.ids.get('policy-timeout').value = '97';
  await h.ids.get('detail-tab-connection').click(); await h.settle();
  assert.equal(h.ids.get('host-name').value, '连接草稿');
  await h.ids.get('detail-tab-policy').click(); await h.settle();
  assert.equal(h.ids.get('policy-timeout').value, '97');
  assert.equal(h.calls.filter(call => call.name === 'ssh_permissions').length, 1);
  await h.ids.get('detail-back').click();
  assert.equal(h.ids.get('discard-confirmation').hidden, false);
  assert.equal(h.ids.get('host-list-view').hidden, true);
  await h.ids.get('keep-editing').click();
  assert.equal(h.ids.get('discard-confirmation').hidden, true);
  assert.equal(h.ids.get('policy-timeout').value, '97');
  await h.ids.get('detail-back').click(); await h.ids.get('discard-detail').click();
  assert.equal(h.ids.get('host-list-view').hidden, false);
  assert.equal(h.ids.get('host-detail-view').hidden, true);
});

test('new host must save connection settings before permissions become available', async () => {
  const h = await harness(initial({ hosts: [] }), governanceReply);
  await h.ids.get('add-host').click();
  assert.equal(h.ids.get('detail-tab-policy').disabled, true);
  h.ids.get('host-id').value = 'new-server'; h.ids.get('host-name').value = '新服务器';
  h.ids.get('host-hostname').value = 'new.example.invalid'; h.ids.get('host-username').value = 'deploy';
  await h.ids.get('host-form').onsubmit({ preventDefault() {} }); await h.settle();
  assert.equal(h.ids.get('host-detail-view').hidden, false);
  assert.equal(h.ids.get('detail-tab-policy').disabled, false);
  assert.equal(h.ids.get('host-id').disabled, true);
  assert.match(h.ids.get('detail-title').textContent, /新服务器/);
  await h.ids.get('detail-back').click();
  assert.equal(h.ids.get('discard-confirmation').hidden, true);
  assert.equal(h.ids.get('host-list-view').hidden, false);
});

test('sidebar has no approval queue or manual-retry tools and native decline is shown distinctly', async () => {
  const h = await harness(initial({ grantedHostIds: ['prod'] }), call => call.name === 'ssh_test_connection'
    ? { isError: true, structuredContent: { code: 'approval_declined' }, content: [{ type: 'text', text: '用户拒绝执行本次操作。' }] } : undefined);
  assert.equal(h.ids.has('tab-approvals'), false);
  assert.equal(h.ids.has('approval-list'), false);
  await h.findAction('test', 'prod').click(); await h.settle();
  assert.match(findConnectionResult(h, 'prod').textContent, /未获批准|拒绝执行/);
  assert.doesNotMatch(findConnectionResult(h, 'prod').textContent, /查看待审批|连接成功/);
  assert.equal(h.calls.some(call => /^ssh_approval_/.test(call.name)), false);
});

const historyItem = (id, overrides = {}) => ({ id, operationId: 'op-' + id, threadId: 'original-chat', hostId: 'prod', summary: '重启应用服务', explanation: '使新的应用配置生效', status: 'completed', startedAt: 1770000000000, finishedAt: 1770000001000, exitCode: 0, completionKnown: true, truncated: false, redacted: false, outputNotice: '', ...overrides });
const historyDetail = (id, overrides = {}) => ({ ...historyItem(id), hostSnapshot: { id: 'prod', name: '生产主机', hostname: 'prod.example.invalid', username: 'deploy', port: 22 }, operationSnapshot: { kind: 'command', command: 'systemctl restart app' }, requestedCommand: 'systemctl restart app', command: '/usr/bin/systemctl restart app', cwd: '/', stdout: '<script>output as text</script>', stderr: '', policyRevision: 3, ...overrides });

test('execution history lists and paginates without fetching bodies or executing commands', async () => {
  const h = await harness(initial(), (call, state) => call.name === 'ssh_history_list' ? { content: [], structuredContent: { state, items: [historyItem(call.arguments.beforeId ? 1 : 2)], nextCursor: call.arguments.beforeId ? null : 2 } } : undefined);
  await h.ids.get('tab-history').click(); await h.settle();
  assert.match(h.ids.get('history-list').textContent, /使新的应用配置生效/);
  assert.equal(h.calls.some(call => call.name === 'ssh_history_get'), false);
  await h.ids.get('history-more').click(); await h.settle();
  assert.equal(h.ids.get('history-list').children.length, 2);
  assert.equal(h.calls.filter(call => call.name === 'ssh_history_list').at(-1).arguments.beforeId, 2);
  h.ids.get('history-status').value = 'failed'; h.ids.get('history-status').onchange(); await h.settle();
  const last = h.calls.filter(call => call.name === 'ssh_history_list').at(-1);
  assert.equal(last.arguments.status, 'failed'); assert.equal(last.arguments.uiToken, '__SSH_UI_TOKEN__');
  assert.equal('beforeId' in last.arguments, false);
  assert.equal(h.calls.some(call => ['ssh_exec', 'ssh_run_action'].includes(call.name)), false);
});

test('history detail shows purpose before exact commands and output strictly as text', async () => {
  const entry = historyDetail(2, { explanation: '应用修改后的配置 <img onerror=alert(1)>', truncated: true });
  const h = await harness(initial(), (call, state) => {
    if (call.name === 'ssh_history_list') return { content: [], structuredContent: { state, items: [historyItem(2)], nextCursor: null } };
    if (call.name === 'ssh_history_get') return { content: [], structuredContent: { state, entry } };
  });
  await h.ids.get('tab-history').click(); await h.settle();
  await findData(h.ids.get('history-list'), 'historyId', '2').click(); await h.settle();
  assert.deepEqual(h.calls.find(call => call.name === 'ssh_history_get').arguments, { historyId: 2, uiToken: '__SSH_UI_TOKEN__' });
  assert.equal(h.ids.get('history-list-view').hidden, true);
  const detail = h.ids.get('history-detail-content').textContent;
  assert.ok(detail.includes(entry.explanation)); assert.ok(detail.includes(entry.stdout));
  assert.ok(detail.includes(entry.requestedCommand)); assert.ok(detail.includes(entry.command));
  assert.ok(detail.indexOf(entry.explanation) < detail.indexOf(entry.requestedCommand));
  assert.match(detail, /截断/);
  await h.ids.get('history-back').click();
  assert.equal(h.ids.get('history-list-view').hidden, false);
});

test('redacted and unknown history state never presents hidden output or invented completion', async () => {
  const h = await harness(initial(), (call, state) => {
    if (call.name === 'ssh_history_list') return { content: [], structuredContent: { state, items: [historyItem(3)], nextCursor: null } };
    if (call.name === 'ssh_history_get') return { content: [], structuredContent: { state, entry: historyDetail(3, { status: 'unknown', completionKnown: false, redacted: true, stdout: 'must-not-render', stderr: 'must-not-render', outputNotice: '敏感输出已隐藏。' }) } };
  });
  await h.ids.get('tab-history').click(); await h.settle(); await findData(h.ids.get('history-list'), 'historyId', '3').click(); await h.settle();
  const detail = h.ids.get('history-detail-content').textContent;
  assert.match(detail, /状态未知/); assert.match(detail, /敏感输出已隐藏/);
  assert.doesNotMatch(detail, /must-not-render|执行已完成/);
});

test('running history detail refreshes while visible and stops after final completion', async () => {
  let reads = 0;
  const h = await harness(initial(), (call, state) => {
    if (call.name === 'ssh_history_list') return { content: [], structuredContent: { state, items: [historyItem(4, { status: 'running' })], nextCursor: null } };
    if (call.name === 'ssh_history_get') return { content: [], structuredContent: { state, entry: historyDetail(4, ++reads === 1 ? { status: 'running', finishedAt: null, stdout: '', completionKnown: false } : {}) } };
  });
  await h.ids.get('tab-history').click(); await h.settle(); await findData(h.ids.get('history-list'), 'historyId', '4').click(); await h.settle();
  assert.match(h.ids.get('history-detail-content').textContent, /执行中/);
  h.document.hidden = true; h.intervals[0](); await h.settle(); assert.equal(reads, 1);
  h.document.hidden = false; h.intervals[0](); await h.settle();
  assert.equal(reads, 2); assert.match(h.ids.get('history-detail-content').textContent, /已完成/);
  h.intervals[0](); await h.settle(); assert.equal(reads, 2);
});

test('a delayed history detail cannot replace a later selection or a different active tab', async () => {
  let finishOld;
  const h = await harness(initial(), (call, state) => {
    if (call.name === 'ssh_history_list') return { content: [], structuredContent: { state, items: [historyItem(1), historyItem(2)], nextCursor: null } };
    if (call.name === 'ssh_history_get') return call.arguments.historyId === 1
      ? new Promise(resolve => { finishOld = () => resolve({ content: [], structuredContent: { state, entry: historyDetail(1, { explanation: 'old result' }) } }); })
      : { content: [], structuredContent: { state, entry: historyDetail(2, { explanation: 'new selected result' }) } };
  });
  await h.ids.get('tab-history').click(); await h.settle();
  const old = findData(h.ids.get('history-list'), 'historyId', '1').click(); await h.settle();
  await h.ids.get('history-back').click(); await findData(h.ids.get('history-list'), 'historyId', '2').click(); await h.settle();
  finishOld(); await old; await h.settle();
  assert.match(h.ids.get('history-detail-content').textContent, /new selected result/);
  assert.doesNotMatch(h.ids.get('history-detail-content').textContent, /old result/);
});


test('native approval error prefixes preserve state classification but display only the human reason', async () => {
  for (const [code, label] of [['APPROVAL_DECLINED', '未获批准'], ['APPROVAL_CANCELLED', '已取消'], ['APPROVAL_TIMEOUT', '确认超时'], ['APPROVAL_UNSUPPORTED', '无法请求确认']]) {
    const h = await harness(initial({ grantedHostIds: ['prod'] }), call => call.name === 'ssh_test_connection'
      ? { isError: true, content: [{ type: 'text', text: code + ': 本次操作没有执行。' }] } : undefined);
    await h.findAction('test', 'prod').click(); await h.settle();
    assert.ok(findConnectionResult(h, 'prod').textContent.includes(label));
    assert.match(h.ids.get('error-message').textContent, /本次操作没有执行/);
    assert.equal(h.ids.get('error-message').textContent.includes(code), false);
  }
});

test('completed history content is not rebuilt by periodic status refresh while a user reads it', async () => {
  const h = await harness(initial(), (call, state) => {
    if (call.name === 'ssh_history_list') return { content: [], structuredContent: { state, items: [historyItem(8)], nextCursor: null } };
    if (call.name === 'ssh_history_get') return { content: [], structuredContent: { state, entry: historyDetail(8) } };
  });
  await h.ids.get('tab-history').click(); await h.settle(); await findData(h.ids.get('history-list'), 'historyId', '8').click(); await h.settle();
  const original = h.ids.get('history-detail-content').children[0];
  h.intervals[0](); await h.settle();
  assert.equal(h.ids.get('history-detail-content').children[0], original);
  assert.equal(h.calls.filter(call => call.name === 'ssh_history_get').length, 1);
});

test('saving one host subtab preserves the other unsaved draft', async () => {
  const h = await harness(initial(), governanceReply);
  await h.findAction('edit', 'prod').click(); h.ids.get('host-name').value = '修改连接名称';
  await h.ids.get('detail-tab-policy').click(); await h.settle(); h.ids.get('policy-timeout').value = '88';
  await h.ids.get('detail-tab-connection').click();
  await h.ids.get('host-form').onsubmit({ preventDefault() {} }); await h.settle();
  await h.ids.get('detail-tab-policy').click(); assert.equal(h.ids.get('policy-timeout').value, '88');
  await h.ids.get('detail-back').click(); assert.equal(h.ids.get('discard-confirmation').hidden, false);
});

test('structured file history shows path and digest without exposing a file body', async () => {
  const h = await harness(initial(), (call, state) => {
    if (call.name === 'ssh_history_list') return { content: [], structuredContent: { state, items: [historyItem(9)], nextCursor: null } };
    if (call.name === 'ssh_history_get') return { content: [], structuredContent: { state, entry: historyDetail(9, { requestedCommand: '', command: '', operationSnapshot: { kind: 'write', path: '/srv/app/a.txt', bytes: 12, sha256: 'abcdef1234', content: 'must-not-show-file-body' }, stdout: '', stderr: '', outputNotice: '文件正文未写入执行历史。' }) } };
  });
  await h.ids.get('tab-history').click(); await h.settle(); await findData(h.ids.get('history-list'), 'historyId', '9').click(); await h.settle();
  const detail = h.ids.get('history-detail-content').textContent;
  assert.match(detail, /写入文件/); assert.ok(detail.includes('/srv/app/a.txt')); assert.ok(detail.includes('abcdef1234'));
  assert.doesNotMatch(detail, /must-not-show-file-body/);
});

for (const scenario of [
  { name: 'successful SSH banner', status: 'completed', exitCode: 0, completionKnown: true, success: true },
  { name: 'failed command with banner and real error', status: 'failed', exitCode: 1, completionKnown: true, success: false },
  { name: 'unknown completion', status: 'unknown', exitCode: null, completionKnown: false, success: false },
  { name: 'timed out despite a zero exit code', status: 'timed_out', exitCode: 0, completionKnown: true, success: false },
  { name: 'unconfirmed completion', status: 'completed', exitCode: 0, completionKnown: false, success: false },
]) {
  test('history presents stderr as diagnostic output: ' + scenario.name, async () => {
    const banner = 'SSH warring: Authorized users only. All activity may be monitored and reported \r\n';
    const stderr = banner + (scenario.status === 'failed' ? 'Error: No such container: jenkins\n' : '');
    const entry = historyDetail(11, { ...scenario, stderr });
    const h = await harness(initial(), (call, state) => {
      if (call.name === 'ssh_history_list') return { content: [], structuredContent: { state, items: [historyItem(11)], nextCursor: null } };
      if (call.name === 'ssh_history_get') return { content: [], structuredContent: { state, entry } };
    });
    await h.ids.get('tab-history').click(); await h.settle();
    await findData(h.ids.get('history-list'), 'historyId', '11').click(); await h.settle();
    const detail = h.ids.get('history-detail-content');
    const diagnostic = detail.children.find(section => section.children?.[0]?.textContent === '诊断输出（stderr）');
    assert.ok(diagnostic, 'stderr must not be labeled as an execution error');
    assert.equal(diagnostic.children.find(child => child.tagName === 'PRE').textContent, stderr, 'retain the complete original banner and any real error');
    assert.match(diagnostic.textContent, /SSH 登录提示/);
    assert.doesNotMatch(detail.textContent, /错误输出/);
    assert.equal(diagnostic.textContent.includes('命令已成功完成（退出码 0）'), scenario.success);
  });
}
