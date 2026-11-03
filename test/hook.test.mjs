import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { handlePrompt } from '../hooks/prompt.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const payload = (extra = {}) => ({ hook_event_name: 'UserPromptSubmit', session_id: 'session-1', turn_id: 'turn-1', prompt: '/ssh-prod /ssh-uat', ...extra });

function recorder() {
  const records = [];
  let opened = 0;
  let closed = 0;
  return {
    records,
    options: { now: () => 1000, openStore: async () => { opened++; return { recordIntent: (value) => records.push(value), close: () => { closed++; } }; } },
    counts: () => ({ opened, closed }),
  };
}

test('hook records an exact session/turn intent for 120 seconds, without granting', async () => {
  const capture = recorder();
  const output = await handlePrompt(payload(), capture.options);
  assert.deepEqual(capture.records, [{ sessionId: 'session-1', turnId: 'turn-1', operation: 'grant', hostIds: ['prod', 'uat'], expiresAt: 121000 }]);
  assert.deepEqual(capture.counts(), { opened: 1, closed: 1 });
  assert.equal(output.hookSpecificOutput.hookEventName, 'UserPromptSubmit');
  assert.match(output.hookSpecificOutput.additionalContext, /ssh_authorization_sync/);
  assert.match(output.hookSpecificOutput.additionalContext, /返回/);
  assert.ok(!JSON.stringify(output).includes(payload().prompt));
});

test('ordinary prompts and other lifecycle events never open state', async () => {
  const capture = recorder();
  for (const data of [payload({ prompt: 'Explain /ssh-prod please. TOKEN=private' }), payload({ prompt: '' }), payload({ hook_event_name: 'Stop' }), null]) {
    assert.deepEqual(await handlePrompt(data, capture.options), {});
  }
  assert.deepEqual(capture.counts(), { opened: 0, closed: 0 });
});

test('visible subagent tags cannot produce authorization intent', async () => {
  const tags = [
    { agent_id: 'child' }, { agentId: 'child' }, { agent_type: 'worker' },
    { subagent: { agent_id: 'child' } }, { subagent_id: 'child' },
    { parent_thread_id: 'parent' }, { session_source: 'subagent' },
    { session_source: { subagent: { parent_thread_id: 'parent' } } },
  ];
  for (const tag of tags) {
    const capture = recorder();
    const output = await handlePrompt(payload(tag), capture.options);
    assert.deepEqual(capture.records, []);
    assert.match(output.systemMessage, /子/);
    assert.deepEqual(capture.counts(), { opened: 0, closed: 0 });
  }
});

test('missing or malformed trusted identity does not write intent', async () => {
  for (const extra of [{ session_id: '' }, { turn_id: null }, { turn_id: 'x\ny' }, { session_id: 42 }]) {
    const capture = recorder();
    const output = await handlePrompt(payload(extra), capture.options);
    assert.match(output.systemMessage, /身份/);
    assert.deepEqual(capture.records, []);
  }
});

test('revoke and status are recorded without changing requested operation', async () => {
  for (const [prompt, operation, hostIds] of [['/ssh-revoke-prod', 'revoke', ['prod']], ['$ssh-status', 'status', []]]) {
    const capture = recorder();
    await handlePrompt(payload({ prompt }), capture.options);
    assert.deepEqual(capture.records[0], { sessionId: 'session-1', turnId: 'turn-1', operation, hostIds, expiresAt: 121000 });
  }
});

test('state failures close the store and never echo sensitive error content', async () => {
  let closed = false;
  const output = await handlePrompt(payload(), {
    now: () => 1000,
    openStore: async () => ({ recordIntent: () => { throw new Error('private host/token raw user prompt'); }, close: () => { closed = true; } }),
  });
  assert.ok(closed);
  assert.match(output.systemMessage, /未/);
  assert.doesNotMatch(JSON.stringify(output), /private|token|raw user/);
});

test('stdin entrypoint ignores ordinary prompts without creating a database', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'ssh-hook-test-'));
  try {
    const result = spawnSync(process.execPath, [path.join(root, 'hooks', 'prompt.mjs')], { input: JSON.stringify(payload({ prompt: 'hello private-token' })), encoding: 'utf8', env: { ...process.env, SSH_CONTROL_DATA: dir } });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, '');
    assert.equal(existsSync(path.join(dir, 'store.sqlite')), false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('stdin rejects malformed or excessive input without echoing it', () => {
  for (const input of ['private-invalid-json', 'private'.repeat(160000)]) {
    const result = spawnSync(process.execPath, [path.join(root, 'hooks', 'prompt.mjs')], { input, encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.match(output.systemMessage, /输入/);
    assert.doesNotMatch(result.stdout + result.stderr, /private/);
  }
});

test('packaged hook command resolves PLUGIN_ROOT through the actual platform shell', () => {
  const config = JSON.parse(readFileSync(path.join(root, 'hooks', 'hooks.json'), 'utf8'));
  const handler = config.hooks.UserPromptSubmit[0].hooks[0];
  assert.equal(handler.type, 'command');
  assert.notEqual(handler.async, true);
  const result = spawnSync(handler.command, { shell: true, input: JSON.stringify(payload({ prompt: 'ordinary message' })), encoding: 'utf8', env: { ...process.env, PLUGIN_ROOT: root } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
});

test('real stdin hook and independent Store instances bind an additive intent to one exact chat', async () => {
  const { Store } = await import('../src/store.mjs');
  const dir = mkdtempSync(path.join(tmpdir(), 'ssh-hook-binding-'));
  const store = new Store(dir);
  try {
    for (const id of ['prod', 'uat', 'existing']) store.saveHost({ id, sshAlias: `demo-${id}`, enabled: true });
    store.grant('chat-main', ['existing']);
    const result = spawnSync(process.execPath, [path.join(root, 'hooks', 'prompt.mjs')], {
      input: JSON.stringify(payload()), encoding: 'utf8', env: { ...process.env, SSH_CONTROL_DATA: dir },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(JSON.parse(result.stdout).hookSpecificOutput.additionalContext, /ssh_authorization_sync/);
    assert.deepEqual(store.state('chat-main').grantedHostIds, ['existing']);
    assert.deepEqual(store.consumeIntent({ threadId: 'chat-other', sessionId: 'session-1', turnId: 'different-turn' }).grantedHostIds, []);
    assert.deepEqual(store.consumeIntent({ threadId: 'chat-main', sessionId: 'session-1', turnId: 'turn-1' }).grantedHostIds, ['existing', 'prod', 'uat']);
    assert.deepEqual(store.consumeIntent({ threadId: 'chat-child', sessionId: 'session-1', turnId: 'turn-1' }).grantedHostIds, []);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
