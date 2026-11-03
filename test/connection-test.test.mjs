import test from 'node:test';
import assert from 'node:assert/strict';
import { CONNECTION_TEST_COMMAND, testConnection } from '../src/connection-test.mjs';



const host = { id: 'prod', hostname: 'example.invalid', username: 'deploy', defaultCwd: '/must-not-run-default-cwd' };
const healthy = { status: 'completed', exitCode: 0, stdout: 'SSH_CONTROL_OK\ndeploy\nnode-1\nLinux\n', stderr: '' };

function fakeRunner(result) {
  const calls = [];
  return {
    calls,
    start(...args) { calls.push(['start', ...args]); return { id: 'fixed-task' }; },
    async wait(...args) { calls.push(['wait', ...args]); return result; },
  };
}

async function check(result) {
  assert.equal(typeof testConnection, 'function', 'testConnection export must exist');
  return testConnection(fakeRunner(result), 'trusted-thread', host);
}

test('runs only the fixed read-only command without the host default working directory', async () => {
  assert.equal(typeof testConnection, 'function', 'testConnection export must exist');
  assert.equal(CONNECTION_TEST_COMMAND, "printf '%s\\n' 'SSH_CONTROL_OK' && id -un && hostname && uname -s");
  const runner = fakeRunner(healthy);
  const result = await testConnection(runner, 'trusted-thread', host);
  assert.deepEqual(runner.calls, [
    ['start', 'trusted-thread', host, CONNECTION_TEST_COMMAND, { cwd: '', timeoutSeconds: 20 }],
    ['wait', 'trusted-thread', 'fixed-task'],
  ]);
  assert.equal(result.hostId, 'prod'); assert.equal(result.ok, true); assert.equal(result.code, 'success');
  assert.equal(result.output, healthy.stdout); assert.equal(result.detail, '');
  assert.match(result.message, /连接|认证/);
  assert.ok(Number.isFinite(Date.parse(result.checkedAt)));
  assert.ok(Number.isFinite(result.durationMs) && result.durationMs >= 0);
});

const errors = [
  ['unknown_host_key', 'No ED25519 host key is known for example.invalid and you have requested strict checking.\r\nHost key verification failed.\r\n'],
  ['unknown_host_key', 'No RSA host key is known for [example.invalid]:2222 and you have requested strict checking.\nHost key verification failed.'],
  ['changed_host_key', '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\nHost key verification failed.'],
  ['host_key_verification_failed', 'Host key verification failed.'],
  ['authentication_failed', 'deploy@example.invalid: Permission denied (publickey,password).\r\n'],
  ['authentication_failed', 'Received disconnect from 192.0.2.1 port 22:2: Too many authentication failures'],
  ['key_unavailable', 'Warning: Identity file C:\\keys\\missing not accessible: No such file or directory.\nPermission denied (publickey).'],
  ['key_unavailable', 'Load key "/keys/id_ed25519": Permission denied\nPermission denied (publickey).'],
  ['network_timeout', 'ssh: connect to host example.invalid port 22: Connection timed out'],
  ['network_timeout', 'Connection to example.invalid port 22 timed out'],
  ['network_timeout', 'Timeout, server example.invalid not responding.'],
  ['connection_refused', 'ssh: connect to host example.invalid port 22: Connection refused'],
  ['dns_failed', 'ssh: Could not resolve hostname example.invalid: Name or service not known'],
  ['dns_failed', 'ssh: Could not resolve hostname example.invalid: No such host is known.'],
  ['ssh_unavailable', 'spawn ssh.exe ENOENT'],
  ['ssh_unavailable', 'spawn ssh ENOENT'],
  ['remote_command_failed', '/bin/sh: hostname: not found'],
];
for (const [code, stderr] of errors) {
  test(`classifies ${code}: ${stderr.split('\n')[0]}`, async () => {
    const result = await check({ status: 'failed', exitCode: 255, stdout: '', stderr });
    assert.equal(result.ok, false); assert.equal(result.code, code);
    assert.equal(result.detail, stderr, 'full bounded stderr must be retained');
    assert.equal(result.output, ''); assert.ok(result.message.length > 0);
  });
}

test('runner timeout outranks earlier marker and authentication text', async () => {
  const result = await check({ ...healthy, status: 'timed_out', exitCode: 0, stderr: 'Permission denied (publickey).' });
  assert.equal(result.ok, false); assert.equal(result.code, 'network_timeout');
  assert.equal(result.output, healthy.stdout); assert.equal(result.detail, 'Permission denied (publickey).');
});

test('an early marker never makes a nonzero, cancelled or unfinished task successful', async () => {
  for (const patch of [{ exitCode: 1 }, { status: 'cancelled' }, { status: 'running' }, { exitCode: null }]) {
    const result = await check({ ...healthy, ...patch });
    assert.equal(result.ok, false); assert.equal(result.code, 'remote_command_failed');
  }
});

test('success requires an exact standalone stdout marker and accepts CRLF', async () => {
  for (const stdout of ['', 'prefixSSH_CONTROL_OK\n', 'SSH_CONTROL_OK_suffix\n', 'SSH_CONTROL_OK \n']) {
    assert.equal((await check({ ...healthy, stdout })).ok, false);
  }
  assert.equal((await check({ ...healthy, stdout: 'Banner\r\nSSH_CONTROL_OK\r\ndeploy\r\nnode\r\nLinux\r\n' })).ok, true);
  assert.equal((await check({ ...healthy, stdout: '', stderr: 'SSH_CONTROL_OK\n' })).ok, false);
});

test('successful check still returns stderr verbatim instead of dropping diagnostic text', async () => {
  const stderr = 'NOTICE: authorized access only\n';
  const result = await check({ ...healthy, stderr });
  assert.equal(result.ok, true); assert.equal(result.detail, stderr);
});

test('spawn failures and rejected task waits return structured failures', async () => {
  assert.equal(typeof testConnection, 'function', 'testConnection export must exist');
  const missing = Object.assign(new Error('spawn ssh.exe ENOENT'), { code: 'ENOENT' });
  const startResult = await testConnection({ start() { throw missing; } }, 't', host);
  assert.equal(startResult.code, 'ssh_unavailable'); assert.equal(startResult.detail, missing.message);
  const waitResult = await testConnection({ start() { return { id: 'x' }; }, async wait() { throw new Error('任务已取消'); } }, 't', host);
  assert.equal(waitResult.code, 'remote_command_failed'); assert.equal(waitResult.ok, false);
  assert.equal(waitResult.detail, '任务已取消');
});