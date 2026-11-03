import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { evaluateOperation, defaultPolicy } from '../src/policy.mjs';
import { normalizeExplanation, operationPresentation, historySnapshot, sanitizeHistoryOutput, createOutputScanner } from '../src/operation-display.mjs';

const host = { id: 'dev', name: '开发环境', hostname: 'example.invalid', sshAlias: '', username: 'deploy', port: 22, identityFile: 'C:/keys/private-key', enabled: true };
const policy = { ...defaultPolicy(), mode: 'approval', roots: [{ id: 'app', path: '/srv/app', read: true, write: true }] };
const evaluation = operation => evaluateOperation(policy, operation);

test('explanations trim, use trusted fallback, and require meaningful purpose for sensitive operations', () => {
  assert.equal(normalizeExplanation('  查看系统状态  '), '查看系统状态');
  assert.equal(normalizeExplanation(undefined, { fallback: '固定诊断' }), '固定诊断');
  assert.equal(normalizeExplanation('第一行\n第二行\t详情'), '第一行\n第二行\t详情');
  for (const value of [undefined, '', 'abc', '   ']) assert.throws(() => normalizeExplanation(value, { required: true }));
  assert.equal(normalizeExplanation('abcd', { required: true }), 'abcd');
  for (const value of ['x'.repeat(1201), 7, {}, 'a\0b', 'a\rb', 'a\x1bb', 'a\x7fb', 'a\u202eb', 'a\u2066b', 'password=fixture', 'Authorization: Bearer fixture']) assert.throws(() => normalizeExplanation(value), JSON.stringify(value));
});

test('presentation distinguishes plugin action meaning, model purpose, request and actual fixed command', () => {
  const result = operationPresentation(evaluation({ kind: 'command', command: 'df -h', cwd: '/srv/app' }), '查看磁盘容量');
  assert.equal(result.explanation, '查看磁盘容量');
  assert.equal(result.requestedCommand, 'df -h');
  assert.match(result.command, /^cd \/ && \/usr\/bin\/env -i /);
  assert.equal(result.cwd, '/');
  assert.equal(result.mutating, false);
  assert.match(result.summary, /磁盘/);
  const status = operationPresentation(evaluation({ kind: 'action', actionId: 'service.status', args: { name: 'app' } }));
  assert.match(status.explanation, /状态/);
  assert.equal(status.requestedCommand, '');
});

test('mutation and raw shell purpose is required, while meaning cannot redefine mutation', () => {
  const mutation = evaluation({ kind: 'action', actionId: 'service.restart', args: { name: 'app' } });
  assert.throws(() => operationPresentation(mutation));
  assert.throws(() => operationPresentation(mutation, '重启'));
  const result = operationPresentation(mutation, '这只是一次只读查询');
  assert.equal(result.mutating, true);
  assert.match(result.summary, /重启/);
  const raw = evaluation({ kind: 'command', command: 'echo hello', cwd: '' });
  assert.throws(() => operationPresentation(raw));
  assert.equal(operationPresentation(raw, '输出测试文字').cwd, '(SSH默认目录)');
  assert.equal(operationPresentation(evaluation({ kind: 'command', command: 'echo hello', cwd: '/srv/app' }), '输出测试文字').cwd, '/srv/app');
});

test('file approval shows original content but history only saves bytes and digest', () => {
  const content = 'hello 中文\n';
  const operation = { kind: 'write', path: '/srv/app/config.txt', content };
  const approved = operationPresentation(evaluation(operation), '更新应用文本配置');
  assert.equal(approved.operation.content, content);
  assert.equal(approved.command, '');
  assert.equal(approved.requestedCommand, '');
  assert.equal(approved.mutating, true);
  const snapshot = historySnapshot(evaluation(operation), '更新应用文本配置', host);
  assert.deepEqual(snapshot.operationSnapshot, { kind: 'write', path: operation.path, bytes: Buffer.byteLength(content), sha256: createHash('sha256').update(content).digest('hex') });
  assert.ok(!JSON.stringify(snapshot).includes(content));
  assert.ok(!JSON.stringify(snapshot).includes('identityFile'));
  assert.ok(!JSON.stringify(snapshot).includes(host.identityFile));
  assert.deepEqual(snapshot.hostSnapshot, { id: 'dev', name: '开发环境', hostname: 'example.invalid', sshAlias: '', username: 'deploy', port: 22 });
});

test('history snapshot redacts recognized sensitive text even in metadata', () => {
  const snapshot = historySnapshot(evaluation({ kind: 'command', command: 'echo password=fixture', cwd: '' }), '输出测试内容', { ...host, name: 'password=fixture' });
  assert.ok(!JSON.stringify(snapshot).includes('password=fixture'));
  assert.ok(!JSON.stringify(snapshot).includes('fixture'));
});

test('history output has a combined 32 KiB UTF-8 cap and preserves code points', () => {
  const result = sanitizeHistoryOutput({ stdout: 'a'.repeat(32767) + '中', stderr: 'error' });
  assert.ok(Buffer.byteLength(result.stdout + result.stderr) <= 32768);
  assert.equal(result.truncated, true);
  assert.equal(result.redacted, false);
  assert.ok(!result.stdout.includes('\uFFFD'));
  assert.ok(result.outputNotice);
  assert.deepEqual(sanitizeHistoryOutput(), { stdout: '', stderr: '', truncated: false, redacted: false, outputNotice: '' });
});

test('known secrets anywhere before truncation hide both streams', () => {
  for (const data of [
    { stdout: 'safe', stderr: 'password=fixture' },
    { stdout: 'x'.repeat(40000) + '\nAuthorization: Bearer fixture', stderr: 'safe' },
    { stdout: 'safe prefix', stderr: '', sensitiveOutput: true },
  ]) {
    const result = sanitizeHistoryOutput(data);
    assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
    assert.equal(result.redacted, true); assert.ok(result.outputNotice);
  }
});

test('scanner catches secrets split across chunks and latches permanently', () => {
  const scanner = createOutputScanner();
  for (const part of ['pass', 'word', '=', 'fix', 'ture']) scanner.push('stdout', part);
  assert.equal(scanner.sensitive, true);
  scanner.push('stdout', 'safe text');
  assert.equal(scanner.sensitive, true);
  for (const value of ['Authorization: Bearer fixture', 'postgres://name:fixture@host/db', '-----BEGIN OPENSSH PRIVATE KEY-----']) {
    const other = createOutputScanner();
    for (const char of value) other.push('stderr', char);
    assert.equal(other.sensitive, true, value);
  }
});

test('scanner checks streams independently and scans unlimited total output with bounded tails', () => {
  const separate = createOutputScanner();
  separate.push('stdout', 'password'); separate.push('stderr', '=fixture');
  assert.equal(separate.sensitive, false);
  const scanner = createOutputScanner();
  for (let i = 0; i < 128; i++) scanner.push('stdout', 'x'.repeat(8192));
  assert.equal(scanner.sensitive, false);
  scanner.push('stderr', 'api_token=fixture');
  assert.equal(scanner.sensitive, true);
});

test('approval command display rejects invisible control and bidirectional spoofing without rewriting', () => {
  for (const command of ['echo hello\x1b[2J', 'echo hello\bworld', 'echo hello\rworld', 'echo \u202etxt', 'echo \u2066txt']) {
    assert.throws(() => operationPresentation(evaluation({ kind: 'command', command, cwd: '' }), '输出测试内容'), JSON.stringify(command));
  }
  const command = "printf 'one\\ntwo'\n\techo three";
  assert.equal(operationPresentation(evaluation({ kind: 'command', command, cwd: '' }), '输出测试内容').requestedCommand, command);
});

test('scanner preserves sensitive prefixes across very long whitespace runs', () => {
  const scanner = createOutputScanner();
  scanner.push('stdout', 'password=');
  for (let i = 0; i < 8; i++) scanner.push('stdout', ' '.repeat(4096));
  assert.equal(scanner.sensitive, false);
  scanner.push('stdout', 'fixture');
  assert.equal(scanner.sensitive, true);
});
