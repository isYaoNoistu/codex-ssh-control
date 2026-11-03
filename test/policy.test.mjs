import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTION_CATALOG, DEFAULT_POLICY, defaultPolicy, validatePolicy, normalizeOperation, evaluateOperation, buildActionCommand, resolveSafeCommand, isProtectedPath, isSensitiveContent } from '../src/policy.mjs';

const configured = (extra = {}) => validatePolicy({ ...defaultPolicy(), roots: [
  { id: 'logs', path: '/var/log/app', read: true, write: false },
  { id: 'app', path: '/srv/app', read: true, write: true },
], ...extra });
const decide = (operation, policy = configured()) => evaluateOperation(policy, operation);

test('defaults grant only reviewed non-mutating actions and no directories', () => {
  const policy = defaultPolicy();
  assert.equal(policy.mode, 'restricted');
  assert.deepEqual(policy.roots, []);
  assert.equal(policy.grantMinutes, 60);
  assert.equal(ACTION_CATALOG.length, 19);
  for (const action of ACTION_CATALOG) {
    assert.equal(typeof action.approvalRequired, 'boolean');
    assert.equal(policy.actions[action.id], action.mutating || action.approvalRequired ? 'ask' : 'allow');
    assert.equal(action.defaultDecision, policy.actions[action.id]);
  }
  policy.actions['system.summary'] = 'deny';
  assert.equal(defaultPolicy().actions['system.summary'], 'allow');
  assert.ok(Object.isFrozen(DEFAULT_POLICY.actions));
});

test('policy validation rejects widening mutations and malformed or unknown settings', () => {
  for (const patch of [
    { mode: 'unrestricted' }, { grantMinutes: 4 }, { grantMinutes: 1441 },
    { timeoutSeconds: 301 }, { maxConcurrent: 0 }, { maxConcurrent: 9 },
    { maxOutputKiB: 15 }, { maxOutputKiB: 129 }, { extra: true },
    { actions: { 'service.start': 'allow' } }, { actions: { unknown: 'allow' } },
    { actions: { 'disk.usage': 'sometimes' } },
    { roots: [{ id: 'app', path: 'relative', read: true, write: false }] },
    { roots: [{ id: 'app', path: '/srv/../etc', read: true, write: false }] },
    { roots: [{ id: 'app', path: '/srv//app', read: true, write: false }] },
    { roots: [{ id: 'app', path: '/srv/app', read: 'true', write: false }] },
    { roots: [{ id: 'app', path: '/srv/app', read: true, write: false, extra: 1 }] },
    { commandRules: [{ id: 'x', match: 'regex', pattern: '.*', decision: 'deny' }] },
    { commandRules: [{ id: 'x', match: 'exact', pattern: 'x', decision: 'allow' }] },
  ]) assert.throws(() => validatePolicy({ ...defaultPolicy(), ...patch }), JSON.stringify(patch));
  assert.throws(() => configured({ roots: [{ id: 'x', path: '/a', read: true, write: false }, { id: 'x', path: '/b', read: true, write: false }] }));
  assert.throws(() => configured({ roots: [{ id: 'x', path: '/a', read: true, write: false }, { id: 'y', path: '/a', read: true, write: false }] }));
  assert.throws(() => configured({ blockedPaths: Array(65).fill('/a') }));
  assert.equal(validatePolicy({}).actions['disk.usage'], 'allow');
});

test('normalization is canonical, rejects unknown fields and malformed paths', () => {
  assert.deepEqual(normalizeOperation({ kind: 'action', actionId: 'disk.usage' }), { kind: 'action', actionId: 'disk.usage', args: {} });
  assert.deepEqual(normalizeOperation({ kind: 'command', command: 'df -h' }), { kind: 'command', command: 'df -h', cwd: '' });
  for (const op of [
    { kind: 'unknown' }, { kind: 'test', command: 'whoami' },
    { kind: 'action', actionId: 'service.start', args: { name: '-x' } },
    { kind: 'action', actionId: 'service.start', args: { name: 'app;id' } },
    { kind: 'action', actionId: 'service.start', args: { name: 'app', other: 'x' } },
    { kind: 'read', path: '/srv/app/a', content: 'ignored' },
    { kind: 'read', path: 'srv/app' }, { kind: 'read', path: '/srv/app/../etc' },
    { kind: 'read', path: '/srv/app/./a' }, { kind: 'read', path: '/srv//app/a' },
    { kind: 'read', path: '/srv/app/\0a' }, { kind: 'read', path: '/srv/app/a\nb' },
    { kind: 'command', command: 'x'.repeat(16001) },
    { kind: 'command', command: 'df -h', cwd: '../' },
    { kind: 'write', path: '/srv/app/a', content: '文'.repeat(45000) },
    { kind: 'delete', path: '/srv/app/a', recursive: true },
  ]) assert.throws(() => normalizeOperation(op), JSON.stringify(op).slice(0, 120));
});

test('directory authorization is component aware and every mutation requires approval', () => {
  assert.equal(decide({ kind: 'read', path: '/var/log/app/info.log' }).decision, 'allow');
  assert.equal(decide({ kind: 'list', path: '/srv/app' }).decision, 'allow');
  assert.equal(decide({ kind: 'write', path: '/srv/app/config.txt', content: 'port=8080' }).decision, 'ask');
  assert.equal(decide({ kind: 'delete', path: '/srv/app/config.txt' }).decision, 'ask');
  for (const path of ['/srv/app-other/a', '/etc/hosts', '/var/log/app-other/a']) assert.equal(decide({ kind: 'read', path }).decision, 'deny');
  assert.equal(decide({ kind: 'write', path: '/var/log/app/a', content: 'hello' }).decision, 'deny');
  assert.equal(decide({ kind: 'read', path: '/srv/app/a' }, defaultPolicy()).decision, 'deny');
  assert.deepEqual(decide({ kind: 'read', path: '/srv/app/sub/a' }).file, { root: '/srv/app', relativePath: 'sub/a', blockedPaths: [] });
  assert.equal(decide({ kind: 'delete', path: '/srv/app' }).decision, 'deny');
});

test('most-specific matching root controls permission and explicit deny always wins', () => {
  const policy = configured({ roots: [{ id: 'app', path: '/srv/app', read: true, write: true }, { id: 'private', path: '/srv/app/internal', read: false, write: false }], blockedPaths: ['/srv/app/cache'] });
  assert.equal(decide({ kind: 'read', path: '/srv/app/internal/a' }, policy).decision, 'deny');
  assert.equal(decide({ kind: 'read', path: '/srv/app/cache/a' }, policy).decision, 'deny');
  assert.equal(decide({ kind: 'read', path: '/srv/app/cache-other/a' }, policy).decision, 'allow');
});

test('protected resources are blocked for every operation even with root permission', () => {
  const policy = configured({ roots: [{ id: 'all', path: '/', read: true, write: true }] });
  for (const path of ['/proc/self/environ', '/sys/kernel/a', '/dev/null', '/run/docker.sock', '/etc/ssh/config', '/etc/ssl/private/a', '/etc/shadow', '/etc/gshadow', '/etc/passwd', '/etc/group', '/home/u/.ssh/config', '/a/.aws/config', '/a/.azure/a', '/a/.kube/config', '/a/.gnupg/a', '/srv/.env', '/srv/.env.production', '/srv/id_rsa.pub', '/srv/id_ed25519', '/srv/cert.pem', '/srv/client.key', '/srv/my-credentials.json', '/srv/secrets.txt']) {
    assert.equal(isProtectedPath(path), true, path);
    for (const kind of ['list', 'read', 'delete', 'write']) assert.equal(decide({ kind, path, ...(kind === 'write' ? { content: 'safe' } : {}) }, policy).decision, 'deny', kind + path);
  }
  assert.equal(isProtectedPath('/etc/passwd-backup'), false);
  assert.equal(isProtectedPath('/srv/app/cache-other', ['/srv/app/cache']), false);
});

test('recognizable secrets are denied before write approval', () => {
  for (const content of ['-----BEGIN OPENSSH PRIVATE KEY-----\nabc', 'password=hunter2', 'export API_TOKEN="abc123"', 'AWS_SECRET_ACCESS_KEY=abc', '{"client_secret":"abc"}', 'Authorization: Bearer abc', 'postgres://user:pass@db/app']) {
    assert.equal(isSensitiveContent(content), true, content);
    const evaluation = decide({ kind: 'write', path: '/srv/app/settings.txt', content });
    assert.equal(evaluation.decision, 'deny');
    assert.equal(evaluation.code, 'SENSITIVE_CONTENT');
  }
  for (const content of ['port=8080', '{"host":"localhost"}', 'password=', 'token: null', '# credential documentation']) assert.equal(isSensitiveContent(content), false, content);
});

test('Docker configuration directories remain protected inside authorized roots', () => {
  const policy = configured({ roots: [{ id: 'home', path: '/home/fixture', read: true, write: true }], mode: 'approval' });
  for (const path of ['/home/fixture/.docker', '/home/fixture/.docker/config.json', '/home/fixture/project/.docker/config.json']) {
    for (const kind of ['list', 'read', 'write', 'delete']) {
      const result = decide({ kind, path, ...(kind === 'write' ? { content: '{}' } : {}) }, policy);
      assert.equal(result.code, 'PROTECTED_PATH', `${kind} ${path}`);
    }
  }
  assert.equal(decide({ kind: 'command', command: 'cat ~/.docker/config.json' }, policy).decision, 'deny');
  assert.equal(decide({ kind: 'read', path: '/home/fixture/.docker-notes/config.json' }, policy).decision, 'allow');
});

test('Docker registry auth content is sensitive even at a custom or renamed path', () => {
  const auth = Buffer.from('fixture-user:fixture-password').toString('base64');
  const config = { auths: { 'registry.example.invalid': { auth } } };
  for (const content of [JSON.stringify(config), JSON.stringify(config, null, 2), JSON.stringify(config).replace('auths', 'a\\u0075ths').replace('"auth"', '"a\\u0075th"'), `output:\n"auth": "${auth}"\nend`]) {
    assert.equal(isSensitiveContent(content), true);
    assert.equal(decide({ kind: 'write', path: '/srv/app/renamed-config.json', content }).code, 'SENSITIVE_CONTENT');
  }
});

test('ordinary auth settings and credential-free Docker configs are not secrets', () => {
  for (const content of ['{"auth":true}', '{"auth":"required"}', '{"auth":"dGVzdA=="}', '{"auths":{}}', '{"auths":{"registry.example.invalid":{}}}', '{"auths":{"registry.example.invalid":{"auth":""}},"credsStore":"desktop"}', '{"auths":{"registry.example.invalid":{"auth":null}}}']) {
    assert.equal(isSensitiveContent(content), false, content);
  }
});

test('actions run only fixed commands in a clean environment', () => {
  for (const action of ACTION_CATALOG) {
    const args = action.parameters.length ? { name: 'my-app' } : {};
    const command = buildActionCommand(action.id, args);
    assert.match(command, /^cd \/ && \/usr\/bin\/env -i /);
    assert.match(command, /PATH=\/usr\/bin:\/bin/);
    assert.ok(!command.includes('inspect'));
    assert.ok(!command.includes('journalctl'));
    assert.equal(decide({ kind: 'action', actionId: action.id, args }).decision, action.mutating || action.approvalRequired ? 'ask' : 'allow');
  }
  assert.match(buildActionCommand('service.status', { name: 'app' }), /show .*--property=/);
  assert.match(buildActionCommand('docker.containers'), /--host unix:\/\/\/var\/run\/docker.sock/);
  assert.match(buildActionCommand('docker.containers'), /--format/);
  assert.throws(() => buildActionCommand('unknown'));
});

test('security service mutations are unconditionally denied', () => {
  for (const name of ['ssh', 'sshd', 'ssh.service', 'sshd@tenant.service', 'ufw', 'firewalld', 'nftables', 'iptables', 'fail2ban', 'auditd', 'polkit', 'apparmor', 'systemd-logind', 'sssd']) {
    for (const actionId of ['service.start', 'service.stop', 'service.restart']) assert.equal(decide({ kind: 'action', actionId, args: { name } }).decision, 'deny', name);
  }
  assert.equal(decide({ kind: 'action', actionId: 'service.status', args: { name: 'sshd' } }).decision, 'allow');
});

test('safe aliases are exact and execute replacement commands, never the original text', () => {
  for (const command of ['df -h', 'df -i', 'free -m', 'docker ps', 'docker ps -a', 'docker stats --no-stream', 'systemctl --failed']) {
    assert.ok(resolveSafeCommand(command), command);
    const result = decide({ kind: 'command', command, cwd: '/srv/app' });
    assert.equal(result.decision, 'allow');
    assert.notEqual(result.command, command);
    assert.match(result.command, /^cd \/ &&/);
  }
  for (const command of [' df -h', 'df -h ', 'df  -h', 'df -h\n', 'df -h; id', 'df -h && id', 'df -h | sh', '$(id)', 'docker inspect app', 'python -c "print(1)"', 'sudo df -h']) {
    assert.equal(resolveSafeCommand(command), null, command);
    assert.equal(decide({ kind: 'command', command }).decision, 'deny', command);
  }
});

test('advanced shell always asks and visible sensitive targets still deny', () => {
  const policy = configured({ mode: 'approval' });
  assert.equal(decide({ kind: 'command', command: 'echo hello > /srv/app/file' }, policy).decision, 'ask');
  for (const command of ['cat /etc/shadow', 'head ~/.ssh/id_rsa', 'cat /srv/app/.env', 'docker inspect app', 'docker secret ls', 'kubectl get secrets', 'aws configure export-credentials', 'printenv', 'sudo -l', 'ssh-keygen -t ed25519']) assert.equal(decide({ kind: 'command', command }, policy).decision, 'deny', command);
});

test('supplemental deny beats ask, can restrict aliases, and never enables raw shell', () => {
  const policy = configured({ commandRules: [{ id: 'ask', match: 'prefix', pattern: 'df', decision: 'ask' }, { id: 'deny', match: 'contains', pattern: '-h', decision: 'deny' }] });
  assert.equal(decide({ kind: 'command', command: 'df -h' }, policy).decision, 'deny');
  assert.equal(decide({ kind: 'command', command: 'df -i' }, policy).decision, 'ask');
  assert.equal(decide({ kind: 'command', command: 'echo hello' }, configured({ commandRules: [{ id: 'ask', match: 'exact', pattern: 'echo hello', decision: 'ask' }] })).decision, 'deny');
  assert.equal(decide({ kind: 'action', actionId: 'disk.usage' }, configured({ actions: { 'disk.usage': 'deny' } })).decision, 'deny');
});

test('security configuration and shell startup resources cannot be accessed', () => {
  for (const path of ['/etc/sudoers', '/etc/sudoers.d/deploy', '/etc/pam.d/login', '/etc/security/access.conf', '/etc/cron.daily/job', '/etc/crontab', '/etc/systemd/system/app.service', '/etc/docker/daemon.json', '/etc/ufw/user.rules', '/etc/nftables.conf', '/etc/iptables/rules.v4', '/home/u/.bashrc', '/home/u/.profile', '/home/u/.zshrc', '/home/u/.config/fish/config.fish']) assert.equal(isProtectedPath(path), true, path);
});

test('visible relative credential paths and quoted sensitive paths are rejected in shell review mode', () => {
  const policy = configured({ mode: 'approval' });
  for (const command of ['cat .env', 'cat .ssh/config', 'cat secrets.txt', 'cat /etc/"shadow"', "cat '/etc/shadow'", 'cat ~/.aws/config', 'cat app/client.key']) assert.equal(decide({ kind: 'command', command }, policy).decision, 'deny', command);
});

test('supplemental rules also cover equivalent catalog action entry points', () => {
  const policy = configured({ commandRules: [{ id: 'docker', match: 'prefix', pattern: 'docker ', decision: 'deny' }, { id: 'df', match: 'exact', pattern: 'df -h', decision: 'ask' }] });
  assert.equal(decide({ kind: 'action', actionId: 'docker.containers' }, policy).decision, 'deny');
  assert.equal(decide({ kind: 'action', actionId: 'disk.usage' }, policy).decision, 'ask');
});

test('environment and credential-management shell operations cannot expose secrets', () => {
  const policy = configured({ mode: 'approval' });
  for (const command of ['env', '/usr/bin/env', 'set', 'export -p', 'declare -x', 'typeset -x', 'gcloud auth print-access-token', 'az account get-access-token', 'docker --context prod inspect app', 'docker container inspect app']) assert.equal(decide({ kind: 'command', command }, policy).decision, 'deny', command);
});

test('root cwd preserves safe aliases and raw shell policy decisions', () => {
  for (const command of ['docker ps', 'df -h', 'free -m']) {
    assert.equal(decide({ kind: 'command', command, cwd: '/' }).code, 'ACTION_ALLOWED', command);
  }
  const operation = { kind: 'command', command: 'docker logs app', cwd: '/' };
  assert.equal(decide(operation).code, 'RAW_SHELL_DISABLED');
  assert.equal(decide(operation, configured({ mode: 'approval' })).code, 'RAW_SHELL_REQUIRES_APPROVAL');
  assert.equal(decide({ kind: 'command', command: 'echo hello', cwd: '/' }, configured({ commandRules: [{ id: 'echo', match: 'exact', pattern: 'echo hello', decision: 'ask' }] })).code, 'RAW_SHELL_DISABLED');
});

test('root cwd does not erase invalid paths or bypass sensitive and blocked paths', () => {
  const policy = configured({ mode: 'approval', blockedPaths: ['/restricted', '/srv/app/cache'] });
  for (const command of ['cat //etc/hosts', 'cat /srv//app/file', 'cat ./file', 'cat ../file', 'cat /srv/./file', 'cat /srv/../file', 'cat /etc/shadow', 'cat .env', 'cat app/.ssh/config', 'cat /restricted/file', 'cat restricted/file', 'cat /srv/app/cache/file', 'echo password=fixture-password', 'docker inspect app']) {
    const result = decide({ kind: 'command', command, cwd: '/' }, policy);
    assert.equal(result.code, 'SENSITIVE_COMMAND', command);
  }
  for (const cwd of ['//', '/srv//app', '/srv/./app', '/srv/../app']) {
    assert.throws(() => normalizeOperation({ kind: 'command', command: 'echo hello', cwd }), cwd);
  }
  assert.equal(decide({ kind: 'command', command: 'cat cache/file', cwd: '/srv/app' }, policy).code, 'SENSITIVE_COMMAND');
  assert.equal(decide({ kind: 'command', command: 'cat restricted-other/file', cwd: '/' }, policy).code, 'RAW_SHELL_REQUIRES_APPROVAL');
  assert.equal(decide({ kind: 'write', path: '/srv/app/settings.txt', content: 'password=fixture-password' }, policy).code, 'SENSITIVE_CONTENT');
});

test('container logs catalog declares bounded optional integers and mandatory approval', () => {
  const action = ACTION_CATALOG.find(item => item.id === 'container.logs');
  assert.ok(action);
  assert.equal(action.mutating, false);
  assert.equal(action.approvalRequired, true);
  assert.equal(action.defaultDecision, 'ask');
  assert.deepEqual(action.parameters.map(({ label, ...parameter }) => parameter), [
    { name: 'name', type: 'string', required: true },
    { name: 'tail', type: 'integer', minimum: 1, maximum: 1000, default: 300, required: false },
    { name: 'sinceMinutes', type: 'integer', minimum: 1, maximum: 1440, default: 15, required: false },
  ]);
  assert.ok(Object.isFrozen(action.parameters));
  for (const parameter of action.parameters) assert.ok(Object.isFrozen(parameter));
});

test('container logs normalizes defaults and produces the exact bounded fixed command', () => {
  const operation = normalizeOperation({ kind: 'action', actionId: 'container.logs', args: { name: 'my-app' } });
  assert.deepEqual(operation, { kind: 'action', actionId: 'container.logs', args: { name: 'my-app', tail: 300, sinceMinutes: 15 } });
  const prefix = 'cd / && /usr/bin/env -i PATH=/usr/bin:/bin HOME=/proc/self/fd LANG=C LC_ALL=C SYSTEMD_PAGER=cat SYSTEMD_COLORS=0 /usr/bin/docker --config /proc/self/fd --host unix:///var/run/docker.sock';
  assert.equal(buildActionCommand('container.logs', { name: 'my-app' }), prefix + " logs --since '900s' --tail 300 --timestamps -- 'my-app'");
  assert.equal(buildActionCommand('container.logs', { name: 'my-app', tail: 1, sinceMinutes: 1 }), prefix + " logs --since '60s' --tail 1 --timestamps -- 'my-app'");
  assert.equal(buildActionCommand('container.logs', { name: 'my-app', tail: 1000, sinceMinutes: 1440 }), prefix + " logs --since '86400s' --tail 1000 --timestamps -- 'my-app'");
  assert.deepEqual(normalizeOperation({ kind: 'action', actionId: 'container.logs', args: { name: 'my-app', tail: 25, sinceMinutes: 30 } }).args, { name: 'my-app', tail: 25, sinceMinutes: 30 });
});

test('container logs rejects missing names, injection and unknown arguments', () => {
  for (const args of [
    undefined, {}, { name: '' }, { name: '-app' }, { name: 'app@host' }, { name: 'app;id' },
    { name: 'app$(id)' }, { name: "app'" }, { name: 'app\nnext' }, { name: '/app' }, { name: 'a'.repeat(129) },
    ...['follow', 'details', 'env', 'since', 'until', 'command', 'args', 'flags'].map(key => ({ name: 'app', [key]: '--follow' })),
  ]) {
    assert.throws(() => normalizeOperation({ kind: 'action', actionId: 'container.logs', args }), /名称|未知字段/, JSON.stringify(args));
    assert.throws(() => buildActionCommand('container.logs', args), /名称|未知字段/, JSON.stringify(args));
  }
});

test('container logs integer limits reject coercion, fractions and non-numeric values', () => {
  for (const [key, maximum] of [['tail', 1000], ['sinceMinutes', 1440]]) {
    for (const value of [0, -1, maximum + 1, 1.5, '5', '1;id', '', null, true, false, NaN, Infinity, {}, []]) {
      const args = { name: 'app', [key]: value };
      assert.throws(() => normalizeOperation({ kind: 'action', actionId: 'container.logs', args }), new RegExp(key), `${key}=${JSON.stringify(value)}`);
      assert.throws(() => buildActionCommand('container.logs', args), new RegExp(key), `${key}=${JSON.stringify(value)}`);
    }
  }
});

test('container logs always needs approval and policy cannot allow it automatically', () => {
  const operation = { kind: 'action', actionId: 'container.logs', args: { name: 'app' } };
  assert.equal(defaultPolicy().actions['container.logs'], 'ask');
  assert.equal(validatePolicy({ actions: { 'disk.usage': 'allow' } }).actions['container.logs'], 'ask');
  for (const mode of ['restricted', 'approval']) {
    const result = decide(operation, configured({ mode }));
    assert.equal(result.code, 'ACTION_REQUIRES_APPROVAL');
    assert.equal(result.decision, 'ask');
    assert.deepEqual(result.operation.args, { name: 'app', tail: 300, sinceMinutes: 15 });
    assert.throws(() => configured({ mode, actions: { 'container.logs': 'allow' } }), /容器日志/);
  }
  assert.equal(decide(operation, configured({ actions: { 'container.logs': 'deny' } })).code, 'ACTION_DENIED');
});

test('container logs honors name allowlists and every command deny entry point', () => {
  const operation = { kind: 'action', actionId: 'container.logs', args: { name: 'app', tail: 50, sinceMinutes: 5 } };
  const policy = configured({ actionArguments: { 'container.logs': { names: ['app'] } } });
  assert.equal(decide(operation, policy).decision, 'ask');
  assert.equal(decide({ ...operation, args: { name: 'other' } }, policy).code, 'ARGUMENT_NOT_ALLOWED');
  for (const name of ['-app', 'app;id', 'app@host']) assert.throws(() => configured({ actionArguments: { 'container.logs': { names: [name] } } }));
  const command = buildActionCommand('container.logs', operation.args);
  for (const [match, pattern] of [['exact', 'container.logs'], ['exact', 'docker logs app'], ['prefix', 'docker logs '], ['exact', command], ['contains', '--tail 50']]) {
    const result = decide(operation, configured({ commandRules: [{ id: 'logs', match, pattern, decision: 'deny' }] }));
    assert.equal(result.code, 'ACTION_DENIED', `${match}: ${pattern}`);
  }
});
