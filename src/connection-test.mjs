import { performance } from 'node:perf_hooks';

export const CONNECTION_TEST_COMMAND = "printf '%s\\n' 'SSH_CONTROL_OK' && id -un && hostname && uname -s";

const messages = {
  success: 'SSH 连接正常，认证和基础命令检查通过。',
  unknown_host_key: '尚未信任此主机的 SSH 密钥。请核验服务器指纹后，在本机 OpenSSH 中建立信任，再重试。',
  changed_host_key: 'SSH 主机密钥已变化，连接被拒绝。请先核验服务器身份和主机指纹。',
  host_key_verification_failed: 'SSH 主机密钥校验失败，请检查 known_hosts 与服务器指纹。',
  authentication_failed: 'SSH 认证失败，请检查用户名、私钥或 SSH 代理。本工具不会请求密码。',
  key_unavailable: '本机 SSH 私钥不可用，请检查密钥路径、权限和格式。',
  network_timeout: 'SSH 连接或检查超时，请检查主机地址、端口和网络。',
  connection_refused: '目标拒绝 SSH 连接，请检查端口和 SSH 服务是否运行。',
  dns_failed: '无法解析 SSH 主机名，请检查地址和 DNS 设置。',
  ssh_unavailable: '未找到本机 OpenSSH 客户端，请安装 SSH 并确认它在 PATH 中。',
  remote_command_failed: 'SSH 检查未成功完成，请查看错误输出和远端基础命令是否可用。',
};

function classify(task, stderr, stdout, exceptionCode) {
  // A marker can arrive before a later command hangs or fails. Completion is mandatory.
  if (task.status === 'timed_out' || /(?:connection|operation) timed out|connection to [^\r\n]+ timed out|timeout, server [^\r\n]+ not responding|connection timeout|timed out during banner exchange/i.test(stderr)) return 'network_timeout';
  if (task.status === 'completed' && task.exitCode === 0 && stdout.split(/\r?\n/u).includes('SSH_CONTROL_OK')) return 'success';
  if (/REMOTE HOST IDENTIFICATION HAS CHANGED|POSSIBLE DNS SPOOFING DETECTED/i.test(stderr)) return 'changed_host_key';
  if (/no (?:[^\r\n]+ )?host key is known[^\r\n]*strict checking/i.test(stderr)) return 'unknown_host_key';
  if (/host key verification failed/i.test(stderr)) return 'host_key_verification_failed';
  // Local key failures often precede a generic final "Permission denied" message.
  if (/identity file[^\r\n]*(?:no such file|not accessible)|load key[^\r\n]*(?:no such file|permission denied|invalid format)|UNPROTECTED PRIVATE KEY FILE/i.test(stderr)) return 'key_unavailable';
  if (/permission denied|authentication failed|too many authentication failures|no supported authentication methods/i.test(stderr)) return 'authentication_failed';
  if (/connection refused/i.test(stderr)) return 'connection_refused';
  if (/could not resolve hostname|name or service not known|temporary failure in name resolution|nodename nor servname provided|no such host is known/i.test(stderr)) return 'dns_failed';
  if (exceptionCode === 'ENOENT' || /spawn [^\r\n]*ssh(?:\.exe)?[^\r\n]*\bENOENT\b/i.test(stderr)) return 'ssh_unavailable';
  return 'remote_command_failed';
}

export async function testConnection(runner, threadId, host, options={}) {
  const started = performance.now();
  let task, exceptionCode;
  try {
    const pending = runner.start(threadId, host, options.command??CONNECTION_TEST_COMMAND, { cwd: '', timeoutSeconds: Math.min(20, options.timeoutSeconds??20), ...(options.outputLimitBytes===undefined?{}:{outputLimitBytes:options.outputLimitBytes}) });
    task = await runner.wait(threadId, pending.id);
  } catch (error) {
    exceptionCode = error?.code;
    task = { status: 'failed', exitCode: null, stdout: '', stderr: error instanceof Error ? error.message : String(error) };
  }
  options.onComplete?.(task);
  // The runner already bounds these streams. Preserve stderr even on a successful check.
  const detail = typeof task?.stderr === 'string' ? task.stderr : '';
  const output = typeof task?.stdout === 'string' ? task.stdout : '';
  const code = classify(task ?? {}, detail, output, exceptionCode);
  return {
    hostId: host.id,
    ok: code === 'success',
    code,
    message: messages[code],
    detail,
    output,
    checkedAt: new Date().toISOString(),
    durationMs: Math.max(0, Math.round(performance.now() - started)),
  };
}
