# 隔离 SSH 集成测试

测试只访问本机 Docker 中临时创建的 sshd。每次生成临时客户端密钥和两个独立 host key；容器使用随机名称与专用标签、独立网络，仅将 sshd 发布至 `127.0.0.1` 的随机端口，不挂载用户数据。跳板通过该独立网络访问目标。结束时只清理本次标签匹配的容器和网络以及本次构建的镜像，不使用 Docker prune。被强制中断时，可能需要根据输出或 `codex.ssh.fixture` 标签人工核对并清理遗留资源。

需要 Node.js 24、系统 OpenSSH 客户端、Docker 和能够拉取基础镜像及安装系统包的网络。运行：

```sh
node --test test/integration/ssh.test.mjs
SSH_INTEGRATION=1 node --test test/integration/runtime.test.mjs
SSH_TRANSFER_INTEGRATION=1 node --test test/transfer-ssh.integration.mjs
SSH_TRANSFER_INTEGRATION=1 SSH_TRANSFER_LARGE_TEST=1 node --test test/transfer-ssh.integration.mjs
SSH_FIXTURE_DISTRO=alpine node --test test/integration/ssh.test.mjs
node test/integration/posix-runner.mjs
node scripts/benchmark-ssh.mjs
SSH_BENCH_COUNT=20 SSH_BENCH_TRANSFER_BYTES=10485760 node scripts/benchmark-ssh.mjs
```

PowerShell 使用 `$env:SSH_FIXTURE_DISTRO='alpine'` 设置变量。支持选择 `debian`、`ubuntu`、`alpine`、`rocky`、`openeuler`，CI 分别运行；矩阵配置本身不代表各平台已经实际通过，需查看对应作业结果。客户端普通测试运行于 Windows、Linux、macOS；真实 SSH 矩阵的客户端是 Linux。Docker 使用宿主共享内核，因此不能证明旧内核、独立虚拟机、systemd 或其他客户端操作系统的兼容性。

fixture API：`createFixture({distro:'debian'})` 返回 `host(user, {viaJump, pooling})`、临时 `key`、`containers` 和 `cleanup()`；调用者必须在 `finally` 中执行清理。所有密钥均为一次性测试密钥。测试覆盖 root/普通用户直连和跳板、逐跳错误 host key、能力探测、POSIX 控制连接，以及远端接受任务后主动终止本地 SSH 进程并协调。此测试不等价于主机掉电。

`posix-runner.mjs` 在同一临时网络中创建独立 Linux 客户端；工作树和临时密钥目录均以只读方式挂载，客户端将测试密钥复制到私有 `/tmp` 后运行。它验证 Node 测试、跳板连接池和真实控制连接，并输出新建及复用连接的五次延迟。客户端容器和镜像均为本轮专用。

基准输出 JSON，包含每次 noop 的实测耗时、平均值以及可选的原始 SSH 上传吞吐；上传计时包括连接建立，不是传输服务的端到端测试。Windows 不测连接复用。结果依赖机器、镜像、负载和 Docker 环境，不能作为跨平台性能保证。

本机记录（2026-11-03，Windows 客户端、Docker Desktop Debian 容器、3 次、无传输）：新建连接 noop 分别为 126.28、128.95、129.06 ms，平均 128.10 ms；连接复用未测。该样本仅证明这次环境的测量结果。

同日独立 Linux 客户端容器（Node v24.22.2，Docker Desktop，Debian 目标，通过 ProxyJump，5 次）：新建连接平均 150.41 ms，已建立的 ControlMaster 连接平均 13.33 ms。先通过 `ssh -O check` 验证 master 存在；测试和基准仅代表该本机环境。

本机验证记录（2026-11-03）：Windows 客户端对 Debian、Ubuntu、Alpine、Rocky 和 openEuler 各运行一次真实 SSH 集成套件，均为 5 项通过、1 项 POSIX 连接池测试按平台跳过。独立 Linux 客户端另行通过跳板复用检查。以上容器共享 Docker Desktop 的 Linux 内核，不构成各发行版独立内核或其他客户端平台的验证。

同日真实 Store/native-approval 模拟确认 → 基础设施 runtime → Windows OpenSSH → Debian 普通用户，4 项通过：能力探测、受管 mkdir0700、持久任务增量/幂等/跨聊天隔离、32 MiB 上传中撤销及重新授权续传。续传保持原操作和单一并发额度，并与下载结果 SHA256 一致。这验证服务门禁与传输，不等同于点击真实 Codex 原生确认界面。

500 MiB 大文件真实 SSH 验收：524288000 字节，上传在 4 MiB 后主动断开，恢复原计划后下载验证完整 SHA256。传输阶段 83.969 秒，客户端峰值 RSS 78131200 字节（约 74.5 MiB）；该成绩来自本机 Docker fixture，包含上传/中断恢复/下载，不是普适网络吞吐保证。最终哈希 `bdf28cce880bf034cada8b93aa354d28b4f290f5d9e197974e120cff44e4c428`。另 16 MiB + 递归逐目录/逐文件流程已通过；内部 receipt 不进入清单。

macOS 本机制品通道当前明确不支持，因未实现等价 ACL/xattr 检查；CI 跳过依赖该能力的文件传输用例，保留平台拒绝和普通路径/SSH/任务测试。未运行 macOS 实机；不能把 CI 配置或 Linux 容器通过当作 macOS 通过。
