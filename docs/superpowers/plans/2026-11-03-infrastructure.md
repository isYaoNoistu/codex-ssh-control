# SSH Infrastructure Implementation Plan

> **For agentic workers:** Use subagent-driven-development and test-driven-development. Complete each owned module and its security tests before integration.

**Goal:** Deliver the four approved stages: governed connections, recoverable tasks, safe resumable artifact transfer, and integration/compatibility/performance validation.

**Architecture:** Retain system OpenSSH. Separate transport, durable task control and artifact transfer behind the existing Store authorization/approval boundary. Keep the current native sidebar and explicit chat-scoped grants. Remote helpers are per-operation processes, not installed daemons.

**Tech Stack:** Node 24 built-ins and SQLite, system OpenSSH, Python 3 Linux helpers, native MCP Apps HTML, isolated SSH integration fixtures.

## Global constraints

- Never connect to user production hosts for implementation tests.
- No automatic acceptance of unknown/changed host keys; enforce policy on every hop.
- Raw commands remain explicitly approved and cannot claim directory sandboxing.
- New execution fields and transfer source identities participate in approval digests.
- No command replay after ambiguous disconnect; remote task submissions use stable identities.
- Filesystem helpers must fail closed; no fallback from openat2 to string-only checks.
- Artifact transfer governs both local and remote paths; binary transfer is a separate explicitly approved capability.
- Stop, revoke, expiry and configuration changes must not permit final transfer commit or duplicate execution.
- Existing state directory and user settings must migrate without loss. Version/cache publication occurs last.
- All settings are visual; keep immediate native approval and execution-history workflows.
- PTY, password vault and key rotation were identified as separate follow-on projects; this implementation covers the four approved delivery stages.

## Task 1: Transport and host identity

Files: new src/transport.mjs, src/host-keys.mjs, src/capabilities.mjs, focused tests; integrate src/ssh.mjs, connection-test.mjs, host schema and sidebar.

Interfaces: `normalizeConnection(value)` validates optional host.connection; `prepareInvocation(host, command, cwd, {dataDir, platform})` returns `{file,args}` for spawn with shell:false. Transport accepts safe structured jump entries and pinned public keys; native alias mode is explicitly trusted local configuration. Managed mode generates isolated config for all hops. Host-key scans produce candidates only; app-only confirmation saves exact keys. Capability detection reports platform and remote prerequisites.

- [x] Write tests rejecting host/option injection, unknown key replacement, unsafe jumps and invalid options.
- [x] Implement managed config, per-hop strict keys, keepalive/timeouts, bounded pooling on supported platforms, errors and read-only capability probes.
- [x] Verify existing SSH tests and new transport tests, including Windows lack of native multiplexing.

## Task 2: Persistent task engine

Files: new src/job-service.mjs, remote/task_guard.py, task tests. Core interface receives `execute(host, command, {input,timeoutSeconds,maxOutputBytes}) -> Promise<{stdout,stderr,exitCode,status}>` and authorization callbacks; no direct Store dependency.

Create/read/cancel/list/reconcile tasks by opaque IDs owned by a chat. Persist immutable host/operation snapshot and remote identity, not process-local promises. Remote wrapper uses private owned state, deduplicated submission, process-group identity validation, bounded logs and atomic result recording. Output API uses byte cursors and explicit truncation. Runtime state and observation uncertainty are distinct. Persist leases without releasing unknown running tasks blindly.

- [x] Write failure tests for duplicate submission, wrong chat/token, stale PID, timeout and reconnect without command replay.
- [x] Implement remote wrapper and durable local service, then verify real Linux temporary-process tests.
- [x] Integrate approved task submission/control and existing execution history.

## Task 3: Artifact transfer

Files: new src/transfer-service.mjs, src/local-files.mjs, remote/transfer_guard.py, transfer tests. Core receives `spawnRemote(host, command) -> ChildProcess` for streaming and authorization callbacks; it returns opaque transfer IDs and bounded progress/status.

Use remote descriptor-based protected staging, identity-bound resume, prefix and final SHA256, conditional same-filesystem atomic commit. Freeze source identity and approval payload; never place binary payloads in MCP JSON. Govern local paths and reject links/reparse points; do not overwrite via unchecked paths. Add single-file upload/download first, then manifests for bounded recursive transfer, preserving ordinary permissions where supported. Cleanup only owned partials with matching identities.

- [x] Reproduce interrupted transfer, wrong prefix/hash, source changes, path races and revoked commit in tests.
- [x] Implement streaming, resume, progress, cleanup, metadata and recursive manifests.
- [x] Validate 500 MB interrupted transfer against an isolated SSH fixture.

## Task 4: Policy, persistence and MCP integration

Files: src/policy.mjs, src/store.mjs, src/server.mjs, src/operation-display.mjs, protocol tests.

Extend policy with exact/recursive roots, local transfer roots, action-parameter allowlists, controlled env/shell and task/transfer limits. Preserve defaults and migrate old policies. Keep new job and transfer control behind exact operation approvals and startup authorization checks. Add app-only key management/diagnostics and model-safe task/transfer operations. Bind transport configuration and pinned key revisions into host revisions.

- [x] Write migration and approval/revocation tests for new fields and stages.
- [x] Add policy/Store APIs and integrate services with consistent history.
- [x] Verify cancellation, unknown states and fail-closed audit/database errors.

## Task 5: Unified visual management

Files: ui/panel.html and UI tests.

- [x] Add connection/jump/key/capability controls to existing host details.
- [x] Add parameter/local-root/task/transfer limits to permissions editor.
- [x] Add running task/transfer progress, paging, resume and cancel to execution area; no approval queue.
- [x] Verify narrow/wide layouts, accessibility, error and revoked states.

## Task 6: Integration, documentation and release

Files: test/integration, .github/workflows, scripts, README.md, docs/compatibility.md and contracts.

- [x] Add isolated SSH test fixtures for direct/jump, key failures, connection loss, tasks and transfer.
- [x] Add Linux distributions/user modes and client matrix; document VM-only kernel/systemd coverage honestly.
- [x] Record benchmark scripts and measured local results without inventing cross-platform results.
- [x] Run complete Node and Linux helper suites, real SSH and transfer fixtures, and independent security review.
- [x] Merge validated work into main, install new plugin version, verify actual MCP runtime and retained settings, push authorized project update.
