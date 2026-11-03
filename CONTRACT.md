# codex-ssh-control runtime contract

Node >=24; stdio JSON-RPC MCP; native OpenSSH; SQLite shared across MCP processes and hook. No npm runtime dependencies. Permission semantics are specified in [docs/governance-contract.md](docs/governance-contract.md); native confirmation, presentation and history in [docs/interaction-history-contract.md](docs/interaction-history-contract.md).

Version 0.4.0 adds managed transport, durable tasks and governed artifact streams. Their authoritative fields, lifecycle and limitations are in [docs/infrastructure-contract.md](docs/infrastructure-contract.md). Schema5 extends existing state without enabling new permissions. Additional tools: `ssh_capabilities`, `ssh_job_submit/read/list/reconcile/cancel`, `ssh_transfer_prepare/start/read/list/resume/cancel/cleanup/manifest/mkdir`; host-key scan and confirmation are app-only. Background job observation uncertainty does not release execution concurrency. Transfer resume consumes a new exact approval while renewing the original slot. Neither connection loss nor an unknown result authorizes replay.

## Package identity and compatibility

Project, plugin and MCP server name: `codex-ssh-control`. The bundled local marketplace uses the same name; install reference: `codex-ssh-control@codex-ssh-control`. Existing installations must disable `ssh-control@ssh-control-local` before enabling the renamed package, so only one plugin registers its hook and tools.

Persistent data intentionally remains at `~/.codex/ssh-control/`; `SSH_CONTROL_DATA`, `SSH_CONTROL_SKILLS`, generated skill ownership markers, `ssh_*` tool names and `/ssh-*` shortcuts remain compatible. Renaming the package does not reset grants or delete host/policy/history data.

## Identity and authorization

Only host-supplied `_meta.threadId` identifies a chat. Model arguments cannot set thread/session identity. Hook intent also binds trusted session and turn, has a 120-second lifetime, and is consumed once. Forks/subagents have separate grants even when their sessionId matches.

Shortcut grants also snapshot the latest SQLite revocation sequence at recording time. Revocation writes an ordered tombstone for the exact chat/host, even if no grant currently exists. Consumption rejects any older intent targeting a revoked host before granting any member; other chats and hosts are unaffected. Fresh post-revocation intents can authorize normally. Schema4 preserves hosts, policies and valid grants but rejects pending legacy grant intents whose ordering cannot be established.

Hosts store IDs, display names, connection fields, enabled state and monotonically increasing revisions. Key paths are passed to OpenSSH; the plugin does not read private keys. Policy revisions, host revisions, grant generations and expiration bind operation permissions. Policy updates, connection changes, disabling and revoking invalidate affected grants and confirmations. Re-enabling does not restore them. Native host authorization uses a transaction snapshot of the shown hosts, revisions and grant duration; confirmation rejects any intervening change, including change-and-restore races.

`beginNativeOperation(threadId,hostId,operation,explanation,promptToken,expectedPolicyRevision)` is the execution gate. It normalizes input, reevaluates policy and verifies current host/grant/revisions/expiry inside SQLite. An allowed operation atomically acquires a cross-process execution lease, creates history and writes audit. An operation requiring confirmation receives a unique private-nonce-bound ticket for that invocation; identical concurrent requests never share approval. No execution lease/history row is created while awaiting confirmation.

`completeNativeApproval(threadId,approvalId,promptToken,decision)` checks the exact ticket owner, nonce, state, expiry and authorization generation, reevaluates policy and checks concurrency. Approval directly consumes that ticket and creates the lease/history/audit in one transaction. The runner uses the returned `host`, `policy`, `evaluation` and `presentation` snapshots. Audit/history write failure prevents execution. Legacy Store approval APIs remain only for compatibility and cannot approve or consume native tickets.

Raw shell is disabled by default. Known exact aliases execute catalog replacements. Advanced raw shell always asks, has no claim of filesystem confinement, and still rejects recognizable sensitive operations. File actions use the Python/openat2 broker with no unsafe fallback. `explanation` describes purpose and impact; it never changes permission decisions.

## MCP and confirmation

Success: `{content,structuredContent:{state,version,...}}`. Errors use `isError:true`; clients must not interpret a missing task/result as success. An operation requiring confirmation waits for native `elicitation/create` during the original tool call. The prompt shows purpose before the requested command and full executable command, with target/cwd or file path/content. Only explicit acceptance with `confirm:true` continues that same invocation. Decline, cancellation, timeout, stale authorization or missing elicitation support means no execution; the client is not sent to a separate approval queue or asked to retry an approved command. Late/duplicate responses cannot run it.

Model tools: `ssh_manager`, `ssh_status`, `ssh_authorization_sync`, `ssh_request_access`, `ssh_permissions`, `ssh_run_action`, `ssh_exec`, `ssh_test_connection`, `ssh_read_file`, `ssh_write_file`, `ssh_list_directory`, `ssh_delete_file`, `ssh_task_read`, `ssh_task_cancel`.

`ssh_exec`, `ssh_run_action`, `ssh_write_file` and `ssh_delete_file` require `explanation`; read/list/test may use trusted fixed-operation descriptions. The agent states purpose and impact in chat before submitting the tool call. Unknown controls, recognized secrets and invalid explanations are rejected; explanation and exact operation are bound together in the confirmation hash.

App-only: `ssh_host_save`, `ssh_host_remove`, `ssh_host_enabled`, `ssh_grant`, `ssh_revoke`, `ssh_policy_save`, `ssh_policy_preview`, `ssh_audit_list`, `ssh_history_list`, `ssh_history_get`. Every app-only call requires a per-process UI token injected into the UI resource. This supplements trusted host app visibility, not authentication against arbitrary MCP clients that can read the resource.

UI resource: `ui://codex-ssh-control/manager-v1`, MIME `text/html;profile=mcp-app`, thread entrypoint. Main navigation is hosts / audit / execution history. One host detail view contains connection and permission tabs with separate saves and preserved drafts. Policy revision conflicts preserve the draft; draft preview cannot execute SSH. Host/command/file/audit/history data render as text. History has no replay/execution controls.

## Limits and data

Default policy: restricted, no file roots, nonmutating catalog actions allowed, mutations ask, grant60min / timeout60sec / concurrent2 / output128KiB. Maximum file text128KiB; command16000 characters; MCP input1MiB. Native confirmation TTL is min(120sec, grant remaining lifetime), with at most16 pending requests per host/chat. Shutdown cancels outstanding confirmations. Pending rows briefly contain the exact operation for review; all native terminal states erase operation/presentation/explanation bodies while retaining hashes and status. Schema3 invalidates legacy outstanding approvals.

Audit retains5000 metadata records and excludes file body, full raw command and remote stdout/stderr. Execution history is separate: it stores purpose, actual host/operation snapshots, requested/full executed command, status, exit code and sanitized stdout/stderr. Host snapshots exclude key paths. The UI-only list returns metadata; details return the safe snapshot and output. Output is scanned before truncation and capped at32KiB total across both streams; recognized secrets or a runner sensitivity flag hide both streams. Only the most recent500 finished records within30days are retained, plus running records. Old outputs that were never stored cannot be reconstructed.

History never stores file read/write bodies, helper source or stdin: reads store path/byte-count/result metadata; writes store byte count and SHA256. Pending confirmation text is separate short-lived state. Protect the local state directory: history intentionally retains commands and non-detected output. Screening recognizes known patterns and does not guarantee discovery of arbitrary encoded secrets.

`finishOperation` atomically finalizes the lease, sanitized history and audit. Expired leases become history status `unknown` with `completionKnown:false`; one actual late completion may replace that unknown result. This does not restore permissions. File tool stdout stays private to its awaiting broker and cannot be read via task APIs. Remote contents and outputs are untrusted and must never trigger authorization changes.

Native SSH uses BatchMode, strict host verification and the real user known_hosts path. No PTY/password prompting. Fixed actions and catalog aliases ignore host defaultCwd and use `/`. Raw commands with omitted cwd inherit the saved host defaultCwd; explicit cwd overrides it, including an explicit empty string for the SSH login directory. Store resolves omitted defaults inside the same transaction as authorization and policy evaluation, before approval and history snapshots; preview uses the same normalization. Cancel stops the local process; detached remote processes may remain. Revoking access cannot undo work already started.

## Validation

Node tests use temporary SQLite, simulated SSH and UI bridges. Coverage includes migrations, policy precedence, input/command injection, expiring grants, native acceptance/decline/cancellation, exact ticket consumption under process races, stale prompts, rollback on audit/history failure, history retention/redaction, leases, every remote tool gate, private output, UI, shortcuts and skill file ownership. Linux tests exercise real openat2 and filesystem mutations only in isolated temporary fixtures. Final test counts, native UI installation and live SSH evidence are separately recorded in [docs/compatibility.md](docs/compatibility.md).
