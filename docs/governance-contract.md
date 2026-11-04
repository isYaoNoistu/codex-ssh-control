# codex-ssh-control permission governance contract

0.5 presets: newly inserted hosts use readonly, which denies all mutations and arbitrary shell. Existing restricted/approval policies retain their semantics. Explicit app-only, host- and revision-bound native confirmation can select god, which allows arbitrary remote shell without per-command approval and ignores host command deny rules. SSH authentication, expiring chat grants, auditing, recognized output redaction, local artifact confinement and lifecycle fences remain enforced. The ordinary-mode rules below describe behavior outside god.

User requirement: visual configuration, no JSON editing. Non-sensitive reads/status can run automatically; writes, modifications, start/stop/restart/delete require native confirmation; secrets/security resources denied. Reference Netcatty commit 8043178d54599b97bcfe8143f8df5c722d99b7f6 for design only; no copied source. The current operation confirmation and history contract is [interaction-history-contract.md](interaction-history-contract.md).

## Runtime scope

Policy and presentation modules normalize and evaluate operations; Store owns atomic authorization, confirmation tickets, execution leases, audit and history. Server owns trusted chat identity, native elicitation and UI capability checks; runner/file broker use the exact Store permit snapshots. Node >=24, no npm runtime deps. Linux file operations require existing Python3 + openat2; no installed daemon. Tests use temporary databases, simulated SSH and local Linux fixtures, not real user state or servers.

## Policy module exports (independent)
ACTION_CATALOG: [{id,label,description,category,mutating,approvalRequired,defaultDecision,parameters:[{name,label,type:'string'|'integer',required,minimum?,maximum?,default?}]}].
Required IDs (fixed system binaries/clean environment, no user-controlled command text):
connection.test; system.summary; disk.usage; disk.inodes; memory.usage; network.listeners;
docker.containers; docker.stats; docker.disk; system.services; system.failed;
service.status({name}); service.start({name}); service.stop({name}); service.restart({name});
container.start({name}); container.stop({name}); container.restart({name}); container.logs({name,tail?:integer,sinceMinutes?:integer}).
Status actions default allow; mutations and container.logs default ask. The log action is nonmutating but approvalRequired, so policy validation rejects allow and execution always requires confirmation unless denied. tail is 1..1000, default300; sinceMinutes is 1..1440, default15. Reject unknown parameters, nonintegers, null and unsafe names. Existing policy action maps missing container.logs normalize to ask. Security service names (ssh/sshd/firewall/ufw/firewalld/nftables/iptables/fail2ban/auditd etc) cannot be controlled by mutation templates.
DEFAULT_POLICY (or defaultPolicy() returning fresh object):
{mode:'restricted',roots:[],blockedPaths:[],commandRules:[],actions:{[id]:'allow'|'ask'|'deny'},grantMinutes:60,timeoutSeconds:60,maxConcurrent:2,maxOutputKiB:128}.
roots:[{id:string,path:absolute POSIX,read:boolean,write:boolean}] (read includes list; write covers create/replace/delete).
blockedPaths:[absolute POSIX subtree strings].
commandRules:[{id:string,match:'exact'|'prefix'|'contains',pattern:string,decision:'deny'|'ask'}]; no regex. Supplemental rules cannot enable arbitrary shell.
mode='restricted' rejects arbitrary shell except exact safe aliases mapped to catalog; mode='approval' allows requesting raw shell, always ask (never automatic). Clearly this mode does not confine shell internals to directory rules.
validatePolicy(value) -> normalized full policy; reject unknown fields, all invalid saves, mutation allow, numeric bounds grantMinutes 5..1440 / timeoutSeconds1..300 / maxConcurrent1..8 / maxOutputKiB16..128. Root IDs valid slug max48; unique IDs/path; <=64roots,blockedPaths,commandRules; command pattern<=256, nonempty.
normalizeOperation(input) -> canonical validated operation:
{kind:'action',actionId,args:{}}
{kind:'command',command,cwd:''}
{kind:'list'|'read'|'write'|'delete',path,content?}
{kind:'test'}
Reject unknown fields and invalid values; max command16000 chars/file content128KiB.
evaluateOperation(policy,operation) -> {decision:'allow'|'ask'|'deny',code,reason,operation,summary,command?:string,file?:{root:string,relativePath:string,blockedPaths:string[]}}.
All mutating operations have minimum ask. File list/read allow only inside read roots; file write/delete ask only inside write roots. No root = deny. Explicit/core blocked paths always win and can't be approved. Refuse '..', NUL, ambiguous/relative paths, root prefix collisions.
Core sensitive dirs/files deny in all file operations: /proc,/sys,/dev,/run,/etc/ssh,/etc/ssl/private,/etc/shadow,/etc/gshadow,/etc/passwd,/etc/group, plus ANY path segments .ssh,.aws,.azure,.kube,.gnupg,.docker, and file names .env*,id_rsa*,id_ed25519*,*.pem,*.key,*credential*,*secret*. Include exported protected-path helper so the remote helper can mirror these semantics.
Sensitive writes (private-key markers/recognizable credential assignments) deny before approval. Docker auths registry entries containing auth and recognizable Base64 auth fragments are sensitive, including renamed/custom-location configs. Export isSensitiveContent(text) for file-broker read verification. Built-in guard is defense in depth, not a promise to detect every secret at arbitrary locations.
Raw command reject visible sensitive paths and known credential operations; full shell remains explicit advanced escape with mandatory review, not filesystem sandbox.
buildActionCommand(actionId,args) -> fixed shell command with carefully quoted validated params; status output must omit env/config secrets (no generic docker inspect/status logs). The separately approved container.logs template uses the fixed Docker binary/socket/config plus logs --since '<sinceMinutes*60>s' --tail <tail> --timestamps -- '<name>'; no follow, details, arbitrary flags or Shell syntax. Both output streams retain existing sensitivity checks and output limits. See [Docker logs semantics](https://docs.docker.com/reference/cli/docker/container/logs/). Avoid PATH/cwd/hooks as much as practical, use fixed Linux tools + env -i.
resolveSafeCommand(command) -> canonical action op|null for common exact read-only aliases (df -h, docker ps, docker ps -a, docker stats --no-stream, systemctl --failed, etc). No shell token rewriting; complex scripts can't match.
The server uses evaluation.command to run actions and never original string for safe aliases.

## Store and authorization

Preserve listHosts/saveHost/setEnabled/removeHost/requireHost/state/grant/revoke/intents/grantConfirmed. Policies, expiring grants, private native confirmation tickets, execution leases, audit and history share SQLite transactions.

getPolicy(hostId) -> {hostId,revision:number,policy}.
savePolicy(actorThreadId,hostId,policy,expectedRevision) -> same; validate whole object, reject optimistic concurrency conflicts, increment revision, revoke all host grants and invalidate outstanding confirmations atomically with audit.
grant(threadId,ids,{minutes?,source?}={}) -> state; minutes cannot exceed any selected host policy.grantMinutes. Bind exact host revision, policy revision, grant generation and expiresAt. Legacy grants on first migration receive 60min expiry once; reissued/shortcut/native grants honor current policy.
authorizationPreview(hostIds) -> [{host,hostRevision,policyRevision,grantMinutes}] in one transaction. Native host access prompts display this snapshot. grantConfirmed(threadId,expectedHosts,{expectedSnapshots:preview,source:'native'}) compares the complete displayed host set, revisions and duration atomically; an intervening change-and-restore cannot resurrect the old confirmation.
state(threadId) includes hosts/grantedHostIds/shortcutHelp, grants:[{hostId,expiresAt,policyRevision}], policies and internal pendingApprovalCount. Only valid enabled unexpired grants appear in grantedHostIds. The count does not expose a user approval queue. requireHost excludes expired/stale grants.

## Native operation confirmation

beginNativeOperation(threadId,hostId,operation,explanation,promptToken,expectedPolicyRevision) -> ready | pending | denied. Recheck enabled host/current grant/revisions/expiry and normalize/reevaluate policy in the transaction. Normalize explanation; bind the complete canonical operation, including content/cwd, together with explanation in the request hash. A meaningful explanation is required for raw shell and mutating operations; trusted fixed-operation descriptions can supply nonmutating defaults. Explanation does not grant permission.

Allow creates the execution lease, history snapshot and audit atomically. Ask creates a distinct ticket for each invocation, even when operation hashes match. The private random server promptToken is stored only as a hash and never returned. Native pending TTL is min(120sec,grant expiry), with at most16 pending tickets per host/chat. The pending result contains an immutable host/policy/operation/explanation/presentation snapshot for the native prompt, no execution lease.

completeNativeApproval(threadId,approvalId,promptToken,decision:'approve'|'deny'|'cancel') -> ready | denied. Exact owner/nonce/pending state/host revision/policy revision/grant generation/expiry are checked; wrong owner/nonce does not invalidate another prompt. Acceptance reevaluates policy and checks cross-process concurrency, then directly consumes the exact ticket and creates lease+history+audit atomically. There is no separately reusable approved state. ready is {status:'ready',operationId,host,policy,evaluation,presentation}; runner and broker use these transaction snapshots. A rejected, expired, cancelled, stale or busy ticket cannot execute later. Any audit/history write failure rolls back the permit.

Terminal native tickets erase their operation/presentation/explanation bodies after consume/deny/cancel/expire/invalidate; hashes, status and audit metadata remain. Pending file content is temporary local review state, never execution history. Server shutdown cancels its outstanding confirmations; duplicate/late native responses cannot execute. Legacy beginOperation/resolveApproval/listApprovals/getApproval remain Store-only compatibility methods and cannot resolve or consume native tickets. Schema3 invalidates legacy outstanding approvals; no missing output is fabricated.

Host changes/revoke/disable invalidate affected confirmations and mark active permissions stale; already-started remote actions are not undone. Active execution leases last timeoutSeconds+30sec and are counted across SQLite processes.

## Execution history and audit

listAudit({hostId?,threadId?,result?,beforeId?,limit?}={}) -> {items,nextCursor}; default50/max100, latest5000 metadata records. Audit excludes full raw commands, file bodies, arbitrary remote errors and stdout/stderr.

listHistory({hostId?,threadId?,status?,beforeId?,limit?}={}) -> {items,nextCursor}; default50/max100, descending numeric ID cursor. List items contain id,operationId,threadId,hostId,summary,explanation,status,startedAt,finishedAt,exitCode,completionKnown,truncated,redacted,outputNotice, without command/output bodies. getHistory(id) adds hostSnapshot,operationSnapshot,requestedCommand,command,cwd,stdout,stderr,policyRevision. Host snapshots omit key paths. Persist only operations entering execution, not denied or still-waiting requests.

finishOperation(operationId,{status,exitCode?,stdout?,stderr?,truncated?,sensitiveOutput?,reason?,taskId?}) atomically finalizes lease/history/audit. sanitizeHistoryOutput always runs before writes: recognized sensitive output or sensitiveOutput hides both streams; otherwise stdout+stderr combined are capped at32KiB on UTF-8 boundaries. The runner scans incoming output before its own truncation, so recognized secrets in discarded suffixes still hide output. Store metadata notices distinguish truncation, redaction and unknown completion.

History retains500 finished entries within30days plus active records. Expired leases become history unknown/completionKnown=false; one real late result may finalize them, without restoring access. Completion is idempotent. History snapshots never store read/write file bodies, helper code or stdin: file read records safe path/byte-count/result summaries, write records bytes/SHA256. Old output that was not saved cannot be backfilled. Local commands and non-detected output are sensitive state; content detection is not exhaustive secret discovery.

## MCP and user interface

All remote tools share the native gate. Model-visible tools include ssh_permissions, ssh_run_action, ssh_exec, ssh_test_connection and the four managed file tools. ssh_exec/ssh_run_action/ssh_write_file/ssh_delete_file require explanation; read/list/test may use trusted defaults. The agent explains purpose and impact in chat before submitting. Task read/cancel require the exact owner; cancellation remains possible after revocation. File broker output is private to its awaiting call.

Success includes {state,version,...}; denied/cancelled/failed calls return isError=true. When confirmation is required, server immediately requests elicitation/create in the same tool invocation. Prompt order is purpose, target and actual operation, requested original command/full executable command/cwd, or file path/content. Only native acceptance with confirm===true continues the original call. Decline/cancel/timeout/unsupported client causes no execution; there is no queue fallback or manual resubmission after approval. User cancellation invalidates the ticket and late responses are ignored.

App-only tools include ssh_policy_save, ssh_policy_preview, ssh_audit_list, ssh_history_list({hostId?,status?,beforeId?,uiToken}) and ssh_history_get({historyId,uiToken}), plus host/grant administration. History output is absent from model tools and state. Every app-only call requires the per-process random capability injected at '__SSH_UI_TOKEN__'. This protects ordinary model calls under a trusted host, not arbitrary MCP clients able to read the HTML resource, nor processes with same-user OS file access. Rule preview evaluates the draft without SSH execution.

Main navigation: 主机 / 审计 / 执行历史. A single host detail page has 连接设置 / 权限设置 tabs, separate saves, preserved drafts across tabs and policy conflicts, and a discard/keep choice when leaving dirty forms. New hosts must be saved before permissions can be configured. History filters and pages; details show purpose then exact commands and sanitized results, with no replay controls. Running details refresh until settled and stale responses cannot overwrite another selected entry. Render all remote/user strings with textContent.

All settings use Chinese forms/selects; no JSON editor. Read/write directory toggles are separate; core sensitive protection cannot be disabled. Advanced raw shell explains that directory rules cannot confine arbitrary shell internals. Policy save explicitly warns that current grants are revoked. Connection testing may wait for native confirmation: UI timeout180sec, confirmation at most120sec, SSH diagnostic at most20sec.

## Remote file helper
Python3 + Linux openat2, shipped source sent over SSH stdin (no remote install). Protocol JSON {operation,root,relativePath,blockedPaths,...}; the file broker fills these fields from policy, and the caller cannot supply code.
open root with NO_SYMLINKS/NO_MAGICLINKS, children BENEATH+NO_SYMLINKS+NO_MAGICLINKS+NO_XDEV; operate pinned directory/file descriptors; fail closed on unsupported kernel/python; regular files only, nlink==1, no devices/FIFO/sockets. Bounded UTF8 read/list; sensitive content no return. Write: atomic temp in pinned parent + replace; delete regular file only, no recursive dirs. Consider fd directory rename limitation and hostile remote root explicitly out of scope.
Integration tests cover traversal, path-prefix collisions, symlinks, hardlinks, special files and writes outside the allowed root, plus command/tool bypasses, approval binding and races, and schema migration.

## Validation/delivery
Use meaningful authorization, confirmation race, history, UI and integration tests; independent review before install. Do not bump manifest until final code is ready (Codex auto-caches changed versions). Preserve user host configs; default policy remains restricted / no file roots / readonly status allowed / mutations require native confirmation. Final counts and actual installed native UI/runtime evidence belong in compatibility.md, separate from historical verification.
No server changes or real remote writes for implementation testing unless specifically needed and authorized later. Prefer local WSL Linux for helper tests.
