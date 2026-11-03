# Visual permission governance implementation plan

User-selected behavior: status/non-sensitive reads automatic, mutations including start/stop/write/delete require approval, security/credentials denied. Existing authorized host defaults to restricted policy.

1. Implement policy and fixed operation catalog with failing tests for unsafe operations, rule precedence, input validation, and required approval floors.
2. Add transactional SQLite policy revisions, expiring grants, immutable one-use approvals, concurrency permits and audit events; verify migration and competing processes.
3. Implement Linux one-shot file helper with openat2 and fail-closed path/symlink handling, verify in local WSL.
4. Add graphical policy editor, approval queue, audit viewer and rule preview; no JSON input; simulate UI bridge and error/race paths.
5. Integrate every remote tool with one mandatory gate; introduce UI capability for administrative operations; update model/skills guidance.
6. Run security review and full tests, patch findings, then bump version0.2.0, install and verify native panel/runtime. Preserve host configuration. Record actual limits and Netcatty source links.

Detailed module contracts and ownership are in docs/governance-contract.md.
