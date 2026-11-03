# Controlled Container Logs Implementation Plan

**Goal:** Correct the root-cwd path false positive and add bounded, approved container log reads without changing the native confirmation presentation.

**Architecture:** Extend the existing action catalog and canonical argument validation. Reuse the Store approval snapshot, grant and policy revision checks, command execution, output screening, audit and history. No new approval endpoint or remote agent.

**Tech Stack:** Node.js >=24, SQLite, native OpenSSH, Docker CLI, self-contained sidebar HTML.

## Approved scope

The user approved implementation, tests, GitHub push, local plugin update and a subsequent Jenkins log inspection. Preserve the native grouped cards. Do not widen existing raw Shell policy or automatically change host grants.

- Fix only the extra separator inserted by the path checker for cwd `/`; keep rejection of user-supplied ambiguous paths and protected resources.
- Add `container.logs` with required container `name`; optional integer `tail` (1..1000, default300) and `sinceMinutes` (1..1440, default15).
- Use the existing clean environment, fixed Docker binary/config/socket, and a fixed `logs --since '<seconds>s' --tail <lines> --timestamps -- '<name>'` template. Reject all other parameters.
- Mark the action read-only with `approvalRequired:true`, default ask, policy choices ask/deny, and normal name-whitelist enforcement.
- Keep the complete command and normalized arguments bound to the native approval. Screen both output streams before exposing or saving them; do not claim arbitrary secrets can always be detected.

## Tasks and verification

1. `src/policy.mjs`, `test/policy.test.mjs`: reproduce the root-cwd false positive and missing log action first, then implement. Check allowed aliases, retained raw-shell rejection, protected paths, name/number/unknown-parameter validation, defaulting and mandatory approval.
2. `ui/panel.html`, `test/ui.test.mjs`: show only ask/deny for approval-required reads. Render bounded numeric preview inputs and send JSON numbers; omit cleared optional numbers so server defaults apply. Preview must not execute SSH.
3. `test/container-logs-server.test.mjs`, `test/fixtures/fake-ssh.mjs`: exercise the real RPC approval gate with temporary state and simulated SSH. Assert no execution before confirmation or after cancel/revoke, exact approved command execution, and sensitivity hiding in tool output and history. Test legacy policy maps missing the new action.
4. Update README, governance contract, plugin skill and host-skill template; release version 0.4.4 in package, manifest and server. Preserve native card code.
5. Run `node --test test/*.test.mjs`, `npm run check`, `git diff --check`, and independent review. Use scoped filesystem approval for platform-specific isolated fixture operations when necessary; no real SSH during regression tests.
6. Commit the tested result, fast-forward the main checkout, push main, and install the local plugin using the official Codex CLI. Verify source/remote/installed versions separately from live MCP version.
7. Through the reloaded SSH Control MCP only, check current host authorization and permissions, request the bounded Jenkins log operation, and inspect its returned task output. If the host runtime cannot reload during the turn, report that remaining dependency precisely; never bypass it using local SSH or direct database calls.
