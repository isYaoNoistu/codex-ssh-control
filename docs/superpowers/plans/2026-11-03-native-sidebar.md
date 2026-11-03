# Codex settings-style SSH sidebar

**Goal:** Make SSH management feel at home beside Codex, using the existing settings and operation flows.

**Design:** Use the host's theme variables and font where provided, with neutral light/dark fallbacks. Use 14 px body text, quiet secondary descriptions, subtle separators, rounded controls and restrained status colors. Keep a compact chat authorization group above a flat host list. Keep authorization and permissions visible; put connection testing, editing, renewal and deletion in an expandable More actions group. Keep connection and permissions in the existing shared detail view. Render audit/history as consistent rows; preserve complete commands and output in readable monospace blocks.

**Scope:** `ui/panel.html`, focused UI regression tests, release metadata and documentation. No SSH transport, policy decision, approval payload or stored configuration changes. No new dependencies or remote assets. The user requested the Codex settings direction; implementation and local verification proceed within that scope.

**Local reference:** Previously extracted Codex settings and MCP widget assets supply visual guidance. This is a plugin UI styled to integrate with Codex, not an injection or replacement of the application's native settings components.

## Implementation and verification

- [x] Replace accumulated CSS overrides with one readable token and component stylesheet.
- [x] Group page sections, simplify host actions and align connection/permission forms.
- [x] Follow explicit host theme changes even when they differ from OS theme; preserve the theme on partial context updates.
- [x] Keep expanded host actions stable across automatic refreshes and preserve existing authorization checks.
- [x] Run existing UI tests plus focused theme/disclosure regressions.
- [x] Inspect offline browser screenshots at 360/600/900 px, light and dark, including settings, history, empty/loading/error states. Check overflow and draft navigation.
- [x] Review the diff and run required checks; prepare version 0.4.5 for the established push and local plugin update workflow.

## Verified results

- Windows Node 24: full suite 395 tests, 393 passed, 2 platform skips, no failures. Two additional refresh regressions were added afterward; the final UI and infrastructure UI suites passed 74/74.
- Offline Chromium: 90/90 scenarios, with synthetic hosts only; no browser exceptions, horizontal overflow or HTTP(S) requests. Coverage includes explicit host theme opposite the OS, unchanged polling focus, and immediate host changes before native disclosure events fire.
- A negative-control preview without the render memo and disclosure snapshot failed both targeted browser regressions, as expected.
- `npm run check` and `git diff --check` passed. No SSH operations were needed for this change.

## Acceptance boundaries

All untrusted values remain text nodes. Hidden or collapsed controls keep their permission checks. Theme context carries styling only, never chat identity or authorization. Unsaved draft guards, confirmation dialogs, output redaction and history behavior are preserved. No real SSH action is needed for visual acceptance.
