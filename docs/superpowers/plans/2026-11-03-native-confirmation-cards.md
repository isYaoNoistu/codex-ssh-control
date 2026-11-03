# Native confirmation cards implementation plan

**Goal:** Replace the hard-to-read ordinary form with native readonly confirmation cards; the user explicitly accepts a click to open the confirmation dialog.

**Architecture:** Keep the existing MCP form and exact required boolean response. Generate the full text fallback and `openai/confirmation` presentation from one set of immutable display entries. No changes to approval identity, policy checks, audit, SSH execution, or sidebar approval routes.

**Tech Stack:** Node.js 24, MCP elicitation, Codex Desktop native presentation version 1, Node tests, isolated replay of shipped renderer functions and CSS.

## Constraints

- The first card contains purpose and target. The second contains full execution content and the one-time confirmation notice.
- Use native normal-size, primary-color values; do not add Markdown/HTML to native plain-text fields or editable command inputs.
- Preserve every character of the approved operation. Chunk large fields without splitting surrogate pairs; encode whitespace-only content explicitly when necessary for native field validation.
- Each native field is at most 10000 UTF-16 units; at most 20 fields. If content cannot fit the field budget, use the complete message in the native scrollable dialog, never a truncated preview.
- A full standard form message remains usable if the client ignores the display extension. Never count viewing/opening the dialog as approval.
- Native X/Escape only collapses this dialog; the Cancel button declines execution. Keep the existing approval timeout and revoke invalidation.

## Work

- [x] Test exact field contents, section indexes, compatibility fallback, long/empty content, and immutable required boolean.
- [x] Implement native operation and host-access presentations in `src/approval-presentation.mjs`; update affected protocol assertions.
- [x] Check approve/cancel/revoke/concurrent requests using the existing RPC suite and simulate the native accepted boolean response.
- [x] Inspect screenshots rendered from the shipped card functions and CSS at desktop and narrow widths, including long content and dark mode.
- [x] Update instructions/docs/version and run release checks.

Delivery verification: commit and push the verified source, install the versioned plugin, and report the actual running version separately from the installed version.
