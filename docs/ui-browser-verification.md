# Infrastructure sidebar browser verification

Verified on 2026-11-03 using the repository's unmodified `ui/panel.html` in Chromium 145.0.7632.6 (Playwright 1.58.2). A loopback-only parent page mocked the MCP App `postMessage` bridge. No real host, secret, or user configuration was used.

The browser exercised:

- Managed connection settings with a jump host; saved settings preserved the jump and confirmed public keys.
- Public-key scanning as untrusted candidates; confirmation remained disabled until the fingerprint checkbox was selected.
- Windows capability results disabling unsupported connection reuse.
- Visual policy editing and saving task limits, shells, environment names, transfer limits, and named action restrictions.
- Task history, raw-output text escaping, incremental byte cursor requests, and exact task cancellation with an explanation.
- Transfer history, byte progress, and the resume action; revoked chat grants disabled controls until a fresh grant was observed.
- A 320 × 900 viewport with no horizontal overflow; desktop checks used 620 × 960.

No browser console errors or uncaught page errors were observed. Screenshots of connection settings, policy settings, task output, and the narrow transfer detail were inspected visually. This verifies browser rendering and bridge payloads; it does not claim that Codex Desktop's native confirmation surface or a deployed plugin was exercised. The server and SSH fixture suites cover the execution boundary separately.

The browser test harness and screenshots were kept as local verification artifacts outside the source repository. The repository's `test/infrastructure-ui.test.mjs` retains deterministic controller-level regression coverage, including stale replies, invalid authorization, output escaping, and confirmation timeouts.
