# Compact chat access and distinct host cards

The 0.4.5 live screenshot shows that the chat-access group takes too much vertical space and the flat host list lacks visible boundaries. Host-provided primary and secondary backgrounds can both be white, so grouping must remain clear without a background-color difference.

## Design

- Replace the large chat-access box with a compact summary: current chat, effective enabled-host count, and an expandable authorization-duration setting. Remove duplicated per-host chips and the visible internal chat identifier. Keep the zero-access explanation.
- Give every host its own bordered, rounded card with spacing between cards. Show name and stable ID, separate connection address and working directory, and a distinct authorization state plus expiry when applicable. Keep authorization and permission actions in a footer and preserve the expandable secondary actions.
- Derive state from host enablement and the authoritative effective grant set: disabled first, then granted, expired, otherwise ungranted. A future grant record without membership in grantedHostIds must not display as authorized. This changes presentation only, not backend permissions.
- Preserve theme integration, stale-response handling, draft guards and unchanged-refresh focus from 0.4.5.

## Verification

Use existing UI/infrastructure suites and focused card-association/state tests. Reuse offline Chromium QA with 1/3/6 synthetic hosts, duplicate display names, distinct IDs, long endpoints, and disabled/expired/ungranted states. Test 360/600/900 px in both themes, including host tokens whose primary and secondary backgrounds are identical. Check disclosure behavior, keyboard focus, card separation, no overflow and no real network requests. Publish and locally install the verified patch through the established project workflow.

## Results

- UI, infrastructure UI and server integration: 78/78 tests passed. Coverage includes exact host-ID targeting with duplicate names, disabled-host precedence, revoked grants with future records, clock-only expiry and duration changes that leave existing grants untouched.
- Offline Chromium: 114/114 cases passed with no browser exceptions, horizontal overflow or HTTP(S) requests. The collapsed summary measured 26.5–28 px high in the narrow/medium fixtures. Card borders and spacing remain visible when primary and secondary surfaces have the same color.
- The browser matrix ran before the final appInfo version string changed from 0.4.5 to 0.4.6; reversing that single string change reproduces the tested source SHA-256. Styling and behavior are identical.
- `npm run check` and `git diff --check` passed. No live SSH command was used for this UI update.
