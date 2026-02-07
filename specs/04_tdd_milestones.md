# TDD Milestones (Playwright-Verifiable)

OpenClaw Lite is implemented test-first: each milestone corresponds to a Playwright test.

Run:
```bash
npm test
```

## M0 — Gateway Boot

Done when:
- `GET /lite` renders the Gateway Panel.
- Worker becomes `ready`.

Test:
- `e2e/openclaw_lite/01_gateway_boot.spec.js`

## M1 — Approvals + Logs

Done when:
- Runtime requests an approval.
- Human can approve/reject.
- Runtime logs the decision.

Test:
- `e2e/openclaw_lite/02_approvals.spec.js`

## M2 — Local Checkpoints

Done when:
- Checkpoints are written on chat send.
- Checkpoints are written on `pagehide`.
- Checkpoint history is bounded.

Test:
- `e2e/openclaw_lite/03_checkpoints.spec.js`

## M3 — House Creation + Append

Done when:
- Lite creates a house (client-side ceremony, no server reveals).
- Lite appends an encrypted entry.
- `/house` can unlock and decrypt the entry.

Test:
- `e2e/openclaw_lite/04_house_ceremony_and_append.spec.js`

## M4 — Vault Backup Roundtrip

Done when:
- “Lock + backup” uploads an encrypted vault backup.
- Server pointer updates.
- “Restore” decrypts and restores.

Test:
- `e2e/openclaw_lite/05_vault_backup_roundtrip.spec.js`

## M5 — Device Loss Restore

Done when:
- Clearing browser storage simulates a device wipe.
- Wallet lookup + keyWrap recovery restores house keys.
- Latest vault backup restores full state.

Test:
- `e2e/openclaw_lite/06_device_loss_restore.spec.js`

## M6 — Public Profile + Town Grid

Done when:
- Lite publishes a public profile.
- `/town` renders the profile safely (sanitized).

Test:
- `e2e/openclaw_lite/07_public_profile_town_grid.spec.js`

## M7 — OpenClaw-Compatible Export Zip

Done when:
- Export produces a zip with OpenClaw-compatible layout + manifest.
- Validator accepts it.

Test:
- `e2e/openclaw_lite/08_export_zip.spec.js`

## M8 — PI-AI LLM Integration (No Mocks)

Done when:
- Chat uses PI agent loop + PI-AI provider path.
- Runtime calls the OpenAI-compatible proxy (same origin).

Test:
- `e2e/openclaw_lite/09_pi_ai_llm_integration.spec.js`

## Global Gates (Always-On)

These tests protect “hard requirements”:
- OpenClaw export compatibility: `e2e/13_openclaw_compat_validator.spec.js`
- PI version alignment + pi-mono requirement: `e2e/14_openclaw_lite_pi_versions.spec.js`
- No in-runtime mocks: `e2e/15_openclaw_lite_no_mocks.spec.js`

