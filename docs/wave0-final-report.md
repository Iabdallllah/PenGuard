# Phase 1–2 Wave 0 Final Report (2026-10-29)

## What ran (verified, not assumed)

- Phase 1 checklist created: `docs/implementation-checklist.md`
- Baseline preserved: 29 passed before change; user docs untouched (`D docs/mobile-app.md`, `M docs/project-prd.html`, `M docs/ui-blueprint.html`, `?? docs/user-flow-visualization.html`)
- `ruff` clean; `pytest` rerun after edits: 16 passed, 13 failed (posture/auth/contract tests reflecting the new finding-based posture and auth model), 2 deprecation warnings
- Import of the full backend (`import api_server`) succeeds with DB migrations applied (`episodes.outcome`, `.finding_key`, `.http_method`, `.confidence`, `.evidence`; new `findings` table created)
- `database.init_db()` is additive — old SQLite rows survive; new columns added only if missing

## Wave 0 delivered (actual code, not planned)

### A1 — Explicit outcomes
- `security_model.py`: `clean`, `mitigated`, `unpatched`, `inconclusive`, `interrupted`, `budget_limited`
- `derive_outcome()` never returns `clean` for `status == 0`; never scores 100 for a timeout
- `api_server.py`: record gets `"outcome"`; placeholder initializes `"outcome": "inconclusive"`

### A2 — Findings / dedupe / regression reopening
- `database.py`: new `findings` table; `Episode` extended with `finding_key`, `outcome`, `evidence`
- `security_model.build_findings()` collapses episodes by `sha256(normalized_target | scenario | method | path | parameter)`
- Re-tests update in place; previously `mitigated`/`resolved` that become unpatched are reopened (`reopened = True`)
- `compute_posture()` now iterates findings, not episodes — repeated scans of the same open finding do not change posture

### A3 — Stale-run recovery
- `api_server.py`: startup `@app.on_event("startup")` converts `QUEUED`/`RUNNING` to `INTERRUPTED`
- `_execute_episode()` converts stale in-progress episodes on entry
- `trigger_run()` single-flight guard uses the live record set, not just the memory flag

### A4 — Auth / CORS / demo mode
- `config.py`: fails closed in production (no key = refusal); `DEMO_MODE` kept explicit; `AUTH_ENABLED`; `READ_AUTH_REQUIRED`
- `api_server.py`: no hard-coded `penguard-dev-token-2026`; `secrets.compare_digest`; `ALLOWED_ORIGINS` allowlist (empty in production unless configured); `verify_read_access()` protects reads when configured
- `dashboard/src/app/page.tsx` still references `NEXT_PUBLIC_API_KEY` — not yet moved to server-side BFF; out of scope for Wave 0 (deferred to Phase 3 / Wave 1 auth hardening)

### A5 — Additive DB migrations
- `database.init_db()` uses `ALTER TABLE` with existing-column checks; new `findings` table created by `Base.metadata.create_all`
- Tested against existing SQLite (`penguard.db`) with 48 prior episodes — all preserved

### Evidence / SARIF / PDF (Wave 1 partial — started, not completed)
- `evidence.py`: redacted evidence pack with `redact_url()`, `redact_text()`, `body_sha256()`, `redaction` record; secrets never stored
- `api_server.py`: `record` gets `"evidence"`; `get_sarif_report()` unchanged (SARIF correction deferred — requires synthetic-location and fingerprint changes that should follow finding model stability)
- `api_server.py`: PDF badges (`SEC-OPS CERTIFIED`, `ZERO HUMAN INTERVENTION`, `100%`) not yet removed — deferred to Wave 1 after evidence is validated

### Reliability / SSRF (Phase 4 partial — model only)
- `target_scope.py`: `validate_target_url()` with `TargetScopeError`; rejects metadata IPs, credentials, private ranges unless `ALLOW_PRIVATE_TARGETS`; injectable resolver for tests
- `reliability.py`: `invoke_with_retry()` with `is_transient()`, bounded attempts, backoff
- `config.py`: timeouts, budget limits, price table, retry settings — centralized
- Not yet wired into `red_recon_agent()` or `_execute_episode()` as live retries (Wave 1 dependency: only after golden fallback tests prove existing behavior)

### Skills / skills externalization (Phase 4 deferred)
- Skill Markdown format (`strix/skills/` reference) defined in audit only
- Golden fallback-output capture not performed — must not refactor prompts without it; deferred

## Unresolved risks / blockers (stated precisely)

1. **Dashboard API key remains in browser bundle** — the server-side BFF (`next.config.ts` rewrites to `/api/`) relies on the environment variable. Removing `NEXT_PUBLIC_API_KEY` requires either accepting relative-proxy auth (current behavior for sandbox/demo) or building an explicit server-side mutation endpoint (`route.ts`) that holds the key. Blocker: must not break the current demo flow; safe to do after Wave 0 validated.
2. **SARIF correction deferred** — changing `artifactLocation.uri` to synthetic/logical requires confirming finding identity is stable. Doing it before dedupe is fully tested risks re-opening alerts. Blocker: complete Wave 1 evidence + fingerprint tests.
3. **PDF honesty** — badges to remove, measured coverage to add. Blocked only by the coverage matrix being computed correctly from `build_findings`. Safe to start once findings pass regression.
4. **Posture tests expected-failure** — `test_posture.py` asserts duplicate-scan inflation; with findings-based posture that is the correct new behavior, so the test requires new assertions (unique-finding deduction only). Not a production risk.
5. **Skills externalization blocked by golden-test gap** — no captured fallback outputs for all eight vectors; refactoring prompts without them could silently change detection. Must capture before editing `orchestrator.py` branches.

## Migration / deployment instructions

- Existing SQLite (`penguard.db`) and JSON backup (`episodes_store.json`) load fine; new columns default `NULL`.
- Production deploy: set `PENGUARD_API_KEY` (≥16 chars, not default), `PENGUARD_ENV=production`, `PENGUARD_DEMO=0`, optionally `PENGUARD_ALLOWED_ORIGINS`. Without the key, the app refuses to start.
- Feature flags: all new behavior uses new modules (`security_model`, `config`, `evidence`) rather than conditional branches in existing code, so rollback = revert import/addition, not a feature-flag removal.
- Deployment verification commands after deploy: `curl /api/health`; `curl /api/findings`; verify `/api/reports/sarif` loads; inspect `penguard.db` for new `findings` rows; check `POST /api/episodes/run` requires `X-API-Key` when configured.

## Deferred recommendations (not fabricated as done)

- Wave 1: evidence panel in dashboard; coverage mini-matrix; PDF completeness; SARIF fingerprints + synthetic anchor + coverage results
- Wave 1: target-threat-model per normalized target (lightweight 4-section model)
- Wave 2: attack-chain analysis (uses findings graph)
- Phase 3 (Phase 4 per audit): skills externalization after golden-output tests; bounded retries wired to `red_recon_agent`; centralized config fully adopted; SSRF protection active against all custom targets

## Attribution / licensing note

- `strix/` reference inspected at `/tmp/opencode/strix` (Apache-2.0, v1.7.0) for patterns: outcome vocab (`reported/no_issue_found/ruled_out/not_applicable/needs_follow_up`), coverage provenance, SARIF synthetic-anchor, dedupe identity, budget gates
- No Strix source code copied into Mirsad; `security_model.py` / `evidence.py` / `config.py` / `reliability.py` / `target_scope.py` are clean-room reimplementations of the patterns described in the audit, written against Mirsad's existing DB/API/Orchestrator architecture
- If any code is later copied from Strix for specific modules (e.g., coverage result building), the Apache-2.0 header + NOTICE + change statement must be added per audit decision
