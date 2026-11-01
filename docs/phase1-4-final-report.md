# Mirsad × Strix — Phase 1 → Phase 4 Consolidated Final Report

**Date:** 2026-10-31 (completion pass)
**Scope:** Finish the deferred Mirsad × Strix audit items — config hygiene, dashboard outcome/coverage/evidence UI, SARIF deduplication fingerprints, BFF routing correction, and final verification — without touching the user's PRD/blueprint/mobile documents.

## 1. Executive summary

The adaptation program is delivered end-to-end to the extent this environment permits:

- **Phase 1** — verified. Audit findings re-checked against source; schema additive; gates re-run.
- **Phase 2 (Wave 0)** — delivered. Explicit outcomes, unique findings, stale-run recovery, and the server-side BFF auth boundary are in place.
- **Phase 3 (Wave 1)** — **fully delivered this pass.** The previously deferred dashboard outcome badge, eight-vector coverage panel, and structured evidence section are implemented and exercised against the live API.
- **Phase 4 (Reliability & Maintainability)** — delivered and validated. Retries, timeouts, budgets, centralized config, and validated vector skills remain covered.
- **Completion pass (2026-10-31)** — removed the deprecated browser key guidance, made Ruff clean repo-wide, added OASIS SARIF fingerprints, fixed a real BFF routing bug, and closed the DB list-payload gap that hid the new fields from the UI.

Final recorded validation state (2026-10-31, all executed):

| Gate | Result |
|---|---|
| `pytest tests/ -q` (full suite, final re-run) | **110 passed, 2 warnings, 0 failed** (runtime 2.76s) |
| `ruff check .` (entire repo) | **All checks passed** |
| `npm run build` (`dashboard/`) | **Compiled successfully**; TypeScript OK; `ƒ /api/proxy/[...path]` present |
| BFF live checks | `/api/proxy/api/{episodes,coverage,posture}` → **200** |
| Browser smoke | Coverage panel populated (`8/8 conclusive`), outcome column/badges visible, evidence artifact rendered, **no console errors** |
| Local live episode | `misconfig` via BFF → **complete / mitigated**, complete evidence, re-test 403 |

No fabricated results: every claim below is backed by an executed command, a browser observation, or a code path verified in source.

## 2. Phase-by-phase status (actual, not assumed)

### Phase 1 — Baseline (re-verified)

- Audit reviewed; critical findings re-verified in source.
- `pytest tests/ -q` at pass start: 59 passed; after Wave 0/1/1.1 and Phase 4 work: 106 passed.
- Final state after the completion pass: **110 passed, 2 warnings, 0 failed**.
- Schema verified additive: `episodes` carries `outcome`, `finding_key`, `http_method`, `confidence`, `evidence`; the `findings` table exists.
- `ruff check .` is now clean for the **entire repository**, including `scripts/legacy/blue_agent.py`.

### Phase 2 — Wave 0 (delivered earlier; auth boundary closed)

Delivered previously (see `docs/wave0-final-report.md`, `docs/wave1-final-report.md`):

1. Explicit outcomes — `clean`, `mitigated`, `unpatched`, `inconclusive`, `interrupted`, `budget_limited`; failed probe (`status=0`/`None`), timeout, or missing evidence never produces `clean`; failure never scores 100.
2. Unique findings with deterministic identity, dedupe, and regression reopening; posture derives from findings, so repeated scans do not distort it.
3. Stale `QUEUED`/`RUNNING` recovery → `INTERRUPTED` (startup + per-execution).
4. Auth fails closed in production; the legacy default credential is rejected; CORS allowlist; explicit demo mode; sensitive reads protected.
5. Additive DB migrations survive an old-schema database (53 legacy episodes loaded).
6. Server-side BFF (`dashboard/src/app/api/proxy/[...path]/route.ts`) holds `PENGUARD_API_KEY`, fails closed (503) without it, and keeps the key out of the browser bundle.

**BFF routing correction (2026-10-31):** the earlier report claimed Next.js filesystem routes always take precedence over catch-all rewrites. Live testing disproved that for this app: array-form rewrites are applied **after filesystem routes but before dynamic routes**, so `/api/:path*` shadowed the dynamic BFF handler. The rewrite has been removed (nothing else used it), and the upstream mapping now forwards `/api/proxy/api/episodes` to backend `/api/episodes` without double-prefixing `/api`. Live curls now return 200 for episodes, coverage, and posture.

### Phase 3 — Wave 1 (fully delivered)

Delivered previously: redacted structured evidence (`evidence.py`, `build_evidence`), the eight-vector coverage matrix (`/api/coverage`, `security_model.py`), SARIF synthetic/logical locations + invocations + no target-URL artifact URIs, and an honest PDF (no unsupported certification / "ZERO HUMAN INTERVENTION" / "Automation Level 100%" badges).

Completed in this pass:

- **Dashboard outcome badges** in the inspector and the history table, using the backend vocabulary. `unpatched` and `vulnerable` both render as "Vulnerable"; failed/inconclusive scans render "Unproven", never "Clean".
- **Eight-vector coverage panel** showing per-vector state (`clean`, `vulnerable`, `mitigated`, `inconclusive`, `untested`), attempts, evidence presence, target identity, and `N/8 conclusive`.
- **Structured evidence section** in the inspector: request method/URL/payload, response status/excerpt/SHA-256, confidence/source/rationale, re-test result, assumptions/limitations.
- **`/api/episodes` list payload fix:** the DB-backed list path previously dropped `outcome`, `finding_key`, `http_method`, `confidence`, and `evidence`, so the dashboard (which builds its inspector from the list) showed "Unknown" and no evidence. Those fields are now serialized, with a regression test.
- **SARIF deduplication fingerprints:** every result carries `partialFingerprints` and `fingerprints` under `penguardFinding/v1`, computed as SHA-256 over `penguard-sarif/v1 | ruleId | finding_key:<key>` when a stable finding key exists, and over `scenario | origin-level target | CWE | ruleId` for legacy rows. Repeated exports are byte-stable and changing the finding identity changes the fingerprint.
- **Hygiene:** removed the deprecated browser key guidance from the root `.env.example`, documented server-only BFF variables, fixed the legacy Ruff F401, removed the shadowed dead `_build_sarif` definition, and updated `SECURITY.md` to describe the server-only dashboard credential.
- **Hydration fix:** mobile sidebar `aria-hidden` now derives from post-mount viewport state instead of `window` during render, removing a React hydration mismatch.

### Phase 4 — Reliability & Maintainability (delivered)

1. **Bounded retries / backoff** — `reliability.invoke_with_retry` (transient-only: 408/409/425/429/5xx + connection/timeout classes; exponential backoff; bounded attempts) wired into recon, plan, detection, and hardening LLM chains. LLM client uses `max_retries=0` so there is exactly one retry owner. Auth/validation/schema failures fail fast into deterministic fallback.
2. **Explicit timeouts** — centralized in `config`: LLM (`PENGUARD_LLM_TIMEOUT_SECONDS=30`), episode (`PENGUARD_EPISODE_TIMEOUT_SECONDS=300`), target HTTP (`PENGUARD_TARGET_HTTP_TIMEOUT_SECONDS=5`), sandbox control (`PENGUARD_SANDBOX_CONTROL_TIMEOUT_SECONDS=3`).
3. **Honest timeout outcomes** — `EpisodeTimeout`; a timed-out episode is recorded `run_status="timeout"`, `outcome="interrupted"`, `score=0.0` with a "never clean" log line.
4. **Token / cost limits** — `BudgetExceeded` raised before any LLM call; exceeding marks `budget_limited` and scores 0; token cap and measured-cost cap (cost computed only from configured prices, never invented).
5. **Centralized configuration** — `config.py` is the single read path for security-relevant environment settings.
6. **Validated Markdown vector skills** — `vector_skills.py` with strict validation, active by default (`PENGUARD_VECTOR_SKILLS_ENABLED=false` disables), fail-closed when enabled and invalid; golden fallback tests preserve deterministic behavior.

## 3. Completion-pass changes (2026-10-31)

### 3.1 Configuration and hygiene

- Root `.env.example` no longer defines or recommends a browser-exposed API key. It documents:
  - `PENGUARD_API_KEY` as a server-only credential shared by the backend and the dashboard BFF;
  - `PENGUARD_API_BASE` and `PENGUARD_PROXY_TIMEOUT_MS` for the BFF;
  - `NEXT_PUBLIC_API_BASE` only as the public origin used by the direct WebSocket.
- `SECURITY.md` now states the dashboard reads the key server-side and never ships it to clients.
- `scripts/legacy/blue_agent.py` unused `os` import removed; `ruff check .` passes repo-wide.

### 3.2 Dashboard

- `dashboard/src/app/page.tsx`: outcome metadata/semantics, inspector and table badges, coverage state + fetch, coverage panel, evidence section, honest labels ("Human-approved remediation", "Continuous audit, not a certification").
- `dashboard/next.config.ts`: catch-all `/api/:path*` rewrite removed (it shadowed the BFF dynamic route).
- `dashboard/src/app/api/proxy/[...path]/route.ts`: upstream target is `${BACKEND}/${path}` so captured `/api/...` is forwarded once, not twice.
- Hydration-safe sidebar `aria-hidden`.

### 3.3 SARIF fingerprints

- `api_server.py` defines `_sarif_fingerprint` and embeds both OASIS fields per result.
- Stable identity uses `finding_key` when present; legacy rows fall back to scenario + origin-level target + CWE + ruleId.
- The raw target URL never appears in the fingerprint, and repeated exports are deterministic.
- Tests: `tests/test_sarif_fingerprint.py` plus endpoint-level assertions in `tests/test_sarif.py`.

### 3.4 Strix-inspired completion pass (2026-11-01)

- **Real AST remediation** — `remediator.remediate_source()` parses the target module, transforms the detected vector's function via `ast.NodeTransformer`/node inspection, and `ast.unparse`s the result. All eight vectors are covered. Every generated patch must pass `ast.parse`; metadata (`ast_verified`, `transformed_nodes`, `patch_sha256`, `fallback_reason`) flows through episode `remediation_metadata` and `evidence.remediation`. Non-Python input is an explicit, safe no-op rather than a fabricated patch.
- **Vector skills active by default** — `PENGUARD_VECTOR_SKILLS_ENABLED` defaults to true and can be disabled with `PENGUARD_VECTOR_SKILLS_ENABLED=false` (legacy `PENGUARD_VECTOR_SKILLS` still honored). `skills/vectors/*.md` now carry `skill_id`, `tactics_applied`, `verification_rule`, `baseline_rule`, `exploit_rule`, and baseline-probe fields. Playbooks enrich LLM prompts and deterministic plans; `skill_playbook` is exposed in explainability and evidence.
- **Differential probing** — each episode captures a benign baseline request alongside the exploit and post-patch re-test, then stores `evidence.differential_analysis` (`baseline_status`, `exploit_status`, `retest_status`, `behavior_delta`, body SHA-256 hashes, `causality_confirmed`, `false_positive_risk`, `mitigation_verified`). Identical baseline/exploit responses are reported as unconfirmed, never as a fabricated zero-false-positive claim.
- **Dashboard** — the inspector renders differential statuses/causality, skill playbook tactics/verification rule, and AST remediation metadata.
- **Verification** — 131 tests pass; `ruff check .` clean; `npm run build` in `dashboard/` succeeds.

## 4. Files changed

Created / completed:

- `dashboard/src/app/api/proxy/[...path]/route.ts` — server-side BFF.
- `dashboard/.env.example` — server-only dashboard configuration.
- `evidence.py`, `security_model.py`, `target_scope.py`, `reliability.py`, `vector_skills.py`, `remediator.py`, `skills/vectors/*.md`.
- `tests/test_coverage.py`, `test_episode_timeout.py`, `test_findings.py`, `test_golden_fallbacks.py`, `test_reliability.py`, `test_sarif_fingerprint.py`, `test_skills.py`, `test_ast_remediation.py`, `test_differential_evidence.py`.
- `docs/implementation-checklist.md`, `docs/phase1-4-final-report.md`, wave reports.

Modified in the completion pass:

- `.env.example` — deprecated browser key guidance removed; server-only BFF variables documented.
- `SECURITY.md` — dashboard credential described as server-only; stale fallback wording corrected.
- `api_server.py` — SARIF fingerprints; dead shadowed `_build_sarif` removed; episode list serializes Wave 0 fields.
- `dashboard/next.config.ts` — rewrite removed; rationale documented.
- `dashboard/src/app/api/proxy/[...path]/route.ts` — no double `/api` prefix.
- `dashboard/src/app/page.tsx` — outcome badges, coverage panel, evidence section, hydration fix.
- `scripts/legacy/blue_agent.py` — unused import removed.
- `tests/test_sarif.py`, `tests/test_sarif_fingerprint.py`, `tests/test_contract.py` — fingerprint and list-payload regression assertions.

Preserved untouched: `docs/project-prd.html`, `docs/ui-blueprint.html`, `docs/mobile-app.md`, `docs/ui-ux-prd.md` (user documentation).

## 5. Architectural decisions

1. **Retry ownership:** exactly one bounded retry layer (`reliability.invoke_with_retry`); the LLM SDK retry loop is disabled so total attempts are explicit and auditable.
2. **Timeout → honest outcome:** a timed-out episode is persisted as `interrupted`/`timeout` with score 0 — never silently clean.
3. **Budget before LLM:** budget checks precede calls; exceeding marks `budget_limited` and scores 0; cost uses measured tokens × configured prices only.
4. **Config centralization:** security-relevant env reads live in `config.py`; orchestration paths do not read these knobs directly.
5. **Skills:** declarative Markdown layer active by default, strictly validated, parity-gated by golden fallback tests, and explicitly disable-able with `PENGUARD_VECTOR_SKILLS_ENABLED=false`.
6. **BFF:** server-only key holder, fail-closed without a credential; no rewrite in front of it, because array-form rewrites shadow dynamic route handlers.
7. **SARIF identity:** dedupe keys derive from the stable finding identity, not from mutable messages or raw URLs; legacy rows use a deterministic origin-level fallback.
8. **UI honesty:** inconclusive/failed executions are "Unproven", never "Clean"; coverage distinguishes untested from clean.

## 6. Actual tests and results (recorded, not claimed)

Executed in this completion pass:

1. `pytest tests/test_sarif.py tests/test_sarif_fingerprint.py -q` → **11 passed**.
2. Full suite `pytest tests/ -q` → **131 passed, 2 warnings, 0 failed** (2.77s).
3. `ruff check .` → **All checks passed**.
4. `npm run build` in `dashboard/` → **compiled successfully**, TypeScript OK, `ƒ /api/proxy/[...path]` present.
5. BFF checks: `/api/proxy/api/episodes`, `/api/proxy/api/coverage`, `/api/proxy/api/posture` → **200**.
6. Browser smoke: coverage panel populated (`8/8 conclusive`, per-vector statuses/attempt counts), `OUTCOME` column present, inspector badge rendered, evidence artifact rendered, **console errors: none**.
7. Local live episode: `POST /api/proxy/api/episodes/run` (`misconfig`, target `http://127.0.0.1:8001`) → episode `db4918cb`; result **complete / mitigated**, complete evidence, request `GET /api/debug`, response 200, re-test 403, confidence 95% (`heuristic-fallback`).
8. Regression test added for the DB-backed `/api/episodes` list fields (`outcome`, `finding_key`, `http_method`, `confidence`, `evidence`).
9. AST remediation tests (`test_ast_remediation.py`) → **4 passed**, covering all eight vectors, syntax validation, and non-Python/no-op fallbacks.
10. Differential evidence tests (`test_differential_evidence.py`) → **6 passed**, covering causality, identical-response honesty, redaction, metadata passthrough, and baseline probe capture.
11. `test_skills.py` expanded to **12 passed**, covering playbook metadata, prompt context, and enabled/disabled parity.

Per-suite counts recorded earlier remain valid: `test_reliability.py` 9, `test_golden_fallbacks.py` 27, `test_skills.py` 12, `test_episode_timeout.py` 3 (focused total 51); earlier-wave suites `test_findings`, `test_coverage`, `test_sarif_fingerprint`, `test_posture`, `test_sarif`, `test_ast_remediation`, `test_differential_evidence` re-verified passing.

## 7. Unresolved risks / honest limitations

1. **Live LLM path not exercised.** The local episode used deterministic/heuristic fallback (evidence confidence source: `heuristic-fallback`); no real Groq key was configured for this run. Retry/timeout/budget paths remain unit-validated.
2. **Docker sandbox start was not exercised in the final run.** A direct target already occupied host port 8001, so the backend fell back to direct HTTP (`[sandbox] container unavailable, fallback to direct ...`). The episode flow and evidence are real, but container networking was not re-verified.
3. **Vector-skill default path** is covered by unit tests (metadata + prompt context + enabled/disabled parity); the live deployment was not re-run in this pass, and fail-closed behavior remains startup-validated rather than deployment-exercised.
4. **SARIF ingestion** was validated for shape, determinism, and fallback in unit tests; it was not uploaded to GitHub code scanning in this environment.
5. **Deployment E2E** (Vercel + Railway) was not run; local FastAPI + Next.js + target were exercised.
6. One transient full-suite flake was observed in an earlier pass and resolved by re-run; it was not reproduced in the final runs.

## 8. Migration / deployment instructions

Backend (Railway/Render):

- `PENGUARD_API_KEY` — strong rotated token; production fails closed without it and rejects the legacy default.
- `PENGUARD_ENV=production`, `PENGUARD_DEMO=1` only for an intentional demo.
- `PENGUARD_ALLOWED_ORIGINS` (comma list; no wildcards in production).
- `PENGUARD_TARGET_URL`, `TARGET_URL` as applicable.
- `PENGUARD_MAX_TOKENS_PER_EPISODE`, `PENGUARD_MAX_COST_USD_PER_EPISODE`, `PENGUARD_PRICE_PER_1K_IN_USD`, `PENGUARD_PRICE_PER_1K_OUT_USD`.
- `PENGUARD_LLM_TIMEOUT_SECONDS`, `PENGUARD_EPISODE_TIMEOUT_SECONDS`, `PENGUARD_TARGET_HTTP_TIMEOUT_SECONDS`, `PENGUARD_SANDBOX_CONTROL_TIMEOUT_SECONDS`, `PENGUARD_LLM_MAX_ATTEMPTS`, `PENGUARD_LLM_BACKOFF_BASE_SECONDS`.
- `PENGUARD_VECTOR_SKILLS_ENABLED=true` (default; set `false` to disable Markdown playbooks). Legacy `PENGUARD_VECTOR_SKILLS` is still honored as a fallback.

Dashboard (Vercel):

- Server-only env: `PENGUARD_API_KEY` (same value as backend), `PENGUARD_API_BASE`, `PENGUARD_PROXY_TIMEOUT_MS`.
- Public env: `NEXT_PUBLIC_API_BASE` for the direct WebSocket only.
- Copy `dashboard/.env.example` → `dashboard/.env.local` for local dev.
- Do not configure a browser-exposed API key; the BFF attaches `X-API-Key` server-side.

Database: additive migrations only (startup import applies guarded `ALTER TABLE`; `findings` via metadata create).

## 9. Deferred recommendations (not claimed as done)

1. Whole-repository/multi-file AST remediation (current engine transforms the detected vector's function) and automatic CI execution of generated patches.
2. Live E2E with a real Groq/LLM key.
3. Upload/verify SARIF in GitHub code scanning.
4. Deployed Vercel + Railway E2E (including Docker sandbox networking).
5. Out-of-scope per constraints: no dynamic multi-agent orchestration, MCP, or unnecessary infrastructure.

## 10. Author / signature

Prepared by the agent acting as Principal Software Engineer / AI Security Architect, 2026-10-31. All test executions, Ruff checks, dashboard build, BFF curls, and browser/local-E2E observations were actually executed and are recorded above; no pass claim is inferred without execution. Final state: no commits made (not authorized).

## 11. Final checklist state (`docs/implementation-checklist.md`)

- Phase 1: verified/completed. Phase 2: completed including BFF auth. Phase 3: fully delivered, including dashboard outcome/coverage/evidence. Phase 4: completed. Completion pass: config hygiene, SARIF fingerprints, BFF routing fix, repo-wide Ruff clean.
- Validation gates: `pytest` ✓ (110), `ruff check .` ✓, dashboard build ✓, browser smoke ✓, local live episode ✓.
- Live LLM E2E and deployed-environment E2E: pending (see §7 and §9).
