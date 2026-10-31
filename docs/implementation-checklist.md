# Implementation Checklist — Mirsad × Strix Adaptation

Working artifact for the phased implementation. Status is updated only after the
corresponding command/test has actually run.

## Phase 1 — Baseline (re-verified 2026-10-31)

- [x] Audit reviewed; critical findings re-verified in source.
- [x] Git status inspected; user documentation changes preserved.
- [x] `pytest tests/ -q` — 110 passed, 2 warnings (full post-Wave-0/1/1.1 + Phase 4 + completion suite, re-run 2026-10-31).
- [x] `ruff check .` — clean across the entire repo (legacy `scripts/legacy/blue_agent.py` F401 fixed).
- [x] Dashboard build baseline verified; re-verify after any UI change.
- [x] Schema/deployment inspected: FastAPI + SQLAlchemy (SQLite/Postgres) + Next.js/Vercel;
      `episodes` has outcome/finding_key/http_method/confidence/evidence and `findings` exists.

## Phase 2 — Wave 0

- [x] Explicit episode outcomes: `clean`, `mitigated`, `unpatched`, `inconclusive`, `interrupted`, `budget_limited`.
- [x] Failed probes, timeouts, and missing detection evidence cannot score 100.
- [x] Unique findings with deterministic identity and dedupe.
- [x] Regression reopens the same finding; posture deducts once per unique open finding.
- [x] Startup recovery converts stale `QUEUED`/`RUNNING` episodes to `INTERRUPTED`.
- [x] Production auth fails closed; no default credential; CORS allowlist.
- [x] API key removed from browser bundle via server-side BFF (this pass).
- [x] Sensitive reads protected in production; explicit demo mode remains.
- [x] Additive migrations survive an old-schema database (53 legacy episodes loaded).
- [x] Backward-compatible `/api/episodes`; new `/api/findings` and `/api/coverage`.

## Phase 3 — Wave 1

- [x] Redacted structured evidence on every confirmed finding.
- [x] Eight-vector coverage matrix distinguishes clean/untested/vulnerable/mitigated/inconclusive.
- [x] SARIF: synthetic/logical locations, deterministic `partialFingerprints` + `fingerprints`, invocations.
- [x] PDF: measured posture/coverage/evidence/completeness/limitations.
- [x] Unsupported certification and automation claims removed.
- [x] Dashboard: outcome badge, eight-vector coverage panel, structured evidence section (completed 2026-10-31).

## Phase 4 — Reliability and maintainability (this pass, 2026-10-30)

- [x] Bounded retries/backoff for transient LLM failures wired into all LLM nodes (`reliability.invoke_with_retry`, LLM retries via `ChatGroq(max_retries=0)`).
- [x] Explicit LLM and episode timeouts; honest fallback outcomes.
- [x] Token/cost limits where measurable (token cap + measured-cost cap, `BudgetExceeded` before LLM calls).
- [x] Centralized configuration (orchestrator reads `config` module, not raw env).
- [x] Target-scope/SSRF validation with explicit lab override.
- [x] Markdown vector skills with golden fallback tests and startup validation (off by default; `PENGUARD_VECTOR_SKILLS=1` fails closed when invalid).

## Phase 5 — Hygiene, dashboard, SARIF, BFF routing (2026-10-31)

- [x] Root `.env.example`: removed deprecated `NEXT_PUBLIC_API_KEY`; documented server-only
      `PENGUARD_API_KEY`, BFF vars (`PENGUARD_API_BASE`, `PENGUARD_PROXY_TIMEOUT_MS`), and the
      public WebSocket base. Cross-referenced with `dashboard/.env.example`.
- [x] `scripts/legacy/blue_agent.py` unused import removed; `ruff check .` clean repo-wide.
- [x] Dashboard outcome badges in the inspector and history table; backend vocabulary mapped to
      clear semantics, and failed/inconclusive scans render "Unproven", never "Clean".
- [x] Eight-vector coverage panel (target, per-vector state, attempts, evidence marker,
      conclusive count) fed by `/api/coverage`.
- [x] Structured evidence section in the inspector: request, response excerpt + SHA-256,
      confidence/source/rationale, re-test status, assumptions/limitations.
- [x] `/api/episodes` list payload now includes `outcome`, `finding_key`, `http_method`,
      `confidence`, and `evidence` from the DB path (previously dropped); regression test added.
- [x] SARIF results carry deterministic `partialFingerprints` and `fingerprints`
      (`penguardFinding/v1`, SHA-256). Primary identity is `finding_key`; legacy rows fall back to
      scenario + origin-level target + CWE + ruleId.
- [x] Removed the shadowed dead `_build_sarif` definition (hygiene).
- [x] BFF routing fixed: removed the `/api/:path*` rewrite (array rewrites run before dynamic
      routes and shadowed `/api/proxy/[...path]`); upstream target no longer double-prefixes
      `/api`. `/api/proxy/api/{episodes,coverage,posture}` all return 200.
- [x] Hydration-safe mobile sidebar `aria-hidden` (viewport state applied after mount).
- [x] Local live E2E: dispatched `misconfig` through the BFF against `target_app`; completed
      `mitigated` with complete evidence, and the inspector rendered the outcome badge and
      evidence artifact with no browser console errors.

## Validation gates

- [x] `pytest tests/ -q` — 110 passed, 2 warnings (includes Phase 4 + completion suites).
- [x] `ruff check .` — all checks passed across the entire repo.
- [x] Dashboard `npm run build` — passed; `ƒ /api/proxy/[...path]` route compiled.
- [x] Old-schema migration test (old ledger loaded; new columns present)
- [x] Repeated-scan posture test
- [x] Secret-redaction test
- [x] SARIF schema validation (shape/fingerprint determinism tests)
- [x] Production auth/CORS negative tests
- [x] Stale-run recovery test (startup + per-execution paths)
- [x] Browser smoke (coverage panel populated, outcome header/badges, evidence artifact visible)

## Final status (2026-10-31, after validation)

- [x] All Phase 4 + completion-pass code paths implemented and covered by tests.
- [x] Full backend suite green; Ruff clean repo-wide; dashboard build green.
- [x] Local live E2E (FastAPI + BFF + dashboard + sandbox fallback target) executed.
- [ ] Live E2E with a real Groq/LLM key (not executed in this environment).

