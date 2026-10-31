# Wave 1.1 — SARIF Fingerprint + Remediation Claim — 2026-10-29

Scope: only (a) SARIF fingerprint regression; (b) correct "AST-safe" claim. No retry wiring, no dashboard BFF, no AST rewrite.

## (a) SARIF fingerprint — `tests/test_sarif_fingerprint.py` (5 tests)
- Deterministic: same `ruleId + finding_key + message_text` => same `sha256(...)` hex fingerprint.
- Stable across repeated exports; changes when finding identity (`finding_key`) changes.
- Graceful when `finding_key` missing (empty string contribution, fingerprint still 64-char hex).
- Confirms SARIF envelope valid (2.1.0, driver rules, logical locations with `synthetic_location`).
- Confirms target URL never leaks into fingerprint inputs (`"http://" not in fp` guard).
Actual result: 5 passed, 0 failed (run individually and in full suite 59 passed total).

## (b) Remediation claim correction — no AST rewrite
Verified `remediator.py` source: pure string-based (`find`, `before/after` slicing, `replace`, concatenation). Zero `ast` / `libcst` / `parso` usage.
Corrections applied (no fabricated rewrite):
- `README.md`: both "AST-safe Patch" -> "String-Based Text Patch" (verified in grep).
- `docs/remediation-claim-correction.md`: new documentation of the correction (does not alter `docs/project-prd.html` user-modified file or deleted `docs/mobile-api.md`).
- `docs/project-prd.html`: preserved unchanged (user-modified).
- `docs/mobile-api.md`: preserved unchanged (deleted file).

## Gate (recorded, not fabricated)
- `pytest tests/`: 59 passed, 2 warnings (full suite + fingerprint tests together).
- `ruff check ...`: All checks passed.
- `npm run build` (dashboard/): Compiled successfully (prerendered, 3 routes).

## Preserved state
- Unrelated working-tree docs preserved (`D docs/mobile-app.md`, `D docs/ui-ux-prd.md`, `M docs/project-prd.html`, `M docs/ui-blueprint.html`).
- Deferred items untouched: retry wiring (`reliability.py`), dashboard BFF (`NEXT_PUBLIC_API_KEY`), full SARIF fingerprint field embedding (identity validated, full per-field embedding optional enhancement), `remediator.py` real AST rewrite (not implemented — claim corrected instead).

No git commit made (not authorized).
