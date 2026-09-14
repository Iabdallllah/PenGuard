# PenGuard UI/UX PRD — Dashboard (Web) + Mobile Companion

## 1. Goal & Users

Give a CISO / AppSec lead a 30-second answer to "are we safe right now, and what was fixed?" Primary user: security operator. Secondary: auditor (needs PDF evidence).

## 2. Information Architecture

* **Web (`https://penguardai.vercel.app/`):** Sidebar (Command Center / Attack Ledger / Findings) → Dispatch Bar (base_url + scenario only) → Metrics (Posture Score + grade ring, Completed Loops, Auto-Patches, Sandbox) → Posture Trend + Execution Inspector → Audit & Hardening History (search + All/Threats/Patched + Clear).
* **Mobile:** Posture Home → Dispatch → Episodes Feed → Episode Detail → Settings (see `docs/mobile-app.md`).

## 3. Design System (shared web + mobile)

* **Theme:** dark-only `#06080F` surface, `#0B0F1A` panels, borders `#1E293B`; accent cyan `#06b6d4`, success emerald, warn amber, critical rose.
* **Type:** Inter for UI, JetBrains Mono for telemetry (IDs, endpoints, codes, scores).
* **Status language (never change wording):** `PATCH VERIFIED / UNPATCHED`, `THREAT CONFIRMED / CLEAN`, `VIEW PULL REQUEST`, scores as `n/100`.
* **Severity chips:** HIGH rose, MEDIUM amber, patched emerald; OWASP tag (`A01:2021`…) next to every vector.

## 4. Key Interactions

1. **Dispatch:** pick 1 of 8 scenario chips (label + OWASP + CVSS) → optional target URL (empty = isolated sandbox) → `DISPATCH SCENARIO` → spinner `DISPATCHING...` → inspector auto-selects new episode; errors shown inline (incl. `401 Invalid API Key`).
2. **Inspect:** click any ledger row → Execution Inspector shows vector + OWASP, endpoint, Initial/Patch/Re-test, advisory, expandable numbered logs, `VIEW PULL REQUEST` (only when `pr_url` is an `http` URL, else show `PR Skipped` text), Copy JSON footer.
3. **History hygiene:** `Clear` button (confirm dialog) calls `DELETE /api/episodes`; empty state offers `Dispatch now` focus.
4. **Report:** `EXPORT AUDIT TRAIL` downloads per-operation PDF (`penguard-audit-report.pdf`) generated from the live ledger.
5. **Mobile drawer:** slide-in `300px` panel with `X` close, overlay tap closes, item tap navigates + closes; collapsed rail is desktop-only.

## 5. Responsive Rules

* `≥1280px`: full sidebar `288px` (collapsible to `80px` rail with tooltips).
* `<1024px`: sidebar becomes overlay drawer (`max 85vw`); header keeps menu button + Export; metrics grid `1col → 2col → 4col`.
* No `overflow-hidden` ancestors above dropdowns/popovers (regression: clipped scenario list).

## 6. Accessibility & Robustness

* All icon buttons have `aria-label`; dropdown uses `combobox/listbox/option` roles + Esc/outside-click close.
* No `Date.now()`-style values in SSR render path (hydration); client clocks update via effect with `suppressHydrationWarning`.
* Every mutating call sends `X-API-Key`; `401` surfaces a human message, never a blank state.
* WS-first updates with polling fallback; offline shows stale banner, never fake data.

## 7. Acceptance Criteria (UX sign-off)

* [ ] New user dispatches first scenario in < 60s with only base URL + scenario selected.
* [ ] Ledger row → inspector opens with correct OWASP + `200→403`-style statuses for all 8 vectors.
* [ ] PR button visible only for real `http` URLs; skipped state shows reason text.
* [ ] Mobile drawer opens/closes via menu, `X`, overlay tap, and item tap.
* [ ] `npm run build` passes with zero TS errors; no hydration warnings in console.