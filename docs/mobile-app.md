# PenGuard Mobile App — Flutter Client Specification

Operator companion app for PenGuard: start scenarios, monitor posture, review episodes and PRs, receive critical alerts. Notification-first, lightweight UI. Full wire contract lives in `docs/mobile-api.md`.

## 1. Tech & Architecture

* **Framework:** Flutter (Dart 3), Material 3 dark theme matching web dashboard (`#06080F` background, cyan `#06b6d4` accent, `JetBrains Mono` for telemetry).
* **State:** Riverpod + `StateNotifier` per feature (`PostureNotifier`, `EpisodesNotifier`, `DispatchNotifier`). Single `ApiClient` (Dio) injecting `X-API-Key` from `--dart-define=PENGUARD_API_KEY` / secure storage.
* **Realtime:** `web_socket_channel` to `/ws/episodes`; auto-reconnect with backoff; fallback to 5s `GET /api/episodes` polling when WS drops (same strategy as web).
* **Push:** `firebase_messaging` + deep links `penguard://episode/{id}` carrying `episode_id` + `pr_url`.
* **PDF:** `GET /api/reports/compliance` → cache in temp dir → native share sheet (`share_plus`).

## 2. Screens (4 tabs + detail)

| # | Screen | Content | Source |
|---|---|---|---|
| 1 | Posture Home | Gauge (`score` 0–100), status pill (`HEALTHY/DEGRADED/CRITICAL`), active vs mitigated counts, last-audit time | `GET /api/posture` |
| 2 | Dispatch | Scenario picker (8 vectors with CVSS/severity/CWE from `GET /api/scenarios`), target URL field (empty = sandbox), Dispatch button with `X-API-Key` | `POST /api/episodes/run` |
| 3 | Episodes Feed | Reverse-chron list: attack label + severity chip + `200→403` + score + patch state; pull-to-refresh | `GET /api/episodes` / WS push |
| 4 | Episode Detail | Header badges, `cvss_score/severity/cwe`, target endpoint, Initial/Patch/Re-test cards, remediation text, expandable logs, `VIEW PULL REQUEST` button (only when `pr_url` starts with `http`), Copy JSON | `GET /api/episodes/{id}` |
| 5 | Settings | Base URL override, API key field (obscured), Clear history (confirm dialog → `DELETE /api/episodes`) | local + API |

## 3. Key Behaviors

* **Dispatch flow:** validate URL (or empty) → `POST` with key → on `200` navigate to detail of returned `episode`; on `401` show "Invalid API key" prompting Settings.
* **Realtime:** WS array frame replaces feed; single-object frame upserts one episode; `ping` frames ignored.
* **Offline:** cache last feed + posture in Hive; show stale banner; queue nothing (dispatch requires connectivity).
* **Severity colors:** HIGH = rose, MEDIUM = amber, patched = emerald — same tokens as web.

## 4. Acceptance Criteria (MVP)

* [ ] Cold start → posture gauge renders from `/api/posture` in < 2s on LTE.
* [ ] Dispatch XSS with empty target → detail opens with `200→403`, remediation, and PR button when `pr_url` is a URL.
* [ ] Killing the WS → feed keeps updating via polling with no crash.
* [ ] 401 with wrong key → clear error + deep link to Settings.
* [ ] Release build size < 30 MB (Android APK, `--split-per-abi`).