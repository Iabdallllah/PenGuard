# PenGuard Mobile API & Streaming Specification (Flutter Client)

This document defines the client-server contract between the PenGuard mobile application (Flutter) and the FastAPI backend deployed on Railway.

---

## 1. Network Topology & Transport Protocols

* **REST Base URL:** `https://heroic-insight-production-d97d.up.railway.app`
* **WebSocket Streaming URL:** `wss://heroic-insight-production-d97d.up.railway.app/ws/episodes`
* **Authentication Header:** `X-API-Key: <PENGUARD_API_KEY>` (required on `POST /api/episodes/run` and `DELETE /api/episodes`; all `GET` routes are open)

---

## 2. Core REST Endpoints

| Method | Route | Description | Flutter Usage |
| --- | --- | --- | --- |
| `GET` | `/api/posture` | Real-time security posture score $S(t)$, active vulnerabilities count, and status. | Dashboard Header & Gauge Chart |
| `GET` | `/api/episodes` | List all historical scan and remediation episodes (supports pagination). | Audit Trail & Incident Feed |
| `POST` | `/api/episodes/run` | Trigger an autonomous Red/Blue execution run. | `Dispatch Scenario` Action Button |
| `GET` | `/api/episodes/{id}` | Detailed trace of an episode (logs, payload, diff, and PR link). | Episode Detail Screen |
| `DELETE` | `/api/episodes` | Purge telemetry and episode ledger from PostgreSQL. | Reset / Purge Action |
| `POST` | `/api/episodes/{id}/approve` | Approve the attached GitHub PR via official review (requires `X-API-Key`; 409 if no PR or still running). | Approve Button (Episode Detail) |
| `GET` | `/api/scenarios` | List 8 OWASP vectors with CVSS/severity/CWE. | Scenario Picker |
| `GET` | `/api/reports/compliance` | Returns dynamic binary PDF audit report. | PDF Viewer / Native Share Sheet |

---

## 3. Request & Response Payload Schemas

### Trigger Scenario (`POST /api/episodes/run` — requires `X-API-Key` header)

```json
// Request Body
{
  "scenario": "xss",
  "target_url": "http://127.0.0.1:8001"
}
// scenario ∈ {idor, sql_injection, business_logic, xss, csrf, ssrf, broken_auth, misconfig}
// target_url may be "" (isolated sandbox)

// Response (202 Accepted)
{
  "status": "QUEUED",
  "episode_id": "02effdae-5412-4c22-b91b-877717bc42b0",
  "timestamp": "2026-09-10T00:05:00Z"
}
// The run continues in background; completion is pushed over WS /ws/episodes
// (poll GET /api/episodes as fallback). Only one run at a time — a second
// dispatch while QUEUED/RUNNING returns 409.
```

### Approve PR (`POST /api/episodes/{id}/approve` — requires `X-API-Key` header)

```json
// Response (200 OK)
{
  "status": "approved",
  "episode_id": "02effdae-5412-4c22-b91b-877717bc42b0",
  "pr_number": 4,
  "pr_url": "https://github.com/Iabdallllah/PenGuard/pull/4",
  "review_url": "https://github.com/Iabdallllah/PenGuard/pull/4#pullrequestreview-123"
}
// 404 unknown id · 409 still running or no PR attached (only XSS yields real
// PRs) · 503 GitHub not configured · 502 review call failed. Idempotent.
```

### Security Posture (`GET /api/posture`)

```json
// Response (200 OK)
{
  "score": 92.5,
  "status": "HEALTHY",
  "active_vulnerabilities": 1,
  "mitigated_vulnerabilities": 7,
  "last_audit_timestamp": "2026-09-10T00:00:12Z"
}
```

### Episode Ledger Details (`GET /api/episodes/{id}`)

```json
// Response (200 OK)
{
  "id": "02effdae-5412-4c22-b91b-877717bc42b0",
  "scenario": "A03:2021 · Cross-Site Scripting (XSS)",
  "state": "PATCHED",
  "cvss_score": 6.1,
  "exploit_payload": "<script>alert(1)</script>",
  "target_file": "target_app.py",
  "pr_url": "https://github.com/Iabdallllah/PenGuard/pull/4",
  "ci_status": "PASSED",
  "logs": [
    "[INFO] Scanning target endpoints...",
    "[EXPLOIT] Reflected payload verified at /api/search?q=...",
    "[BLUE] Generated AST-safe patch preserving TransferPayload",
    "[GIT] PR #4 created and preview deployment passed"
  ]
}
```

---

## 4. Real-Time Streaming Contract (WebSocket)

The Flutter client maintains a persistent WebSocket connection to receive asynchronous agent progress and metric updates without polling.

* **Connection Handshake:**
```text
GET /ws/episodes HTTP/1.1
Host: heroic-insight-production-d97d.up.railway.app
Upgrade: websocket
Connection: Upgrade
```
* Server pushes the full episode ledger (JSON array) on connect and after every run; 30s `ping` keepalive otherwise. Client falls back to `GET /api/episodes` polling if WS fails.

* **Event Schema (Server $\to$ Client JSON Frame):**
```json
{
  "event": "AGENT_STEP",
  "episode_id": "02effdae-5412-4c22-b91b-877717bc42b0",
  "stage": "REMEDIATION",
  "status": "IN_PROGRESS",
  "message": "Generating defensive patch via Blue Agent LLM...",
  "timestamp": 1788998700
}
```

* **Standard Event Types:**
* `RECON_DISCOVERED`: New attack surface or endpoint crawled.
* `EXPLOIT_VERIFIED`: Red Agent confirmed vulnerability exploitability.
* `PR_OPENED`: Pull request generated on GitHub.
* `POSTURE_UPDATED`: System posture score recalculated.

---

## 5. Push Notifications Architecture (FCM Webhook)

Critical, high-severity events trigger out-of-band notifications via Firebase Cloud Messaging (FCM):

* **Trigger Conditions:** Detection of critical vulnerabilities ($\text{CVSS} \ge 8.0$) or failed CI builds on auto-generated remediation PRs.
* **Payload:** Contains `episode_id` and `pr_url` to enable Flutter deep linking directly to the affected incident screen.
