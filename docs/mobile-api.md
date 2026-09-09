# PenGuard Mobile API & Streaming Specification (Flutter Client)

This document defines the client-server contract between the PenGuard mobile application (Flutter) and the FastAPI backend deployed on Railway.

---

## 1. Network Topology & Transport Protocols

* **REST Base URL:** `https://heroic-insight-production-d97d.up.railway.app`
* **WebSocket Streaming URL:** `wss://heroic-insight-production-d97d.up.railway.app/ws/telemetry`
* **Authentication Header:** `X-PenGuard-Key: <SECURE_CLIENT_TOKEN>` or `Authorization: Bearer <TOKEN>`

---

## 2. Core REST Endpoints

| Method | Route | Description | Flutter Usage |
| --- | --- | --- | --- |
| `GET` | `/api/posture` | Real-time security posture score $S(t)$, active vulnerabilities count, and status. | Dashboard Header & Gauge Chart |
| `GET` | `/api/episodes` | List all historical scan and remediation episodes (supports pagination). | Audit Trail & Incident Feed |
| `POST` | `/api/scenarios/dispatch` | Trigger an autonomous Red/Blue execution run. | `Dispatch Scenario` Action Button |
| `GET` | `/api/episodes/{id}` | Detailed trace of an episode (logs, payload, diff, and PR link). | Episode Detail Screen |
| `DELETE` | `/api/episodes` | Purge telemetry and episode ledger from PostgreSQL. | Reset / Purge Action |
| `GET` | `/api/report/pdf` | Returns dynamic binary PDF audit report. | PDF Viewer / Native Share Sheet |

---

## 3. Request & Response Payload Schemas

### Trigger Scenario (`POST /api/scenarios/dispatch`)

```json
// Request Body
{
  "scenario_id": "A03-XSS",
  "target_url": "http://127.0.0.1:8001",
  "autonomous_patch": true
}

// Response (202 Accepted)
{
  "status": "QUEUED",
  "episode_id": "02effdae-5412-4c22-b91b-877717bc42b0",
  "timestamp": "2026-09-10T00:05:00Z"
}
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
  "pr_url": "https://github.com/labdallllah/PenGuard/pull/4",
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
GET /ws/telemetry HTTP/1.1
Host: heroic-insight-production-d97d.up.railway.app
Upgrade: websocket
Connection: Upgrade
```

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
